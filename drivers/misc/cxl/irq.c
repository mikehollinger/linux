/*
 * Copyright 2014 IBM Corp.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#if 1
#define DEBUG
#else
#undef DEBUG
#endif

#include <linux/interrupt.h>
#include <linux/workqueue.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/slab.h>
#include <linux/pid.h>
#include <asm/cputable.h>
#include <misc/cxl.h>

#include "cxl.h"

/* XXX: This is implementation specific */
static irqreturn_t handle_psl_slice_error(struct cxl_context_t *ctx, u64 dsisr, u64 errstat)
{
	u64 fir1, fir2, fir_slice, serr, afu_debug;

	fir1 = cxl_p1_read(ctx->afu->adapter, CXL_PSL_FIR1);
	fir2 = cxl_p1_read(ctx->afu->adapter, CXL_PSL_FIR2);
	fir_slice = cxl_p1n_read(ctx->afu, CXL_PSL_FIR_SLICE_An);
	serr = cxl_p1n_read(ctx->afu, CXL_PSL_SERR_An);
	afu_debug = cxl_p1n_read(ctx->afu, CXL_AFU_DEBUG_An);

	pr_crit("PSL ERROR STATUS: 0x%.16llx\n", errstat);
	pr_crit("PSL_FIR1: 0x%.16llx\n", fir1);
	pr_crit("PSL_FIR2: 0x%.16llx\n", fir2);
	pr_crit("PSL_SERR_An: 0x%.16llx\n", serr);
	pr_crit("PSL_FIR_SLICE_An: 0x%.16llx\n", fir_slice);
	pr_crit("CXL_PSL_AFU_DEBUG_An: 0x%.16llx\n", afu_debug);

	pr_crit("STOPPING CXL TRACE\n");
	cxl_stop_trace(ctx->afu->adapter);

	return cxl_ops->ack_irq(ctx, 0, errstat);
}

irqreturn_t cxl_slice_irq_err(int irq, void *data)
{
	struct cxl_afu_t *afu = data;
	u64 fir_slice, errstat, serr, afu_debug;

	WARN(irq, "CXL SLICE ERROR interrupt %i\n", irq);

	serr = cxl_p1n_read(afu, CXL_PSL_SERR_An);
	fir_slice = cxl_p1n_read(afu, CXL_PSL_FIR_SLICE_An);
	errstat = cxl_p2n_read(afu, CXL_PSL_ErrStat_An);
	afu_debug = cxl_p1n_read(afu, CXL_AFU_DEBUG_An);
	pr_crit("PSL_SERR_An: 0x%.16llx\n", serr);
	pr_crit("PSL_FIR_SLICE_An: 0x%.16llx\n", fir_slice);
	pr_crit("CXL_PSL_ErrStat_An: 0x%.16llx\n", errstat);
	pr_crit("CXL_PSL_AFU_DEBUG_An: 0x%.16llx\n", afu_debug);

	cxl_p1n_write(afu, CXL_PSL_SERR_An, serr);

	return IRQ_HANDLED;
}

irqreturn_t cxl_irq_err(int irq, void *data)
{
	struct cxl_t *adapter = data;
	u64 fir1, fir2, err_ivte;
	int slice;

	WARN(1, "CXL ERROR interrupt %i\n", irq);

	err_ivte = cxl_p1_read(adapter, CXL_PSL_ErrIVTE);
	pr_crit("PSL_ErrIVTE: 0x%.16llx\n", err_ivte);

	pr_crit("STOPPING CXL TRACE\n");
	cxl_stop_trace(adapter);

	fir1 = cxl_p1_read(adapter, CXL_PSL_FIR1);
	fir2 = cxl_p1_read(adapter, CXL_PSL_FIR2);

	pr_crit("PSL_FIR1: 0x%.16llx\nPSL_FIR2: 0x%.16llx\n", fir1, fir2);

	for (slice = 0; slice < adapter->slices; slice++) {
		pr_warn("SLICE %i\n", slice);
		cxl_slice_irq_err(0, &adapter->slice[slice]);
	}

	return IRQ_HANDLED;
}

static irqreturn_t schedule_cxl_fault(struct cxl_context_t *ctx, u64 dsisr, u64 dar)
{
	ctx->dsisr = dsisr;
	ctx->dar = dar;
	schedule_work(&ctx->fault_work);
	return IRQ_HANDLED;
}

static irqreturn_t cxl_irq(int irq, void *data)
{
	struct cxl_context_t *ctx = data;
	struct cxl_irq_info irq_info;
	u64 dsisr, dar;
	int result;

	if ((result = cxl_ops->get_irq(ctx, &irq_info))) {
		WARN(1, "Unable to get CXL IRQ Info: %i\n", result);
		return IRQ_HANDLED;
	}

	dsisr = irq_info.dsisr;
	dar = irq_info.dar;

	pr_devel("CXL interrupt %i for afu pe: %i DSISR: %#llx DAR: %#llx\n", irq, ctx->ph, dsisr, dar);

	if (dsisr & CXL_PSL_DSISR_An_DS) {
		/* We don't inherently need to sleep to handle this, but we do
		 * need to get a ref to the task's mm, which we can't do from
		 * irq context without the potential for a deadlock since it
		 * takes the task_lock. An alternate option would be to keep a
		 * reference to the task's mm the entire time it has cxl open,
		 * but to do that we need to solve the issue where we hold a
		 * ref to the mm, but the mm can hold a ref to the fd after an
		 * mmap preventing anything from being cleaned up. */
		pr_devel("Scheduling segment miss handling for later pe: %i\n", ctx->ph);
		return schedule_cxl_fault(ctx, dsisr, dar);
	}

	if (dsisr & CXL_PSL_DSISR_An_M)
		pr_devel("CXL interrupt: PTE not found\n");
	if (dsisr & CXL_PSL_DSISR_An_P)
		pr_devel("CXL interrupt: Storage protection violation\n");
	if (dsisr & CXL_PSL_DSISR_An_A)
		pr_devel("CXL interrupt: AFU lock access to write through or cache inhibited storage\n");
	if (dsisr & CXL_PSL_DSISR_An_S)
		pr_devel("CXL interrupt: Access was afu_wr or afu_zero\n");
	if (dsisr & CXL_PSL_DSISR_An_K)
		pr_devel("CXL interrupt: Access not permitted by virtual page class key protection\n");

	if (dsisr & CXL_PSL_DSISR_An_DM) {
		/* In some cases we might be able to handle the fault
		 * immediately if hash_page would succeed, but we still need
		 * the task's mm, which as above we can't get without a lock */
		pr_devel("Scheduling page fault handling for later pe: %i\n", ctx->ph);
		return schedule_cxl_fault(ctx, dsisr, dar);
	}
	if (dsisr & CXL_PSL_DSISR_An_ST)
		WARN(1, "CXL interrupt: Segment Table PTE not found\n");
	if (dsisr & CXL_PSL_DSISR_An_UR)
		pr_devel("CXL interrupt: AURP PTE not found\n");
	if (dsisr & CXL_PSL_DSISR_An_PE)
		return handle_psl_slice_error(ctx, dsisr, irq_info.errstat);
	if (dsisr & CXL_PSL_DSISR_An_AE) {
		pr_devel("CXL interrupt: AFU Error %.llx\n", irq_info.afu_err);

		if (ctx->pending_afu_err) {
			/* This shouldn't happen - the PSL treats these errors
			 * as fatal and will have reset the AFU, so there's not
			 * much point buffering multiple AFU errors.
			 * OTOH if we DO ever see a storm of these come in it's
			 * probably best that we log them somewhere: */
			pr_err_ratelimited("CXL AFU Error undelivered to pe %i: %.llx\n",
					ctx->ph, irq_info.afu_err);
		} else {
			spin_lock(&ctx->lock);
			ctx->afu_err = irq_info.afu_err;
			ctx->pending_afu_err = 1;
			spin_unlock(&ctx->lock);

			wake_up_all(&ctx->wq);
		}

		cxl_ops->ack_irq(ctx, CXL_PSL_TFC_An_A, 0);
	}
	if (dsisr & CXL_PSL_DSISR_An_OC)
		pr_devel("CXL interrupt: OS Context Warning\n");

	WARN(1, "Unhandled CXL PSL IRQ\n");
	return IRQ_HANDLED;
}

static irqreturn_t cxl_irq_multiplexed(int irq, void *data)
{
	struct cxl_afu_t *afu = data;
	struct cxl_context_t *ctx;
	int ph = cxl_p2n_read(afu, CXL_PSL_PEHandle_An) & 0xffff;
	int ret;

	rcu_read_lock();
	ctx = idr_find(&afu->contexts_idr, ph);
	if (ctx) {
		ret = cxl_irq(irq, ctx);
		rcu_read_unlock();
		return ret;
	}
	rcu_read_unlock();

	WARN(1, "Unable to demultiplex CXL PSL IRQ\n");
	return IRQ_HANDLED;
}

static irqreturn_t cxl_irq_afu(int irq, void *data)
{
	struct cxl_context_t *ctx = data;
	irq_hw_number_t hwirq = irqd_to_hwirq(irq_get_irq_data(irq));
	int irq_off, afu_irq = 1;
	__u16 range;
	int r;

	for (r = 1; r < CXL_IRQ_RANGES; r++) {
		irq_off = hwirq - ctx->irqs.offset[r];
		range = ctx->irqs.range[r];
		if (irq_off >= 0 && irq_off < range) {
			afu_irq += irq_off;
			break;
		}
		afu_irq += range;
	}
	if (unlikely(r >= CXL_IRQ_RANGES)) {
		WARN(1, "Recieved AFU IRQ out of range for pe %i (virq %i hwirq %lx)\n",
		     ctx->ph, irq, hwirq);
		return IRQ_HANDLED;
	}

	pr_devel("Received AFU interrupt %i for pe: %i (virq %i hwirq %lx)\n",
	       afu_irq, ctx->ph, irq, hwirq);

	if (unlikely(!ctx->irq_bitmap)) {
		WARN(1, "Recieved AFU IRQ for context with no IRQ bitmap\n");
		return IRQ_HANDLED;
	}
	spin_lock(&ctx->lock);
	set_bit(afu_irq - 1, ctx->irq_bitmap);
	ctx->pending_irq = true;
	spin_unlock(&ctx->lock);

	wake_up_all(&ctx->wq);

	return IRQ_HANDLED;
}

unsigned int
cxl_map_irq(struct cxl_t *adapter, irq_hw_number_t hwirq,
		irq_handler_t handler, void *cookie)
{
	unsigned int virq;
	int result;

	/* IRQ Domain? */
	virq = irq_create_mapping(NULL, hwirq);
	if (!virq) {
		pr_warn("cxl_map_irq: irq_create_mapping failed\n");
		return 0;
	}

	if (adapter->driver->setup_irq)
		adapter->driver->setup_irq(adapter, hwirq, virq);

	pr_devel("hwirq %#lx mapped to virq %u\n", hwirq, virq);

	result = request_irq(virq, handler, 0, "cxl", cookie);
	if (result) {
		pr_warn("cxl_map_irq: request_irq failed: %i\n", result);
		return 0;
	}

	return virq;
}

void cxl_unmap_irq(unsigned int virq, void *cookie)
{
	free_irq(virq, cookie);
	irq_dispose_mapping(virq);
}

int cxl_register_psl_err_irq(struct cxl_t *adapter)
{
	int hwirq, virq;

	if ((hwirq = adapter->driver->alloc_one_irq(adapter)) < 0)
		return hwirq;

	if (!(virq = cxl_map_irq(adapter, hwirq, cxl_irq_err, adapter)))
		goto err;

	adapter->err_hwirq = hwirq;
	adapter->err_virq = virq;

	cxl_p1_write(adapter, CXL_PSL_ErrIVTE, adapter->err_hwirq & 0xffff);

	return 0;

err:
	adapter->driver->release_one_irq(adapter, hwirq);
	return -ENOMEM;
}

void cxl_release_psl_err_irq(struct cxl_t *adapter)
{
	cxl_unmap_irq(adapter->err_virq, adapter);
	adapter->driver->release_one_irq(adapter, adapter->err_hwirq);
}

int cxl_register_psl_irq(struct cxl_afu_t *afu)
{
	int hwirq, virq;

	if ((hwirq = afu->adapter->driver->alloc_one_irq(afu->adapter)) < 0)
		return hwirq;

	if (!(virq = cxl_map_irq(afu->adapter, hwirq, cxl_irq_multiplexed, afu)))
		goto err;

	afu->psl_hwirq = hwirq;
	afu->psl_virq = virq;

	return 0;
err:
	afu->adapter->driver->release_one_irq(afu->adapter, hwirq);
	return -ENOMEM;
}

void cxl_release_psl_irq(struct cxl_afu_t *afu)
{
	cxl_unmap_irq(afu->psl_virq, afu);
	afu->adapter->driver->release_one_irq(afu->adapter, afu->psl_hwirq);
}

int afu_register_irqs(struct cxl_context_t *ctx, u32 count)
{
	irq_hw_number_t hwirq;
	int rc, r, i;

	if ((rc = ctx->afu->adapter->driver->alloc_irq_ranges(&ctx->irqs, ctx->afu->adapter, count)))
		return rc;

	/* Multiplexed PSL Interrupt */
	ctx->irqs.offset[0] = ctx->afu->psl_hwirq;
	ctx->irqs.range[0] = 1;

	ctx->irq_count = count;
	ctx->irq_bitmap = kcalloc(BITS_TO_LONGS(count),
				  sizeof(*ctx->irq_bitmap), GFP_KERNEL);
	if (!ctx->irq_bitmap)
		return -ENOMEM;
	for (r = 1; r < CXL_IRQ_RANGES; r++) {
		hwirq = ctx->irqs.offset[r];
		for (i = 0; i < ctx->irqs.range[r]; hwirq++, i++) {
			cxl_map_irq(ctx->afu->adapter, hwirq,
				     cxl_irq_afu, ctx);
		}
	}

	return 0;
}

void afu_enable_irqs(struct cxl_context_t *ctx)
{
	irq_hw_number_t hwirq;
	unsigned int virq;
	int r, i;

	pr_info("Enabling CXL Interrupts\n");

	for (r = 1; r < CXL_IRQ_RANGES; r++) {
		hwirq = ctx->irqs.offset[r];
		for (i = 0; i < ctx->irqs.range[r]; hwirq++, i++) {
			virq = irq_find_mapping(NULL, hwirq);
			enable_irq(virq);
		}
	}
}

void afu_disable_irqs(struct cxl_context_t *ctx)
{
	irq_hw_number_t hwirq;
	unsigned int virq;
	int r, i;

	pr_info("Disabling CXL Interrupts\n");

	for (r = 1; r < CXL_IRQ_RANGES; r++) {
		hwirq = ctx->irqs.offset[r];
		for (i = 0; i < ctx->irqs.range[r]; hwirq++, i++) {
			virq = irq_find_mapping(NULL, hwirq);
			disable_irq(virq);
		}
	}
}

void afu_release_irqs(struct cxl_context_t *ctx)
{
	irq_hw_number_t hwirq;
	unsigned int virq;
	int r, i;

	for (r = 1; r < CXL_IRQ_RANGES; r++) {
		hwirq = ctx->irqs.offset[r];
		for (i = 0; i < ctx->irqs.range[r]; hwirq++, i++) {
			virq = irq_find_mapping(NULL, hwirq);
			if (virq)
				cxl_unmap_irq(virq, ctx);
		}
	}

	ctx->afu->adapter->driver->release_irq_ranges(&ctx->irqs, ctx->afu->adapter);
}
