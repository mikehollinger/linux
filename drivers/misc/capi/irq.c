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
#include <linux/of.h>
#include <asm/cputable.h>

#include "capi.h"

/* XXX: This is implementation specific */
static irqreturn_t handle_psl_slice_error(struct capi_context_t *ctx, u64 dsisr, u64 fir_recov_slice)
{
	u64 fir1, fir2, fir_slice;

	pr_devel("CAPI interrupt: PSL Error (implementation specific, recoverable: %#.16llx)\n", fir_recov_slice);

	if (fir_recov_slice)
		return capi_ops->ack_irq(ctx, 0, fir_recov_slice);

	if (cpu_has_feature(CPU_FTR_HVMODE)) { /* TODO: Refactor */
		pr_crit("STOPPING CAPI TRACE\n");
		capi_stop_trace(ctx->afu->adapter);

		fir1 = capi_p1_read(ctx->afu->adapter, CAPI_PSL_FIR1);
		fir2 = capi_p1_read(ctx->afu->adapter, CAPI_PSL_FIR2);
		fir_slice = capi_p1n_read(ctx->afu, CAPI_PSL_FIR_SLICE_An);

		pr_warn("PSL_FIR1: 0x%.16llx\nPSL_FIR2: 0x%.16llx\nPSL_FIR_SLICE_An: 0x%.16llx\nPSL_FIR_RECOV_SLICE_An: 0x%.16llx\n",
				fir1, fir2, fir_slice, fir_recov_slice);
		return IRQ_HANDLED;
	}

	pr_warn("PSL_FIR_RECOV_SLICE_An: 0x%.16llx\n", fir_recov_slice);
	return IRQ_HANDLED;
}

irqreturn_t capi_slice_irq_err(int irq, void *data)
{
	struct capi_afu_t *afu = (struct capi_afu_t *)data;
	u64 fir_slice, fir_recov_slice, serr;

	WARN(irq, "CAPI SLICE ERROR interrupt %i\n", irq);

	serr = capi_p1n_read(afu, CAPI_PSL_SERR_An);
	fir_slice = capi_p1n_read(afu, CAPI_PSL_FIR_SLICE_An);
	fir_recov_slice = capi_p1n_read(afu, CAPI_PSL_R_FIR_SLICE_An);
	pr_warn("PSL_SERR_An: 0x%.16llx\n", serr);
	pr_warn("PSL_FIR_SLICE_An: 0x%.16llx\n", fir_slice);
	pr_warn("PSL_FIR_RECOV_SLICE_An: 0x%.16llx\n", fir_recov_slice);

	capi_p1n_write(afu, CAPI_PSL_SERR_An, serr);

	BUG(); // we never recover, so let's just die

	return IRQ_HANDLED;
}

irqreturn_t capi_irq_err(int irq, void *data)
{
	struct capi_t *adapter = (struct capi_t *)data;
	u64 fir1, fir2, err_ivte;
	int slice;

	WARN(1, "CAPI ERROR interrupt %i\n", irq);

	err_ivte = capi_p1_read(adapter, CAPI_PSL_ErrIVTE);
	pr_warn("PSL_ErrIVTE: 0x%.16llx\n", err_ivte);

	pr_crit("STOPPING CAPI TRACE\n");
	capi_stop_trace(adapter);

	fir1 = capi_p1_read(adapter, CAPI_PSL_FIR1);
	fir2 = capi_p1_read(adapter, CAPI_PSL_FIR2);

	pr_warn("PSL_FIR1: 0x%.16llx\nPSL_FIR2: 0x%.16llx\n", fir1, fir2);

	for (slice = 0; slice < adapter->slices; slice++) {
		pr_warn("SLICE %i\n", slice);
		capi_slice_irq_err(0, (void *)(&adapter->slice[slice]));
	}

	BUG(); // we never recover, so let's just die

	return IRQ_HANDLED;
}

static irqreturn_t schedule_capi_fault(struct capi_context_t *ctx, u64 dsisr, u64 dar)
{
	ctx->dsisr = dsisr;
	ctx->dar = dar;
	schedule_work(&ctx->fault_work);
	return IRQ_HANDLED;
}

static irqreturn_t capi_irq(int irq, void *data)
{
	struct capi_context_t *ctx = (struct capi_context_t *)data;
	struct capi_irq_info irq_info;
	u64 dsisr, dar;
	int result;

	if ((result = capi_ops->get_irq(ctx, &irq_info))) {
		WARN(1, "Unable to get CAPI IRQ Info: %i\n", result);
		return IRQ_HANDLED;
	}

	dsisr = irq_info.dsisr;
	dar = irq_info.dar;

	pr_devel("CAPI interrupt %i for afu pe: %i DSISR: %#llx DAR: %#llx\n", irq, ctx->ph, dsisr, dar);

	if (dsisr & CAPI_PSL_DSISR_An_DS) {
		/* We don't inherently need to sleep to handle this, but we do
		 * need to get a ref to the task's mm, which we can't do from
		 * irq context without the potential for a deadlock since it
		 * takes the task_lock. An alternate option would be to keep a
		 * reference to the task's mm the entire time it has capi open,
		 * but to do that we need to solve the issue where we hold a
		 * ref to the mm, but the mm can hold a ref to the fd after an
		 * mmap preventing anything from being cleaned up. */
		pr_devel("Scheduling segment miss handling for later pe: %i\n", ctx->ph);
		return schedule_capi_fault(ctx, dsisr, dar);
	}

	if (dsisr & CAPI_PSL_DSISR_An_M )
		pr_devel("CAPI interrupt: PTE not found\n");
	if (dsisr & CAPI_PSL_DSISR_An_P )
		pr_devel("CAPI interrupt: Storage protection violation\n");
	if (dsisr & CAPI_PSL_DSISR_An_A )
		pr_devel("CAPI interrupt: AFU lock access to write through or cache inhibited storage\n");
	if (dsisr & CAPI_PSL_DSISR_An_S )
		pr_devel("CAPI interrupt: Access was afu_wr or afu_zero\n");
	if (dsisr & CAPI_PSL_DSISR_An_K )
		pr_devel("CAPI interrupt: Access not permitted by virtual page class key protection\n");

	if (dsisr & CAPI_PSL_DSISR_An_DM) {
		/* In some cases we might be able to handle the fault
		 * immediately if hash_page would succeed, but we still need
		 * the task's mm, which as above we can't get without a lock */
		pr_devel("Scheduling page fault handling for later pe: %i\n", ctx->ph);
		return schedule_capi_fault(ctx, dsisr, dar);
	}
	if (dsisr & CAPI_PSL_DSISR_An_ST)
		WARN(1, "CAPI interrupt: Segment Table PTE not found\n");
	if (dsisr & CAPI_PSL_DSISR_An_UR)
		pr_devel("CAPI interrupt: AURP PTE not found\n");
	if (dsisr & CAPI_PSL_DSISR_An_PE)
		return handle_psl_slice_error(ctx, dsisr, irq_info.fir_r_slice);
	if (dsisr & CAPI_PSL_DSISR_An_AE) {
		pr_devel("CAPI interrupt: AFU Error\n");

		spin_lock(&ctx->lock);
		WARN(ctx->pending_afu_err,
		     "FIXME: Potentially clobbering undelivered AFU interrupt\n");
		ctx->afu_err = irq_info.afu_err;
		ctx->pending_afu_err = 1;
		spin_unlock(&ctx->lock);

		wake_up_all(&ctx->wq);
		capi_ops->ack_irq(ctx, CAPI_PSL_TFC_An_A, 0);
	}
	if (dsisr & CAPI_PSL_DSISR_An_OC)
		pr_devel("CAPI interrupt: OS Context Warning\n");

	WARN(1, "Unhandled CAPI IRQ\n");

	return IRQ_HANDLED;
}

static irqreturn_t capi_irq_afu(int irq, void *data)
{
	struct capi_context_t *ctx = (struct capi_context_t *)data;
	irq_hw_number_t hwirq = irqd_to_hwirq(irq_get_irq_data(irq));
	int irq_off, afu_irq = 0;
	__u16 range;
	int r;

	for (r = 0; r < CAPI_IRQ_RANGES; r++) {
		irq_off = hwirq - ctx->irqs.offset[r];
		range = ctx->irqs.range[r];
		if (irq_off >= 0 && irq_off < range) {
			afu_irq += irq_off;
			break;
		}
		afu_irq += range;
	}
	BUG_ON(r >= CAPI_IRQ_RANGES);

	pr_devel("Received AFU interrupt %i for afu context %p (virq %i hwirq %lx)\n",
	       afu_irq, ctx, irq, hwirq);

	BUG_ON(!ctx->irq_bitmap);
	spin_lock(&ctx->lock);
	set_bit(afu_irq - 1, ctx->irq_bitmap);
	ctx->pending_irq = true;
	spin_unlock(&ctx->lock);

	wake_up_all(&ctx->wq);

	return IRQ_HANDLED;
}

unsigned int
capi_map_irq(struct capi_t *adapter, irq_hw_number_t hwirq,
		irq_handler_t handler, void *cookie)
{
	unsigned int virq;
	int result;

	/* IRQ Domain? */
	virq = irq_create_mapping(NULL, hwirq);
	if (!virq) {
		pr_warning("capi_map_irq: irq_create_mapping failed\n");
		return 0;
	}

	if (adapter->driver->setup_irq)
		adapter->driver->setup_irq(adapter, hwirq, virq);

	pr_devel("hwirq %#lx mapped to virq %u\n", hwirq, virq);

	result = request_irq(virq, handler, 0, "capi", cookie);
	if (result) {
		pr_warning("capi_map_irq: request_irq failed: %i\n", result);
		return 0;
	}

	return virq;
}

void capi_unmap_irq(unsigned int virq, void *cookie)
{
	free_irq(virq, cookie);
	irq_dispose_mapping(virq);
}

int afu_register_irqs(struct capi_context_t *ctx, u32 count)
{
	irq_handler_t handler = capi_irq;
	irq_hw_number_t hwirq;
	int rc, r, i;

	/* FIXME: Assign all PSL IRQs to same IRQ to reduce wastage
	 * FIXME: Will be completely broken on phyp & BML/Mambo until we add an
	 * irq allocator for them - alloc_hwirq_ranges() can be used if
	 * refactored to remove pnv phb dependency */
	BUG_ON(!ctx->afu->adapter->driver);
	BUG_ON(!ctx->afu->adapter->driver->alloc_irqs);
	if ((rc = ctx->afu->adapter->driver->alloc_irqs(&ctx->irqs, ctx->afu->adapter, count + 1)))
		return rc;

	ctx->irq_count = count;
	ctx->irq_bitmap = kcalloc(BITS_TO_LONGS(count),
				  sizeof(*ctx->irq_bitmap), GFP_KERNEL);
	if (!ctx->irq_bitmap)
		return -ENOMEM;
	for (r = 0; r < CAPI_IRQ_RANGES; r++) {
		hwirq = ctx->irqs.offset[r];
		for (i = 0; i < ctx->irqs.range[r]; hwirq++, i++) {
			capi_map_irq(ctx->afu->adapter, hwirq,
				     handler, (void*)ctx);
			handler = capi_irq_afu;
		}
	}

	return 0;
}

void afu_enable_irqs(struct capi_context_t *ctx)
{
	irq_hw_number_t hwirq;
	unsigned int virq;
	int r, i;

	pr_info("Enabling CAPI Interrupts\n");

	for (r = 0; r < CAPI_IRQ_RANGES; r++) {
		hwirq = ctx->irqs.offset[r];
		for (i = 0; i < ctx->irqs.range[r]; hwirq++, i++) {
			virq = irq_find_mapping(NULL, hwirq);
			enable_irq(virq);
		}
	}
}

void afu_disable_irqs(struct capi_context_t *ctx)
{
	irq_hw_number_t hwirq;
	unsigned int virq;
	int r, i;

	pr_info("Disabling CAPI Interrupts\n");

	for (r = 0; r < CAPI_IRQ_RANGES; r++) {
		hwirq = ctx->irqs.offset[r];
		for (i = 0; i < ctx->irqs.range[r]; hwirq++, i++) {
			virq = irq_find_mapping(NULL, hwirq);
			disable_irq(virq);
		}
	}
}

void afu_release_irqs(struct capi_context_t *ctx)
{
	irq_hw_number_t hwirq;
	unsigned int virq;
	int r, i;

	for (r = 0; r < CAPI_IRQ_RANGES; r++) {
		hwirq = ctx->irqs.offset[r];
		for (i = 0; i < ctx->irqs.range[r]; hwirq++, i++) {
			virq = irq_find_mapping(NULL, hwirq);
			if (virq)
				capi_unmap_irq(virq, (void*)ctx);
		}
	}

	ctx->afu->adapter->driver->release_irqs(&ctx->irqs, ctx->afu->adapter);
}
