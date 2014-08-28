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

#include <linux/spinlock.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/mutex.h>
#include <linux/mm.h>
#include <asm/synch.h>
#include <asm/uaccess.h>

#include "cxl.h"

static int afu_control(struct cxl_afu_t *afu, u64 command,
		       u64 result, u64 mask, bool enabled)
{
	u64 AFU_Cntl = cxl_p2n_read(afu, CXL_AFU_Cntl_An);
	unsigned long timeout = jiffies + (HZ * CXL_TIMEOUT);

	spin_lock(&afu->afu_cntl_lock);
	pr_devel("AFU command starting: %llx\n", command);

	cxl_p2n_write(afu, CXL_AFU_Cntl_An, AFU_Cntl | command);

	AFU_Cntl = cxl_p2n_read(afu, CXL_AFU_Cntl_An);
	while ((AFU_Cntl & mask) != result) {
		if (time_after_eq(jiffies, timeout)) {
			pr_warn("WARNING: AFU control timed out!\n");
			return -EBUSY;
		}
		pr_devel_ratelimited("AFU control... (0x%.16llx)\n",
				     AFU_Cntl | command);
		cpu_relax();
		AFU_Cntl = cxl_p2n_read(afu, CXL_AFU_Cntl_An);
	};
	pr_devel("AFU command complete: %llx\n", command);
	afu->enabled = enabled;
	spin_unlock(&afu->afu_cntl_lock);

	return 0;
}

static int afu_enable(struct cxl_afu_t *afu)
{
	pr_devel("AFU enable request\n");

	return afu_control(afu, CXL_AFU_Cntl_An_E,
			   CXL_AFU_Cntl_An_ES_Enabled,
			   CXL_AFU_Cntl_An_ES_MASK, true);
}

static int afu_disable(struct cxl_afu_t *afu)
{
	pr_devel("AFU disable request\n");

	return afu_control(afu, 0, CXL_AFU_Cntl_An_ES_Disabled,
			   CXL_AFU_Cntl_An_ES_MASK, false);
}

int afu_reset(struct cxl_afu_t *afu)
{
	pr_devel("AFU reset request\n");

	return afu_control(afu, CXL_AFU_Cntl_An_RA,
			   CXL_AFU_Cntl_An_RS_Complete,
			   CXL_AFU_Cntl_An_RS_MASK, false);
}
EXPORT_SYMBOL(afu_reset);

static int afu_check_and_enable(struct cxl_afu_t *afu)
{
	if (afu->enabled)
		return 0;
	return afu_enable(afu);
}

static int psl_purge(struct cxl_afu_t *afu)
{
	u64 PSL_CNTL = cxl_p1n_read(afu, CXL_PSL_SCNTL_An);
	u64 AFU_Cntl = cxl_p2n_read(afu, CXL_AFU_Cntl_An);
	u64 dsisr, dar;
	u64 start, end;
	unsigned long timeout = jiffies + (HZ * CXL_TIMEOUT);

	pr_devel("PSL purge request\n");

	if ((AFU_Cntl & CXL_AFU_Cntl_An_ES_MASK) != CXL_AFU_Cntl_An_ES_Disabled) {
		WARN(1, "psl_purge request while AFU not disabled!\n");
		afu_disable(afu);
	}

	cxl_p1n_write(afu, CXL_PSL_SCNTL_An,
		       PSL_CNTL | CXL_PSL_SCNTL_An_Pc);
	start = local_clock();
	PSL_CNTL = cxl_p1n_read(afu, CXL_PSL_SCNTL_An);
	while ((PSL_CNTL &  CXL_PSL_SCNTL_An_Ps_MASK)
			== CXL_PSL_SCNTL_An_Ps_Pending) {
		if (time_after_eq(jiffies, timeout)) {
			pr_warn("WARNING: PSL Purge timed out!\n");
			return -EBUSY;
		}
		dsisr = cxl_p2n_read(afu, CXL_PSL_DSISR_An);
		pr_devel_ratelimited("PSL purging... PSL_CNTL: 0x%.16llx  PSL_DSISR: 0x%.16llx\n", PSL_CNTL, dsisr);
		if (dsisr & CXL_PSL_DSISR_TRANS) {
			dar = cxl_p2n_read(afu, CXL_PSL_DAR_An);
			pr_warn("PSL purge terminating pending translation, DSISR: 0x%.16llx, DAR: 0x%.16llx\n", dsisr, dar);
			cxl_p2n_write(afu, CXL_PSL_TFC_An, CXL_PSL_TFC_An_AE);
		} else if (dsisr) {
			pr_warn("PSL purge acknowledging pending non-translation fault, DSISR: 0x%.16llx\n", dsisr);
			cxl_p2n_write(afu, CXL_PSL_TFC_An, CXL_PSL_TFC_An_A);
		} else {
			cpu_relax();
		}
		PSL_CNTL = cxl_p1n_read(afu, CXL_PSL_SCNTL_An);
	};
	end = local_clock();
	pr_devel("PSL purged in %lld ns\n", end - start);

	cxl_p1n_write(afu, CXL_PSL_SCNTL_An,
		       PSL_CNTL & ~CXL_PSL_SCNTL_An_Pc);
	return 0;
}

static int
init_adapter_native(struct cxl_t *adapter, void *backend_data)
{
	struct cxl_native_data *data = backend_data;
	int rc;

	pr_devel("cxl_mmio_p1:        ");
	if (!(adapter->p1_mmio = ioremap(data->p1_base, data->p1_size)))
		return -ENOMEM;

	if (data->p2_base) {
		if (!(adapter->p2_mmio = ioremap(data->p2_base, data->p2_size))) {
			rc = -ENOMEM;
			goto out;
		}
	}

	if (adapter->driver && adapter->driver->init_adapter) {
		if ((rc = adapter->driver->init_adapter(adapter)))
			goto out1;
	}

	pr_devel("cxl implementation specific PSL_VERSION: 0x%llx\n",
			cxl_p1_read(adapter, CXL_PSL_VERSION));

	adapter->err_hwirq = data->err_hwirq;
	pr_devel("cxl_err_ivte: %#lx\n", adapter->err_hwirq);

	adapter->err_virq = cxl_map_irq(adapter, adapter->err_hwirq, cxl_irq_err, (void*)adapter);
	if (!adapter->err_virq) {
		rc = -ENOSPC;
		goto out2;
	}

	cxl_p1_write(adapter, CXL_PSL_ErrIVTE, adapter->err_hwirq & 0xffff);

	return 0;

out:
	iounmap(adapter->p1_mmio);
out1:
	iounmap(adapter->p2_mmio);
out2:
	if (adapter->driver && adapter->driver->release_adapter)
		adapter->driver->release_adapter(adapter);
	return rc;
}

static void release_adapter_native(struct cxl_t *adapter)
{
	iounmap(adapter->p1_mmio);
	iounmap(adapter->p2_mmio);
	cxl_unmap_irq(adapter->err_virq, (void*)adapter);
	if (adapter->driver && adapter->driver->release_adapter)
		adapter->driver->release_adapter(adapter);
}

static int spa_max_procs(int spa_size)
{
	/* From the CAIA:
	 *    end_of_SPA_area = SPA_Base + ((n+4) * 128) + (( ((n*8) + 127) >> 7) * 128) + 255
	 * Most of that junk is really just an overly-complicated way of saying
	 * the last 256 bytes are __aligned(128), so it's really:
	 *    end_of_SPA_area = end_of_PSL_queue_area + __aligned(128) 255
	 * and
	 *    end_of_PSL_queue_area = SPA_Base + ((n+4) * 128) + (n*8) - 1
	 * so
	 *    sizeof(SPA) = ((n+4) * 128) + (n*8) + __aligned(128) 256
	 * Ignore the alignment (which is safe in this case as long as we are
	 * careful with our rounding) and solve for n:
	 */
	return ((spa_size / 8) - 96) / 17;
}

static int alloc_spa(struct cxl_afu_t *afu)
{
	u64 spap;

	/* Work out how many pages to allocate */
	afu->spa_order = 0;
	do {
		afu->spa_order++;
		afu->spa_size = (1 << afu->spa_order) * PAGE_SIZE;
		afu->spa_max_procs = spa_max_procs(afu->spa_size);
	} while (afu->spa_max_procs < afu->num_procs);

	WARN_ON(afu->spa_size > 0x100000); /* Max size supported by the hardware */

	/* TODO: Fall back to less pages if allocation is not possible. */
	if (!(afu->spa = (struct cxl_process_element *)__get_free_pages(GFP_KERNEL | __GFP_ZERO, afu->spa_order))) {
		pr_err("cxl_alloc_spa: Unable to allocate scheduled process area\n");
		return -ENOMEM;
	}
	pr_devel("spa pages: %i afu->spa_max_procs: %i   afu->num_procs: %i\n",
		 1<<afu->spa_order, afu->spa_max_procs, afu->num_procs);
	BUG_ON(afu->spa_max_procs < afu->num_procs);

	afu->sw_command_status = (__be64 *)((char *)afu->spa + ((afu->spa_max_procs + 3) * 128));

	spap = virt_to_phys(afu->spa) & CXL_PSL_SPAP_Addr;
	spap |= ((afu->spa_size >> (12 - CXL_PSL_SPAP_Size_Shift)) - 1) & CXL_PSL_SPAP_Size;
	spap |= CXL_PSL_SPAP_V;
	pr_devel("cxl: SPA allocated at 0x%p. Max processes: %i, sw_command_status: 0x%p CXL_PSL_SPAP_An=0x%016llx\n", afu->spa, afu->spa_max_procs, afu->sw_command_status, spap);
	cxl_p1n_write(afu, CXL_PSL_SPAP_An, spap);

	ida_init(&afu->pe_index_ida);

	return 0;
}

static void release_spa(struct cxl_afu_t *afu)
{
	free_pages((unsigned long) afu->spa, afu->spa_order);
}

static int
init_afu_native(struct cxl_afu_t *afu, u64 handle)
{
	u64 val;
	int rc = 0;

	if (afu->err_hwirq) { /* Can drop this test when the BML support is pulled out - under phyp we use cxl-of.c */
		pr_devel("cxl slice error IVTE: %#lx\n", afu->err_hwirq);
		afu->err_virq = cxl_map_irq(afu->adapter, afu->err_hwirq, cxl_slice_irq_err, (void*)afu);
		val = cxl_p1n_read(afu, CXL_PSL_SERR_An);
		val = (val & 0x00ffffffffff0000ULL) | (afu->err_hwirq & 0xffff);
		cxl_p1n_write(afu, CXL_PSL_SERR_An, val);
	}

	if (afu->adapter->driver && afu->adapter->driver->init_afu) {
		if ((rc = afu->adapter->driver->init_afu(afu)))
			return rc;
	}

	// FIXME: check we are afu_directed in this whole function
	if (alloc_spa(afu))
		return -ENOMEM;

	cxl_p1n_write(afu, CXL_PSL_SCNTL_An, CXL_PSL_SCNTL_An_PM_AFU);
	cxl_p1n_write(afu, CXL_PSL_AMOR_An, 0xFFFFFFFFFFFFFFFFULL);
	cxl_p1n_write(afu, CXL_PSL_ID_An, CXL_PSL_ID_An_F | CXL_PSL_ID_An_L);

	afu_disable(afu); /* FIXME: remove this */
	if ((rc = psl_purge(afu))) /* FIXME: remove this */
		return rc;

	if ((rc = afu_reset(afu)))
		return rc;

	return rc;
}

static void release_afu_native(struct cxl_afu_t *afu)
{
	release_spa(afu);
	iounmap(afu->p1n_mmio);
	iounmap(afu->p2n_mmio);
	iounmap(afu->psn_mmio);

	cxl_unmap_irq(afu->err_virq, (void*)afu);
	if (afu->adapter->driver && afu->adapter->driver->release_afu)
		afu->adapter->driver->release_afu(afu);
}

static void cxl_write_sstp(struct cxl_afu_t *afu, u64 sstp0, u64 sstp1)
{
	/* 1. Disable SSTP by writing 0 to SSTP1[V] */
	cxl_p2n_write(afu, CXL_SSTP1_An, 0);

	/* 2. Invalidate all SLB entries */
	cxl_p2n_write(afu, CXL_SLBIA_An, 0);
	/* TODO: Poll for completion */

	/* 3. Set SSTP0_An */
	cxl_p2n_write(afu, CXL_SSTP0_An, sstp0);

	/* 4. Set SSTP1_An */
	cxl_p2n_write(afu, CXL_SSTP1_An, sstp1);
}

/* must hold ctx->afu->spa_mutex */
static void
slb_invalid(struct cxl_context_t *ctx)
{
	/* FIXME use per slice version of SLBIA? */
	struct cxl_t *adapter = ctx->afu->adapter;
	u64 slbia;

	cxl_p1_write(adapter, CXL_PSL_LBISEL,
		      ((u64)ctx->elem->common.pid << 32) | ctx->elem->lpid);
	cxl_p1_write(adapter, CXL_PSL_SLBIA, CXL_SLBI_IQ_LPIDPID);

	while (1) {
		slbia = cxl_p1_read(adapter, CXL_PSL_SLBIA);
		if (!(slbia & CXL_SLBIA_P))
			break;
		cpu_relax();
	}
	/* TODO: assume TLB is already invalidated via broadcast tlbie */
}

static int do_process_element_cmd(struct cxl_context_t *ctx,
				  u64 cmd, u64 pe_state)
{
	u64 state;
	u64 dsisr, dar;

	BUG_ON(!ctx->afu->enabled);

	ctx->elem->software_state = cpu_to_be32(pe_state);
	smp_wmb();
	*(ctx->afu->sw_command_status) = cpu_to_be64(cmd | 0 | ctx->ph);
	smp_mb();
	cxl_p1n_write(ctx->afu, CXL_PSL_LLCMD_An, cmd | ctx->ph);
	while (1) {
		state = be64_to_cpup(ctx->afu->sw_command_status);
		if (state == ~0ULL) {
			pr_err("cxl: Error adding process element to AFU\n");
			return -1;
		}
		if ((state & (CXL_SPA_SW_CMD_MASK | CXL_SPA_SW_STATE_MASK  | CXL_SPA_SW_LINK_MASK)) ==
		    (cmd | (cmd >> 16) | ctx->ph))
			break;
		/* FIXME: maybe look for a while before schedule if this
		 * becomes a performance bottleneck
		 */
		schedule();

		/* debug code to double check DSISR */
		dsisr = cxl_p2n_read(ctx->afu, CXL_PSL_DSISR_An);
		if (dsisr) {
			dar = cxl_p2n_read(ctx->afu, CXL_PSL_DAR_An);
			pr_warn_ratelimited("DSISR non-zero  DSISR: 0x%.16llx, DAR: 0x%.16llx\n", dsisr, dar);
		}
	}
	return 0;
}

/* TODO: Make sure all operations on the linked list are serialised to prevent
 * races on SPA->sw_command_status */
static int
add_process_element(struct cxl_context_t *ctx)
{
	int rc = 0;

	mutex_lock(&ctx->afu->spa_mutex);
	pr_devel("%s Adding pe: %i started\n", __FUNCTION__, ctx->ph);
	if (!(rc = do_process_element_cmd(ctx, CXL_SPA_SW_CMD_ADD, CXL_PE_SOFTWARE_STATE_V)))
		ctx->pe_inserted = true;
	pr_devel("%s Adding pe: %i finished\n", __FUNCTION__, ctx->ph);
	mutex_unlock(&ctx->afu->spa_mutex);
	return rc;
}

/* TODO: merge this with add_process_element */
static int
terminate_process_element(struct cxl_context_t *ctx)
{
	int rc = 0;

	/* fast path terminate if it's already invalid */
	if (!(ctx->elem->software_state & cpu_to_be32(CXL_PE_SOFTWARE_STATE_V)))
		return rc;

	mutex_lock(&ctx->afu->spa_mutex);
	pr_devel("%s Terminate pe: %i started\n", __FUNCTION__, ctx->ph);
	rc = do_process_element_cmd(ctx, CXL_SPA_SW_CMD_TERMINATE,
				    CXL_PE_SOFTWARE_STATE_V | CXL_PE_SOFTWARE_STATE_T);
	ctx->elem->software_state = 0; 	/* Remove Valid bit */
	pr_devel("%s Terminate pe: %i finished\n", __FUNCTION__, ctx->ph);
	mutex_unlock(&ctx->afu->spa_mutex);
	return rc;
}

/* TODO: Make sure all operations on the linked list are serialised to prevent
 * races on SPA->sw_command_status */
static int
remove_process_element(struct cxl_context_t *ctx)
{
	int rc = 0;

	mutex_lock(&ctx->afu->spa_mutex);
	pr_devel("%s Remove pe: %i started\n", __FUNCTION__, ctx->ph);
	if (!(rc = do_process_element_cmd(ctx, CXL_SPA_SW_CMD_REMOVE, 0)))
		ctx->pe_inserted = false;
	slb_invalid(ctx);
	pr_devel("%s Remove pe: %i finished\n", __FUNCTION__, ctx->ph);
	mutex_unlock(&ctx->afu->spa_mutex);

	return rc;
}


static void assign_psn_space(struct cxl_context_t *ctx)
{
	if (!ctx->afu->pp_size || ctx->master) {
		ctx->psn_phys = ctx->afu->psn_phys;
		ctx->psn_size = ctx->afu->psn_size;
	} else {
		ctx->psn_phys = ctx->afu->psn_phys +
			(ctx->afu->pp_offset + ctx->afu->pp_size * ctx->ph);
		ctx->psn_size = ctx->afu->pp_size;
	}
}


static int
init_afu_directed_process(struct cxl_context_t *ctx, u64 wed, u64 amr)
{

	u64 sr, sstp0, sstp1;
	int r, result;

	/* FIXME:
	 * - Add to existing SPA list if one already exists
	 * - Reject if already enabled in different mode, max processes
	 *   exceeded, etc
	 */

	assign_psn_space(ctx);

	ctx->elem->ctxtime = 0; /* disable */
	ctx->elem->lpid = cpu_to_be32(mfspr(SPRN_LPID));
	ctx->elem->haurp = 0; /* disable */
	ctx->elem->sdr = cpu_to_be64(mfspr(SPRN_SDR1));

	sr = CXL_PSL_SR_An_SC;
	if (ctx->master)
		sr |= CXL_PSL_SR_An_MP;
	if (mfspr(SPRN_LPCR) & LPCR_TC)
		sr |= CXL_PSL_SR_An_TC;
	if (!ctx->kernel) {
		/* GA1: HV=0, PR=1, R=1 */
		/* FIXME: Set HV properly */
		sr |= CXL_PSL_SR_An_HV | CXL_PSL_SR_An_PR | CXL_PSL_SR_An_R;
		if (!test_tsk_thread_flag(current, TIF_32BIT))
			sr |= CXL_PSL_SR_An_SF;
		ctx->elem->common.pid = cpu_to_be32(current->pid);
	} else { /* Initialise for kernel */
		WARN_ONCE(1, "CXL initialised for kernel, this won't work on GA1 hardware!\n");
		sr |= (mfmsr() & MSR_SF) | CXL_PSL_SR_An_HV;
		ctx->elem->common.pid = 0;
	}
	ctx->elem->common.tid = 0;
	ctx->elem->sr = cpu_to_be64(sr);

	ctx->elem->common.csrp = 0; /* disable */
	ctx->elem->common.aurp0 = 0; /* disable */
	ctx->elem->common.aurp1 = 0; /* disable */

	if ((result = cxl_alloc_sst(ctx, &sstp0, &sstp1)))
		return result;

	/* TODO: If the wed looks like a valid EA, preload the appropriate segment */
	cxl_prefault(ctx, wed);

	ctx->elem->common.sstp0 = cpu_to_be64(sstp0);
	ctx->elem->common.sstp1 = cpu_to_be64(sstp1);

	for (r = 0; r < CXL_IRQ_RANGES; r++) {
		ctx->elem->ivte_offsets[r] = cpu_to_be16(ctx->irqs.offset[r]);
		ctx->elem->ivte_ranges[r] = cpu_to_be16(ctx->irqs.range[r]);
	}

	ctx->elem->common.amr = cpu_to_be64(amr);
	ctx->elem->common.wed = cpu_to_be64(wed);

	/* first guy needs to enable */
	if ((result = afu_check_and_enable(ctx->afu)))
		return result;

	add_process_element(ctx);

	return 0;
}

static int
init_dedicated_process_native(struct cxl_context_t *ctx, u64 wed, u64 amr)
{
	struct cxl_afu_t * afu = ctx->afu;
	u64 sr, sstp0, sstp1;
	int result;


	/* Ensure AFU is disabled */
	afu_disable(afu);
	if ((result = psl_purge(afu)))
		return result;

	cxl_p1n_write(afu, CXL_PSL_SCNTL_An, CXL_PSL_SCNTL_An_PM_Process);

	/* Hypervisor initialise: */
	cxl_p1n_write(afu, CXL_PSL_CtxTime_An, 0); /* disable */
	cxl_p1n_write(afu, CXL_PSL_SPAP_An, 0);    /* disable */
	cxl_p1n_write(afu, CXL_PSL_AMOR_An, 0xFFFFFFFFFFFFFFFFULL);

	cxl_p1n_write(afu, CXL_PSL_LPID_An, mfspr(SPRN_LPID));
	cxl_p1n_write(afu, CXL_HAURP_An, 0);       /* disable */
	cxl_p1n_write(afu, CXL_PSL_SDR_An, mfspr(SPRN_SDR1));

	sr = CXL_PSL_SR_An_SC;
	if (ctx->master)
		sr |= CXL_PSL_SR_An_MP;
	if (mfspr(SPRN_LPCR) & LPCR_TC)
		sr |= CXL_PSL_SR_An_TC;
	if (!ctx->kernel) {
		/* GA1: HV=0, PR=1, R=1 */
		sr |= CXL_PSL_SR_An_PR | CXL_PSL_SR_An_R;
		if (!test_tsk_thread_flag(current, TIF_32BIT))
			sr |= CXL_PSL_SR_An_SF;
		cxl_p2n_write(afu, CXL_PSL_PID_TID_An, (u64)current->pid << 32); /* Not using tid field */
	} else { /* Initialise for kernel */
		WARN_ONCE(1, "CXL initialised for kernel, this won't work on GA1 hardware!\n");
		sr |= (mfmsr() & MSR_SF) | CXL_PSL_SR_An_HV;
		cxl_p2n_write(afu, CXL_PSL_PID_TID_An, 0);
	}
	cxl_p1n_write(afu, CXL_PSL_SR_An, sr);

	/* OS initialise: */
	cxl_p2n_write(afu, CXL_CSRP_An, 0);        /* disable */
	cxl_p2n_write(afu, CXL_AURP0_An, 0);       /* disable */
	cxl_p2n_write(afu, CXL_AURP1_An, 0);       /* disable */

	if ((result = cxl_alloc_sst(ctx, &sstp0, &sstp1)))
		return result;

	/* TODO: If the wed looks like a valid EA, preload the appropriate segment */
	cxl_prefault(ctx, wed);

	cxl_write_sstp(afu, sstp0, sstp1);
	cxl_p1n_write(afu, CXL_PSL_IVTE_Offset_An,
		       (((u64)ctx->irqs.offset[0] & 0xffff) << 48) |
		       (((u64)ctx->irqs.offset[1] & 0xffff) << 32) |
		       (((u64)ctx->irqs.offset[2] & 0xffff) << 16) |
		        ((u64)ctx->irqs.offset[3] & 0xffff));
	cxl_p1n_write(afu, CXL_PSL_IVTE_Limit_An, (u64)
		       (((u64)ctx->irqs.range[0] & 0xffff) << 48) |
		       (((u64)ctx->irqs.range[1] & 0xffff) << 32) |
		       (((u64)ctx->irqs.range[2] & 0xffff) << 16) |
		        ((u64)ctx->irqs.range[3] & 0xffff));

	cxl_p2n_write(afu, CXL_PSL_AMR_An, amr);

	/* master only context for dedicated */
	assign_psn_space(ctx);

	if ((result = afu_reset(afu)))
		return result;

	/* XXX: Might want the WED & enable in a separate fn? */
	cxl_p2n_write(afu, CXL_PSL_WED_An, wed);

	if ((result = afu_enable(afu)))
		return result;

	return 0;
}

static int
init_process_native(struct cxl_context_t *ctx, bool kernel, u64 wed,
		  u64 amr)
{
	ctx->kernel = kernel;
	if (ctx->afu->afu_directed_mode)
		return init_afu_directed_process(ctx, wed, amr);
	return init_dedicated_process_native(ctx, wed, amr);
}

static int detach_process_native(struct cxl_context_t *ctx)
{
	if (!ctx->afu->afu_directed_mode) {
		afu_reset(ctx->afu);
		afu_disable(ctx->afu);
		psl_purge(ctx->afu);
		return 0;
	}

	if (!ctx->pe_inserted)
		return 0;
	if (terminate_process_element(ctx))
		return -1;
	if (remove_process_element(ctx))
		return -1;

	return 0;
}

static int get_irq_native(struct cxl_context_t *ctx, struct cxl_irq_info *info)
{
	u64 pidtid;
	info->dsisr = cxl_p2n_read(ctx->afu, CXL_PSL_DSISR_An);
	info->dar = cxl_p2n_read(ctx->afu, CXL_PSL_DAR_An);
	info->dsr = cxl_p2n_read(ctx->afu, CXL_PSL_DSR_An);
	pidtid = cxl_p2n_read(ctx->afu, CXL_PSL_PID_TID_An);
	info->pid = pidtid >> 32;
	info->tid = pidtid & 0xffffffff;
	info->afu_err = cxl_p2n_read(ctx->afu, CXL_AFU_ERR_An);
	info->fir_r_slice = cxl_p1n_read(ctx->afu, CXL_PSL_R_FIR_SLICE_An);
	return 0;
}

static void recover_psl_err(struct cxl_afu_t *afu, u64 recov)
{
	u64 dsisr;

	pr_devel("RECOVERING FROM PSL ERROR... (0x%.16llx)\n", recov);

	/* Clear PSL_DSISR[PE] */
	dsisr = cxl_p2n_read(afu, CXL_PSL_DSISR_An);
	cxl_p2n_write(afu, CXL_PSL_DSISR_An, dsisr & ~CXL_PSL_DSISR_An_PE);

	/* Write 1s to clear FIR bits */
	cxl_p1n_write(afu, CXL_PSL_R_FIR_SLICE_An, recov);
}

static int ack_irq_native(struct cxl_context_t *ctx, u64 tfc, u64 psl_reset_mask)
{
	if (tfc)
		cxl_p2n_write(ctx->afu, CXL_PSL_TFC_An, tfc);
	if (psl_reset_mask)
		recover_psl_err(ctx->afu, psl_reset_mask);

	return 0;
}

int cxl_map_slice_regs(struct cxl_afu_t *afu,
		  u64 p1n_base, u64 p1n_size,
		  u64 p2n_base, u64 p2n_size,
		  u64 psn_base, u64 psn_size,
		  u64 afu_desc, u64 afu_desc_size)
{
	pr_devel("cxl_map_slice_regs: p1: %#.16llx %#llx, p2: %#.16llx %#llx, ps: %#.16llx %#llx, afu_desc: %#.16llx %#llx\n",
			p1n_base, p1n_size, p2n_base, p2n_size, psn_base, psn_size, afu_desc, afu_desc_size);

	afu->p1n_mmio = NULL;
	afu->afu_desc_mmio = NULL;
	if (p1n_base)
		if (!(afu->p1n_mmio = ioremap(p1n_base, p1n_size)))
			goto err;
	if (!(afu->p2n_mmio = ioremap(p2n_base, p2n_size)))
		goto err1;
	if (!(afu->psn_mmio = ioremap(psn_base, psn_size)))
		goto err2;
	if (afu_desc)
		if (!(afu->afu_desc_mmio = ioremap(afu_desc, afu_desc_size)))
			goto err3;
	afu->psn_phys = psn_base;
	afu->psn_size = psn_size;
	afu->afu_desc_size = afu_desc_size;

	return 0;
err3:
	iounmap(afu->psn_mmio);
err2:
	iounmap(afu->p2n_mmio);
err1:
	if (afu->p1n_mmio)
		iounmap(afu->p1n_mmio);
err:
	WARN(1, "Error mapping AFU MMIO regions\n");
	return -EFAULT;
}
EXPORT_SYMBOL(cxl_map_slice_regs);

void cxl_unmap_slice_regs(struct cxl_afu_t *afu)
{
	if (afu->psn_mmio)
		iounmap(afu->psn_mmio);

	if (afu->p1n_mmio)
		iounmap(afu->p2n_mmio);

	if (afu->p1n_mmio)
		iounmap(afu->p1n_mmio);
}
EXPORT_SYMBOL(cxl_unmap_slice_regs);

static int check_error(struct cxl_afu_t *afu)
{
	return (cxl_p1n_read(afu, CXL_PSL_SCNTL_An) == ~0ULL);
}

static const struct cxl_backend_ops cxl_native_ops = {
	.init_adapter = init_adapter_native,
	.init_afu = init_afu_native,
	.init_process = init_process_native,
	.detach_process = detach_process_native,
	.get_irq = get_irq_native,
	.ack_irq = ack_irq_native,
	.release_adapter = release_adapter_native,
	.release_afu = release_afu_native,
	.check_error = check_error,
	.afu_reset = afu_reset,
};

void init_cxl_native(void)
{
	cxl_ops = &cxl_native_ops;
}
