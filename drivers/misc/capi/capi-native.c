#if 1
#define DEBUG
#else
#undef DEBUG
#endif

#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <asm/synch.h>
#include <linux/mm.h>
#include <asm/uaccess.h>

#include "capi.h"
#include "capi_hcalls.h"

int afu_reset(struct capi_afu_t *afu)
{
	u64 AFU_Cntl;
	unsigned long timeout = jiffies + (HZ * CAPI_TIMEOUT);

	pr_devel("AFU reset request\n");
	capi_p2n_write(afu, CAPI_AFU_Cntl_An, CAPI_AFU_Cntl_An_RA);
	AFU_Cntl = capi_p2n_read(afu, CAPI_AFU_Cntl_An);
	while ((AFU_Cntl & CAPI_AFU_Cntl_An_RS_MASK)
			!= CAPI_AFU_Cntl_An_RS_Complete) {
		if (time_after_eq(jiffies, timeout)) {
			pr_warn("WARNING: AFU reset timed out!\n");
			return -EBUSY;
		}
		pr_devel_ratelimited("AFU resetting... (0x%.16llx)\n", AFU_Cntl);
		cpu_relax();
		AFU_Cntl = capi_p2n_read(afu, CAPI_AFU_Cntl_An);
	};
	WARN((capi_p2n_read(afu, CAPI_AFU_Cntl_An)
	     & CAPI_AFU_Cntl_An_ES_MASK)
	     != CAPI_AFU_Cntl_An_ES_Disabled,
	     "AFU not disabled after reset!\n");
	pr_devel("AFU reset\n");
	return 0;
}
EXPORT_SYMBOL(afu_reset);

static int afu_enable(struct capi_afu_t *afu)
{
	u64 AFU_Cntl = capi_p2n_read(afu, CAPI_AFU_Cntl_An);
	unsigned long timeout = jiffies + (HZ * CAPI_TIMEOUT);

	pr_devel("AFU enable request\n");
	WARN((AFU_Cntl & CAPI_AFU_Cntl_An_ES_MASK)
	     != CAPI_AFU_Cntl_An_ES_Disabled,
	     "Enabling AFU not in disabled state\n");

	capi_p2n_write(afu, CAPI_AFU_Cntl_An, AFU_Cntl | CAPI_AFU_Cntl_An_E);
	AFU_Cntl = capi_p2n_read(afu, CAPI_AFU_Cntl_An);
	while ((AFU_Cntl & CAPI_AFU_Cntl_An_ES_MASK)
			!= CAPI_AFU_Cntl_An_ES_Enabled) {
		if (time_after_eq(jiffies, timeout)) {
			pr_warn("WARNING: AFU enable timed out!\n");
			return -EBUSY;
		}
		pr_devel_ratelimited("AFU enabling... (0x%.16llx)\n", AFU_Cntl);
		cpu_relax();
		AFU_Cntl = capi_p2n_read(afu, CAPI_AFU_Cntl_An);
	};
	pr_devel("AFU enabled\n");
	return 0;
}

static int afu_disable(struct capi_afu_t *afu)
{
	u64 AFU_Cntl = capi_p2n_read(afu, CAPI_AFU_Cntl_An);
	unsigned long timeout = jiffies + (HZ * CAPI_TIMEOUT);

	pr_devel("AFU disable request\n");
	if ((AFU_Cntl & CAPI_AFU_Cntl_An_ES_MASK) != CAPI_AFU_Cntl_An_ES_Enabled) {
		pr_devel("Attempted to disable already disabled AFU\n");
		return 0;
	}

	capi_p2n_write(afu, CAPI_AFU_Cntl_An, AFU_Cntl | CAPI_AFU_Cntl_An_RA);
	AFU_Cntl = capi_p2n_read(afu, CAPI_AFU_Cntl_An);
	while ((AFU_Cntl & CAPI_AFU_Cntl_An_RS_MASK)
			!= CAPI_AFU_Cntl_An_RS_Complete) {
		if (time_after_eq(jiffies, timeout)) {
			pr_warn("WARNING: PSL disable timed out!\n");
			return -EBUSY;
		}
		pr_devel_ratelimited("AFU disabling... (0x%.16llx)\n", AFU_Cntl);
		cpu_relax();
		AFU_Cntl = capi_p2n_read(afu, CAPI_AFU_Cntl_An);
	};
	pr_devel("AFU disabled\n");
	return 0;
}

static int psl_purge(struct capi_afu_t *afu)
{
	u64 PSL_CNTL = capi_p1n_read(afu, CAPI_PSL_SCNTL_An);
	u64 AFU_Cntl = capi_p2n_read(afu, CAPI_AFU_Cntl_An);
	u64 dsisr, dar;
	u64 start, end;
	unsigned long timeout = jiffies + (HZ * CAPI_TIMEOUT);

	pr_devel("PSL purge request\n");

	BUG_ON(PSL_CNTL == ~0ULL); /* FIXME: eeh path */
	BUG_ON(AFU_Cntl == ~0ULL); /* FIXME: eeh path */

	if ((AFU_Cntl & CAPI_AFU_Cntl_An_ES_MASK) != CAPI_AFU_Cntl_An_ES_Disabled) {
		WARN(1, "psl_purge request while AFU not disabled!\n");
		afu_disable(afu);
	}

	capi_p1n_write(afu, CAPI_PSL_SCNTL_An,
		       PSL_CNTL | CAPI_PSL_SCNTL_An_Pc);
	start = mftb();
	PSL_CNTL = capi_p1n_read(afu, CAPI_PSL_SCNTL_An);
	while ((PSL_CNTL &  CAPI_PSL_SCNTL_An_Ps_MASK)
			== CAPI_PSL_SCNTL_An_Ps_Pending) {
		if (time_after_eq(jiffies, timeout)) {
			pr_warn("WARNING: PSL Purge timed out!\n");
			return -EBUSY;
		}
		dsisr = capi_p2n_read(afu, CAPI_PSL_DSISR_An);
		BUG_ON(dsisr == ~0ULL); /* FIXME: eeh path */
		pr_devel_ratelimited("PSL purging... PSL_CNTL: 0x%.16llx  PSL_DSISR: 0x%.16llx\n", PSL_CNTL, dsisr);
		if (dsisr & CAPI_PSL_DSISR_TRANS) {
			dar = capi_p2n_read(afu, CAPI_PSL_DAR_An);
			pr_warn("PSL purge terminating pending translation, DSISR: 0x%.16llx, DAR: 0x%.16llx\n", dsisr, dar);
			capi_p2n_write(afu, CAPI_PSL_TFC_An, CAPI_PSL_TFC_An_AE);
		} else if (dsisr) {
			pr_warn("PSL purge acknowledging pending non-translation fault, DSISR: 0x%.16llx\n", dsisr);
			capi_p2n_write(afu, CAPI_PSL_TFC_An, CAPI_PSL_TFC_An_A);
		} else {
			cpu_relax();
		}
		PSL_CNTL = capi_p1n_read(afu, CAPI_PSL_SCNTL_An);
		BUG_ON(PSL_CNTL == ~0ULL); /* FIXME: eeh path */
	};
	end = mftb();
	pr_devel("PSL purged in %lld 512MHz tb ticks\n", end - start);
	/* FIXME: Should this be re-enabled here, or after resetting the AFU? */
	capi_p1n_write(afu, CAPI_PSL_SCNTL_An,
		       PSL_CNTL & ~CAPI_PSL_SCNTL_An_Pc);
	return 0;
}

static int
init_adapter_native(struct capi_t *adapter, void *backend_data)
{
	struct capi_native_data *data = backend_data;
	int rc;

	pr_devel("capi_mmio_p1:        ");
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

	pr_devel("capi implementation specific PSL_VERSION: 0x%llx\n",
			capi_p1_read(adapter, CAPI_PSL_VERSION));

	adapter->err_hwirq = data->err_hwirq;
	pr_devel("capi_err_ivte: %#lx\n", adapter->err_hwirq);

	adapter->err_virq = capi_map_irq(adapter, adapter->err_hwirq, capi_irq_err, (void*)adapter);
	if (!adapter->err_virq) {
		rc = -ENOSPC;
		goto out2;
	}

	capi_p1_write(adapter, CAPI_PSL_ErrIVTE, adapter->err_hwirq & 0xffff);

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

static void release_adapter_native(struct capi_t *adapter)
{
	iounmap(adapter->p1_mmio);
	iounmap(adapter->p2_mmio);
	capi_unmap_irq(adapter->err_virq, (void*)adapter);
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

static int alloc_spa(struct capi_afu_t *afu)
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
	if (!(afu->spa = (struct capi_process_element *)__get_free_pages(GFP_KERNEL | __GFP_ZERO, afu->spa_order))) {
		pr_err("capi_alloc_spa: Unable to allocate scheduled process area\n");
		return -ENOMEM;
	}
	pr_devel("spa pages: %i afu->spa_max_procs: %i   afu->num_procs: %i\n",
		 1<<afu->spa_order, afu->spa_max_procs, afu->num_procs);
	BUG_ON(afu->spa_max_procs < afu->num_procs);

	afu->sw_command_status = (__be64 *)((char *)afu->spa + ((afu->spa_max_procs + 3) * 128));

	spap = virt_to_phys(afu->spa) & CAPI_PSL_SPAP_Addr;
	spap |= ((afu->spa_size >> (12 - CAPI_PSL_SPAP_Size_Shift)) - 1) & CAPI_PSL_SPAP_Size;
	spap |= CAPI_PSL_SPAP_V;
	pr_devel("capi: SPA allocated at 0x%p. Max processes: %i, sw_command_status: 0x%p CAPI_PSL_SPAP_An=0x%016llx\n", afu->spa, afu->spa_max_procs, afu->sw_command_status, spap);
	capi_p1n_write(afu, CAPI_PSL_SPAP_An, spap);

	ida_init(&afu->pe_index_ida);

	return 0;
}

static void release_spa(struct capi_afu_t *afu)
{
	free_pages((unsigned long) afu->spa, afu->spa_order);
}

static int
init_afu_native(struct capi_afu_t *afu, u64 handle)
{
	u64 val;
	int rc = 0;

	if (afu->err_hwirq) { /* Can drop this test when the BML support is pulled out - under phyp we use capi-of.c */
		pr_devel("capi slice error IVTE: %#lx\n", afu->err_hwirq);
		afu->err_virq = capi_map_irq(afu->adapter, afu->err_hwirq, capi_slice_irq_err, (void*)afu);
		val = capi_p1n_read(afu, CAPI_PSL_SERR_An);
		val = (val & 0x00ffffffffff0000ULL) | (afu->err_hwirq & 0xffff);
		capi_p1n_write(afu, CAPI_PSL_SERR_An, val);
	}

	if (afu->adapter->driver && afu->adapter->driver->init_afu) {
		if ((rc = afu->adapter->driver->init_afu(afu)))
			return rc;
	}

	// FIXME: check we are afu_directed in this whole function
	if (alloc_spa(afu))
		return -ENOMEM;

	capi_p1n_write(afu, CAPI_PSL_SCNTL_An, CAPI_PSL_SCNTL_An_PM_AFU);
	capi_p1n_write(afu, CAPI_PSL_AMOR_An, 0xFFFFFFFFFFFFFFFF);
	capi_p1n_write(afu, CAPI_PSL_ID_An, CAPI_PSL_ID_An_F | CAPI_PSL_ID_An_L);

	afu_disable(afu); /* FIXME: remove this */
	if ((rc = psl_purge(afu))) /* FIXME: remove this */
		return rc;

	if ((rc = afu_reset(afu)))
		return rc;

	if (afu->afu_directed_mode) {
		if ((rc = afu_enable(afu)))
			return rc;
		afu->enabled = true;
	}

	return rc;
}

static void release_afu_native(struct capi_afu_t *afu)
{
	release_spa(afu);
	iounmap(afu->p1n_mmio);
	iounmap(afu->p2n_mmio);
	iounmap(afu->psn_mmio);

	capi_unmap_irq(afu->err_virq, (void*)afu);
	if (afu->adapter->driver && afu->adapter->driver->release_afu)
		afu->adapter->driver->release_afu(afu);
}

static void capi_write_sstp(struct capi_afu_t *afu, u64 sstp0, u64 sstp1)
{
	/* 1. Disable SSTP by writing 0 to SSTP1[V] */
	capi_p2n_write(afu, CAPI_SSTP1_An, 0);

	/* 2. Invalidate all SLB entries */
	capi_p2n_write(afu, CAPI_SLBIA_An, 0);
	/* TODO: Poll for completion */

	/* 3. Set SSTP0_An */
	capi_p2n_write(afu, CAPI_SSTP0_An, sstp0);

	/* 4. Set SSTP1_An */
	capi_p2n_write(afu, CAPI_SSTP1_An, sstp1);
}

/* must hold ctx->afu->spa_lock */
static void
slb_invalid(struct capi_context_t *ctx)
{
	/* FIXME use per slice version of SLBIA? */
	struct capi_t *adapter = ctx->afu->adapter;
	u64 slbia;

	capi_p1_write(adapter, CAPI_PSL_LBISEL,
		      ((u64)be32_to_cpu(ctx->elem->common.pid) << 32) | be32_to_cpu(ctx->elem->lpid));
	capi_p1_write(adapter, CAPI_PSL_SLBIA, CAPI_SLBIA_IQ_LPIDPID);

	while (1) {
		slbia = capi_p1_read(adapter, CAPI_PSL_SLBIA);
		if (!(slbia & CAPI_SLBIA_P))
			break;
		cpu_relax();
	}
	/* TODO: assume TLB is already invalidated via broadcast tlbie */
}

static int do_process_element_cmd(struct capi_context_t *ctx,
				  u64 cmd, u64 pe_state)
{
	u64 state;

	ctx->elem->software_state = cpu_to_be32(pe_state);
	smp_wmb();
	*(ctx->afu->sw_command_status) = cpu_to_be64(cmd | 0 | ctx->ph);
	smp_mb();
	capi_p1n_write(ctx->afu, CAPI_PSL_LLCMD_An, cmd | ctx->ph);
	while (1) {
		state = be64_to_cpup(ctx->afu->sw_command_status);
		if (state == ~0ULL) {
			pr_err("capi: Error adding process element to AFU\n");
			return -1;
		}
		if ((state & (CAPI_SPA_SW_CMD_MASK | CAPI_SPA_SW_STATE_MASK  | CAPI_SPA_SW_LINK_MASK)) ==
		    (cmd | (cmd >> 16) | ctx->ph))
			break;
		cpu_relax();
	}
	return 0;
}

/* TODO: Make sure all operations on the linked list are serialised to prevent
 * races on SPA->sw_command_status */
static int
add_process_element(struct capi_context_t *ctx)
{
	int rc = 0;

	pr_devel("%s Adding pe=%i\n", __FUNCTION__, ctx->ph);
	spin_lock(&ctx->afu->spa_lock);
	rc = do_process_element_cmd(ctx, CAPI_SPA_SW_CMD_ADD, CAPI_PE_SOFTWARE_STATE_V);
	spin_unlock(&ctx->afu->spa_lock);
	return rc;
}

/* FIXME merge this with add_process_element */
static int
terminate_process_element(struct capi_context_t *ctx)
{
	int rc = 0;

	/* fast path terminate if it's already invalid */
	if (!(ctx->elem->software_state & cpu_to_be32(CAPI_PE_SOFTWARE_STATE_V)))
		return rc;

	pr_devel("%s Terminate pe=%i\n", __FUNCTION__, ctx->ph);
	spin_lock(&ctx->afu->spa_lock);
	rc = do_process_element_cmd(ctx, CAPI_SPA_SW_CMD_TERMINATE,
				    CAPI_PE_SOFTWARE_STATE_V | CAPI_PE_SOFTWARE_STATE_T);
	ctx->elem->software_state = cpu_to_be32(0); 	/* Remove Valid bit */
	spin_unlock(&ctx->afu->spa_lock);
	return rc;
}

/* TODO: Make sure all operations on the linked list are serialised to prevent
 * races on SPA->sw_command_status */
static int
remove_process_element(struct capi_context_t *ctx)
{
	int rc = 0;

	pr_devel("%s Remove pe=%i\n", __FUNCTION__, ctx->ph);

	spin_lock(&ctx->afu->spa_lock);
	rc = do_process_element_cmd(ctx, CAPI_SPA_SW_CMD_REMOVE, 0);
	slb_invalid(ctx);
	spin_unlock(&ctx->afu->spa_lock);

	return rc;
}


static void assign_psn_space(struct capi_context_t *ctx)
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
init_afu_directed_process(struct capi_context_t *ctx, bool kernel, u64 wed,
			  u64 amr)
{

	u64 sr, sstp0, sstp1;
	int r, result;

	/* FIXME:
	 * - Add to exising SPA list if one already exists
	 * - Reject if already enabled in different mode, max processes
	 *   exceeded, etc
	 */

	assign_psn_space(ctx);

	ctx->elem->ctxtime = cpu_to_be64(0); /* disable */
	ctx->elem->lpid = cpu_to_be64(mfspr(SPRN_LPID));
	ctx->elem->haurp = cpu_to_be64(0); /* disable */
	ctx->elem->sdr = cpu_to_be64(mfspr(SPRN_SDR1));

	sr = CAPI_PSL_SR_An_SC;
	if (ctx->master)
		sr |= CAPI_PSL_SR_An_MP;
	if (mfspr(SPRN_LPCR) & LPCR_TC)
		sr |= CAPI_PSL_SR_An_TC;
	if (!kernel) {
		/* GA1: HV=0, PR=1, R=1 */
		sr |= CAPI_PSL_SR_An_PR | CAPI_PSL_SR_An_R;
		if (!test_tsk_thread_flag(current, TIF_32BIT))
			sr |= CAPI_PSL_SR_An_SF;
		ctx->elem->common.pid = cpu_to_be32(current->pid);
	} else { /* Initialise for kernel */
		WARN_ONCE(1, "CAPI initialised for kernel, this won't work on GA1 hardware!\n");
		sr |= (mfmsr() & MSR_SF) | CAPI_PSL_SR_An_HV;
		ctx->elem->common.pid = cpu_to_be32(0);
	}
	ctx->elem->common.tid = cpu_to_be32(0);
	ctx->elem->sr = cpu_to_be64(sr);

	ctx->elem->common.csrp = cpu_to_be64(0); /* disable */
	ctx->elem->common.aurp0 = cpu_to_be64(0); /* disable */
	ctx->elem->common.aurp1 = cpu_to_be64(0); /* disable */

	if ((result = capi_alloc_sst(ctx, &sstp0, &sstp1)))
		return result;

	/* TODO: If the wed looks like a valid EA, preload the appropriate segment */
	capi_prefault(ctx, wed);

	ctx->elem->common.sstp0 = cpu_to_be64(sstp0);
	ctx->elem->common.sstp1 = cpu_to_be64(sstp1);

	for (r = 0; r < CAPI_IRQ_RANGES; r++) {
		ctx->elem->ivte_offsets[r] = cpu_to_be16(ctx->irqs.offset[r]);
		ctx->elem->ivte_ranges[r] = cpu_to_be16(ctx->irqs.range[r]);
	}

	ctx->elem->common.amr = cpu_to_be64(amr);
	ctx->elem->common.wed = cpu_to_be64(wed);

	add_process_element(ctx);

	return 0;
}

static int
init_dedicated_process_native(struct capi_context_t *ctx, bool kernel,
			      u64 wed, u64 amr)
{
	struct capi_afu_t * afu = ctx->afu;
	u64 sr, sstp0, sstp1;
	int result;


	/* Ensure AFU is disabled */
	afu_disable(afu);
	if ((result = psl_purge(afu)))
		return result;

	capi_p1n_write(afu, CAPI_PSL_SCNTL_An, CAPI_PSL_SCNTL_An_PM_Process);

	/* Hypervisor initialise: */
	capi_p1n_write(afu, CAPI_PSL_CtxTime_An, 0); /* disable */
	capi_p1n_write(afu, CAPI_PSL_SPAP_An, 0);    /* disable */
	capi_p1n_write(afu, CAPI_PSL_AMOR_An, 0xFFFFFFFFFFFFFFFF);

	capi_p1n_write(afu, CAPI_PSL_LPID_An, mfspr(SPRN_LPID));
	capi_p1n_write(afu, CAPI_HAURP_An, 0);       /* disable */
	capi_p1n_write(afu, CAPI_PSL_SDR_An, mfspr(SPRN_SDR1));

	sr = CAPI_PSL_SR_An_SC;
	if (ctx->master)
		sr |= CAPI_PSL_SR_An_MP;
	if (mfspr(SPRN_LPCR) & LPCR_TC)
		sr |= CAPI_PSL_SR_An_TC;
	if (!kernel) {
		/* GA1: HV=0, PR=1, R=1 */
		sr |= CAPI_PSL_SR_An_PR | CAPI_PSL_SR_An_R;
		if (!test_tsk_thread_flag(current, TIF_32BIT))
			sr |= CAPI_PSL_SR_An_SF;
		capi_p2n_write(afu, CAPI_PSL_PID_TID_An, (u64)current->pid << 32); /* Not using tid field */
	} else { /* Initialise for kernel */
		WARN_ONCE(1, "CAPI initialised for kernel, this won't work on GA1 hardware!\n");
		sr |= (mfmsr() & MSR_SF) | CAPI_PSL_SR_An_HV;
		capi_p2n_write(afu, CAPI_PSL_PID_TID_An, 0);
	}
	capi_p1n_write(afu, CAPI_PSL_SR_An, sr);

	/* OS initialise: */
	capi_p2n_write(afu, CAPI_CSRP_An, 0);        /* disable */
	capi_p2n_write(afu, CAPI_AURP0_An, 0);       /* disable */
	capi_p2n_write(afu, CAPI_AURP1_An, 0);       /* disable */

	if ((result = capi_alloc_sst(ctx, &sstp0, &sstp1)))
		return result;

	/* TODO: If the wed looks like a valid EA, preload the appropriate segment */
	capi_prefault(ctx, wed);

	capi_write_sstp(afu, sstp0, sstp1);
	capi_p1n_write(afu, CAPI_PSL_IVTE_Offset_An,
		       (((u64)ctx->irqs.offset[0] & 0xffff) << 48) |
		       (((u64)ctx->irqs.offset[1] & 0xffff) << 32) |
		       (((u64)ctx->irqs.offset[2] & 0xffff) << 16) |
		        ((u64)ctx->irqs.offset[3] & 0xffff));
	capi_p1n_write(afu, CAPI_PSL_IVTE_Limit_An, (u64)
		       (((u64)ctx->irqs.range[0] & 0xffff) << 48) |
		       (((u64)ctx->irqs.range[1] & 0xffff) << 32) |
		       (((u64)ctx->irqs.range[2] & 0xffff) << 16) |
		        ((u64)ctx->irqs.range[3] & 0xffff));

	capi_p2n_write(afu, CAPI_PSL_AMR_An, amr);

	/* master only context for dedicated */
	assign_psn_space(ctx);

	if ((result = afu_reset(afu)))
		return result;

	/* XXX: Might want the WED & enable in a separate fn? */
	capi_p2n_write(afu, CAPI_PSL_WED_An, wed);

	if ((result = afu_enable(afu)))
		return result;

	afu->enabled = true;
	return 0;
}

static int
init_process_native(struct capi_context_t *ctx, bool kernel, u64 wed,
		  u64 amr)
{
	if (ctx->afu->afu_directed_mode)
		return init_afu_directed_process(ctx, kernel, wed, amr);
	return init_dedicated_process_native(ctx, kernel, wed, amr);
}

static int detach_process_native(struct capi_context_t *ctx)
{
	if (!ctx->afu->afu_directed_mode) {
		psl_purge(ctx->afu);
		return 0;
	}

	if (terminate_process_element(ctx))
		return -1;
	if (remove_process_element(ctx))
		return -1;

	return 0;
}

static int get_irq_native(struct capi_context_t *ctx, struct capi_irq_info *info)
{
	u64 pidtid;
	info->dsisr = capi_p2n_read(ctx->afu, CAPI_PSL_DSISR_An);
	info->dar = capi_p2n_read(ctx->afu, CAPI_PSL_DAR_An);
	info->dsr = capi_p2n_read(ctx->afu, CAPI_PSL_DSR_An);
	pidtid = capi_p2n_read(ctx->afu, CAPI_PSL_PID_TID_An);
	info->pid = pidtid >> 32;
	info->tid = pidtid & 0xffffffff;
	info->afu_err = capi_p2n_read(ctx->afu, CAPI_AFU_ERR_An);
	info->fir_r_slice = capi_p1n_read(ctx->afu, CAPI_PSL_R_FIR_SLICE_An);
	return 0;
}

static void recover_psl_err(struct capi_afu_t *afu, u64 recov)
{
	u64 dsisr;

	pr_devel("RECOVERING FROM PSL ERROR... (0x%.16llx)\n", recov);

	/* Clear PSL_DSISR[PE] */
	dsisr = capi_p2n_read(afu, CAPI_PSL_DSISR_An);
	capi_p2n_write(afu, CAPI_PSL_DSISR_An, dsisr & ~CAPI_PSL_DSISR_An_PE);

	/* Write 1s to clear FIR bits */
	capi_p1n_write(afu, CAPI_PSL_R_FIR_SLICE_An, recov);
}

static int ack_irq_native(struct capi_context_t *ctx, u64 tfc, u64 psl_reset_mask)
{
	if (tfc)
		capi_p2n_write(ctx->afu, CAPI_PSL_TFC_An, tfc);
	if (psl_reset_mask)
		recover_psl_err(ctx->afu, psl_reset_mask);

	return 0;
}

static int load_afu_image_native(struct capi_afu_t *afu, u64 vaddress, u64 length)
{
	unsigned long tmp_allocation;
	u64   block_length;
	u64   reg;
	int   rc = 0;

	tmp_allocation = get_zeroed_page(GFP_KERNEL);

	/* 1a Write AFU_CNTL_An(R)='1' */
	/* 1b Wait for AFU_CNTL_An[RS] = '10' */
	afu_reset(afu);

	/* 2a Write PSL_CNTL_An[Pc]='1' */
	/* 2b Wait for PSL_CNTL_An[Ps]='11' */
	reg = capi_p1n_read(afu, CAPI_PSL_SCNTL_An);
	capi_p1n_write(afu, CAPI_PSL_SCNTL_An, reg | CAPI_PSL_SCNTL_An_Pc);
	while((capi_p1n_read(afu, CAPI_PSL_SCNTL_An) & CAPI_PSL_SCNTL_An_Ps_MASK) != CAPI_PSL_SCNTL_An_Ps_Complete) {
		cpu_relax();
	}

	/* 3. Set PSL_CNTL_AN[CR] bit */
	reg = capi_p1n_read(afu, CAPI_PSL_SCNTL_An);
	capi_p1n_write(afu, CAPI_PSL_SCNTL_An, reg | CAPI_PSL_SCNTL_An_CR);

	/* Write the AFU image a page at a time. */
	while(length) {
		block_length = min((u64)PAGE_SIZE, length);
		if (copy_from_user((void*)tmp_allocation, (void*)vaddress, block_length)) {
			rc = -EFAULT;
			goto out;
		}
		memset((char*)tmp_allocation + block_length, 0, PAGE_SIZE - block_length);

		/* round upto cacheline */
		block_length = (block_length + 127) & (~127ull);

		/* 4. Write address of image block to AFU_DLADDR */
		capi_p1_write(afu->adapter, CAPI_PSL_DLADDR, (u64)tmp_allocation);

		/* 5. Write block size and set start download bit to AFU_DLCNTL */
		capi_p1_write(afu->adapter, CAPI_PSL_DLCNTL, CAPI_PSL_DLCNTL_S | (block_length/128));

		/* 6. Poll for AFU download errors or completion. */
		while ((reg = capi_p1_read(afu->adapter, CAPI_PSL_DLCNTL) & CAPI_PSL_DLCNTL_DCES) == CAPI_PSL_DLCNTL_S) {
			cpu_relax();
		}

		if ((reg & CAPI_PSL_DLCNTL_CE) != 0) {
			rc = -EIO;
			goto out;
		}

		/* 7. repeat steps 4-6 until complete. */

		vaddress += block_length;
		length -= block_length;

		if (length && ((reg & CAPI_PSL_DLCNTL_D) != 0)) {
			WARN(1, "AFU download completed earlier than expected with %llu bytes remaining\n", length);
			goto out;
		}
	}
out:
	free_page(tmp_allocation);
	return rc;
}

int capi_map_slice_regs(struct capi_afu_t *afu,
		  u64 p1n_base, u64 p1n_size,
		  u64 p2n_base, u64 p2n_size,
		  u64 psn_base, u64 psn_size,
		  u64 afu_desc, u64 afu_desc_size)
{
	pr_devel("capi_map_slice_regs: p1: %#.16llx %#llx, p2: %#.16llx %#llx, ps: %#.16llx %#llx, afu_desc: %#.16llx %#llx\n",
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
EXPORT_SYMBOL(capi_map_slice_regs);

void capi_unmap_slice_regs(struct capi_afu_t *afu)
{
	if (afu->psn_mmio)
		iounmap(afu->psn_mmio);

	if (afu->p1n_mmio)
		iounmap(afu->p2n_mmio);

	if (afu->p1n_mmio)
		iounmap(afu->p1n_mmio);
}
EXPORT_SYMBOL(capi_unmap_slice_regs);

static int check_error(struct capi_afu_t *afu)
{
	return (capi_p1n_read(afu, CAPI_PSL_SCNTL_An) == ~0ULL);
}

static const struct capi_backend_ops capi_native_ops = {
	.init_adapter = init_adapter_native,
	.init_afu = init_afu_native,
	.init_process = init_process_native,
	.detach_process = detach_process_native,
	.get_irq = get_irq_native,
	.ack_irq = ack_irq_native,
	.release_adapter = release_adapter_native,
	.release_afu = release_afu_native,
	.load_afu_image = load_afu_image_native,
	.check_error = check_error,
	.afu_reset = afu_reset,
};

void init_capi_native()
{
	capi_ops = &capi_native_ops;
}
