#if 1
#define DEBUG
#else
#undef DEBUG
#endif

#include <linux/sched.h>

#include "capi.h"
#include "capi_hcalls.h"

static void afu_reset(struct capi_afu_t *afu)
{
	u64 AFU_Cntl;

	pr_devel("AFU reset request\n");
	capi_p2n_write(afu, CAPI_AFU_Cntl_An, CAPI_AFU_Cntl_An_RA);
	AFU_Cntl = capi_p2n_read(afu, CAPI_AFU_Cntl_An);
	while ((AFU_Cntl & CAPI_AFU_Cntl_An_RS_MASK)
			!= CAPI_AFU_Cntl_An_RS_Complete) {
		pr_devel_ratelimited("AFU resetting... (0x%.16llx)\n", AFU_Cntl);
		cpu_relax();
		AFU_Cntl = capi_p2n_read(afu, CAPI_AFU_Cntl_An);
	};
	WARN((capi_p2n_read(afu, CAPI_AFU_Cntl_An)
	     & CAPI_AFU_Cntl_An_ES_MASK)
	     != CAPI_AFU_Cntl_An_ES_Disabled,
	     "AFU not disabled after reset!\n");
	pr_devel("AFU reset\n");
}

static void afu_enable(struct capi_afu_t *afu)
{
	u64 AFU_Cntl = capi_p2n_read(afu, CAPI_AFU_Cntl_An);

	pr_devel("AFU enable request\n");
	WARN((AFU_Cntl & CAPI_AFU_Cntl_An_ES_MASK)
	     != CAPI_AFU_Cntl_An_ES_Disabled,
	     "Enabling AFU not in disabled state\n");

	capi_p2n_write(afu, CAPI_AFU_Cntl_An, AFU_Cntl | CAPI_AFU_Cntl_An_E);
	AFU_Cntl = capi_p2n_read(afu, CAPI_AFU_Cntl_An);
	while ((AFU_Cntl & CAPI_AFU_Cntl_An_ES_MASK)
			!= CAPI_AFU_Cntl_An_ES_Enabled) {
		pr_devel_ratelimited("AFU enabling... (0x%.16llx)\n", AFU_Cntl);
		cpu_relax();
		AFU_Cntl = capi_p2n_read(afu, CAPI_AFU_Cntl_An);
	};
	pr_devel("AFU enabled\n");
}

void afu_disable(struct capi_afu_t *afu)
{
	u64 AFU_Cntl = capi_p2n_read(afu, CAPI_AFU_Cntl_An);

	pr_devel("AFU disable request\n");
	if ((AFU_Cntl & CAPI_AFU_Cntl_An_ES_MASK) != CAPI_AFU_Cntl_An_ES_Enabled) {
		pr_devel("Attempted to disable already disabled AFU\n");
		return;
	}

	capi_p2n_write(afu, CAPI_AFU_Cntl_An, AFU_Cntl | CAPI_AFU_Cntl_An_RA);
	AFU_Cntl = capi_p2n_read(afu, CAPI_AFU_Cntl_An);
	while ((AFU_Cntl & CAPI_AFU_Cntl_An_RS_MASK)
			!= CAPI_AFU_Cntl_An_RS_Complete) {
		pr_devel_ratelimited("AFU disabling... (0x%.16llx)\n", AFU_Cntl);
		cpu_relax();
		AFU_Cntl = capi_p2n_read(afu, CAPI_AFU_Cntl_An);
	};
	pr_devel("AFU disabled\n");
}

void psl_purge(struct capi_afu_t *afu)
{
	u64 PSL_CNTL = capi_p1n_read(afu, CAPI_PSL_CNTL_An);
	u64 AFU_Cntl = capi_p2n_read(afu, CAPI_AFU_Cntl_An);
	u64 start, end;

	pr_devel("PSL purge request\n");

	BUG_ON(PSL_CNTL == ~0ULL); /* FIXME: eeh path */
	BUG_ON(AFU_Cntl == ~0ULL); /* FIXME: eeh path */

	if ((AFU_Cntl & CAPI_AFU_Cntl_An_ES_MASK) != CAPI_AFU_Cntl_An_ES_Disabled) {
		WARN(1, "psl_purge request while AFU not disabled!\n");
		afu_disable(afu);
	}

	capi_p1n_write(afu, CAPI_PSL_CNTL_An,
		       PSL_CNTL | CAPI_PSL_CNTL_An_Pc);
	start = mftb();
	PSL_CNTL = capi_p1n_read(afu, CAPI_PSL_CNTL_An);
	while ((PSL_CNTL &  CAPI_PSL_CNTL_An_Ps_MASK)
			== CAPI_PSL_CNTL_An_Ps_Pending) {
		pr_devel_ratelimited("PSL purging... (0x%.16llx)\n", PSL_CNTL);
		cpu_relax();
		PSL_CNTL = capi_p1n_read(afu, CAPI_PSL_CNTL_An);
		BUG_ON(PSL_CNTL == ~0ULL); /* FIXME: eeh path */
	};
	end = mftb();
	pr_devel("PSL purged in %lld 512MHz tb ticks\n", end - start);
	/* FIXME: Should this be re-enabled here, or after resetting the AFU? */
	capi_p1n_write(afu, CAPI_PSL_CNTL_An,
		       PSL_CNTL & ~CAPI_PSL_CNTL_An_Pc);
}


static int
init_adapter_native(struct capi_t *adapter, u64 unused,
		    u64 p1_base, u64 p1_size,
		    u64 p2_base, u64 p2_size,
		    irq_hw_number_t err_hwirq)
{
	pr_devel("capi_mmio_p1:        ");
	if (!(adapter->p1_mmio = ioremap(p1_base, p1_size)))
		return -ENOMEM;

	if (!(adapter->p2_mmio = ioremap(p2_base, p2_size)))
		return -ENOMEM;

	if (err_hwirq) {
		/* XXX: Only BML passes this in, can drop this for upstream */
		adapter->err_hwirq = err_hwirq;
	} else
		adapter->err_hwirq = capi_alloc_one_hwirq();
	pr_devel("capi_err_ivte: %#lx", adapter->err_hwirq);
	adapter->err_virq = capi_map_irq(adapter->err_hwirq, capi_irq_err, (void*)adapter);
	capi_p1_write(adapter, CAPI_PSL_ErrIVTE, adapter->err_hwirq);

	return 0;
}

/* XXX: Untested */
static void release_adapter_native(struct capi_t *adapter)
{
	capi_unmap_irq(adapter->err_virq, (void*)adapter);
	iounmap(adapter->p1_mmio);
}

static int
init_afu_native(struct capi_afu_t *afu, u64 handle,
		u64 p1n_base, u64 p1n_size,
		u64 p2n_base, u64 p2n_size,
		u64 psn_base, u64 psn_size,
		u32 irq_start, u32 irq_count)
{
	if (!(afu->p1n_mmio = ioremap(p1n_base, p1n_size)))
		goto err;
	if (!(afu->p2n_mmio = ioremap(p2n_base, p2n_size)))
		goto err1;
	if (!(afu->psn_mmio = ioremap(psn_base, psn_size)))
		goto err2;
	afu->psn_phys = psn_base;
	afu->psn_size = psn_size;

	afu_disable(afu);
	psl_purge(afu);

	afu_register_irqs(afu, irq_start, irq_count);

	return 0;

err2:
	iounmap(afu->p2n_mmio);
err1:
	iounmap(afu->p1n_mmio);
err:
	WARN(1, "Error mapping AFU MMIO regions\n");
	return -EFAULT;
}

static void release_afu_native(struct capi_afu_t *afu)
{
	iounmap(afu->p1n_mmio);
	iounmap(afu->p2n_mmio);
	iounmap(afu->psn_mmio);
}

static void capi_write_sstp(struct capi_afu_t *afu, u64 sstp0, u64 sstp1)
{
	/* 1. Disable SSTP by writing 0 to SSTP1[V] */
	capi_p2n_write(afu, CAPI_SSTP1_An, 0);

	/* 2. Invalidate all SLB entries */
	capi_p2n_write(afu, CAPI_SLBIA_An, 0);

	/* 3. Set SSTP0_An */
	capi_p2n_write(afu, CAPI_SSTP0_An, sstp0);

	/* 4. Set SSTP1_An */
	capi_p2n_write(afu, CAPI_SSTP1_An, sstp1);
}

static int
init_dedicated_process_native(struct capi_afu_t *afu, bool kernel,
			      u64 wed, u64 amr)
{
	u64 sr, sstp0, sstp1;
	int result;

	/* Ensure AFU is disabled */
	afu_disable(afu);
	psl_purge(afu);

	capi_p1n_write(afu, CAPI_PSL_CNTL_An, CAPI_PSL_CNTL_An_PM_Process);

	/* Hypervisor initialise: */
	capi_p1n_write(afu, CAPI_PSL_CtxTime_An, 0); /* disable */
	capi_p1n_write(afu, CAPI_PSL_SPAP_An, 0);    /* disable */
	capi_p1n_write(afu, CAPI_PSL_AMOR_An, 0xFFFFFFFFFFFFFFFF); /* XXX: Is 0 or 1 allowed? */
	capi_p1n_write(afu, CAPI_PSL_IVTE_Limit_An, 0); /* XXX: Hypervisor limit interrupts */

	capi_p1n_write(afu, CAPI_PSL_SR_An,
		       CAPI_PSL_SR_An_SF |
		       CAPI_PSL_SR_An_PR | /* GA1: HV=0,PR=1 */
		       CAPI_PSL_SR_An_R);  /* GA1: R=1 */

	capi_p1n_write(afu, CAPI_PSL_LPID_An, mfspr(SPRN_LPID));
	capi_p1n_write(afu, CAPI_HAURP_An, 0);       /* disable */
	capi_p1n_write(afu, CAPI_PSL_SDR_An, mfspr(SPRN_SDR1));

	sr = CAPI_PSL_SR_An_SC;
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

	if ((result = capi_alloc_sst(afu, &sstp0, &sstp1)))
		return result;

	/* TODO: If the wed looks like a valid EA, preload the appropriate segment */
	capi_prefault(afu, wed);

	capi_write_sstp(afu, sstp0, sstp1);
	capi_p2n_write(afu, CAPI_PSL_IVTE_An,
			(afu->hwirq[0] & 0xffff) << 48 |
			(afu->hwirq[1] & 0xffff) << 32 |
			(afu->hwirq[2] & 0xffff) << 16 |
			(afu->hwirq[3] & 0xffff));
	capi_p2n_write(afu, CAPI_PSL_AMR_An, amr);

	afu_reset(afu);

	/* XXX: Might want the WED & enable in a separate fn? */
	capi_p2n_write(afu, CAPI_PSL_WED_An, wed);

	afu_enable(afu);

	return 0;
}

static int detach_process_native(struct capi_afu_t *afu)
{
	afu_disable(afu);
	psl_purge(afu);
	return 0;
}

static int get_irq_native(struct capi_afu_t *afu, struct capi_irq_info *info)
{
	u64 pidtid;
	info->dsisr = capi_p2n_read(afu, CAPI_PSL_DSISR_An);
	info->dar = capi_p2n_read(afu, CAPI_PSL_DAR_An);
	info->dsr = capi_p2n_read(afu, CAPI_PSL_DSR_An);
	pidtid = capi_p2n_read(afu, CAPI_PSL_PID_TID_An);
	info->pid = pidtid >> 32;
	info->tid = pidtid & 0xffffffff;
	info->afu_err = capi_p2n_read(afu, CAPI_AFU_ERR_An);
	info->fir_r_slice = capi_p1n_read(afu, CAPI_PSL_R_FIR_SLICE_An);
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

static int ack_irq_native(struct capi_afu_t *afu, u64 tfc, u64 psl_reset_mask)
{
	if (tfc)
		capi_p2n_write(afu, CAPI_PSL_TFC_An, tfc);
	if (psl_reset_mask)
		recover_psl_err(afu, psl_reset_mask);

	return 0;
}


static const struct capi_ops capi_native_ops = {
	.init_adapter = init_adapter_native,
	.init_afu = init_afu_native,
	.init_dedicated_process = init_dedicated_process_native,
	.detach_process = detach_process_native,
	.get_irq = get_irq_native,
	.ack_irq = ack_irq_native,
	.release_adapter = release_adapter_native,
	.release_afu = release_afu_native,
};

void init_capi_native()
{
	capi_ops = &capi_native_ops;
}
