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

static int afu_reset(struct capi_afu_t *afu)
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
			pr_warn("WARNING: PSL Purge timed out!\n");
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
			pr_warn("WARNING: PSL Purge timed out!\n");
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
		pr_devel_ratelimited("PSL purging... (0x%.16llx)\n", PSL_CNTL);
		cpu_relax();
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
init_adapter_native(struct capi_t *adapter, u64 unused,
		    u64 p1_base, u64 p1_size,
		    u64 p2_base, u64 p2_size,
		    irq_hw_number_t err_hwirq)
{
	int rc;

	pr_devel("capi_mmio_p1:        ");
	if (!(adapter->p1_mmio = ioremap(p1_base, p1_size)))
		return -ENOMEM;

	if (p2_base) {
		if (!(adapter->p2_mmio = ioremap(p2_base, p2_size)))
			return -ENOMEM;
	}

	if (adapter->driver && adapter->driver->init_adapter) {
		if ((rc = adapter->driver->init_adapter(adapter)))
			return rc;
	}

	pr_devel("capi implementation specific PSL_VERSION: 0x%llx\n",
			capi_p1_read(adapter, CAPI_PSL_VERSION));

	adapter->err_hwirq = err_hwirq;
	pr_devel("capi_err_ivte: %#lx\n", adapter->err_hwirq);
	adapter->err_virq = capi_map_irq(adapter, adapter->err_hwirq, capi_irq_err, (void*)adapter);
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
		irq_hw_number_t irq_start, irq_hw_number_t irq_count)
{
	int rc = 0;

	if (!(afu->p1n_mmio = ioremap(p1n_base, p1n_size)))
		goto err;
	if (!(afu->p2n_mmio = ioremap(p2n_base, p2n_size)))
		goto err1;
	if (!(afu->psn_mmio = ioremap(psn_base, psn_size)))
		goto err2;
	afu->psn_phys = psn_base;
	afu->psn_size = psn_size;

	afu_register_irqs(afu, irq_start, irq_count);

	if (afu->adapter->driver && afu->adapter->driver->init_afu) {
		if ((rc = afu->adapter->driver->init_afu(afu)))
			return rc;
	}

	afu_disable(afu);
	rc = psl_purge(afu);

	return rc;

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

static int alloc_spa(struct capi_afu_t *afu, int max_procs)
{
	u64 spap;

	/* TODO: Calculate required size to fit that many procs and try to
	 * allocate enough contiguous pages to support it, but fall back to
	 * less pages if allocation is not possible.
	 */
	if (!(afu->spa = (struct capi_process_element *)get_zeroed_page(GFP_KERNEL))) {
		pr_err("capi_alloc_spa: Unable to allocate scheduled process area\n");
		return -ENOMEM;
	}
	afu->spa_size = PAGE_SIZE;

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
	afu->max_procs = (((afu->spa_size / 8) - 96) / 17);

	afu->sw_command_status = (__be64 *)(afu->spa + (afu->max_procs * 128) + 16);

	pr_devel("capi: SPA allocated at 0x%p. Max processes: %i, sw_command_status: 0x%p\n", afu->spa, afu->max_procs, afu->sw_command_status);

	spap = virt_to_phys(afu->spa) & CAPI_PSL_SPAP_Addr;
	spap |= ((afu->spa_size >> (12 - CAPI_PSL_SPAP_Size_Shift)) - 1) & CAPI_PSL_SPAP_Size;
	spap |= CAPI_PSL_SPAP_V;
	capi_p1n_write(afu, CAPI_PSL_SPAP_An, spap);

	return 0;
}

static inline u64 pe_handle(struct capi_process_element *elem)
{
	return ((u64)elem >> 7) & CAPI_LLCMD_HANDLE_MASK;
}

/* TODO: Make sure all operations on the linked list are serialised to prevent
 * races on SPA->sw_command_status */
static int
add_process_element(struct capi_afu_t *afu, struct capi_process_element *elem)
{
	u64 state;

	elem->software_state = CAPI_PE_SOFTWARE_STATE_V;
	*afu->sw_command_status = 0; /* XXX: Not listed in CAIA procedure */
	smp_mb();
	capi_p1n_write(afu, CAPI_PSL_LLCMD_An, CAPI_LLCMD_ADD | pe_handle(elem));

	while (1) {
		state = be64_to_cpup(afu->sw_command_status);
		if (state == ~0ULL) {
			pr_err("capi: Error adding process element to AFU\n");
			return -1;
		}
		if ((state & (CAPI_SPA_SW_CMD_MASK | CAPI_SPA_SW_STATE_MASK  | CAPI_SPA_SW_LINK_MASK)) ==
			     (CAPI_SPA_SW_CMD_ADD  | CAPI_SPA_SW_STATE_ADDED | pe_handle(elem))) {
			break;
		}
		cpu_relax();
	}

	return 0;
}

static int
init_afu_directed_native(struct capi_afu_t *afu, bool kernel,
			 u64 wed, u64 amr)
{
	struct capi_process_element *elem;
	u64 sr, sstp0, sstp1;
	int result;
	int i;

	/* FIXME:
	 * - Add to exising SPA list if one already exists
	 * - Reject if already enabled in different mode, max processes
	 *   exceeded, etc
	 */

	if (alloc_spa(afu, 1))
		return -ENOMEM;

	/* TODO: Find free entry */
	elem = &afu->spa[0];

	capi_p1n_write(afu, CAPI_PSL_SCNTL_An, CAPI_PSL_SCNTL_An_PM_AFU);
	capi_p1n_write(afu, CAPI_PSL_AMOR_An, 0xFFFFFFFFFFFFFFFF);

	elem->ctxtime = cpu_to_be64(0); /* disable */
	elem->lpid = cpu_to_be64(mfspr(SPRN_LPID));
	elem->haurp = cpu_to_be64(0); /* disable */
	elem->sdr = cpu_to_be64(mfspr(SPRN_SDR1));

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
	elem->sr = cpu_to_be64(sr);

	elem->common.csrp = cpu_to_be64(0); /* disable */
	elem->common.aurp0 = cpu_to_be64(0); /* disable */
	elem->common.aurp1 = cpu_to_be64(0); /* disable */

	if ((result = capi_alloc_sst(afu, &sstp0, &sstp1)))
		return result;

	printk("%s 10\n", __FUNCTION__);
	/* TODO: If the wed looks like a valid EA, preload the appropriate segment */
	capi_prefault(afu, wed);

	printk("%s 20\n", __FUNCTION__);
	elem->common.sstp0 = cpu_to_be64(sstp0);
	elem->common.sstp1 = cpu_to_be64(sstp1);

	for (i = 0; i < 4; i++) {
		elem->ivte.offsets[i] = cpu_to_be16(afu->hwirq[i] & 0xffff);
		elem->ivte.ranges[i] = cpu_to_be16(1);
	}

	elem->common.amr = cpu_to_be64(amr);
	elem->common.wed = cpu_to_be64(wed);


	printk("%s 30\n", __FUNCTION__);
	add_process_element(afu, elem);
	printk("%s 40\n", __FUNCTION__);

	if ((result = afu_reset(afu)))
		return result;
	printk("%s 50\n", __FUNCTION__);
	if ((result = afu_enable(afu)))
		return result;

	printk("%s 60\n", __FUNCTION__);
	return 0;
}

static int
init_dedicated_process_native(struct capi_afu_t *afu, bool kernel,
			      u64 wed, u64 amr)
{
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
	if (CAIA_VERSION < 11) {
		/* handle older versions of CAIA in the lab for now */
		/* fixme remove this */
		const capi_p1n_reg_t CAPI_PSL_IVTE_Limit_An_OLD = {0xA8};
		const capi_p2n_reg_t CAPI_PSL_IVTE_An_OLD = {0x80};
		capi_p1n_write(afu, CAPI_PSL_IVTE_Limit_An_OLD, 0);
		capi_p2n_write(afu, CAPI_PSL_IVTE_An_OLD,
			       ((afu->hwirq[0] & 0xffff) << 48) |
			       ((afu->hwirq[1] & 0xffff) << 32) |
			       ((afu->hwirq[2] & 0xffff) << 16) |
			       (afu->hwirq[3] & 0xffff));
	} else {
		capi_p1n_write(afu, CAPI_PSL_IVTE_Limit_An,
			       (1ULL << 48) |
			       (1ULL << 32) |
			       (1ULL << 16) |
			       1ULL);
		capi_p1n_write(afu, CAPI_PSL_IVTE_Offset_An,
			       ((afu->hwirq[0] & 0xffff) << 48) |
			       ((afu->hwirq[1] & 0xffff) << 32) |
			       ((afu->hwirq[2] & 0xffff) << 16) |
			       (afu->hwirq[3] & 0xffff));
	}

	capi_p2n_write(afu, CAPI_PSL_AMR_An, amr);

	if ((result = afu_reset(afu)))
		return result;

	/* XXX: Might want the WED & enable in a separate fn? */
	capi_p2n_write(afu, CAPI_PSL_WED_An, wed);

	if ((result = afu_enable(afu)))
		return result;

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

static const struct capi_backend_ops capi_native_ops = {
	.init_adapter = init_adapter_native,
	.init_afu = init_afu_native,
	.init_dedicated_process = init_afu_directed_native,
	.init_afu_directed = init_afu_directed_native,
	.detach_process = detach_process_native,
	.get_irq = get_irq_native,
	.ack_irq = ack_irq_native,
	.release_adapter = release_adapter_native,
	.release_afu = release_afu_native,
	.load_afu_image = load_afu_image_native,
};

void init_capi_native()
{
	capi_ops = &capi_native_ops;
}
