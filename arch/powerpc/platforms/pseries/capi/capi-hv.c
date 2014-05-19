#if 1
#define DEBUG
#else
#undef DEBUG
#endif

#include <linux/sched.h>

#include "capi.h"
#include "capi_hcalls.h"

static int
init_adapter_hv(struct capi_t *adapter, u64 handle, u64 unused1, u64 unused2,
		irq_hw_number_t unused3)
{
	adapter->handle = handle;
	pr_devel("PSL Handle: 0x%.16llx", adapter->handle);

	return 0;
}

static int
init_afu_hv(struct capi_afu_t *afu, u64 handle,
	    u64 p1n_base, u64 p1n_size, /* unused */
	    u64 p2n_base, u64 p2n_size,
	    u64 psn_base, u64 psn_size,
	    u32 irq_start, u32 irq_count)

{
	int result;

	afu->handle = handle;
	if (!(afu->p2n_mmio = ioremap(p2n_base, p2n_size)))
		goto err1;
	if (!(afu->psn_mmio = ioremap(psn_base, psn_size)))
		goto err2;
	afu->psn_phys = psn_base;
	afu->psn_size = psn_size;

	if ((result = capi_h_full_reset(afu->handle)) != H_SUCCESS) {
		WARN(1, "Unable to reset AFU: %i\n", result);
		return result;
	}

	afu_register_irqs(afu, irq_start, irq_count);
	afu_disable_irqs(afu);

	return 0;

err2:
	iounmap(afu->p2n_mmio);
err1:
	WARN(1, "Error mapping AFU MMIO regions\n");
	return -EFAULT;
}

static void release_afu_hv(struct capi_afu_t *afu)
{
	iounmap(afu->p2n_mmio);
	if (afu->psn_mmio)
		iounmap(afu->psn_mmio);
}

static int get_irq_hv(struct capi_afu_t *afu, struct capi_irq_info *info)
{
	return capi_h_collect_int_info(afu->handle, afu->process_token, info);
}

static int ack_irq_hv(struct capi_afu_t *afu, u64 tfc, u64 psl_reset_mask)
{
	u64 ret; /* Indicates pending state - may be useful for debugging */

	return capi_h_control_faults(afu->handle, afu->process_token,
				     tfc >> 32,
				     !!psl_reset_mask, /* XXX: PAPR describes
							  this as a mask, yet
							  indicates only the
							  low bit is used? */
				     &ret);
}

static int clear_pending_irqs(struct capi_afu_t *afu)
{
	struct capi_irq_info info;
	int result;

	pr_warn("Attempting to clear any pending PSL interrupts...\n");
	if ((result = capi_ops->get_irq(afu, &info))) {
		pr_warn("Unable to get CAPI IRQ Info: %i\n", result);
		return result;
	}

	if (info.dsisr & CAPI_PSL_DSISR_TRANS) {
		pr_warn("Clearing PSL translation fault 0x%.16llx...\n", info.dsisr);
		return ack_irq_hv(afu, CAPI_PSL_TFC_An_AE, 0);
	}
	if (info.dsisr & CAPI_PSL_DSISR_An_PE) {
		pr_warn("Clearing implementation specific PSL error 0x%.16llx 0x%.16llx...\n",
				info.dsisr, info.fir_r_slice);
		return ack_irq_hv(afu, CAPI_PSL_TFC_An_A, 1);
	}
	pr_warn("Clearing non-translation PSL fault... 0x%.16llx\n", info.dsisr);
	return ack_irq_hv(afu, CAPI_PSL_TFC_An_A, 0);
}

static int detach_process_hv(struct capi_afu_t *afu)
{
	int ret;

	if (!afu->process_token) {
		pr_devel("capi: Attempted to detach non-attached process\n");
		return -1;
	}
	afu_disable_irqs(afu);
	ret = capi_h_detach_process(afu->handle, afu->process_token);
	if (ret == -EIO) {
		clear_pending_irqs(afu);
		ret = capi_h_detach_process(afu->handle, afu->process_token);
	}
	afu->process_token = 0;

	return ret;
}

static int
init_dedicated_process_hv(struct capi_afu_t *afu, bool kernel,
		          u64 wed, u64 amr)
{
	struct capi_process_element_hcall *elem;
	u64 sstp0, sstp1;
	int rc = 0, result;
	const struct cred *cred;

	if (afu->process_token) {
		pr_info("capi: init dedicated process while attached, detaching...\n");
		if ((result = detach_process_hv(afu))) {
			WARN(1, "Unable to detach existing process\n");
			return result;
		}
	}

	/* Must be 8 byte aligned and cannot cross a 4096 byte boundary */
	if (!(elem = (struct capi_process_element_hcall*)get_zeroed_page(GFP_KERNEL)))
		return -ENOMEM;

	if ((result = capi_alloc_sst(afu, &sstp0, &sstp1))) {
		rc = result;
		goto out;
	}

#if 1 /* FIXME: These are bitfields, replace this section to ensure
	 compatibility with compiler changes + little endian */
	elem->csrpValid = 0;
	if (!kernel) {
		elem->problemState = 1;
		elem->translationEnabled = 1;
		/* elem->userState - Unsupported in GA1 */
		if (!test_tsk_thread_flag(current, TIF_32BIT))
			elem->sixtyFourBit = 1;
		cred = get_current_cred();
		elem->isPrivilegedProcess = cred->euid == 0;
		put_cred(cred);
		elem->common.processId = cpu_to_be32(current->pid);
	} else { /* Initialise for kernel */
		WARN(1, "CAPI initialised for kernel under phyp, this is untested and won't work on GA1 hardware!\n");
		if (mfmsr() & MSR_SF)
			elem->sixtyFourBit = 1;
		elem->isPrivilegedProcess = 1;
		elem->common.processId = 0;
	}
	/*
	 * FIXME: Set this to match our partition's settings. For now it should
	 * be safe to just enable it.
	 */
	elem->secondarySegmentTableSearchEnabled = 1;
	/* elem->tagsActive - Unsupported in GA1 */
#endif

	elem->version               = cpu_to_be64(CAPI_PROCESS_ELEMENT_VERSION);
	elem->common.threadId       = cpu_to_be32(0); /* Unused */
	elem->common.csrp           = cpu_to_be64(0); /* Disable */
	elem->common.aurp0          = cpu_to_be64(0); /* Disable */
	elem->common.aurp1          = cpu_to_be64(0); /* Disable */
	elem->common.sstp0          = cpu_to_be64(sstp0);
	elem->common.sstp1          = cpu_to_be64(sstp1);
	elem->common.amr            = cpu_to_be64(amr);
	elem->pslVirtualIsn         = cpu_to_be32(afu->hwirq[0]);
	elem->applicationVirtualIsnBitmap[0] = 0x70; /* Initially use three (after the PSL irq), for compatibility with old CAIA */
	elem->common.workElementDescriptor = cpu_to_be64(wed);

	if ((rc = capi_h_attach_process(afu->handle, elem, &afu->process_token)))
		goto out;

	afu_enable_irqs(afu);

out:
	free_page((u64)elem);
	return rc;
}

static const struct capi_ops capi_hv_ops = {
	.init_adapter = init_adapter_hv,
	.init_afu = init_afu_hv,
	.init_dedicated_process = init_dedicated_process_hv,
	.detach_process = detach_process_hv,
	.get_irq = get_irq_hv,
	.ack_irq = ack_irq_hv,
	.release_afu = release_afu_hv,
};

void init_capi_hv()
{
	capi_ops = &capi_hv_ops;
}
