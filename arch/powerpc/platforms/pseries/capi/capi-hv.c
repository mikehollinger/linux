#if 1
#define DEBUG
#else
#undef DEBUG
#endif

#include <linux/sched.h>
#include <linux/of.h>

#include "capi.h"
#include "capi_hcalls.h"

static int read_handle(struct device_node *np, u64 *handle)
{
	const __be32 *prop;
	u64 size;

	prop = of_get_address(np, 0, &size, NULL);
	if (size)
		return -EINVAL;

	/* FIXME: Hardcoded 2 cells, should recursively search parents for
	 * #address-cells like of_translate_address does (in fact, I could
	 * probably just cheat and use of_translate_address since the
	 * translation should be 1:1): */
	*handle = of_read_number(prop, 2);
	return 0;
}

static int __init
init_adapter_hv(struct capi_t *adapter, struct device_node *np)
{
	if (read_handle(np, &adapter->handle)) {
		pr_err("Error reading CAPI PSL handle\n");
		return -EINVAL;
	}

	pr_devel("PSL Handle: 0x%.16llx", adapter->handle);

	return 0;
}

static int __init
init_afu_hv(struct capi_afu_t *afu, struct device_node *np)
{
	int result;

	if (read_handle(np, &afu->handle))
		return -EINVAL;
	if (capi_map_mmio(&(afu->p2n_mmio), NULL, NULL, np, 1))
		goto err;
	if (capi_map_mmio(&(afu->psn_mmio), &afu->psn_phys, &afu->psn_size, np, 2))
		goto err;

	if ((result = capi_h_full_reset(afu->handle)) != H_SUCCESS) {
		WARN(1, "Unable to reset AFU: %i\n", result);
		return result;
	}

	afu_register_irqs(afu, np);
	afu_disable_irqs(afu);

	return 0;
err:
	WARN(1, "Error mapping AFU MMIO regions\n");
	return -EFAULT;
}

static void release_afu_hv(struct capi_afu_t *afu)
{
	capi_unmap_mmio(afu->p2n_mmio);
	if (afu->psn_mmio)
		capi_unmap_mmio(afu->psn_mmio);
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
	struct capi_process_element *elem;
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
	if (!(elem = (struct capi_process_element*)get_zeroed_page(GFP_KERNEL)))
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
		elem->processId = cpu_to_be32(current->pid);
	} else { /* Initialise for kernel */
		WARN(1, "CAPI initialised for kernel under phyp, this is untested and won't work on GA1 hardware!\n");
		if (mfmsr() & MSR_SF)
			elem->sixtyFourBit = 1;
		elem->isPrivilegedProcess = 1;
		elem->processId = 0;
	}
#if 0
	/* XXX: Causes program check */
	if (mfspr(SPRN_LPCR) & LPCR_TC)
		elem->secondarySegmentTableSearchEnabled = 1;
#else
	/*
	 * FIXME: Set this to match our partition's settings. For now it should
	 * be safe to just enable it.
	 */
	elem->secondarySegmentTableSearchEnabled = 1;
#endif
	/* elem->tagsActive - Unsupported in GA1 */
#endif

	elem->version               = cpu_to_be64(CAPI_PROCESS_ELEMENT_VERSION);
	elem->threadId              = cpu_to_be32(0); /* Unused */
	elem->csrp                  = cpu_to_be64(0); /* Disable */
	elem->aurp0                 = cpu_to_be64(0); /* Disable */
	elem->aurp1                 = cpu_to_be64(0); /* Disable */
	elem->sstp0                 = cpu_to_be64(sstp0);
	elem->sstp1                 = cpu_to_be64(sstp1);
	elem->amr                   = cpu_to_be64(amr);
	elem->pslVirtualIsn         = cpu_to_be32(afu->hwirq[0]);
	elem->applicationVirtualIsnBitmap[0] = 0x70; /* Initially use three (after the PSL irq), for compatibility with old CAIA */
	elem->workElementDescriptor = cpu_to_be64(wed);

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
