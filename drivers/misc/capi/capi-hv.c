#if 1
#define DEBUG
#else
#undef DEBUG
#endif

#include <linux/sched.h>

#include "capi.h"
#include "capi_hcalls.h"

static int
init_adapter_hv(struct capi_t *adapter, void *backend_data)
{
	adapter->handle = ((struct capi_hv_data *) backend_data)->handle;
	pr_devel("PSL Handle: 0x%.16llx", adapter->handle);

	return 0;
}

static int
init_afu_hv(struct capi_afu_t *afu, u64 handle)
{
	int result;

	afu->handle = handle;

	if ((result = capi_h_full_reset(afu->handle)) != H_SUCCESS) {
		WARN(1, "Unable to reset AFU: %i\n", result);
		return result;
	}

#if 0 /* FIXME: afu_register_irqs() is now done in file.c, but we still need
	 this afu_disable_irqs() in the guest code path only... */

	afu_register_irqs(afu, irq_start, irq_count);
	afu_disable_irqs(afu);
#endif

	return 0;
}

static void release_afu_hv(struct capi_afu_t *afu)
{
	iounmap(afu->p2n_mmio);
	if (afu->psn_mmio)
		iounmap(afu->psn_mmio);
}

static int get_irq_hv(struct capi_context_t *ctx, struct capi_irq_info *info)
{
	return capi_h_collect_int_info(ctx->afu->handle, ctx->process_token, info);
}

static int ack_irq_hv(struct capi_context_t *ctx, u64 tfc, u64 psl_reset_mask)
{
	u64 ret; /* Indicates pending state - may be useful for debugging */

	return capi_h_control_faults(ctx->afu->handle, ctx->process_token,
				     tfc >> 32,
				     !!psl_reset_mask, /* XXX: PAPR describes
							  this as a mask, yet
							  indicates only the
							  low bit is used? */
				     &ret);
}

static int clear_pending_irqs(struct capi_context_t *ctx)
{
	struct capi_irq_info info;
	int result;

	pr_warn("Attempting to clear any pending PSL interrupts...\n");
	if ((result = capi_ops->get_irq(ctx, &info))) {
		pr_warn("Unable to get CAPI IRQ Info: %i\n", result);
		return result;
	}

	if (info.dsisr & CAPI_PSL_DSISR_TRANS) {
		pr_warn("Clearing PSL translation fault 0x%.16llx...\n", info.dsisr);
		return ack_irq_hv(ctx, CAPI_PSL_TFC_An_AE, 0);
	}
	if (info.dsisr & CAPI_PSL_DSISR_An_PE) {
		pr_warn("Clearing implementation specific PSL error 0x%.16llx 0x%.16llx...\n",
				info.dsisr, info.fir_r_slice);
		return ack_irq_hv(ctx, CAPI_PSL_TFC_An_A, 1);
	}
	pr_warn("Clearing non-translation PSL fault... 0x%.16llx\n", info.dsisr);
	return ack_irq_hv(ctx, CAPI_PSL_TFC_An_A, 0);
}

static int detach_process_hv(struct capi_context_t *ctx)
{
	int ret;

	if (!ctx->process_token) {
		pr_devel("capi: Attempted to detach non-attached process\n");
		return -1;
	}
	afu_disable_irqs(ctx);
	ret = capi_h_detach_process(ctx->afu->handle, ctx->process_token);
	if (ret == -EIO) {
		clear_pending_irqs(ctx);
		ret = capi_h_detach_process(ctx->afu->handle, ctx->process_token);
	}
	ctx->process_token = 0;

	return ret;
}

static int
init_dedicated_process_hv(struct capi_context_t *ctx, bool kernel,
		          u64 wed, u64 amr)
{
	struct capi_process_element_hcall *elem;
	u64 sstp0, sstp1;
	int rc = 0, result;
	const struct cred *cred;
	u32 irq;
	int i, r;

	if (ctx->process_token) {
		pr_info("capi: init dedicated process while attached, detaching...\n");
		if ((result = detach_process_hv(ctx))) {
			WARN(1, "Unable to detach existing process\n");
			return result;
		}
	}

	/* Must be 8 byte aligned and cannot cross a 4096 byte boundary */
	if (!(elem = (struct capi_process_element_hcall*)get_zeroed_page(GFP_KERNEL)))
		return -ENOMEM;

	if ((result = capi_alloc_sst(ctx, &sstp0, &sstp1))) {
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
		elem->isPrivilegedProcess = uid_eq(cred->euid, GLOBAL_ROOT_UID);
		put_cred(cred);
		elem->common.pid = cpu_to_be32(current->pid);
	} else { /* Initialise for kernel */
		WARN(1, "CAPI initialised for kernel under phyp, this is untested and won't work on GA1 hardware!\n");
		if (mfmsr() & MSR_SF)
			elem->sixtyFourBit = 1;
		elem->isPrivilegedProcess = 1;
		elem->common.pid = 0;
	}
	/*
	 * FIXME: Set this to match our partition's settings. For now it should
	 * be safe to just enable it.
	 */
	elem->secondarySegmentTableSearchEnabled = 1;
	/* elem->tagsActive - Unsupported in GA1 */
#endif

	elem->version               = cpu_to_be64(CAPI_PROCESS_ELEMENT_VERSION);
	elem->common.tid            = cpu_to_be32(0); /* Unused */
	elem->common.csrp           = cpu_to_be64(0); /* Disable */
	elem->common.aurp0          = cpu_to_be64(0); /* Disable */
	elem->common.aurp1          = cpu_to_be64(0); /* Disable */
	elem->common.sstp0          = cpu_to_be64(sstp0);
	elem->common.sstp1          = cpu_to_be64(sstp1);
	elem->common.amr            = cpu_to_be64(amr);
	elem->pslVirtualIsn         = cpu_to_be32(ctx->irqs.offset[0]);
	for (r = 0; r < CAPI_IRQ_RANGES; r++) {
		/* FIXME: Test this and maybe optimise - can we use bitmap.h? */
		irq = ctx->irqs.offset[r];
		for (i = 0; i < ctx->irqs.range[r]; i++) {
			if (r == 0 && i == 0) /* PSL interrupt, set above */
				continue;
			elem->applicationVirtualIsnBitmap[irq / 8] |= 0x80 >> (irq % 8);
		}
	}
	elem->common.wed = cpu_to_be64(wed);

	if ((rc = capi_h_attach_process(ctx->afu->handle, elem, &ctx->process_token)))
		goto out;

	afu_enable_irqs(ctx);

out:
	free_page((u64)elem);
	return rc;
}

static const struct capi_backend_ops capi_hv_ops = {
	.init_adapter = init_adapter_hv,
	.init_afu = init_afu_hv,
	.init_process = init_dedicated_process_hv,
	.detach_process = detach_process_hv,
	.get_irq = get_irq_hv,
	.ack_irq = ack_irq_hv,
	.release_afu = release_afu_hv,
};

void init_capi_hv()
{
	capi_ops = &capi_hv_ops;
}
