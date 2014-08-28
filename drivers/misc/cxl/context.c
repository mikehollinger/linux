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

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/bitmap.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/debugfs.h>
#include <linux/slab.h>
#include <asm/cputable.h>
#include <asm/current.h>
#include <asm/copro.h>

#include "cxl.h"

/*
 * Allocates space for a CXL context.
 */
struct cxl_context_t *cxl_context_alloc(void)
{
	return kzalloc(sizeof(struct cxl_context_t), GFP_KERNEL);
}

/*
 * Initialises a CXL context.
 */
int cxl_context_init(struct cxl_context_t *ctx, struct cxl_afu_t *afu, bool master)
{
	int i;

	spin_lock_init(&ctx->sst_lock);
	ctx->sstp = NULL;
	ctx->afu = afu;
	ctx->master = master;
	ctx->pid = get_pid(get_task_pid(current, PIDTYPE_PID));

	INIT_WORK(&ctx->fault_work, cxl_handle_fault);

	init_waitqueue_head(&ctx->wq);
	spin_lock_init(&ctx->lock);

	ctx->irq_bitmap = NULL;
	ctx->pending_irq = false;
	ctx->pending_fault = false;
	ctx->pending_afu_err = false;

	/* FIXME: need to make this two stage between the open and the ioctl */
	ctx->attached = 1;

	i = ida_simple_get(&ctx->afu->pe_index_ida, 0,
			   ctx->afu->num_procs, GFP_KERNEL);
	if (i < 0)
		return i;

	ctx->ph = i;
	ctx->elem = &ctx->afu->spa[i];
	ctx->pe_inserted = false;
	return 0;
}

/*
 * Activate a context on its AFU.
 */
void cxl_context_start(struct cxl_context_t *ctx)
{
	spin_lock(&ctx->afu->contexts_lock);
	list_add(&ctx->list, &ctx->afu->contexts);
	spin_unlock(&ctx->afu->contexts_lock);
}

/*
 * Map a per-context mmio space into the given vma.
 */
int cxl_context_iomap(struct cxl_context_t *ctx, struct vm_area_struct *vma)
{
	u64 len = vma->vm_end - vma->vm_start;
	len = min(len, ctx->psn_size);

	/* FIXME: Clean this up to separate current vs. supported models */
	if (!ctx->afu->afu_directed_mode) {
		vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
		return vm_iomap_memory(vma, ctx->afu->psn_phys, ctx->afu->psn_size);
	}

	/* make sure there is a valid per process space for this AFU */
	if ((ctx->master && !ctx->afu->mmio) || (!ctx->afu->pp_mmio)) {
		pr_devel("AFU doesn't support mmio space\n");
		return -EINVAL;
	}

	/* Can't mmap until the AFU is enabled
	   FIXME: check on teardown */
	if (!ctx->afu->enabled)
		return -EBUSY;

	pr_devel("%s: mmio physical: %llx pe: %i master:%i\n", __FUNCTION__,
		 ctx->psn_phys, ctx->ph , ctx->master);

	/* FIXME: Return error if virtualised AFU */
	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
	return vm_iomap_memory(vma, ctx->psn_phys, len);
}

/*
 * Detach a context from the hardware. This disables interrupts and doesn't return until
 * all outstanding interrupts for this context have completed. The hardware should no longer
 * access *ctx after this has returned.
 */
static void __detach_context(struct cxl_context_t *ctx)
{
	/* FIXME: Shut down AFU, ensure that any running interrupts are
	 * finished and no more interrupts are possible */
	/* FIXME: If we opened it but never started it, this will WARN */
	/* FIXME: check this is the last context to shut down */


	spin_lock(&ctx->afu->contexts_lock);
	if (!ctx->attached) {
		spin_unlock(&ctx->afu->contexts_lock);
		return;
	}
	ctx->attached = false;
	list_del(&ctx->list);
	spin_unlock(&ctx->afu->contexts_lock);
	WARN_ON(cxl_ops->detach_process(ctx));
	afu_release_irqs(ctx);
	WARN_ON(work_busy(&ctx->fault_work)); /* FIXME: maybe bogus.  hardware may not be done */
	wake_up_all(&ctx->wq);
}

/*
 * Detach the given context from the AFU. This doesn't actually
 * free the context but it should stop the context running in hardware
 * (ie. prevent this context from generating any further interrupts
 * so that it can be freed).
 */
void cxl_context_detach(struct cxl_context_t *ctx)
{
	__detach_context(ctx);
}

/*
 * Detach all contexts on the given AFU.
 */
void cxl_context_detach_all(struct cxl_afu_t *afu)
{
	struct cxl_context_t *ctx, *tmp;

	list_for_each_entry_safe(ctx, tmp, &afu->contexts, list)
		__detach_context(ctx);
}

void cxl_context_free(struct cxl_context_t *ctx)
{
	unsigned long flags;

	ida_simple_remove(&ctx->afu->pe_index_ida, ctx->ph);
	spin_lock_irqsave(&ctx->sst_lock, flags);
	free_page((u64)ctx->sstp);
	ctx->sstp = NULL;
	spin_unlock_irqrestore(&ctx->sst_lock, flags);
	put_pid(ctx->pid);
	kfree(ctx);
}
