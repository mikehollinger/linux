/*
 * Copyright 2014 IBM Corp.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#undef DEBUG

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/bitmap.h>
#include <linux/sched.h>
#include <linux/pid.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/debugfs.h>
#include <linux/slab.h>
#include <linux/idr.h>
#include <asm/cputable.h>
#include <asm/current.h>
#include <asm/copro.h>

#include "cxl.h"

/*
 * Allocates space for a CXL context.
 */
struct cxl_context *cxl_context_alloc(void)
{
	return kzalloc(sizeof(struct cxl_context), GFP_KERNEL);
}

/*
 * Initialises a CXL context.
 */
int cxl_context_init(struct cxl_context *ctx, struct cxl_afu *afu, bool master)
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

	mutex_init(&ctx->status_mutex);

	/* Don't need to lock just writing this */
	ctx->status = OPENED;

	idr_preload(GFP_KERNEL);
	spin_lock(&afu->contexts_lock);
	i = idr_alloc(&ctx->afu->contexts_idr, ctx, 0,
		      ctx->afu->num_procs, GFP_NOWAIT);
	spin_unlock(&afu->contexts_lock);
	idr_preload_end();
	if (i < 0)
		return i;

	ctx->pe = i;
	ctx->elem = &ctx->afu->spa[i];
	ctx->pe_inserted = false;
	return 0;
}

/*
 * Map a per-context mmio space into the given vma.
 */
int cxl_context_iomap(struct cxl_context *ctx, struct vm_area_struct *vma)
{
	u64 len = vma->vm_end - vma->vm_start;
	len = min(len, ctx->psn_size);

	if (ctx->afu->current_model == CXL_MODEL_DEDICATED) {
		vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
		return vm_iomap_memory(vma, ctx->afu->psn_phys, ctx->afu->adapter->ps_size);
	}

	/* make sure there is a valid per process space for this AFU */
	if ((ctx->master && !ctx->afu->psa) || (!ctx->afu->pp_psa)) {
		pr_devel("AFU doesn't support mmio space\n");
		return -EINVAL;
	}

	/* Can't mmap until the AFU is enabled */
	if (!ctx->afu->enabled)
		return -EBUSY;

	pr_devel("%s: mmio physical: %llx pe: %i master:%i\n", __func__,
		 ctx->psn_phys, ctx->pe , ctx->master);

	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
	return vm_iomap_memory(vma, ctx->psn_phys, len);
}

/*
 * Detach a context from the hardware. This disables interrupts and doesn't
 * return until all outstanding interrupts for this context have completed. The
 * hardware should no longer access *ctx after this has returned.
 */
static void __detach_context(struct cxl_context *ctx)
{
	unsigned long flags;
	enum cxl_context_status status;

	mutex_lock(&ctx->status_mutex);
	status = ctx->status;
	ctx->status = CLOSED;
	mutex_unlock(&ctx->status_mutex);
	if (status != STARTED)
		return;

	WARN_ON(cxl_detach_process(ctx));
	afu_release_irqs(ctx);
	flush_work(&ctx->fault_work); /* Only needed for dedicated process */
	wake_up_all(&ctx->wq);
}

/*
 * Detach the given context from the AFU. This doesn't actually
 * free the context but it should stop the context running in hardware
 * (ie. prevent this context from generating any further interrupts
 * so that it can be freed).
 */
void cxl_context_detach(struct cxl_context *ctx)
{
	__detach_context(ctx);
}

/*
 * Detach all contexts on the given AFU.
 */
void cxl_context_detach_all(struct cxl_afu *afu)
{
	struct cxl_context *ctx;
	int tmp;

	rcu_read_lock();
	idr_for_each_entry(&afu->contexts_idr, ctx, tmp)
		__detach_context(ctx);
	rcu_read_unlock();
}

void cxl_context_free(struct cxl_context *ctx)
{
	unsigned long flags;

	spin_lock(&ctx->afu->contexts_lock);
	idr_remove(&ctx->afu->contexts_idr, ctx->pe);
	spin_unlock(&ctx->afu->contexts_lock);
	synchronize_rcu();

	spin_lock_irqsave(&ctx->sst_lock, flags);
	free_page((u64)ctx->sstp);
	ctx->sstp = NULL;
	spin_unlock_irqrestore(&ctx->sst_lock, flags);

	put_pid(ctx->pid);
	kfree(ctx);
}
