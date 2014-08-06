#if 1
#define DEBUG
#else
#undef DEBUG
#endif

#include <linux/module.h>
#include <linux/export.h>
#include <linux/kernel.h>
#include <linux/bitmap.h>
#include <linux/sched.h>
#include <linux/poll.h>
#include <linux/pid.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <asm/cputable.h>
#include <asm/current.h>
#include <asm/copro.h>
#include <linux/debugfs.h>
#include <linux/slab.h>
#include <linux/idr.h>

#include "capi.h"

/*
 * Allocates space for a CAPI context.
 */
struct capi_context_t *capi_context_alloc(void)
{
	return kzalloc(sizeof(struct capi_context_t), GFP_KERNEL);
}

/*
 * Initialises a CAPI context.
 */
int capi_context_init(struct capi_context_t *ctx, struct capi_afu_t *afu, bool master)
{
	int i;

	spin_lock_init(&ctx->sst_lock);
	ctx->sstp = NULL;
	ctx->afu = afu;
	ctx->master = master;
	ctx->pid = get_pid(get_task_pid(current, PIDTYPE_PID));

	init_waitqueue_head(&ctx->wq);
	spin_lock_init(&ctx->lock);

	ctx->irq_bitmap = NULL;
	ctx->pending_irq = false;
	ctx->pending_fault = false;
	ctx->pending_afu_err = false;

	/* FIXME: Need to move this. */
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
void capi_context_start(struct capi_context_t *ctx)
{
	spin_lock(&ctx->afu->contexts_lock);
	list_add(&ctx->list, &ctx->afu->contexts);
	spin_unlock(&ctx->afu->contexts_lock);
}

/*
 * Map a per-context mmio space into the given vma.
 */
int capi_context_iomap(struct capi_context_t *ctx, struct vm_area_struct *vma)
{
	u64 len = vma->vm_end - vma->vm_start;
	len = min(len, ctx->psn_size);

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
static void __detach_context(struct capi_context_t *ctx)
{
	/* FIXME: Shut down AFU, ensure that any running interrupts are
	 * finished and no more interrupts are possible */
	/* FIXME: If we opened it but never started it, this will WARN */
	/* FIXME: check this is the last context to shut down */

	if (!test_and_clear_bit(0, &ctx->attached))
		return;

	list_del(&ctx->list);
	WARN_ON(capi_ops->detach_process(ctx));
	afu_release_irqs(ctx);
	flush_work(&ctx->work);
	wake_up_all(&ctx->wq);
}

/*
 * Detach the given context from the AFU. This doesn't actually
 * free the context but it should stop the context running in hardware
 * (ie. prevent this context from generating any further interrupts
 * so that it can be freed).
 */
void capi_context_detach(struct capi_context_t *ctx)
{
	spin_lock(&ctx->afu->contexts_lock);
	__detach_context(ctx);
	spin_unlock(&ctx->afu->contexts_lock);
}

/*
 * Detach all contexts on the given AFU.
 */
void capi_context_detach_all(struct capi_afu_t *afu)
{
	struct capi_context_t *ctx, *tmp;

	spin_lock(&afu->contexts_lock);
	list_for_each_entry_safe(ctx, tmp, &afu->contexts, list)
		__detach_context(ctx);
	spin_unlock(&afu->contexts_lock);
}

void capi_context_free(struct capi_context_t *ctx)
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
