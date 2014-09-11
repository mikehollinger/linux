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
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/mutex.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/of.h>
#include <linux/slab.h>
#include <linux/idr.h>
#include <asm/cputable.h>
#include <misc/cxl.h>

#include "cxl.h"

static DEFINE_SPINLOCK(adapter_idr_lock);
static DEFINE_IDR(cxl_adapter_idr);

const struct cxl_backend_ops *cxl_ops;
EXPORT_SYMBOL(cxl_ops);

static inline void cxl_slbia_core(struct mm_struct *mm)
{
	struct cxl_t *adapter;
	struct cxl_afu_t *afu;
	struct cxl_context_t *ctx;
	struct task_struct *task;
	unsigned long flags;
	int card, slice, id;

	pr_devel("%s called\n", __func__);

	spin_lock(&adapter_idr_lock);
	idr_for_each_entry(&cxl_adapter_idr, adapter, card) {
		/* XXX: Make this lookup faster with link from mm to ctx */
		for (slice = 0; slice < adapter->slices; slice++) {
			afu = &adapter->slice[slice];
			if (!afu->enabled)
				continue;
			rcu_read_lock();
			idr_for_each_entry(&afu->contexts_idr, ctx, id) {
				if (!(task = get_pid_task(ctx->pid, PIDTYPE_PID))) {
					pr_devel("%s unable to get task %i\n",
						 __func__, pid_nr(ctx->pid));
					continue;
				}

				if (task->mm != mm)
					goto next;

				pr_devel("%s matched mm - card: %i afu: %i pe: %i\n",
					 __func__, adapter->adapter_num, slice, ctx->ph);

				spin_lock_irqsave(&ctx->sst_lock, flags);
				if (!ctx->sstp)
					goto next_unlock;
				memset(ctx->sstp, 0, ctx->sst_size);
				mb();
				cxl_ops->slbia(afu);

next_unlock:
				spin_unlock_irqrestore(&ctx->sst_lock, flags);
next:
				put_task_struct(task);
			}
			rcu_read_unlock();
		}
	}
	spin_unlock(&adapter_idr_lock);
}

struct cxl_calls cxl_calls = {
	.cxl_slbia = cxl_slbia_core,
	.owner = THIS_MODULE,
};

int cxl_alloc_sst(struct cxl_context_t *ctx, u64 *sstp0, u64 *sstp1)
{
	unsigned long vsid, flags;
	u64 ea_mask;
	u64 size;

	*sstp0 = 0;
	*sstp1 = 0;

	ctx->sst_size = PAGE_SIZE;
	ctx->sst_lru = 0;
	if (!ctx->sstp) {
		ctx->sstp = (struct cxl_sste *)get_zeroed_page(GFP_KERNEL);
		pr_devel("SSTP allocated at 0x%p\n", ctx->sstp);
	} else {
		pr_devel("Zeroing and reusing SSTP already allocated at 0x%p\n", ctx->sstp);
		spin_lock_irqsave(&ctx->sst_lock, flags);
		memset(ctx->sstp, 0, PAGE_SIZE);
		cxl_ops->slbia(ctx->afu);
		spin_unlock_irqrestore(&ctx->sst_lock, flags);
	}
	if (!ctx->sstp) {
		pr_err("cxl_alloc_sst: Unable to allocate segment table\n");
		return -ENOMEM;
	}

	vsid  = get_kernel_vsid((u64)ctx->sstp, mmu_kernel_ssize) << 12;

	*sstp0 |= (u64)mmu_kernel_ssize << CXL_SSTP0_An_B_SHIFT;
	*sstp0 |= (SLB_VSID_KERNEL | mmu_psize_defs[mmu_linear_psize].sllp) << 50;

	size = (((u64)ctx->sst_size >> 8) - 1) << CXL_SSTP0_An_SegTableSize_SHIFT;
	if (unlikely(size & ~CXL_SSTP0_An_SegTableSize_MASK)) {
		WARN(1, "Impossible segment table size\n");
		return -EINVAL;
	}
	*sstp0 |= size;

	if (mmu_kernel_ssize == MMU_SEGSIZE_256M)
		ea_mask = 0xfffff00ULL;
	else
		ea_mask = 0xffffffff00ULL;

	*sstp0 |=  vsid >>     (50-14);  /*   Top 14 bits of VSID */
	*sstp1 |= (vsid << (64-(50-14))) & ~ea_mask;
	*sstp1 |= (u64)ctx->sstp & ea_mask;
	*sstp1 |= CXL_SSTP1_An_V;

	pr_devel("Looked up %#llx: slbfee. %#llx (ssize: %x, vsid: %#lx), copied to SSTP0: %#llx, SSTP1: %#llx\n",
			(u64)ctx->sstp, (u64)ctx->sstp & ESID_MASK, mmu_kernel_ssize, vsid, *sstp0, *sstp1);

	return 0;
}

struct cxl_t *get_cxl_adapter(int num)
{
	struct cxl_t *adapter;

	rcu_read_lock();
	adapter = idr_find(&cxl_adapter_idr, num);
	rcu_read_unlock();

	return adapter;
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

int cxl_alloc_adapter_nr(struct cxl_t *adapter)
{
	int i;

	idr_preload(GFP_KERNEL);
	spin_lock(&adapter_idr_lock);
	i = idr_alloc(&cxl_adapter_idr, adapter, 0, 0, GFP_NOWAIT);
	spin_unlock(&adapter_idr_lock);
	idr_preload_end();
	if (i < 0)
		return i;

	adapter->adapter_num = i;

	return 0;
}
EXPORT_SYMBOL(cxl_alloc_adapter_nr);

void cxl_remove_adapter_nr(struct cxl_t *adapter)
{
	idr_remove(&cxl_adapter_idr, adapter->adapter_num);
}
EXPORT_SYMBOL(cxl_remove_adapter_nr);

int cxl_init_afu(struct cxl_afu_t *afu, u64 handle, irq_hw_number_t err_irq)
{
	int rc;

	pr_devel("cxl_init_afu: slice: %i, handle: %#llx, err_irq: %#lx\n",
			afu->slice, handle, err_irq);

	afu->err_hwirq = err_irq;

	if ((rc = cxl_register_psl_irq(afu)))
		return rc;

	/* Initialise the hardware? */
	if ((rc = cxl_ops->init_afu(afu, handle)))
		goto err;

	/* Add afu character devices */
	if ((rc = add_cxl_afu_dev(afu)))
		/* FIXME: init_afu may have allocated an error interrupt */
		goto err;

	cxl_debugfs_afu_add(afu);

	return 0;

err:
	cxl_release_psl_irq(afu);
	return rc;
}
EXPORT_SYMBOL(cxl_init_afu);

void cxl_unregister_afu(struct cxl_afu_t *afu)
{
	cxl_release_psl_irq(afu);
	del_cxl_afu_dev(afu);
	cxl_ops->release_afu(afu);
}
EXPORT_SYMBOL(cxl_unregister_afu);

static int __init init_cxl(void)
{
	int rc = 0;

	if (!cpu_has_feature(CPU_FTR_HVMODE))
		return -EPERM;

	if ((rc = cxl_file_init()))
		return rc;

	cxl_debugfs_init();
	init_cxl_native();

	if ((rc = register_cxl_calls(&cxl_calls)))
		goto err;

	return 0;

err:
	cxl_debugfs_exit();
	cxl_file_exit();

	return rc;
}

static void exit_cxl(void)
{
	cxl_debugfs_exit();
	cxl_file_exit();
	unregister_cxl_calls(&cxl_calls);
}

module_init(init_cxl);
module_exit(exit_cxl);

MODULE_DESCRIPTION("IBM Coherent Accelerator");
MODULE_AUTHOR("Ian Munsie <imunsie@au1.ibm.com>");
MODULE_LICENSE("GPL");
