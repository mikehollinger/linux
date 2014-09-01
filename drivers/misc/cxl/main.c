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
#include <asm/cputable.h>
#include <misc/cxl.h>

#include "cxl.h"

static DEFINE_SPINLOCK(adapter_list_lock);
static LIST_HEAD(adapter_list);

const struct cxl_backend_ops *cxl_ops;
EXPORT_SYMBOL(cxl_ops);

/* FIXME: Move this to file.c */
struct class *cxl_class;
EXPORT_SYMBOL(cxl_class);

static void cxl_adapter_wide_slbie(struct cxl_t *adapter, unsigned long addr, int ssize)
{
	u64 val = (addr & ESID_MASK) | (ssize << CXL_SLBIE_SS_SHIFT);

	/* FIXME: If we start using Class and Tags Active, we need to set the
	 * corresponding bits here to match the segment we are invalidating */

	/* TODO: Use Locking to ensure we can never have > Max_SLBIEs
	 * outstanding. For the moment we are only ever called with
	 * adapter_list_lock held, so there can only be one at a time */
	cxl_p1_write(adapter, CXL_PSL_SLBIE, val);
	while (cxl_p1_read(adapter, CXL_PSL_SLBIE) & CXL_SLBIE_PENDING)
		cpu_relax();
}

/* FIXME: This is called from the PPC mm code, which will break when CXL is
 * compiled as a module */
void cxl_slbie(unsigned long addr)
{
	struct cxl_t *adapter;
	int ssize;

	/* Potential optimisation - may be able to use slbfee instruction to
	 * get SLB from current CPU and grab B, C and TA fields from it */
	switch (REGION_ID(addr)) {
	case USER_REGION_ID:
		ssize = user_segment_size(addr);
		break;
	case VMALLOC_REGION_ID:
	case KERNEL_REGION_ID:
		ssize = mmu_kernel_ssize;
		break;
	default:
		WARN(1, "cxl_slbie: Unsupported region\n");
		return;
	}

	spin_lock(&adapter_list_lock);
	list_for_each_entry(adapter, &adapter_list, list) {
		/* FIXME: Will need to use the per slice version of PSL_SLBIE
		 * when under a HV (if we have access to the p2 regs), or ask
		 * the HV to do this for us */
		cxl_adapter_wide_slbie(adapter, addr, ssize);
	}
	spin_unlock(&adapter_list_lock);
}
EXPORT_SYMBOL(cxl_slbie);

static void cxl_afu_slbia(struct cxl_afu_t *afu)
{
	pr_devel("cxl_afu_slbia issuing SLBIA command\n");
	cxl_p2n_write(afu, CXL_SLBIA_An, CXL_SLBI_IQ_ALL);
	while (cxl_p2n_read(afu, CXL_SLBIA_An) & CXL_SLBIA_P)
		cpu_relax();
}

/* FIXME: This is called from the PPC mm code, which will break when CXL is
 * compiled as a module */
static inline void cxl_slbia_core(struct mm_struct *mm)
{
	struct cxl_t *adapter;
	struct cxl_afu_t *afu;
	struct cxl_context_t *ctx;
	struct task_struct *task;
	unsigned long flags;
	int card = 0, slice, id;

	pr_devel("%s called\n", __func__);

	spin_lock(&adapter_list_lock);
	list_for_each_entry(adapter, &adapter_list, list) {
		/* TODO: Link mm_struct straight to the context to skip having
		 * to search for it (but one process/single mm can have
		 * multiple cxl contexts) */
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
					 __func__, card, slice, ctx->ph);

				spin_lock_irqsave(&ctx->sst_lock, flags);
				if (!ctx->sstp)
					goto next_unlock;
				memset(ctx->sstp, 0, ctx->sst_size);
				mb();
				cxl_afu_slbia(afu);

next_unlock:
				spin_unlock_irqrestore(&ctx->sst_lock, flags);
next:
				put_task_struct(task);
			}
			rcu_read_unlock();
		}
		card++;
	}
	spin_unlock(&adapter_list_lock);
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
		cxl_afu_slbia(ctx->afu);
		spin_unlock_irqrestore(&ctx->sst_lock, flags);
	}
	if (!ctx->sstp) {
		pr_err("cxl_alloc_sst: Unable to allocate segment table\n");
		return -ENOMEM;
	}

	/* FIXME: Did I need to handle 1TB segments? I have a vague
	 * recollection that the answer was no - I'll need to recheck */
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
	int i = 0;
	struct cxl_t *ret = NULL;

	spin_lock(&adapter_list_lock);
	list_for_each_entry(adapter, &adapter_list, list) {
		if (i++ == num) {
			ret = adapter;
			break;
		}
	}
	spin_unlock(&adapter_list_lock);

	return ret;
}

static void afu_t_init(struct cxl_t *adapter, int slice)
{
	struct cxl_afu_t *afu = &adapter->slice[slice];

	afu->adapter = adapter;
	afu->slice = slice;
	idr_init(&afu->contexts_idr);
	spin_lock_init(&afu->contexts_lock);
	spin_lock_init(&afu->afu_cntl_lock);
	mutex_init(&afu->spa_mutex);
}

static atomic_t nr_adapters;

/* FIXME: The calling convention here is a mess and needs to be cleaned up.
 * Maybe better to have the caller fill in the struct and call us? */
int cxl_init_adapter(struct cxl_t *adapter,
		      struct cxl_driver_ops *driver,
		      struct device *parent,
		      int slices, void *backend_data)
{
	int slice, rc = 0;

	pr_devel("cxl_alloc_adapter");

	/* There must be at least one AFU */
	if (!slices)
		return -EINVAL;

	adapter->adapter_num = atomic_inc_return(&nr_adapters) - 1;

	adapter->driver = driver;
	adapter->device.class = cxl_class;
	adapter->device.parent = parent;
	adapter->slices = slices;
	pr_devel("%i slices\n", adapter->slices);

	/* Prepare the backend hardware */
	if ((rc = cxl_ops->init_adapter(adapter, backend_data)))
		goto out;

	/* Register the adapter device */
	dev_set_name(&adapter->device, "card%i", adapter->adapter_num);
	adapter->device.devt = MKDEV(MAJOR(cxl_dev), adapter->adapter_num * CXL_DEV_MINORS);
	if ((rc = device_register(&adapter->device)))
		goto out1;

	/* Add adapter character device and sysfs entries */
	if (add_cxl_dev(adapter, adapter->adapter_num)) {
		rc = -1;
		goto out2;
	}

	for (slice = 0; slice < slices; slice++)
		afu_t_init(adapter, slice);

	cxl_debugfs_adapter_add(adapter);

	spin_lock(&adapter_list_lock);
	list_add_tail(&(adapter)->list, &adapter_list);
	spin_unlock(&adapter_list_lock);

	return 0;

out2:
	device_unregister(&adapter->device);
out1:
	cxl_ops->release_adapter(adapter);
out:
	atomic_dec(&nr_adapters);
	pr_devel("cxl_init_adapter: %i\n", rc);
	return rc;
}
EXPORT_SYMBOL(cxl_init_adapter);

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
	if ((rc = add_cxl_afu_dev(afu))) {
		/* FIXME: init_afu may have allocated an error interrupt */
		goto err;
	}

	cxl_debugfs_afu_add(afu);

	return 0;

err:
	cxl_release_psl_irq(afu);
	return rc;
}
EXPORT_SYMBOL(cxl_init_afu);

static char *cxl_devnode(struct device *dev, umode_t *mode)
{
	if (MINOR(dev->devt) % CXL_DEV_MINORS == 0) {
		/* These minor numbers will eventually be used to program the
		 * PSL and AFUs once we have dynamic reprogramming support */
		return NULL;
	}
	return kasprintf(GFP_KERNEL, "cxl/%s", dev_name(dev));
}

static int __init init_cxl(void)
{
	int ret = 0;

	if (!cpu_has_feature(CPU_FTR_HVMODE))
		return -1;

	cxl_class = class_create(THIS_MODULE, "cxl");
	if (IS_ERR(cxl_class)) {
		pr_warn("Unable to create cxl class\n");
		return PTR_ERR(cxl_class);
	}
	cxl_class->devnode = cxl_devnode;

	if (register_cxl_dev())
		return -1;

	cxl_debugfs_init();
	init_cxl_native();

	ret = register_cxl_calls(&cxl_calls);

	return ret;
}

void cxl_unregister_afu(struct cxl_afu_t *afu)
{
	cxl_release_psl_irq(afu);
	del_cxl_afu_dev(afu);
	cxl_ops->release_afu(afu);
}
EXPORT_SYMBOL(cxl_unregister_afu);

void cxl_unregister_adapter(struct cxl_t *adapter)
{
	int slice;

	/* Unregister CXL adapter device */

	spin_lock(&adapter_list_lock);
	list_del(&adapter->list);
	spin_unlock(&adapter_list_lock);

	for (slice = 0; slice < adapter->slices; slice++)
		cxl_unregister_afu(&adapter->slice[slice]);
	del_cxl_dev(adapter);

	/* CXL-HV/Native adapter release */
	if (cxl_ops->release_adapter)
		cxl_ops->release_adapter(adapter);

	unregister_cxl_dev();

	atomic_dec(&nr_adapters);
}
EXPORT_SYMBOL(cxl_unregister_adapter);

static void exit_cxl(void)
{
	cxl_debugfs_exit();
	class_destroy(cxl_class);
	unregister_cxl_calls(&cxl_calls);
}

module_init(init_cxl);
module_exit(exit_cxl);

MODULE_DESCRIPTION("IBM Coherent Accelerator");
MODULE_AUTHOR("Ian Munsie <imunsie@au1.ibm.com>");
MODULE_LICENSE("GPL");
