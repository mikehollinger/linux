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
#include <linux/module.h>
#include <linux/export.h>
#include <linux/kernel.h>
#include <linux/bitmap.h>
#include <linux/sched.h>
#include <linux/poll.h>
#include <linux/pid.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <asm/cputable.h>
#include <asm/current.h>
#include <asm/copro.h>

#include "cxl.h"

dev_t cxl_dev;

struct class *cxl_class;
EXPORT_SYMBOL(cxl_class);

static int
__afu_open(struct inode *inode, struct file *file, bool master)
{
	int minor = MINOR(inode->i_rdev);
	int adapter_num = minor / CXL_DEV_MINORS;
	int slice = (minor % CXL_DEV_MINORS - 1) % CXL_MAX_SLICES;
	struct cxl_t *adapter;
	struct cxl_context_t *ctx;

	pr_devel("afu_open adapter %i afu %i\n", adapter_num, slice);

	adapter = get_cxl_adapter(adapter_num);
	if (!adapter)
		return -ENODEV;
	if (slice > adapter->slices)
		return -ENODEV;

	/* We need to stop the bus driver from being unloaded */
	if (!try_module_get(adapter->driver->module))
		return -ENODEV;

	ctx = cxl_context_alloc();
	if (!ctx)
		return -ENOMEM;

	cxl_context_init(ctx, &adapter->slice[slice], master);
	pr_devel("afu_open pe: %i\n", ctx->ph);
	cxl_context_start(ctx);
	file->private_data = ctx;

	return 0;
}
static int
afu_open(struct inode *inode, struct file *file)
{
	return __afu_open(inode, file, false);
}

static int
afu_master_open(struct inode *inode, struct file *file)
{
	return __afu_open(inode, file, true);
}

static int
afu_release(struct inode *inode, struct file *file)
{
	struct cxl_context_t *ctx = file->private_data;

	pr_devel("%s: closing cxl file descriptor. pe: %i\n",
		 __func__, ctx->ph);
	cxl_context_detach(ctx);

	module_put(ctx->afu->adapter->driver->module);

	/* It should be safe to remove the context now */
	cxl_context_free(ctx);

	return 0;
}

static long
afu_ioctl_start_work(struct cxl_context_t *ctx,
		     struct cxl_ioctl_start_work __user *uwork)
{
	struct cxl_ioctl_start_work work;
	u64 amr;
	int rc;

	pr_devel("afu_ioctl: pe: %i CXL_START_WORK\n", ctx->ph);

	if (copy_from_user(&work, uwork,
			   sizeof(struct cxl_ioctl_start_work)))
		return -EFAULT;

	if (work.reserved1 || work.reserved2 || work.reserved3 ||
	    work.reserved4 || work.reserved5 || work.reserved6)
		return -EINVAL;

	/*
	 * Possible TODO: Have an administrative way to limit
	 * the max interrupts per process? This wouldn't be
	 * useful for most AFUs given how domain specific they
	 * tend to be, but may be useful for generic
	 * accelerators used transparently by common libraries
	 * (e.g. zlib accelerator). OTOH it might not help so
	 * much if an evil user can just keep opening new contexts
	 */
	if (work.num_interrupts == -1)
		work.num_interrupts = ctx->afu->pp_irqs;
	else if (work.num_interrupts < ctx->afu->pp_irqs)
		return -EINVAL;
	if ((rc = afu_register_irqs(ctx, work.num_interrupts)))
		return rc;

	amr = work.amr & mfspr(SPRN_UAMOR);

	work.process_element = ctx->ph;

	/* Returns PE and number of interrupts */
	if (copy_to_user(uwork, &work,
			 sizeof(struct cxl_ioctl_start_work)))
		return -EFAULT;

	if ((rc = cxl_ops->init_process(ctx, false, work.wed, amr)))
		return rc;

	ctx->status = STARTED;

	return 0;
}

static long
afu_ioctl_check_error(struct cxl_context_t *ctx)
{
	if (ctx->status != STARTED)
		return -EIO;

	if (cxl_ops->check_error && cxl_ops->check_error(ctx->afu)) {
		/* This may not be enough for some errors.  May need to PERST
		 * the card in some cases if it's very broken.
		 */
		return cxl_ops->afu_reset(ctx->afu);
	}
	return -EPERM;
}

static long
afu_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct cxl_context_t *ctx = file->private_data;

	if (ctx->status == CLOSED)
		return -EIO;

#if 0 /* XXX: No longer holding onto mm due to refcounting issue. */
	if (current->mm != ctx->afu->mm) {
		pr_err("CXL: %s (%i) attempted to perform ioctl on AFU with "
		       "other memory map!\n", current->comm, current->pid);
		return -EPERM;
	}
#endif

	pr_devel("afu_ioctl\n");
	switch (cmd) {
	case CXL_IOCTL_START_WORK:
		return afu_ioctl_start_work(ctx,
			(struct cxl_ioctl_start_work __user *)arg);
	case CXL_IOCTL_CHECK_ERROR:
		return afu_ioctl_check_error(ctx);
	}
	return -EINVAL;
}

static long
afu_compat_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	return afu_ioctl(file, cmd, arg);
}

static int
afu_mmap(struct file *file, struct vm_area_struct *vm)
{
	struct cxl_context_t *ctx = file->private_data;

	/* AFU must be started before we can MMIO */
	if (ctx->status != STARTED)
		return -EIO;

	return cxl_context_iomap(ctx, vm);
}

static unsigned int
afu_poll(struct file *file, struct poll_table_struct *poll)
{
	struct cxl_context_t *ctx = file->private_data;
	int mask = 0;
	unsigned long flags;


	poll_wait(file, &ctx->wq, poll);

	pr_devel("afu_poll wait done pe: %i\n", ctx->ph);

	spin_lock_irqsave(&ctx->lock, flags);
	if (ctx->pending_irq || ctx->pending_fault ||
	    ctx->pending_afu_err)
		mask |= POLLIN | POLLRDNORM;
	else if (ctx->status == CLOSED)
		/* Only error on closed when there are no futher events pending
		 */
		mask |= POLLERR;
	spin_unlock_irqrestore(&ctx->lock, flags);

	pr_devel("afu_poll pe: %i returning %#x\n", ctx->ph, mask);

	return mask;
}

static ssize_t
afu_read(struct file *file, char __user *buf, size_t count, loff_t *off)
{
	struct cxl_context_t *ctx = file->private_data;
	struct cxl_event event;
	unsigned long flags;
	ssize_t size;
	DEFINE_WAIT(wait);

	if (count < sizeof(struct cxl_event_header))
		return -EINVAL;

	while (1) {
		spin_lock_irqsave(&ctx->lock, flags);
		if (ctx->pending_irq || ctx->pending_fault ||
		    ctx->pending_afu_err || (ctx->status == CLOSED))
			break;
		spin_unlock_irqrestore(&ctx->lock, flags);

		if (file->f_flags & O_NONBLOCK)
			return -EAGAIN;

		prepare_to_wait(&ctx->wq, &wait, TASK_INTERRUPTIBLE);
		if (!(ctx->pending_irq || ctx->pending_fault ||
		      ctx->pending_afu_err || (ctx->status == CLOSED))) {
			pr_devel("afu_read going to sleep...\n");
			schedule();
			pr_devel("afu_read woken up\n");
		}
		finish_wait(&ctx->wq, &wait);

		if (signal_pending(current))
			return -ERESTARTSYS;
	}

	memset(&event, 0, sizeof(event));
	event.header.process_element = ctx->ph;
	if (ctx->pending_irq) {
		pr_devel("afu_read delivering AFU interrupt\n");
		event.header.size = sizeof(struct cxl_event_afu_interrupt);
		event.header.type = CXL_EVENT_AFU_INTERRUPT;
		event.irq.irq = find_first_bit(ctx->irq_bitmap, ctx->irq_count) + 1;

		/* Only clear the IRQ if we can send the whole event: */
		if (count >= event.header.size) {
			clear_bit(event.irq.irq - 1, ctx->irq_bitmap);
			if (bitmap_empty(ctx->irq_bitmap, ctx->irq_count))
				ctx->pending_irq = false;
		}
	} else if (ctx->pending_fault) {
		pr_devel("afu_read delivering data storage fault\n");
		event.header.size = sizeof(struct cxl_event_data_storage);
		event.header.type = CXL_EVENT_DATA_STORAGE;
		event.fault.addr = ctx->fault_addr;

		/* Only clear the fault if we can send the whole event: */
		if (count >= event.header.size)
			ctx->pending_fault = false;
	} else if (ctx->pending_afu_err) {
		pr_devel("afu_read delivering afu error\n");
		event.header.size = sizeof(struct cxl_event_afu_error);
		event.header.type = CXL_EVENT_AFU_ERROR;
		event.afu_err.err = ctx->afu_err;

		/* Only clear the fault if we can send the whole event: */
		if (count >= event.header.size)
			ctx->pending_afu_err = false;
	} else if (ctx->status == CLOSED) {
		pr_warn("afu_read fatal error\n");
		spin_unlock_irqrestore(&ctx->lock, flags);
		return -EIO;
	} else
		WARN(1, "afu_read must be buggy\n");

	spin_unlock_irqrestore(&ctx->lock, flags);

	size = min_t(size_t, count, event.header.size);
	copy_to_user(buf, &event, size);

	return size;
}

static const struct file_operations afu_fops = {
	.owner		= THIS_MODULE,
	.open           = afu_open,
	.poll		= afu_poll,
	.read		= afu_read,
	.release        = afu_release,
	.unlocked_ioctl = afu_ioctl,
	.compat_ioctl   = afu_compat_ioctl,
	.mmap           = afu_mmap,
};

static const struct file_operations afu_master_fops = {
	.owner		= THIS_MODULE,
	.open           = afu_master_open,
	.poll		= afu_poll,
	.read		= afu_read,
	.release        = afu_release,
	.unlocked_ioctl = afu_ioctl,
	.compat_ioctl   = afu_compat_ioctl,
	.mmap           = afu_mmap,
};

int __init register_cxl_dev(void)
{
	int result;

	if ((result = alloc_chrdev_region(&cxl_dev, 0,
					  CXL_NUM_MINORS, "cxl"))) {
		pr_err("Unable to allocate CXL major number: %i\n", result);
		return -1;
	}

	pr_devel("CXL device allocated, MAJOR %i\n", MAJOR(cxl_dev));

	return 0;
}

void unregister_cxl_dev(void)
{
	unregister_chrdev_region(cxl_dev, CXL_NUM_MINORS);
}

int add_cxl_dev(struct cxl_t *adapter, int adapter_num)
{
	/* Create sysfs attributes */
	adapter->afu_kobj = kobject_create_and_add("afu", &adapter->device.kobj);
	if (IS_ERR(adapter->afu_kobj))
		return PTR_ERR(adapter->afu_kobj);

	return 0;
}

extern struct class *cxl_class;

static void cxl_release(struct device *dev)
{
	pr_devel("cxl release\n");
}

int add_cxl_afu_dev(struct cxl_afu_t *afu)
{
	int rc;
	unsigned int cxl_major = MAJOR(afu->adapter->device.devt);
	unsigned int cxl_minor = MINOR(afu->adapter->device.devt);

	/* Add the AFU slave device */
	/* FIXME check afu->pp_mmio to see if we need this file */
	afu->device.parent = &afu->adapter->device;
	afu->device.class = cxl_class;
	dev_set_name(&afu->device, "afu%i.%i", afu->adapter->adapter_num, afu->slice);
	afu->device.devt = MKDEV(cxl_major, cxl_minor + CXL_MAX_SLICES + 1 + afu->slice);
	afu->device.release = cxl_release;

	if ((rc = device_register(&afu->device)))
		return rc;

	cdev_init(&afu->adapter->afu_cdev, &afu_fops);
	rc = cdev_add(&afu->adapter->afu_cdev, MKDEV(cxl_major, cxl_minor + CXL_MAX_SLICES + 1 + afu->slice), afu->adapter->slices);
	if (rc) {
		pr_err("Unable to register CXL AFU character devices: %i\n", rc);
		goto out;
	}

	/* Add the AFU master device */
	afu->device_master.parent = &afu->device;
	afu->device_master.class = cxl_class;
	dev_set_name(&afu->device_master, "afu%i.%im", afu->adapter->adapter_num, afu->slice);
	afu->device_master.devt = MKDEV(cxl_major, cxl_minor + 1 + afu->slice);
	afu->device_master.release = cxl_release;

	if ((rc = device_register(&afu->device_master)))
		goto out1;

	if ((rc = cxl_sysfs_afu_add(afu)))
		goto out2;

	cdev_init(&afu->adapter->afu_master_cdev, &afu_master_fops);
	rc = cdev_add(&afu->adapter->afu_master_cdev, MKDEV(cxl_major, cxl_minor + 1 + afu->slice), afu->adapter->slices);
	if (rc) {
		pr_err("Unable to register CXL AFU master character devices: %i\n", rc);
		goto out3;
	}

	/* Create sysfs links */
	if ((rc = sysfs_create_link(afu->adapter->afu_kobj, &afu->device.kobj, dev_name(&afu->device))))
		goto out4;

	return 0;

out4:
	cdev_del(&afu->adapter->afu_master_cdev);
out3:
	cxl_sysfs_afu_remove(afu);
out2:
	device_unregister(&afu->device_master);
out1:
	cdev_del(&afu->adapter->afu_cdev);
out:
	device_unregister(&afu->device);
	return rc;
}

void del_cxl_dev(struct cxl_t *adapter)
{
	kobject_put(adapter->afu_kobj);
	adapter->afu_kobj = NULL;
	adapter->device.release = cxl_release;
	device_unregister(&adapter->device);
}

void del_cxl_afu_dev(struct cxl_afu_t *afu)
{
	sysfs_remove_link(&afu->device.kobj, dev_name(&afu->device));
	cxl_sysfs_afu_remove(afu);
	cdev_del(&afu->adapter->afu_master_cdev);
	device_unregister(&afu->device_master);
	cdev_del(&afu->adapter->afu_cdev);
	device_unregister(&afu->device);
	cxl_context_detach_all(afu);
}
