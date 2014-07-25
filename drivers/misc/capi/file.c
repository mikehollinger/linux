#if 1
#define DEBUG
#else
#undef DEBUG
#endif

/* TODO: Split this out into a separate module now that we have some CAPI
 * devices that won't want to use this generic userspace interface */

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

dev_t capi_dev;

extern struct class *capi_class;

static int
__afu_open(struct inode *inode, struct file *file, bool master)
{
	int minor = MINOR(inode->i_rdev);
	int adapter_num = minor / CAPI_DEV_MINORS;
	int slice = (minor % CAPI_DEV_MINORS - 1) % CAPI_MAX_SLICES;
	struct capi_t *adapter;
	struct capi_context_t *ctx;
	int i;

	pr_devel("afu_open adapter %i afu %i\n", adapter_num, slice);

	adapter = get_capi_adapter(adapter_num);
	if (!adapter)
		return -ENODEV;
	if (slice > adapter->slices)
		return -ENODEV;

	/* We need to stop the bus driver from being unloaded */
	if (!try_module_get(adapter->driver->module))
		return -ENODEV;

	if (!(ctx = kmalloc(sizeof(struct capi_context_t), GFP_KERNEL)))
	    return -ENOMEM;
	ctx->sstp = NULL;
	ctx->afu = &adapter->slice[slice];
	ctx->master = master;

	file->private_data = (void *)ctx;

	ctx->pid = get_pid(get_task_pid(current, PIDTYPE_PID));

	/* FIXME: Move these to afu context initialiser */
	init_waitqueue_head(&ctx->wq);
	spin_lock_init(&ctx->lock);

	ctx->irq_bitmap = NULL;
	ctx->pending_irq = false;
	ctx->pending_fault = false;
	ctx->pending_afu_err = false;

	i = ida_simple_get(&ctx->afu->pe_index_ida, 0,
			   ctx->afu->num_procs, GFP_KERNEL);
	if (i < 0)
		return i;
	ctx->ph = i;
	ctx->elem = &ctx->afu->spa[i];

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
	struct capi_context_t *ctx = (struct capi_context_t *)file->private_data;
	int minor = MINOR(inode->i_rdev);
	int adapter_num = minor / CAPI_DEV_MINORS;
	struct capi_t *adapter;

	adapter = get_capi_adapter(adapter_num);
	WARN_ON(!adapter);

	pr_devel("afu_release\n");

	/* FIXME: Shut down AFU, ensure that any running interrupts are
	 * finished and no more interrupts are possible */
	/* FIXME: If we opened it but never started it, this will WARN */
	/* FIXME: check this is the last context to shut down */
	WARN_ON(capi_ops->detach_process(ctx));

	afu_release_irqs(ctx);

	ida_simple_remove(&ctx->afu->pe_index_ida, ctx->ph);

	free_page((u64)ctx->sstp);
	ctx->sstp = NULL;

	put_pid(ctx->pid);

	kfree(ctx);

	module_put(adapter->driver->module);

	return 0;
}

static long
afu_ioctl_start_work(struct capi_context_t *ctx,
		     struct capi_ioctl_start_work __user *uwork)
{
	struct capi_ioctl_start_work work;
	u64 amr;
	int rc;

	pr_devel("afu_ioctl: CAPI_START_WORK\n");

	if (copy_from_user(&work, uwork,
			   sizeof(struct capi_ioctl_start_work)))
		return -EFAULT;
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
			 sizeof(struct capi_ioctl_start_work)))
		return -EFAULT;

	/* fixme me: decide this based on the AFU */
	if ((rc = capi_ops->init_process(ctx, false, work.wed, amr)))
		return rc;

	return 0;
}

static long
afu_ioctl_check_error(struct capi_context_t *ctx)
{
	if (capi_ops->check_error && capi_ops->check_error(ctx->afu)) {
		/* FIXME: This reset isn't sufficient to recover from the
		 * condition I tested - this will basically need a hotplug or
		 * PERST. May need several tests for different severities and
		 * appropriate actions for each. */
		return capi_ops->afu_reset(ctx->afu);
	}
	return -EPERM;
}

static long
afu_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct capi_context_t *ctx = (struct capi_context_t *)file->private_data;

#if 0 /* XXX: No longer holding onto mm due to refcounting issue. */
	if (current->mm != ctx->afu->mm) {
		pr_err("CAPI: %s (%i) attempted to perform ioctl on AFU with "
		       "other memory map!\n", current->comm, current->pid);
		return -EPERM;
	}
#endif

	pr_devel("afu_ioctl\n");
	switch (cmd) {
		case CAPI_IOCTL_START_WORK:
			return afu_ioctl_start_work(ctx,
				(struct capi_ioctl_start_work __user *)arg);
		case CAPI_IOCTL_LOAD_AFU_IMAGE:
		{
			struct capi_ioctl_load_afu_image __user *uwork =
				(struct capi_ioctl_load_afu_image __user *)arg;
			struct capi_ioctl_load_afu_image work;

                        if (copy_from_user(&work, uwork, sizeof(struct capi_ioctl_load_afu_image)))
                                return -EFAULT;

			// FIXME: check no one is using this
			return capi_ops->load_afu_image(ctx->afu, work.vaddress, work.length);
		}
		case CAPI_IOCTL_CHECK_ERROR:
			return afu_ioctl_check_error(ctx);
	}
	return -EINVAL;
}

static long
afu_compat_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	pr_warning("FIXME: capi_compat_ioctl STUB. cmd: %x, arg: %lx\n", cmd, arg);
	/* FIXME */
	return afu_ioctl(file, cmd, arg);
}

static int
afu_mmap(struct file *file, struct vm_area_struct *vm)
{
	struct capi_context_t *ctx = (struct capi_context_t *)file->private_data;
	u64 len = vm->vm_end - vm->vm_start;
	len = min(len, ctx->psn_size);

	/* make sure there is a valid per process space for this AFU */
	if ((ctx->master && !ctx->afu->mmio) ||
	    (!ctx->master && !ctx->afu->pp_mmio)) {
		pr_devel("%s: AFU doesn't support mmio space\n", __FUNCTION__);
		return -EINVAL;
	}

	/* Can't mmap until the AFU is enabled
	   FIXME: check on teardown */
	if (!ctx->afu->enabled) {
		pr_devel("%s: AFU not enabled\n", __FUNCTION__);
		return -EBUSY;
	}

	pr_devel("%s: mmio physical: %llx pe: %i master:%i\n", __FUNCTION__,
		 ctx->psn_phys, ctx->ph , ctx->master);
	/* FIXME: Return error if virtualised AFU */
	vm->vm_page_prot = pgprot_noncached(vm->vm_page_prot);
	return vm_iomap_memory(vm, ctx->psn_phys, len);
}

static unsigned int
afu_poll(struct file *file, struct poll_table_struct *poll)
{
	struct capi_context_t *ctx = (struct capi_context_t *)file->private_data;
	int mask = 0;
	unsigned long flags;

	pr_devel("afu_poll\n");

	poll_wait(file, &ctx->wq, poll);

	pr_devel("afu_poll wait done\n");

	spin_lock_irqsave(&ctx->lock, flags);
	if (ctx->pending_irq || ctx->pending_fault ||
	    ctx->pending_afu_err)
		mask |= POLLIN | POLLRDNORM;
	spin_unlock_irqrestore(&ctx->lock, flags);

	pr_devel("afu_poll returning %#x\n", mask);

	return mask;
}

static ssize_t
afu_read(struct file *file, char __user *buf, size_t count, loff_t *off)
{
	struct capi_context_t *ctx = (struct capi_context_t *)file->private_data;
	struct capi_event event;
	unsigned long flags;
	ssize_t size;
	DEFINE_WAIT(wait);

	if (count < sizeof(struct capi_event_header))
		return -EINVAL;

	while (1) {
		spin_lock_irqsave(&ctx->lock, flags);
		if (ctx->pending_irq || ctx->pending_fault ||
		    ctx->pending_afu_err)
			break;
		spin_unlock_irqrestore(&ctx->lock, flags);

		if (file->f_flags & O_NONBLOCK)
			return -EAGAIN;

		prepare_to_wait(&ctx->wq, &wait, TASK_INTERRUPTIBLE);
		if (!(ctx->pending_irq || ctx->pending_fault ||
		      ctx->pending_afu_err)) {
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
		event.header.size = sizeof(struct capi_event_afu_interrupt);
		event.header.type = CAPI_EVENT_AFU_INTERRUPT;
		event.irq.irq = find_first_bit(ctx->irq_bitmap, ctx->irq_count) + 1;

		/* Only clear the IRQ if we can send the whole event: */
		if (count >= event.header.size) {
			clear_bit(event.irq.irq - 1, ctx->irq_bitmap);
			if (bitmap_empty(ctx->irq_bitmap, ctx->irq_count))
				ctx->pending_irq = false;
		}
	} else if (ctx->pending_fault) {
		pr_devel("afu_read delivering data storage fault\n");
		event.header.size = sizeof(struct capi_event_data_storage);
		event.header.type = CAPI_EVENT_DATA_STORAGE;
		event.fault.addr = ctx->fault_addr;

		/* Only clear the fault if we can send the whole event: */
		if (count >= event.header.size)
			ctx->pending_fault = false;
	} else if (ctx->pending_afu_err) {
		pr_devel("afu_read delivering afu error\n");
		event.header.size = sizeof(struct capi_event_afu_error);
		event.header.type = CAPI_EVENT_AFU_ERROR;
		event.afu_err.err = ctx->afu_err;

		/* Only clear the fault if we can send the whole event: */
		if (count >= event.header.size)
			ctx->pending_afu_err = false;
	} else BUG();

	spin_unlock_irqrestore(&ctx->lock, flags);

	size = min(count, (size_t)event.header.size);
	copy_to_user(buf, &event, size);
	return size;
}

static int
capi_open(struct inode *inode, struct file *file)
{
	int minor = MINOR(inode->i_rdev);
	int adapter = minor / CAPI_DEV_MINORS;

	pr_devel("STUB: capi_open adapter %i\n", adapter);
	return -EPERM;
}

/*
 * FIXME TODO: This will eventually be used
to enumerate and open the AFUs,
 * (possibly) reprogram them, etc. For now you have to open the AFUs directly
 * as /dev/capiN
 */
static const struct file_operations capi_fops = {
	.owner		= THIS_MODULE,
	.open		= capi_open,
#if 0
	.unlocked_ioctl = capi_ioctl,
	.compat_ioctl   = capi_compat_ioctl,
#endif
};

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

static char capi_dbg_sep[80+2] = "\n--------------------------------------------------------------------------------\n";

static int psl_err_chk_show(struct seq_file *m, void *p)
{
	struct capi_t *capi = m->private;
	struct capi_afu_t *a0 = &capi->slice[0];

	seq_puts(m, "************************ Checking PSL Error Registers **************************");

#define show_reg(name, what) \
	seq_write(m, capi_dbg_sep, sizeof(capi_dbg_sep)); \
	seq_printf(m, "%s = %16llx", name, what)

	show_reg("PSL FIR1", capi_p1_read(capi, CAPI_PSL_FIR1));
	show_reg("PSL FIR2", capi_p1_read(capi, CAPI_PSL_FIR2));
	show_reg("PSL FIR CNTL", capi_p1_read(capi, CAPI_PSL_FIR_CNTL));
	show_reg("PSL FIR SLICE A0", capi_p1n_read(a0, CAPI_PSL_FIR_SLICE_An));
	show_reg("PSL RECOV FIR SLICE A0", capi_p1n_read(a0, CAPI_PSL_R_FIR_SLICE_An));
	show_reg("PSL SERR A0", capi_p1n_read(a0, CAPI_PSL_SERR_An));
	show_reg("PSL ERRIVTE", capi_p1_read(capi, CAPI_PSL_ErrIVTE));
	show_reg("PSL DSISR A0", capi_p2n_read(a0, CAPI_PSL_DSISR_An));
	show_reg("PSL SR", capi_p1n_read(a0, CAPI_PSL_SR_An));
	show_reg("PSL SSTP0 A0", capi_p2n_read(a0, CAPI_SSTP0_An));
	show_reg("PSL SSTP1 A0", capi_p2n_read(a0, CAPI_SSTP1_An));
	show_reg("PSL DAR A0", capi_p2n_read(a0, CAPI_PSL_DAR_An));
	show_reg("PSL ErrStat A0", capi_p2n_read(a0, CAPI_PSL_ErrStat_An));
#undef showreg
	seq_putc(m, '\n');

	return 0;
}

static int psl_err_chk_open(struct inode *inode, struct file *file)
{
	return single_open(file, psl_err_chk_show, inode->i_private);
}

static const struct file_operations psl_err_chk_fops = {
	.open = psl_err_chk_open,
	.release = seq_release,
	.read = seq_read,
	.llseek = seq_lseek,
};

struct trcdsc
{
	unsigned char name[8];
	unsigned int slice;
	unsigned int readsperline;
	unsigned int traceid;
	unsigned int addr;
};

struct trcdsc descriptors[] =
{
#include "trace_stat_descriptor.c"
	{ {0x0}, 0, 0, 0, 0 },
};

static u64 dump_size(void)
{
	struct trcdsc *dsc = &descriptors[0];
	u64 size = 2*8;

	while (dsc->addr) {
		size += 2*8;
		size += 8*(dsc->addr*dsc->readsperline);
		dsc++;
	}

	return size;
}

void capi_stop_trace(struct capi_t *capi)
{
	/* Stop the trace */
	capi_p1_write(capi, CAPI_PSL_TRACE, 0x8000000000000017LL);

	/* Stop the trace slice */
	capi_p1n_write(&capi->slice[0], CAPI_PSL_SLICE_TRACE, 0x8000000000000000LL);
}

static void dump_trace(unsigned long long *buffer, struct capi_t *capi)
{
	struct trcdsc *dsc = &descriptors[0];

	capi_stop_trace(capi);

	/* Get read write machine state */
	*buffer++ = capi_p1_read(capi, CAPI_PSL_TRACE);

	while (dsc->addr) {
		unsigned long long namev = 0;
		unsigned long long sv = 64-8;
		int i,j;

		/* Init trace engine */
		if (dsc->slice)
			capi_p1n_write(&capi->slice[0], CAPI_PSL_SLICE_TRACE,
				       0x8000000000000000LL |
				       dsc->readsperline << 4 |
				       dsc->traceid);
		else
			capi_p1_write(capi, CAPI_PSL_TRACE,
				      0x8000000000000000LL |
				      dsc->readsperline << 4 |
				      dsc->traceid);

		/* Write descriptor record */
		*buffer++ = 0xb0f0000000000000LL | (dsc->addr * dsc->readsperline);

		for (i = 0; i < 8; i++)	{
			namev |= (unsigned long long )(dsc->name[i]) << sv;
			sv -= 8;
		}
		*buffer++ = namev ;

		/* Read out trace */
		for (i = 0; i < dsc->addr; i++)
			for (j = 0; j < dsc->readsperline; j++)
			{
				*buffer++ = (dsc->slice) ?
					capi_p1n_read(&capi->slice[0], CAPI_PSL_SLICE_TRACE) :
					capi_p1_read(capi, CAPI_PSL_TRACE);
			}

		dsc++;
	}

	*buffer++ = 0xE0F0000000000000LL;
	return;
}

static unsigned long long *trace_buffer = NULL;
static ssize_t read_trace(struct file *file, char __user *userbuf,
			 size_t count, loff_t *ppos)
{
	u64 size = dump_size();
	struct capi_t *capi = file->private_data;

	if (!trace_buffer) {
		trace_buffer = (unsigned long long *) kzalloc(size, GFP_KERNEL);
	}

	if (!trace_buffer)
		return -ENOMEM;

	dump_trace(trace_buffer, capi);
	return simple_read_from_buffer(userbuf, count, ppos, trace_buffer, size);
}

static int open_trace (struct inode *inode, struct file *file)
{
	file->private_data = inode->i_private;

	return 0;
}

/* For getting GRUB PSL traces from debugfs */
static const struct file_operations trace_fops = {
	.open = open_trace,
	.read = read_trace,
};

int __init register_capi_dev(void)
{
	int result;

	if ((result = alloc_chrdev_region(&capi_dev, 0,
					  CAPI_NUM_MINORS, "capi"))) {
		pr_err("Unable to allocate CAPI major number: %i\n", result);
		return -1;
	}

	pr_devel("CAPI device allocated, MAJOR %i\n", MAJOR(capi_dev));

	return 0;
}

void unregister_capi_dev(void)
{
	unregister_chrdev_region(capi_dev, CAPI_NUM_MINORS);
}

int add_capi_dev(struct capi_t *adapter, int adapter_num)
{
	int rc;
	int capi_major = MAJOR(capi_dev);
	int capi_minor = adapter_num * CAPI_DEV_MINORS;
	char tmp[32];

	cdev_init(&(adapter->cdev), &capi_fops);
	rc = cdev_add(&(adapter->cdev), MKDEV(capi_major, capi_minor), 1);
	if (rc) {
		pr_err("Unable to register CAPI character device: %i\n", rc);
		return rc;
	}

	/* Create sysfs attributes */
	adapter->afu_kobj = kobject_create_and_add("afu", &adapter->device.kobj);
	if (IS_ERR(adapter->afu_kobj)) {
		rc = PTR_ERR(adapter->afu_kobj);
		goto out;
	}

	if (capi_sysfs_adapter_add(adapter))
		goto out1;

	/* Create debugfs entries */
	/* FIXME: Drop these for upstreaming. Maybe move them somewhere more
	 * appropriate under sysfs or debugfs for debugging - capi%i isn't
	 * great since it assumes 1 afu per card */
	pr_devel("Creating CAPI debugfs entries\n");
	if (cpu_has_feature(CPU_FTR_HVMODE)) {
		snprintf(tmp, 32, "capi%i_trace", adapter_num);
		adapter->trace = debugfs_create_file(tmp, 0444, NULL, adapter, &trace_fops);
		snprintf(tmp, 32, "capi%i_psl_err_chk", adapter_num);
		adapter->psl_err_chk = debugfs_create_file(tmp, 0444, NULL, adapter, &psl_err_chk_fops);
	}
	return 0;

out1:
	kobject_put(adapter->afu_kobj);
	adapter->afu_kobj = NULL;
out:
	cdev_del(&adapter->cdev);
	return rc;
}

extern struct class *capi_class;

void capi_release(struct device *dev)
{
	pr_devel("capi release\n");
}

int add_capi_afu_dev(struct capi_afu_t *afu, int slice)
{
	int rc;
	unsigned int capi_major = MAJOR(afu->adapter->device.devt);
	unsigned int capi_minor = MINOR(afu->adapter->device.devt);

	/* Add the AFU slave device */
	/* FIXME check afu->pp_mmio to see if we need this file */
	afu->device.parent = &afu->adapter->device;
	afu->device.class = capi_class;
	dev_set_name(&afu->device, "afu%i.%i", afu->adapter->adapter_num, slice);
	afu->device.devt = MKDEV(capi_major, capi_minor + CAPI_MAX_SLICES + 1 + slice);
	afu->device.class = capi_class;
	afu->device.release = capi_release;
	spin_lock_init(&afu->spa_lock);

	if ((rc = device_register(&afu->device)))
		return rc;

	cdev_init(&afu->adapter->afu_cdev, &afu_fops);
	rc = cdev_add(&afu->adapter->afu_cdev, MKDEV(capi_major, capi_minor + CAPI_MAX_SLICES + 1 + slice), afu->adapter->slices);
	if (rc) {
		pr_err("Unable to register CAPI AFU character devices: %i\n", rc);
		goto out;
	}

	/* Add the AFU master device */
	afu->device_master.parent = &afu->device;
	afu->device_master.class = capi_class;
	dev_set_name(&afu->device_master, "afu%i.%im", afu->adapter->adapter_num, slice);
	afu->device_master.class = capi_class;
	afu->device_master.devt = MKDEV(capi_major, capi_minor + 1 + slice);
	afu->device_master.release = capi_release;

	if ((rc = device_register(&afu->device_master)))
		goto out1;

	if ((rc = capi_sysfs_afu_add(afu)))
		goto out2;

	cdev_init(&afu->adapter->afu_master_cdev, &afu_master_fops);
	rc = cdev_add(&afu->adapter->afu_master_cdev, MKDEV(capi_major, capi_minor + 1 + slice), afu->adapter->slices);
	if (rc) {
		pr_err("Unable to register CAPI AFU master character devices: %i\n", rc);
		goto out3;
	}

	/* Create sysfs links */
	if ((rc = sysfs_create_link(afu->adapter->afu_kobj, &afu->device.kobj, dev_name(&afu->device))))
		goto out4;

	return 0;

out4:
	cdev_del(&afu->adapter->afu_master_cdev);
out3:
	capi_sysfs_afu_remove(afu);
out2:
	device_unregister(&afu->device_master);
out1:
	cdev_del(&afu->adapter->afu_cdev);
out:
	device_unregister(&afu->device);
	return rc;
}

void del_capi_dev(struct capi_t *adapter, int adapter_num)
{
	debugfs_remove(adapter->trace);
	debugfs_remove(adapter->psl_err_chk);
	capi_sysfs_adapter_remove(adapter);
	sysfs_remove_bin_file(&adapter->device.kobj, &adapter->capi_attr);
	kobject_put(adapter->afu_kobj);
	adapter->afu_kobj = NULL;
	cdev_del(&adapter->cdev);
	adapter->device.release = capi_release;
	device_unregister(&adapter->device);
}

void del_capi_afu_dev(struct capi_afu_t *afu)
{
	sysfs_remove_link(&afu->device.kobj, dev_name(&afu->device));
	capi_sysfs_afu_remove(afu);
	cdev_del(&afu->adapter->afu_master_cdev);
	device_unregister(&afu->device_master);
	cdev_del(&afu->adapter->afu_cdev);
	device_unregister(&afu->device);
}
