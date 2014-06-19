#if 1
#define DEBUG
#else
#undef DEBUG
#endif

/* TODO: Split this out into a separate module now that we have some CAPI
 * devices that won't want to use this generic userspace interface */

#include <linux/export.h>
#include <linux/kernel.h>
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

	if (!(ctx = kmalloc(sizeof(struct capi_context_t), GFP_KERNEL)))
	    return -ENOMEM;
	ctx->sstp = NULL;
	ctx->afu = &adapter->slice[slice];

	file->private_data = (void *)ctx;

	ctx->pid = get_pid(get_task_pid(current, PIDTYPE_PID));

	/* FIXME: Move these to afu context initialiser */
	init_waitqueue_head(&ctx->wq);
	spin_lock_init(&ctx->lock);
	ctx->pending_irq_mask = 0;

	ctx->pending_fault = false;
	ctx->pending_afu_err = false;

	i = ida_simple_get(&ctx->afu->pe_index_ida, 0,
			   ctx->afu->num_procs, GFP_KERNEL);
	if (i < 0)
		return i;
	ctx->ph = i;
	ctx->elem = &ctx->afu->spa[i];

	/* FIXME: Allow userspace to request more IRQs & maybe have an
	 * administrative way to restrict excess per process allocations */
	afu_register_irqs(ctx, ctx->afu->pp_irqs);

	return 0;
}
static int
afu_open(struct inode *inode, struct file *file)
{
	return __afu_open(inode, file, true);
}

static int
afu_ctx_open(struct inode *inode, struct file *file)
{
	return __afu_open(inode, file, false);
}


static int
afu_release(struct inode *inode, struct file *file)
{
	struct capi_context_t *ctx = (struct capi_context_t *)file->private_data;

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

	return 0;
}

static long
afu_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct capi_context_t *ctx = (struct capi_context_t *)file->private_data;
	int result;

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
		{
			struct capi_ioctl_start_work __user *uwork =
				(struct capi_ioctl_start_work __user *)arg;
			struct capi_ioctl_start_work work;
			u64 amr;

			pr_devel("afu_ioctl: CAPI_START_WORK\n");

			if (copy_from_user(&work, uwork, sizeof(struct capi_ioctl_start_work)))
				return -EFAULT;
			amr = work.amr & mfspr(SPRN_UAMOR);

			/* fixme me: decide this based on the AFU */
			if ((result = capi_ops->init_process(ctx, false, work.wed, amr)))
				return result;
			return 0;
		}
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

	/* Can't mmap until the AFU is enabled
	   FIXME: check on teardown */
	if (!ctx->afu->enabled)
		return -EBUSY;

	pr_devel("%s: mmio physical: %llx\n", __FUNCTION__, ctx->psn_phys);
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
	if (ctx->pending_irq_mask || ctx->pending_fault ||
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
		if (ctx->pending_irq_mask || ctx->pending_fault ||
		    ctx->pending_afu_err)
			break;
		spin_unlock_irqrestore(&ctx->lock, flags);

		if (file->f_flags & O_NONBLOCK)
			return -EAGAIN;

		prepare_to_wait(&ctx->wq, &wait, TASK_INTERRUPTIBLE);
		if (!(ctx->pending_irq_mask || ctx->pending_fault ||
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
	if (ctx->pending_irq_mask) {
		pr_devel("afu_read delivering AFU interrupt\n");
		event.header.size = sizeof(struct capi_event_afu_interrupt);
		event.header.type = CAPI_EVENT_AFU_INTERRUPT;
		event.irq.irq = ctx->pending_irq_mask;

		/* Only clear the IRQ if we can send the whole event: */
		if (count >= event.header.size) {
			ctx->pending_irq_mask = 0;
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
	.open           = afu_ctx_open,
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

static struct afx_chk_regs {
	const char *name;
	int reg;
} afx_chk_regs[] = {
	{ "AFX PRng", 0x418 },
	{ "AFX Status Register", 0x40 },
	{ "AFX Flags0 Reg", 0x48 },
	{ "AFX Flags1 Reg", 0x50 },
	{ "AFX More Flags Reg", 0x58 },
	{ "AFX IAR", 0x4F8 },
	{ "AFX IAR again", 0x4F8 },
	{ "AFX SRR0", 0x420 },
	{ "AFX IRC", 0x428 },
	{ "AFX PSL Enable Config", 0x0 },
	{ "AFX PSL Types Config", 0x4E8 },
	{ "AFX Configuration", 0x8 },
	{ "AFX CTR", 0x4F0 },
	{ "AFX Condition Reg", 0x400 },
	{ "AFX PRng", 0x418 },
	{ "AFX Link Reg", 0x408 },
	{ "PSL AFX0 Control", 0x90 },
	{ "GPR 0", 0x100 },
	{ "GPR 1", 0x108 },
	{ "GPR 2", 0x110 },
	{ "GPR 3", 0x118 },
	{ "GPR 4", 0x120 },
	{ "GPR 5", 0x128 },
	{ "GPR 6", 0x130 },
	{ "GPR 7", 0x138 },
	{ "GPR 8", 0x140 },
	{ "GPR 9", 0x148 },
	{ "GPR 10", 0x150 },
	{ "GPR 11", 0x158 },
	{ "GPR 12", 0x160 },
	{ "GPR 13", 0x168 },
	{ "GPR 14", 0x170 },
	{ "GPR 15", 0x178 },
	{ "GPR 16", 0x180 },
	{ "GPR 17", 0x188 },
	{ "GPR 18", 0x190 },
	{ "GPR 19", 0x198 },
	{ "GPR 20", 0x1a0 },
	{ "GPR 21", 0x1a8 },
	{ "GPR 22", 0x1b0 },
	{ "GPR 23", 0x1b8 },
	{ "GPR 24", 0x1c0 },
	{ "GPR 25", 0x1c8 },
	{ "GPR 26", 0x1d0 },
	{ "GPR 27", 0x1d8 },
	{ "GPR 28", 0x1e0 },
	{ "GPR 29", 0x1e8 },
	{ "GPR 30", 0x1f0 },
	{ "GPR 31", 0x1f8 },
};

static int afx_chk_show(struct seq_file *m, void *p)
{
	struct capi_afu_t *afu = m->private;
	int i;

	seq_puts(m, "************************ Checking AFX Registers **************************");

	for (i=0; i < ARRAY_SIZE(afx_chk_regs); i++) {
		seq_write(m, capi_dbg_sep, sizeof(capi_dbg_sep));
		seq_printf(m, "%s = %16llx", afx_chk_regs[i].name,
			capi_afu_ps_read(afu, afx_chk_regs[i].reg));
	}
	seq_putc(m, '\n');

	return 0;
}

static int afx_chk_open(struct inode *inode, struct file *file)
{
	return single_open(file, afx_chk_show, inode->i_private);
}

static const struct file_operations afx_chk_fops = {
	.open = afx_chk_open,
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

int add_capi_dev(struct capi_t *capi, int adapter_num)
{
	int rc;
	int capi_major = MAJOR(capi_dev);
	int capi_minor = adapter_num * CAPI_DEV_MINORS;
	char tmp[32];

	cdev_init(&(capi->cdev), &capi_fops);
	cdev_init(&(capi->afu_master_cdev), &afu_master_fops);
	cdev_init(&(capi->afu_cdev), &afu_fops);

	rc = cdev_add(&(capi->cdev), MKDEV(capi_major, capi_minor), 1);
	if (rc) {
		pr_err("Unable to register CAPI character device: %i\n", rc);
		return -1;
	}

	rc = cdev_add(&(capi->afu_master_cdev), MKDEV(capi_major, capi_minor + 1), capi->slices);
	if (rc) {
		pr_err("Unable to register CAPI AFU master character devices: %i\n", rc);
		return -1;
	}

	rc = cdev_add(&(capi->afu_cdev), MKDEV(capi_major, capi_minor + CAPI_MAX_SLICES + 1), capi->slices);
	if (rc) {
		pr_err("Unable to register CAPI AFU character devices: %i\n", rc);
		return -1;
	}

	/* Create debugfs entries */
	pr_devel("Creating CAPI debugfs entries\n");
	if (cpu_has_feature(CPU_FTR_HVMODE)) {
		snprintf(tmp, 32, "capi%i_trace", adapter_num);
		capi->trace = debugfs_create_file(tmp, 0444, NULL, capi, &trace_fops);
		snprintf(tmp, 32, "capi%i_psl_err_chk", adapter_num);
		capi->psl_err_chk = debugfs_create_file(tmp, 0444, NULL, capi, &psl_err_chk_fops);
		snprintf(tmp, 32, "capi%i_afx_chk", adapter_num);
		capi->afx_chk = debugfs_create_file(tmp, 0444, NULL, &capi->slice[0], &afx_chk_fops);
	}

	return 0;
}

void del_capi_dev(struct capi_t *adapter, int adapter_num)
{
	cdev_del(&adapter->cdev);
	cdev_del(&adapter->afu_master_cdev);
	cdev_del(&adapter->afu_cdev);

	debugfs_remove(adapter->trace);
	debugfs_remove(adapter->psl_err_chk);
	debugfs_remove(adapter->afx_chk);
}
