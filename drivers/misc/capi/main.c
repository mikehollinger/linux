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
#include <asm/cputable.h>
#include <linux/slab.h>

#include "capi.h"

static DEFINE_SPINLOCK(adapter_list_lock);
static LIST_HEAD(adapter_list);

const struct capi_backend_ops *capi_ops;
EXPORT_SYMBOL(capi_ops);

/* FIXME: Move this to file.c */
struct class *capi_class;
EXPORT_SYMBOL(capi_class);

static void capi_adapter_wide_slbie(struct capi_t *adapter, unsigned long addr, int ssize)
{
	u64 val = (addr & ESID_MASK) | (ssize << CAPI_SLBIE_SS_SHIFT);

	/* FIXME: If we start using Class and Tags Active, we need to set the
	 * corresponding bits here to match the segment we are invalidating */

	/* TODO: Use Locking to ensure we can never have > Max_SLBIEs
	 * outstanding. For the moment we are only ever called with
	 * adapter_list_lock held, so there can only be one at a time */
	capi_p1_write(adapter, CAPI_PSL_SLBIE, val);
	while (capi_p1_read(adapter, CAPI_PSL_SLBIE) & CAPI_SLBIE_PENDING)
		cpu_relax();
}

/* FIXME: This is called from the PPC mm code, which will break when CAPI is
 * compiled as a module */
void capi_slbie(unsigned long addr)
{
	struct capi_t *adapter;
	int ssize;

	/* Potential optimisation - may be able to use slbfee instruction to
	 * get SLB from current CPU and grab B, C and TA fields from it */
	switch(REGION_ID(addr)) {
		case USER_REGION_ID:
			ssize = user_segment_size(addr);
			break;
		case VMALLOC_REGION_ID:
		case KERNEL_REGION_ID:
			ssize = mmu_kernel_ssize;
			break;
		default:
			WARN(1, "capi_slbie: Unsupported region\n");
			return;
	}

	spin_lock(&adapter_list_lock);
	list_for_each_entry(adapter, &adapter_list, list) {
		/* FIXME: Will need to use the per slice version of PSL_SLBIE
		 * when under a HV (if we have access to the p2 regs), or ask
		 * the HV to do this for us */
		capi_adapter_wide_slbie(adapter, addr, ssize);
	}
	spin_unlock(&adapter_list_lock);
}
EXPORT_SYMBOL(capi_slbie);

static void capi_afu_slbia(struct capi_afu_t *afu)
{
	pr_devel("capi_afu_slbia issuing SLBIA command\n");
	capi_p2n_write(afu, CAPI_SLBIA_An, CAPI_SLBI_IQ_ALL);
	while (capi_p2n_read(afu, CAPI_SLBIA_An) & CAPI_SLBIA_P)
		cpu_relax();
}

/* FIXME: This is called from the PPC mm code, which will break when CAPI is
 * compiled as a module */
void capi_slbia(struct mm_struct *mm)
{
	struct capi_t *adapter;
	struct capi_afu_t *afu;
	struct capi_context_t *ctx;
	struct task_struct *task;
	unsigned long flags;
	int card = 0, slice;

	pr_devel("capi_slbia called\n");

	spin_lock(&adapter_list_lock);
	list_for_each_entry(adapter, &adapter_list, list) {
		/* TODO: Link mm_struct straight to the context to skip having
		 * to search for it (but one process/single mm can have
		 * multiple capi contexts) */
		for (slice = 0; slice < adapter->slices; slice++) {
			afu = &adapter->slice[slice];
			if (!afu->enabled)
				continue;
			spin_lock(&afu->contexts_lock);
			list_for_each_entry(ctx, &afu->contexts, list) {
				if (!(task = get_pid_task(ctx->pid, PIDTYPE_PID))) {
					pr_devel("capi_slbia unable to get task %i\n", pid_nr(ctx->pid));
					continue;
				}

				if (task->mm != mm)
					goto next;

				pr_devel("capi_slbia matched mm - card %i afu %i pe %i\n", card, slice, ctx->ph);

				spin_lock_irqsave(&ctx->sst_lock, flags);
				if (!ctx->sstp)
					goto next_unlock;
				memset(ctx->sstp, 0, ctx->sst_size);
				mb();
				capi_afu_slbia(afu);

next_unlock:
				spin_unlock_irqrestore(&ctx->sst_lock, flags);
next:
				put_task_struct(task);
			}
			spin_unlock(&afu->contexts_lock);
		}
		card++;
	}
	spin_unlock(&adapter_list_lock);
}

int capi_alloc_sst(struct capi_context_t *ctx, u64 *sstp0, u64 *sstp1)
{
	u64 rt = 0;
	unsigned long vsid, flags;
	u64 ssize;
	u64 ea_mask;
	u64 size;

	*sstp0 = 0;
	*sstp1 = 0;

	ctx->sst_size = PAGE_SIZE;
	ctx->sst_lru = 0;
	if (!ctx->sstp) {
		ctx->sstp = (struct capi_sste*)get_zeroed_page(GFP_KERNEL);
		pr_devel("SSTP allocated at 0x%p\n", ctx->sstp);
	} else {
		pr_devel("Zeroing and reusing SSTP already allocated at 0x%p\n", ctx->sstp);
		spin_lock_irqsave(&ctx->sst_lock, flags);
		memset(ctx->sstp, 0, PAGE_SIZE);
		capi_afu_slbia(ctx->afu);
		spin_unlock_irqrestore(&ctx->sst_lock, flags);
	}
	if (!ctx->sstp) {
		pr_err("capi_alloc_sst: Unable to allocate segment table\n");
		return -ENOMEM;
	}

	/*
	 * Some of the bits in the SSTP are from the segment that CONTAINS the
	 * segment table, so look that up and copy the bits in.
	 *
	 * TODO: Check if any of the functions already defined in mmu.h etc.
	 * are suitable to simplify any of this. In particular, htp_va may be
	 * useful (would require shifting the VSID by slb_vsid_shift(ssize)
	 * instead of what I do below). My main question with that is what
	 * happens to the top 14 bits of the VSID - are they always 0? I can
	 * always copy them into SSTP0 like I do below anyway.
	 */

	rt = slbfee((u64)ctx->sstp);

	ssize = (rt & SLB_VSID_B) >> SLB_VSID_SSIZE_SHIFT;
	/* FIXME: Did I need to handle 1TB segments? I have a vague
	 * recollection that the answer was no - I'll need to recheck */
	vsid  = (rt & SLB_VSID_MASK) >> SLB_VSID_SHIFT;

	*sstp0 |= ssize << CAPI_SSTP0_An_B_SHIFT;
	*sstp0 |= (rt & (SLB_VSID_KS | SLB_VSID_KP | SLB_VSID_N | SLB_VSID_L
		       | SLB_VSID_C | SLB_VSID_TA | SLB_VSID_LP)) << 50;

	size = (((u64)ctx->sst_size >> 8) - 1) << CAPI_SSTP0_An_SegTableSize_SHIFT;
	BUG_ON(size & ~CAPI_SSTP0_An_SegTableSize_MASK);
	*sstp0 |= size;

	if (ssize == MMU_SEGSIZE_256M)
		ea_mask =    0xfffff00;
	else if (ssize == MMU_SEGSIZE_1T)
		ea_mask = 0xffffffff00;
	else {
		WARN(1, "CAPI: Unsupported segment size\n");
		free_page((u64)ctx->sstp);
		ctx->sstp = NULL;
		return -EINVAL;
	}

	*sstp0 |=  vsid >>     (50-14);  /*   Top 14 bits of VSID */
	*sstp1 |= (vsid << (64-(50-14))) & ~ea_mask;
	*sstp1 |= (u64)ctx->sstp & ea_mask;
	*sstp1 |= CAPI_SSTP1_An_V;

	pr_devel("Looked up %#llx: slbfee. %#llx: %#llx (ssize: %#llx, vsid: %#lx), copied to SSTP0: %#llx, SSTP1: %#llx\n",
			(u64)ctx->sstp, (u64)ctx->sstp & ESID_MASK, rt, ssize, vsid, *sstp0, *sstp1);

	return 0;
}

struct capi_t * get_capi_adapter(int num)
{
	struct capi_t *adapter;
	int i = 0;
	struct capi_t * ret = NULL;

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

int capi_get_num_adapters(void)
{
	struct capi_t *adapter;
	int i = 0;

	list_for_each_entry(adapter, &adapter_list, list)
		i++;

	return i;
}

static void afu_t_init(struct capi_t *adapter, int slice)
{
	struct capi_afu_t *afu = &adapter->slice[slice];
	afu->adapter = adapter;
	afu->slice = slice;
	INIT_LIST_HEAD(&afu->contexts);
	spin_lock_init(&afu->contexts_lock);
	spin_lock_init(&afu->afu_cntl_lock);
	mutex_init(&afu->spa_mutex);
}

/* FIXME: The calling convention here is a mess and needs to be cleaned up.
 * Maybe better to have the caller fill in the struct and call us? */
int capi_init_adapter(struct capi_t *adapter,
		      struct capi_driver_ops *driver,
		      struct device *parent,
		      int slices, void *backend_data)
{
	int slice, rc = 0;

	pr_devel("capi_alloc_adapter");

	/* There must be at least one AFU */
	if (!slices)
		return -EINVAL;

	spin_lock(&adapter_list_lock);
	adapter->adapter_num = capi_get_num_adapters();

	adapter->driver = driver;
	adapter->device.class = capi_class;
	adapter->device.parent = parent;
	adapter->slices = slices;
	pr_devel("%i slices\n", adapter->slices);

	/* Prepare the backend hardware */
	if ((rc = capi_ops->init_adapter(adapter, backend_data)))
		goto out;

	/* Register the adapter device */
	dev_set_name(&adapter->device, "card%i", adapter->adapter_num);
	adapter->device.devt = MKDEV(MAJOR(capi_dev), adapter->adapter_num * CAPI_DEV_MINORS);
	if ((rc = device_register(&adapter->device)))
		goto out1;

	/* Add adapter character device and sysfs entries */
	if (add_capi_dev(adapter, adapter->adapter_num)) {
		rc = -1;
		goto out2;
	}

	for (slice = 0; slice < slices; slice++)
		afu_t_init(adapter, slice);

	list_add_tail(&(adapter)->list, &adapter_list);
	spin_unlock(&adapter_list_lock);

	return 0;

out2:
	device_unregister(&adapter->device);
out1:
	capi_ops->release_adapter(adapter);
out:
	spin_unlock(&adapter_list_lock);
	pr_devel("capi_init_adapter: %i\n", rc);
	return rc;
}
EXPORT_SYMBOL(capi_init_adapter);

int capi_init_afu(struct capi_afu_t *afu, u64 handle, irq_hw_number_t err_irq)
{
	int rc;

	pr_devel("capi_init_afu: slice: %i, handle: %#llx, err_irq: %#lx\n",
			afu->slice, handle, err_irq);

	afu->err_hwirq = err_irq;

	/* Initialise the hardware? */
	if ((rc = capi_ops->init_afu(afu, handle)))
	    return rc;

	/* Add afu character devices */
	if ((rc = add_capi_afu_dev(afu, afu->slice)))
		return rc;

	return 0;
}
EXPORT_SYMBOL(capi_init_afu);

static char *capi_devnode(struct device *dev, umode_t *mode)
{
	if (MINOR(dev->devt) % CAPI_DEV_MINORS == 0)
		return NULL;
	return kasprintf(GFP_KERNEL, "cxl/%s", dev_name(dev));
}

static int __init init_capi(void)
{
	int ret = 0;

	pr_devel("---------- init_capi called ---------\n");

	capi_class = class_create(THIS_MODULE, "cxl");
	if (IS_ERR(capi_class)) {
		pr_warn("Unable to create capi class\n");
		return PTR_ERR(capi_class);
	}
	capi_class->devnode = capi_devnode;

	if (cpu_has_feature(CPU_FTR_HVMODE))
		init_capi_native();
	else
		init_capi_hv();

	if (register_capi_dev())
		return -1;

	pr_devel("---------- init_capi done ---------\n");

	return ret;
}

void capi_unregister_afu(struct capi_afu_t *afu)
{
	del_capi_afu_dev(afu);
	capi_ops->release_afu(afu);
}
EXPORT_SYMBOL(capi_unregister_afu);

void capi_unregister_adapter(struct capi_t *adapter)
{
	struct capi_t *tmp;
	int adapter_num = 0, slice;

	/* Unregister CAPI adapter device */

	spin_lock(&adapter_list_lock);
	list_for_each_entry_safe(adapter, tmp, &adapter_list, list) {
		for (slice = 0; slice < adapter->slices; slice++)
			capi_unregister_afu(&adapter->slice[slice]);
		del_capi_dev(adapter, adapter_num++);

		/* CAPI-HV/Native adapter release */
		if (capi_ops->release_adapter)
			capi_ops->release_adapter(adapter);

		list_del(&adapter->list);
	}
	spin_unlock(&adapter_list_lock);

	unregister_capi_dev();
}
EXPORT_SYMBOL(capi_unregister_adapter);

static void exit_capi(void)
{
	class_destroy(capi_class);
}

module_init(init_capi);
module_exit(exit_capi);

MODULE_DESCRIPTION("IBM Coherent Accelerator");
MODULE_AUTHOR("Ian Munsie <imunsie@au1.ibm.com>");
MODULE_LICENSE("GPL");
