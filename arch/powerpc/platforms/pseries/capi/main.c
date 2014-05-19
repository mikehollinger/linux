#if 1
#define DEBUG
#else
#undef DEBUG
#endif

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/of.h>
#include <asm/cputable.h>

#include "capi.h"

static LIST_HEAD(adapter_list);
const struct capi_ops *capi_ops;

int capi_alloc_sst(struct capi_afu_t *afu, u64 *sstp0, u64 *sstp1)
{
	u64 rt = 0;
	unsigned long vsid;
	u64 ssize;
	u64 ea_mask;
	u64 size;

	*sstp0 = 0;
	*sstp1 = 0;

	afu->sst_size = PAGE_SIZE;
	afu->sst_lru = 0;
	if (!afu->sstp) {
		afu->sstp = (struct capi_sste*)get_zeroed_page(GFP_KERNEL);
		pr_devel("SSTP allocated at 0x%p\n", afu->sstp);
	} else {
		pr_devel("Zeroing and reusing SSTP already allocated at 0x%p\n", afu->sstp);
		memset(afu->sstp, 0, PAGE_SIZE);
	}
	if (!afu->sstp) {
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

	rt = slbfee((u64)afu->sstp);

	ssize = (rt & SLB_VSID_B) >> SLB_VSID_SSIZE_SHIFT;
	/* FIXME: Did I need to handle 1TB segments? I have a vague
	 * recollection that the answer was no - I'll need to recheck */
	vsid  = (rt & SLB_VSID_MASK) >> SLB_VSID_SHIFT;

	*sstp0 |= ssize << CAPI_SSTP0_An_B_SHIFT;
	*sstp0 |= (rt & (SLB_VSID_KS | SLB_VSID_KP | SLB_VSID_N | SLB_VSID_L
		       | SLB_VSID_C | SLB_VSID_TA | SLB_VSID_LP)) << 50;

	size = (((u64)afu->sst_size >> 8) - 1) << CAPI_SSTP0_An_SegTableSize_SHIFT;
	BUG_ON(size & ~CAPI_SSTP0_An_SegTableSize_MASK);
	*sstp0 |= size;

	if (ssize == MMU_SEGSIZE_256M)
		ea_mask =    0xfffff00;
	else if (ssize == MMU_SEGSIZE_1T)
		ea_mask = 0xffffffff00;
	else {
		WARN(1, "CAPI: Unsupported segment size\n");
		free_page((u64)afu->sstp);
		afu->sstp = NULL;
		return -EINVAL;
	}

	*sstp0 |=  vsid >>     (50-14);  /*   Top 14 bits of VSID */
	*sstp1 |= (vsid << (64-(50-14))) & ~ea_mask;
	*sstp1 |= (u64)afu->sstp & ea_mask;
	*sstp1 |= CAPI_SSTP1_An_V;

	pr_devel("Looked up %#llx: slbfee. %#llx: %#llx (ssize: %#llx, vsid: %#lx), copied to SSTP0: %#llx, SSTP1: %#llx\n",
			(u64)afu->sstp, (u64)afu->sstp & ESID_MASK, rt, ssize, vsid, *sstp0, *sstp1);

	return 0;
}

struct capi_t * get_capi_adapter(int num)
{
	struct capi_t *adapter;
	int i = 0;

	list_for_each_entry(adapter, &adapter_list, list) {
		if (i++ == num)
			return adapter;
	}

	return NULL;
}

int capi_get_num_adapters(void)
{
	struct capi_t *adapter;
	int i = 0;

	list_for_each_entry(adapter, &adapter_list, list)
		i++;

	return i;
}

static int
capi_init_adapter(struct capi_t *adapter,
		int slices, u64 handle,
		u64 p1_base, u64 p1_size,
		u64 p2_base, u64 p2_size,
		irq_hw_number_t err_hwirq)
{
	int result;
	int adapter_num;

	pr_devel("---------- capi_init_adapter called ---------\n");

	/* FIXME TODO: Ensure this can't change until the adapter is added to the list! */
	adapter_num = capi_get_num_adapters();

	adapter->device.parent = NULL; /* FIXME: Set to PHB on Sapphire? */
	dev_set_name(&adapter->device, "capi%c", 'a' + adapter_num);
	adapter->device.bus = &capi_bus_type;
	adapter->device.devt = MKDEV(MAJOR(capi_dev), adapter_num * CAPI_DEV_MINORS);

	if ((result = device_register(&adapter->device)))
		return result;

	if ((result = capi_ops->init_adapter(adapter, handle,
					p1_base, p1_size,
					p2_base, p2_size,
					err_hwirq)))
		return result;


	adapter->slices = slices;
	pr_devel("%i slices\n", adapter->slices);
	if (!adapter->slices)
		return -1;

	if (add_capi_dev(adapter, adapter_num))
		return -1;

	pr_devel("---------- capi_init_adapter done ---------\n");

	return 0;
}

int capi_init_afu(struct capi_t *adapter, struct capi_afu_t *afu,
		  int slice, u64 handle,
		  u64 p1n_base, u64 p1n_size,
		  u64 p2n_base, u64 p2n_size,
		  u64 psn_base, u64 psn_size,
		  irq_hw_number_t irq_start, irq_hw_number_t irq_count)
{
	pr_devel("capi_init_afu: slice: %i, handle: %#llx, p1: %#.16llx %#llx, p2: %#.16llx %#llx, ps: %#.16llx %#llx, irqs: %#lx %#lx\n",
			slice, handle, p1n_base, p1n_size, p2n_base, p2n_size, psn_base, psn_size, irq_start, irq_count);

	afu->adapter = adapter;

	afu->device.parent = get_device(&adapter->device);
	dev_set_name(&afu->device, "%s%i", dev_name(&adapter->device), slice + 1);
	afu->device.bus = &capi_bus_type;
	afu->device.devt = MKDEV(MAJOR(adapter->device.devt), MINOR(adapter->device.devt) + 1 + slice);

	if (device_register(&afu->device)) {
		/* FIXME: chardev for this AFU should return errors */
		return -EFAULT;
	}

	/* FIXME: Do this first, and only then create the char dev */
	return capi_ops->init_afu(afu, handle,
			p1n_base, p1n_size,
			p2n_base, p2n_size,
			psn_base, psn_size,
			irq_start, irq_count);
}

/* FIXME: The calling convention here is a mess and needs to be cleaned up.
 * Maybe better to have the caller alloc the struct, fill it what it need and
 * call us? */
int capi_alloc_adapter(struct capi_t **adapter,
		       int slices, u64 handle,
		       u64 p1_base, u64 p1_size,
		       u64 p2_base, u64 p2_size,
		       irq_hw_number_t err_hwirq)
{
	int rc;

	pr_devel("capi_alloc_adapter: handle: %#llx p1: %#.16llx %#llx p2: %#.16llx %#llx err: %#lx",
			handle, p1_base, p1_size, p2_base, p2_size, err_hwirq);

	if (!(*adapter = kmalloc(sizeof(struct capi_t), GFP_KERNEL)))
		return -ENOMEM;
	memset(*adapter, 0, sizeof(struct capi_t));

	if ((rc = capi_init_adapter(*adapter, slices, handle,
				    p1_base, p1_size,
				    p2_base, p2_size,
				    err_hwirq))) {
		pr_err("Error initialising CAPI adapter\n");
		kfree(*adapter);
		*adapter = NULL;
		return rc;
	}
	list_add_tail(&(*adapter)->list, &adapter_list);

	return 0;
}

#if 0
static void capi_free_adapter(struct capi_t *adapter)
{
	/* TODO */
}
EXPORT_SYMBOL(capi_free_adapter);
#endif

struct bus_type capi_bus_type = {
	.name = "capi",
	/*
	 * .match
	 * .uevent
	 * .probe
	 * .remove
	 * .shutdown
	 * .dev_attrs
	 * .bus_attrs
	 * .drv_attrs
	 * .pm
	 */
};


static int __init init_capi(void)
{
	int ret = 0;

	pr_devel("---------- init_capi called ---------\n");

	if ((ret = bus_register(&capi_bus_type))) {
		pr_err("ERRPR: Unable to register CAPI bus type\n");
		return ret;
	}

	if (cpu_has_feature(CPU_FTR_HVMODE))
		init_capi_native();
	else
		init_capi_hv();

	if (register_capi_dev())
		return -1;

	pr_devel("---------- init_capi done ---------\n");

	return ret;
}

static void exit_capi(void)
{
	struct capi_t *adapter, *tmp;
	int adapter_num = 0, slice;

	list_for_each_entry_safe(adapter, tmp, &adapter_list, list) {
		for (slice = 0; slice < adapter->slices; slice++) {
			afu_release_irqs(&(adapter->slice[slice]));
			capi_ops->release_afu(&(adapter->slice[slice]));
			put_device(adapter->slice[slice].device.parent);
		}
		del_capi_dev(adapter, adapter_num++);
		if (capi_ops->release_adapter)
			capi_ops->release_adapter(adapter);
		list_del(&adapter->list);
		kfree(adapter);
	}

	unregister_capi_dev();

	bus_unregister(&capi_bus_type);
}

module_init(init_capi);
module_exit(exit_capi);

MODULE_DESCRIPTION("IBM Coherent Accelerator");
MODULE_AUTHOR("Ian Munsie <imunsie@au1.ibm.com>");
MODULE_LICENSE("GPL");
