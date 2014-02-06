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

int capi_map_mmio(void __iomem **mmio, phys_addr_t *phys_ret, u64 *size_ret,
		  struct device_node *np, int index)
{
	const u32 *addr;
	phys_addr_t phys;
	u64 size;

	addr = of_get_address(np, index, &size, NULL);
	if (!addr)
		return -1;

	phys = of_translate_address(np, addr);
	*mmio = ioremap(phys, size);

	pr_devel("phys: %#llx, virt: 0x%p, size: %#llx\n",
		 phys, *mmio, size);

	if (phys_ret)
		*phys_ret = phys;
	if (size_ret)
		*size_ret = size;

	return 0;
}

void capi_unmap_mmio(void __iomem *addr)
{
	iounmap(addr);
}

/* FIXME: duplication from file.c */
extern dev_t capi_dev;
#define CAPI_NUM_MINORS 256 /* Total to reserve */
#define CAPI_DEV_MINORS 8   /* 1 control, up to 4 AFUs, 3 reserved for now */

static int __init
capi_init_adapter(struct capi_t *adapter, struct device_node *np, int adapter_num)
{
	struct device_node *afu_np = NULL;
	struct capi_afu_t *afu;
	int slice, result;

	pr_devel("---------- capi_init_adapter called ---------\n");

	adapter->device.parent = NULL; /* FIXME: Set to PHB on Sapphire? */
	dev_set_name(&adapter->device, "capi%c", 'a' + adapter_num);
	adapter->device.bus = &capi_bus_type;
	adapter->device.devt = MKDEV(MAJOR(capi_dev), adapter_num * CAPI_DEV_MINORS);

	if ((result = device_register(&adapter->device)))
		return result;

	if ((result = capi_ops->init_adapter(adapter, np)))
		return result;

	for (afu_np = NULL, slice = 0; (afu_np = of_get_next_child(np, afu_np)); slice++) {
		afu = &(adapter->slice[slice]);
		afu->adapter = adapter;

		afu->device.parent = get_device(&adapter->device);
		dev_set_name(&afu->device, "capi%c%i", 'a' + adapter_num, slice + 1);
		afu->device.bus = &capi_bus_type;
		afu->device.devt = MKDEV(MAJOR(capi_dev), adapter_num * CAPI_DEV_MINORS + 1 + slice);

		if (device_register(&afu->device)) {
			/* FIXME: chardev for this AFU should return errors */
			continue;
		}

		if (capi_ops->init_afu(afu, afu_np)) {
			/* FIXME: chardev for this AFU should return errors */
			continue;
		}
	}

	adapter->slices = slice;
	pr_devel("%i slices\n", adapter->slices);
	if (!adapter->slices)
		return -1;

	if (add_capi_dev(adapter, adapter_num))
		return -1;

	pr_devel("---------- capi_init_adapter done ---------\n");

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
	struct device_node *np = NULL;
	struct capi_t *adapter;
	int i;
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

	for (i = 0; (np = of_find_compatible_node(np, NULL, "ibm,coherent-platform-facility")); i++) {
		adapter = kmalloc(sizeof(*adapter), GFP_KERNEL);
		if (!adapter) {
			pr_err("ERROR: init_capi out of memory allocating CAPI device\n");
			ret = -ENOMEM;
			goto out;
		}
		memset(adapter, 0, sizeof(*adapter));
		if (capi_init_adapter(adapter, np, i)) {
			pr_err("Error initialising CAPI adapter\n");
			kfree(adapter);
			continue;
		}
		list_add_tail(&adapter->list, &adapter_list);
	}

out:
	of_node_put(np);

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
