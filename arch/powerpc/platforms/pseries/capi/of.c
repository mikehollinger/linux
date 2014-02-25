#define DEBUG

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/of.h>

#include "capi.h"

static int read_handle(struct device_node *np, u64 *handle)
{
	const __be32 *prop;
	u64 size;

	prop = of_get_address(np, 0, &size, NULL);
	if (size)
		return -EINVAL;

	/* FIXME: Hardcoded 2 cells, should recursively search parents for
	 * #address-cells like of_translate_address does (in fact, I could
	 * probably just cheat and use of_translate_address since the
	 * translation should be 1:1): */
	*handle = of_read_number(prop, 2);
	return 0;
}

static u64 read_addr(struct device_node *np, int index, u64 *size)
{
	const u32 *addr;
	phys_addr_t phys;

	if (!(addr = of_get_address(np, index, size, NULL)))
		return OF_BAD_ADDR;

	return of_translate_address(np, addr);
}

static int __init init_capi_of(void)
{
	struct device_node *np = NULL;
	struct device_node *afu_np = NULL;
	struct capi_t *adapter;
	struct capi_afu_t *afu;
	const __be32 *prop;
	int ret = 0;
	int rc;
	u64 handle = 0;
	irq_hw_number_t err_hwirq = 0; /* XXX: Drop for upstream */
	u64 p1_base = 0, p1_size = 0; /* XXX: BML specific - drop for upstream */
	u64 p1n_base = 0, p1n_size = 0; /* XXX: BML specific - drop for upstream */
	u64 p2n_base, p2n_size;
	u64 psn_base, psn_size;
	int ret = -ENODEV;

	pr_devel("init_capi_of\n");

	while (np = of_find_compatible_node(np, NULL, "ibm,coherent-platform-facility")) {

		if (cpu_has_feature(CPU_FTR_HVMODE)) {
			/* XXX: BML Specific, drop for upstream */
			if ((p1_base = read_addr(np, 0, &p1_size)) == OF_BAD_ADDR)
				goto bail;
			if ((prop = of_get_property(np, "interrupt", NULL)))
				err_hwirq = be32_to_cpu(prop[0]);
		} else {
			if (!(ret = read_handle(np, &handle)))
				goto bail;
		}
		if (capi_alloc_adapter(&adapter, handle, p1_base, p1_size, err_hwirq)) {
			ret = -ENOMEM;
			goto bail;
		}

		for (afu_np = NULL, slice = 0; (afu_np = of_get_next_child(np, afu_np)); slice++) {
			/* FIXME: All we should be doing here is probing from the device tree */
			afu = &(adapter->slice[slice]);
			afu->adapter = adapter;

			if (cpu_has_feature(CPU_FTR_HVMODE)) {
				/* XXX: BML Specific, drop for upstream */
				if ((p1n_base = read_addr(afu_np, 0, &p1n_size)) == OF_BAD_ADDR)
					goto bail;
			} else {
				if (!(ret = read_handle(afu_np, &handle)))
					goto bail;
			}
			if ((p2n_base = read_addr(afu_np, 1, &p2n_size)) == OF_BAD_ADDR)
				goto bail;
			if ((psn_base = read_addr(afu_np, 2, &psn_size)) == OF_BAD_ADDR)
				goto bail;

			irq_ranges = of_get_property(afu_np, "interrupt-ranges", NULL);
			irq_start = be32_to_cpu(irq_ranges[0]);
			irq_count = be32_to_cpu(irq_ranges[1]);

			/* FIXME: This belongs in the chardev driver */
			afu->device.parent = get_device(&adapter->device);
			dev_set_name(&afu->device, "%s%i", dev_name(adapter->device), slice + 1);
			afu->device.bus = &capi_bus_type;
			afu->device.devt = MKDEV(MAJOR(adapter->device.devt), MINOR(adapter->device.devt) + 1 + slice);

			if (device_register(&afu->device)) {
				/* FIXME: chardev for this AFU should return errors */
				continue;
			}

			if (capi_ops->init_afu(afu, handle,
					p1n_base, p1n_size,
					p2n_base, p2n_size,
					psn_base, psn_size,
					irq_start, irq_count)) {
				/* FIXME: chardev for this AFU should return errors */
				continue;
			}

		}
	}
	ret = 0;
bail:
	of_node_put(afu_np);
	of_node_put(np);
	return 0;
}

static void exit_capi_of(void)
{
	pr_warn("exit_capi_of\n");
	/* FIXME: Free allocated adapters */
}

module_init(init_capi_of);
module_exit(exit_capi_of);

MODULE_DESCRIPTION("IBM Coherent Accelerator");
MODULE_AUTHOR("Ian Munsie <imunsie@au1.ibm.com>");
MODULE_LICENSE("GPL");
