#define DEBUG

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/of_address.h>

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

	if (!(addr = of_get_address(np, index, size, NULL)))
		return OF_BAD_ADDR;

	return of_translate_address(np, addr);
}

static int __init
init_afu_of(struct capi_t *adapter, int slice, struct device_node *afu_np)
{
	struct capi_afu_t *afu;
	const __be32 *prop;
	u64 handle = 0;
	u64 p1n_base = 0, p1n_size = 0; /* XXX: BML specific - drop for upstream */
	u64 p2n_base, p2n_size;
	u64 psn_base, psn_size;
	u32 irq_start, irq_count;
	int rc;

	afu = &(adapter->slice[slice]);

	if (cpu_has_feature(CPU_FTR_HVMODE)) {
		/* XXX: BML Specific, drop for upstream */
		if ((p1n_base = read_addr(afu_np, 0, &p1n_size)) == OF_BAD_ADDR)
			return -EINVAL;
	} else {
		if (!read_handle(afu_np, &handle))
			return -EINVAL;
	}
	if ((p2n_base = read_addr(afu_np, 1, &p2n_size)) == OF_BAD_ADDR)
		return -EINVAL;
	if ((psn_base = read_addr(afu_np, 2, &psn_size)) == OF_BAD_ADDR)
		return -EINVAL;

	if (!(prop = of_get_property(afu_np, "interrupt-ranges", NULL)))
		return -EINVAL;
	irq_start = be32_to_cpu(prop[0]);
	irq_count = be32_to_cpu(prop[1]);

	if ((rc = capi_map_slice_regs(afu,
			p1n_base, p1n_size,
			p2n_base, p2n_size,
			psn_base, psn_size,
			0, 0))) {
		return rc;
	}

	return capi_init_afu(afu, handle, 0);
}

static struct capi_driver_ops capi_of_driver_ops = {
	.module = THIS_MODULE,
};

static int __init init_capi_of(void)
{
	struct device_node *np = NULL;
	struct device_node *afu_np = NULL;
	struct capi_t *adapter;
	const __be32 *prop;
	int slice;
	irq_hw_number_t err_hwirq = 0; /* XXX: Drop for upstream */
	u64 p1_base = 0, p1_size = 0; /* XXX: BML specific - drop for upstream */
	int ret = -ENODEV;
	struct capi_hv_data hv_data;
	struct capi_native_data native_data;

	pr_devel("init_capi_of\n");

	if (!(adapter = kmalloc(sizeof(struct capi_t), GFP_KERNEL)))
		return -ENOMEM;
	memset(adapter, 0, sizeof(struct capi_t));

	while ((np = of_find_compatible_node(np, NULL, "ibm,coherent-platform-facility"))) {
		/* FIXME: Restructure to avoid needing to iterate over AFUs twice */
		for (afu_np = NULL, slice = 0; (afu_np = of_get_next_child(np, afu_np)); slice++);

		if (cpu_has_feature(CPU_FTR_HVMODE)) {
			/* XXX: BML Specific, drop for upstream */
			if ((p1_base = read_addr(np, 0, &p1_size)) == OF_BAD_ADDR)
				goto bail;
			if ((prop = of_get_property(np, "interrupt", NULL)))
				err_hwirq = be32_to_cpu(prop[0]);

			native_data.p1_base = p1_base;
			native_data.p1_size = p1_size;
			native_data.p2_base = 0;
			native_data.p2_size = 0;
			native_data.err_hwirq = err_hwirq;
			if ((ret = capi_init_adapter(adapter, &capi_of_driver_ops, NULL, slice, &native_data)))
				goto bail;
		} else {
			if (!(ret = read_handle(np, &hv_data.handle)))
				goto bail;

			if ((ret = capi_init_adapter(adapter, &capi_of_driver_ops, NULL, slice, &hv_data)))
				goto bail;
		}

		for (afu_np = NULL, slice = 0; (afu_np = of_get_next_child(np, afu_np)); slice++) {
			if ((ret = init_afu_of(adapter, slice, afu_np)))
				goto bail;
		}
	}
	ret = 0;
bail:
	of_node_put(afu_np);
	of_node_put(np);
	return ret;
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
