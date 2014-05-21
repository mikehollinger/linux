#define DEBUG

#include <linux/pci_regs.h>
#include <linux/pci_ids.h>
#include <linux/device.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/sort.h>
#include <linux/pci.h>
#include <linux/of.h>
#include <asm/opal.h>

#include <asm/msi_bitmap.h>
#include <asm/pci-bridge.h> /* for struct pci_controller */
#include "../arch/powerpc/platforms/powernv/pci.h" /* FIXME - for struct pnv_phb */

#include "capi.h"

#define CAPI_PCI_VSEC_ID	0x1280

#define CAPI_PROTOCOL_256TB	(1ull << 7)
#define CAPI_PROTOCOL_ENABLE	(1ull << 16)

#define CAPI_VSEC_LENGTH(vsec)		(vsec + 0x6) /* WORD */
#define CAPI_VSEC_NAFUS(vsec)		(vsec + 0x8) /* BYTE */
#define CAPI_VSEC_AFU_DESC_OFF(vsec)	(vsec + 0x20)
#define CAPI_VSEC_AFU_DESC_SIZE(vsec)	(vsec + 0x24)
#define CAPI_VSEC_PS_OFF(vsec)		(vsec + 0x28)
#define CAPI_VSEC_PS_SIZE(vsec)		(vsec + 0x2c)
#define CAPI_VSEC_PS_SIZE_V10(vsec)	(vsec + 0xb) /* BYTE - removed in CAIA v0.11*/

DEFINE_PCI_DEVICE_TABLE(capi_pci_tbl) = {
	{ PCI_DEVICE(PCI_VENDOR_ID_IBM, 0x0477), },
	{ PCI_DEVICE_CLASS(0x120000, ~0), },

	{ }
};
MODULE_DEVICE_TABLE(pci, capi_pci_tbl);

struct capi_pci_t {
	struct pci_dev *pdev;
	struct capi_t adapter;
};

static int find_capi_vsec(struct pci_dev *dev)
{
	int vsec = 0;
	u16 val;

	while ((vsec = pci_find_next_ext_capability(dev, vsec, PCI_EXT_CAP_ID_VNDR))) {
		pci_read_config_word(dev, vsec + 0x4, &val);
		if (val == CAPI_PCI_VSEC_ID)
			return vsec;
	}
	return 0;

}

static void dump_capi_config_space(struct pci_dev *dev)
{
	int vsec;
	u32 val;

	dev_info(&dev->dev, "dump_capi_config_space\n");

	pci_read_config_dword(dev, PCI_BASE_ADDRESS_0, &val);
	dev_info(&dev->dev, "BAR0: %#.8x\n", val);
	pci_read_config_dword(dev, PCI_BASE_ADDRESS_1, &val);
	dev_info(&dev->dev, "BAR1: %#.8x\n", val);
	pci_read_config_dword(dev, PCI_BASE_ADDRESS_2, &val);
	dev_info(&dev->dev, "BAR2: %#.8x\n", val);
	pci_read_config_dword(dev, PCI_BASE_ADDRESS_3, &val);
	dev_info(&dev->dev, "BAR3: %#.8x\n", val);
	pci_read_config_dword(dev, PCI_BASE_ADDRESS_4, &val);
	dev_info(&dev->dev, "BAR4: %#.8x\n", val);
	pci_read_config_dword(dev, PCI_BASE_ADDRESS_5, &val);
	dev_info(&dev->dev, "BAR5: %#.8x\n", val);

	dev_info(&dev->dev, "p1 regs: %#llx, len: %#llx\n", pci_resource_start(dev, 2), pci_resource_len(dev, 2));
	dev_info(&dev->dev, "p2 regs: %#llx, len: %#llx\n", pci_resource_start(dev, 0), pci_resource_len(dev, 0));
	dev_info(&dev->dev, "BAR 4/5: %#llx, len: %#llx\n", pci_resource_start(dev, 4), pci_resource_len(dev, 4));

	if (!(vsec = find_capi_vsec(dev)))
		return;

	pci_read_config_dword(dev, vsec + 0x0, &val);
	dev_info(&dev->dev, "capi vsec: %30s: %#x\n", "Cap ID",		(val >>  0) & 0xffff);
	dev_info(&dev->dev, "capi vsec: %30s: %#x\n", "Cap Ver",	(val >> 16) & 0xf);
	dev_info(&dev->dev, "capi vsec: %30s: %#x\n", "Next Cap Ptr",	(val >> 20) & 0xfff);
	pci_read_config_dword(dev, vsec + 0x4, &val);
	dev_info(&dev->dev, "capi vsec: %30s: %#x\n", "VSEC ID",	(val >>  0) & 0xffff);
	dev_info(&dev->dev, "capi vsec: %30s: %#x\n", "VSEC Rev",	(val >> 16) & 0xf);
	dev_info(&dev->dev, "capi vsec: %30s: %#x\n", "VSEC Length",	(val >> 20) & 0xfff);
	pci_read_config_dword(dev, vsec + 0x8, &val);
	dev_info(&dev->dev, "capi vsec: %30s: %#x\n", "Num AFUs",	(val >>  0) & 0xff);
	dev_info(&dev->dev, "capi vsec: %30s: %#x\n", "Status",		(val >>  8) & 0xff);
	dev_info(&dev->dev, "capi vsec: %30s: %#x\n", "Mode Control",	(val >> 16) & 0xff);
	dev_info(&dev->dev, "capi vsec: %30s: %#x\n", "PS_area_size",	(val >> 24) & 0xff); /* Reserved >= 0.12 */
	pci_read_config_dword(dev, vsec + 0xc, &val);
	dev_info(&dev->dev, "capi vsec: %30s: %#x\n", "PSL Rev",	(val >>  0) & 0xffff);
	dev_info(&dev->dev, "capi vsec: %30s: %#x\n", "CAIA Ver",	(val >> 16) & 0xffff);
	pci_read_config_dword(dev, vsec + 0x10, &val);
	dev_info(&dev->dev, "capi vsec: %30s: %#x\n", "Base Image Rev",	(val >>  0) & 0xffff); /* Reserved < 0.11 */
	dev_info(&dev->dev, "capi vsec: %30s: %#x\n", "Reserved",	(val >> 16) & 0x0fff);
	dev_info(&dev->dev, "capi vsec: %30s: %#x\n", "Image Control",	(val >> 28) & 0x3); /* Reserved < 0.12 */
	dev_info(&dev->dev, "capi vsec: %30s: %#x\n", "Reserved",	(val >> 30) & 0x1); /* Reserved < 0.12 */
	dev_info(&dev->dev, "capi vsec: %30s: %#x\n", "Image Loaded",	(val >> 31) & 0x1); /* Reserved < 0.12 */
	pci_read_config_dword(dev, vsec + 0x14, &val);
	dev_info(&dev->dev, "capi vsec: %30s: %#x\n", "Reserved",	val);

	pci_read_config_dword(dev, vsec + 0x18, &val);
	dev_info(&dev->dev, "capi vsec: %30s: %#x\n", "PSL Programming Port", val); /* Reserved >= 0.11 */
	pci_read_config_dword(dev, vsec + 0x1c, &val);
	dev_info(&dev->dev, "capi vsec: %30s: %#x\n", "PSL Programming Control", val); /* Reserved >= 0.11 */

	dev_info(&dev->dev, "capi vsec: end of v0.09 defintion");

	pci_read_config_dword(dev, vsec + 0x20, &val);
	dev_info(&dev->dev, "capi vsec: %30s: %#x\n", "Flash Address Register (v0.10) / AFU Descriptor Offset (v0.11+)", val);
	pci_read_config_dword(dev, vsec + 0x24, &val);
	dev_info(&dev->dev, "capi vsec: %30s: %#x\n", "Flash Size Register (v0.10) / AFU Descriptor Size (v0.11+)", val);
	pci_read_config_dword(dev, vsec + 0x28, &val);
	dev_info(&dev->dev, "capi vsec: %30s: %#x\n", "Flash Status/Control Register (v0.10) / Problem State Offset (v0.11+)", val);
	pci_read_config_dword(dev, vsec + 0x2c, &val);
	dev_info(&dev->dev, "capi vsec: %30s: %#x\n", "Flash Data Port (v0.10) / Problem State Size (v0.11+)", val);

	dev_info(&dev->dev, "capi vsec: end of v0.10 defintion");

	pci_read_config_dword(dev, vsec + 0x30, &val);
	dev_info(&dev->dev, "capi vsec: %30s: %#x\n", "Reserved", val);
	pci_read_config_dword(dev, vsec + 0x34, &val);
	dev_info(&dev->dev, "capi vsec: %30s: %#x\n", "Reserved", val);
	pci_read_config_dword(dev, vsec + 0x38, &val);
	dev_info(&dev->dev, "capi vsec: %30s: %#x\n", "Reserved", val);
	pci_read_config_dword(dev, vsec + 0x3c, &val);
	dev_info(&dev->dev, "capi vsec: %30s: %#x\n", "Reserved", val);

	pci_read_config_dword(dev, vsec + 0x40, &val);
	dev_info(&dev->dev, "capi vsec: %30s: %#x\n", "PSL Programming Port", val);
	pci_read_config_dword(dev, vsec + 0x44, &val);
	dev_info(&dev->dev, "capi vsec: %30s: %#x\n", "PSL Programming Control", val);
	pci_read_config_dword(dev, vsec + 0x48, &val);
	dev_info(&dev->dev, "capi vsec: %30s: %#x\n", "Flash Address Register (v0.11)", val); /* Reserved >= 0.12 */
	pci_read_config_dword(dev, vsec + 0x4c, &val);
	dev_info(&dev->dev, "capi vsec: %30s: %#x\n", "Flash Size Register (v0.11)", val); /* Reserved >= 0.12 */
	pci_read_config_dword(dev, vsec + 0x50, &val);
	dev_info(&dev->dev, "capi vsec: %30s: %#x\n", "Flash Status/Control Register (v0.11) / Flash Address Register (v0.12)", val);
	pci_read_config_dword(dev, vsec + 0x54, &val);
	dev_info(&dev->dev, "capi vsec: %30s: %#x\n", "Flash Data Port (v0.11) / Flash Size Register (v0.12)", val);

	dev_info(&dev->dev, "capi vsec: end of v0.11 defintion");

	pci_read_config_dword(dev, vsec + 0x58, &val);
	dev_info(&dev->dev, "capi vsec: %30s: %#x\n", "Flash Status/Control Register (v0.12)", val); /* Reserved < 0.12 */
	pci_read_config_dword(dev, vsec + 0x58, &val);
	dev_info(&dev->dev, "capi vsec: %30s: %#x\n", "Flash Data Port (v0.12)", val); /* Reserved < 0.12 */

	/* TODO: Dump AFU Descriptor & AFU Configuration Record if present */
}

static int cmpbar(const void *p1, const void *p2)
{
	struct resource *r1 = *(struct resource **)p1;
	struct resource *r2 = *(struct resource **)p2;
	resource_size_t l1 = r1->end - r1->start;
	resource_size_t l2 = r2->end - r2->start;

	pr_warn("capi %#.16llx <> %#.16llx : %#llx\n", l1, l2, l1 - l2);

	return l1 - l2;
}

static struct device_node * get_capi_phb_node(struct pci_dev *dev)
{
	struct device_node *np;
	struct property *prop = NULL;

	np = of_node_get(pci_device_to_OF_node(dev));

	/* Scan up the tree looking for the PHB node */
	while (np) {
		if ((prop = of_find_property(np, "ibm,opal-phbid", NULL)))
			break;
		np = of_get_next_parent(np);
	}

	if (!prop) {
		of_node_put(np);
		return NULL;
	}

	return np;
}

static int init_implementation_adapter_regs(struct capi_t *adapter)
{
	struct pci_dev *dev = container_of(adapter, struct capi_pci_t, adapter)->pdev;
	struct device_node *np;
	const __be32 *prop;
	u64 psl_dsnctl;
	u64 chipid;

	dev_info(&dev->dev, "capi: **** Setup PSL Implementation Specific Registers ****\n");

	if (!(np = get_capi_phb_node(dev)))
		return -ENODEV;

	while (np && !(prop = of_get_property(np, "ibm,chip-id", NULL)))
		np = of_get_next_parent(np);
	if (!np)
		return -ENODEV;
	chipid = be32_to_cpup(prop);
	of_node_put(np);

	dev_info(&dev->dev, "capi: Found ibm,chip-id: %#llx\n", chipid);

	/* cappid 0:2 nodeid 3:5 chipid */
	/* psl_dsnctl = 0x02e8100000000000ULL | (node << (63-2)) | (pos << (63-5)); */
	psl_dsnctl = 0x02e8100000000000ULL | (chipid << (63-5));

	capi_p1_write(adapter, CAPI_PSL_DSNDCTL, psl_dsnctl); /* Tell PSL where to route data to */
	capi_p1_write(adapter, CAPI_PSL_SNWRALLOC, 0x00000000FFFFFFFFULL); /* snoop write mask */
	capi_p1_write(adapter, CAPI_PSL_FIR_CNTL, 0x0800000000000000ULL); /* set fir_accum */

#if 0
	capi_p1_write(adapter, CAPI_PSL_TRACERD, 0x0000F0FC00000000ULL); /* for debugging with trace arrays */
#else
	/* changes recommended per JT and Yoanna 11/15/2013 */
	capi_p1_write(adapter, CAPI_PSL_TRACE, 0x0000FF7C00000000ULL); /* for debugging with trace arrays */
#endif

	dev_info(&dev->dev, "capi: **** Workaround to disable PSL QuickTag to fix miscompares - PSL_SNWRALLOC - HW249157 ****\n");
	capi_p1_write(adapter, CAPI_PSL_SNWRALLOC, 0x80000000FFFFFFFFULL); /* HW249157 */

	dev_info(&dev->dev, "capi: **** Workaround to gate off PSL sending interrupts for bug in PHB - PSL_DSNDCTL(39) - DD1.3 will be fixed****\n");
	dev_info(&dev->dev, "capi: **** Workaround to gate off TLBWait on interrupts - PSL_DSNDCTL(41) - DD1.3 will be fixed****\n");
	capi_p1_write(adapter, CAPI_PSL_DSNDCTL, psl_dsnctl); /* Set to same value again? Is this necessary? */

	return 0;
}

static int init_implementation_afu_regs(struct capi_afu_t *afu)
{
	struct pci_dev *dev = container_of(afu->adapter, struct capi_pci_t, adapter)->pdev;

	capi_p1n_write(afu, CAPI_PSL_APCALLOC_A, 0xFFFFFFFEFEFEFEFEULL); /* read/write masks for this slice */
	capi_p1n_write(afu, CAPI_PSL_COALLOC_A, 0xFF000000FEFEFEFEULL); /* APC read/write masks for this slice */

	/* changes recommended per JT and Yoanna 11/15/2013 */
	capi_p1n_write(afu, CAPI_PSL_SLICE_TRACE, 0x0000FFFF00000000ULL); /* for debugging with trace arrays */

	dev_info(&dev->dev, "capi: **** Workaround to lower croom value to avoid bug in AFX - PSL_RXCTL - HW252777 ****\n");
	capi_p1n_write(afu, CAPI_PSL_RXCTL_A, 0x000F000000000000ULL); /* HW252777 */

	return 0;
}

static struct capi_driver_ops capi_pci_driver_ops = {
	.init_adapter = init_implementation_adapter_regs,
	.init_afu = init_implementation_afu_regs,
};



static void reassign_capi_bars(struct pci_dev *dev)
{
	const u32 *window_prop;
	LIST_HEAD(head);
	u64 window, size;
	u64 off, addr;
	int bar, i;
	struct resource * bars[2];
	resource_size_t len;
	struct device_node *np;

	dev_warn(&dev->dev, "Reassign CAPI BARs\n");

	if (!(np = get_capi_phb_node(dev))) {
		dev_warn(&dev->dev, "WARNING: Unable to get capi phb node, using BAR assignment from Linux\n");
		return;
	}

	/*
	 * MASSIVE HACK: CAPI requires the m64 address space for BAR
	 * assignment. Our PHB code in Linux doesn't use it yet, and Linux will
	 * have assigned BAR's from the m32 space. For now just reassign the
	 * BARs from the m64 space.
	 */
	window_prop = of_get_property(np, "ibm,opal-m64-window", NULL);
	if (!window_prop) {
		dev_warn(&dev->dev, "WARNING: Using BAR assignment from Linux, this probably will break MMIO access.\n");
	} else {

		window = of_read_number(window_prop, 2);
		size = of_read_number(&window_prop[4], 2);
		off = window;

		bars[0] = &dev->resource[0];
		bars[1] = &dev->resource[2];
		sort(bars, 2, sizeof(struct resource *), cmpbar, NULL);

		for (i = 1; i >= 0; i--) {
			bar = bars[i] - &dev->resource[0];
			len = bars[i]->end - bars[i]->start + 1;
			addr = off;

			dev_warn(&dev->dev, "Reassigning resource %i to %#.16llx %#llx\n", bar, addr, len);
			pci_write_config_dword(dev, PCI_BASE_ADDRESS_0 + 4*bar, addr & 0xffffffff);
			pci_write_config_dword(dev, PCI_BASE_ADDRESS_0 + 4*(bar+1), addr >> 32);
			dev->resource[bar].start = addr;
			dev->resource[bar].end = addr + len - 1;

			off += len;
		}
	}

	/* BAR 4/5 is for the CAPI protocol. Bits[48:49] must be set to 10 */
	pci_write_config_dword(dev, PCI_BASE_ADDRESS_4, 0x00020000);
	pci_write_config_dword(dev, PCI_BASE_ADDRESS_5, 0x00000000);
	dev_info(&dev->dev, "wrote BAR4/5\n");
}

static int switch_phb_to_capi(struct pci_dev *dev)
{
	struct device_node *np;
	const u64 *prop64;
	u64 phb_id;
	int rc;

	dev_info(&dev->dev, "switch phb to capi\n");

	if (!(np = get_capi_phb_node(dev)))
		return -ENODEV;

	prop64 = of_get_property(np, "ibm,opal-phbid", NULL);

	dev_info(&dev->dev, "device tree name: %s\n", np->name);
	phb_id = be64_to_cpup(prop64);
	dev_info(&dev->dev, "PHB-ID  : 0x%016llx\n", phb_id);

	rc = opal_pci_set_phb_capi_mode(phb_id, 1, 0);
	dev_info(&dev->dev, "opal_pci_set_phb_capi_mode: %i", rc);

	of_node_put(np);
	return rc;
}

/*
 *  pciex node: ibm,opal-m64-window = <0x3d058 0x0 0x3d058 0x0 0x8 0x0>;
 */

static int switch_card_to_capi(struct pci_dev *dev)
{
	int vsec;
	u32 val;
	int rc;

	dev_info(&dev->dev, "switch card to capi\n");

	if (!(vsec = find_capi_vsec(dev))) {
		dev_err(&dev->dev, "capi: WARNING: CAPI VSEC not found, assuming card is already in CAPI mode!\n");
		/* return -ENODEV; */
		return 0;
	}

	dev_info(&dev->dev, "vsec found at offset %#x\n", vsec);

	/* FIXME: Can probably just read/write one byte and not worry about the
	 * number of AFUs and status fields */
	if ((rc = pci_read_config_dword(dev, vsec + 0x8, &val))) {
		dev_err(&dev->dev, "failed to read current mode control: %i", rc);
		return rc;
	}
	/* FIXME: Clear other protocol size bits */
	val |= CAPI_PROTOCOL_256TB | CAPI_PROTOCOL_ENABLE;
	if ((rc = pci_write_config_dword(dev, vsec + 0x8, val))) {
		dev_err(&dev->dev, "failed to enable capi protocol: %i", rc);
		return rc;
	}

	return 0;
}

int enable_capi_protocol(struct pci_dev *dev)
{
	int rc;

	if ((rc = switch_card_to_capi(dev)))
		return rc;

	if ((rc = switch_phb_to_capi(dev)))
		return rc;

	return rc;
}

static int alloc_hwirqs(struct pci_dev *dev, int num)
{
	struct pci_controller *hose = pci_bus_to_host(dev->bus);
	struct pnv_phb *phb = hose->private_data;
	int hwirq = msi_bitmap_alloc_hwirqs(&phb->msi_bmp, num);
	if (hwirq < 0) {
		dev_warn(&dev->dev, "Failed to find a free MSI\n");
		return -ENOSPC;
	}

	return phb->msi_base + hwirq;
}

#if 0
/* XXX: This hasn't been tested yet. */
int capi_alloc_hwirqs(struct pci_dev *dev, int num, struct capi_ivte_ranges *ranges)
{
	struct pci_controller *hose = pci_bus_to_host(dev->bus);
	struct pnv_phb *phb = hose->private_data;
	int range = 0;
	int hwirq;
	int try;

	memset(ranges, 0, sizeof(struct capi_ivte_ranges));

	for (range = 0; range < 4, num; range++) {
		try = num;
		while (try) {
			hwirq = msi_bitmap_alloc_hwirqs(&phb->msi_bmp, num);
			if (hwirq >= 0)
				break;
			try /= 2;
		}
		if (!try)
			goto fail;

		ranges->offsets[range] = phb->msi_base + hwirq;
		ranges->ranges[range] = try;
		num -= try;
	}
	if (num)
		goto fail;

	return 0;
fail:
	for (range--; range >= 0; range--)
		msi_bitmap_free_hwirqs(&phb->msi_bmp, ranges->offsets[range], ranges->ranges[range])
	return -ENOMEM;
}
#endif

int init_capi_pci(struct pci_dev *dev)
{
	u64 p1_base, p1_size;
	u64 p2_base, p2_size;
	int vsec = find_capi_vsec(dev);
	struct capi_pci_t *wrap;
	struct capi_t *adapter;
	u32 afu_desc_off, afu_desc_size;
	u32 ps_off, ps_size;
	u32 nIRQs;
	u16 vseclen;
	u8 nAFUs;
	int slice;
	int rc = -EBUSY;
	int err_hwirq, afu_irq_base;

	if (!(wrap = kmalloc(sizeof(struct capi_pci_t), GFP_KERNEL))) {
		rc = -ENOMEM;
		goto err1;
	}
	memset(wrap, 0, sizeof(struct capi_pci_t));
	wrap->pdev = dev;
	adapter = &wrap->adapter;

	if (pci_request_region(dev, 2, "priv 2 regs"))
		goto err1;
	if (pci_request_region(dev, 0, "priv 1 regs"))
		goto err2;

	p1_base = pci_resource_start(dev, 2);
	p1_size = pci_resource_len(dev, 2);
	p2_base = pci_resource_start(dev, 0);
	p2_size = pci_resource_len(dev, 0);

	/* TODO: Upload PSL */

	if (vsec) {
		dev_info(&dev->dev, "capi vsec found at offset %#x\n", vsec);

		pci_read_config_word(dev, CAPI_VSEC_LENGTH(vsec), &vseclen);
		vseclen = vseclen >> 4;
		pci_read_config_byte(dev, CAPI_VSEC_NAFUS(vsec), &nAFUs);
		if ((nAFUs == 0) && (vseclen == 0x40)) {
			dev_info(&dev->dev, "***** WORKAROUND capi vsec length 0x40 and  nAFU=0.  Making nAFUs = 1.\n");
			nAFUs = 1;
		}
		if (vseclen == 0x40) {
			u8 tmp;
			dev_info(&dev->dev, "***** WORKAROUND capi vsec length 0x40, reading alternate problem state size.\n");
			pci_read_config_byte(dev, CAPI_VSEC_PS_SIZE_V10(vsec), &tmp);
			ps_size = (1*1024*1024) << tmp;
			ps_off = p2_base + ps_size;
			afu_desc_off = ps_off;
			afu_desc_size = 0x16;
		} else {
			pci_read_config_dword(dev, CAPI_VSEC_AFU_DESC_OFF(vsec), &afu_desc_off);
			pci_read_config_dword(dev, CAPI_VSEC_AFU_DESC_SIZE(vsec), &afu_desc_size);
			pci_read_config_dword(dev, CAPI_VSEC_PS_OFF(vsec), &ps_off);
			pci_read_config_dword(dev, CAPI_VSEC_PS_SIZE(vsec), &ps_size);

		}

		if (ps_size > p2_size - ps_off) {
			dev_warn(&dev->dev, "WARNING: Problem state size larger than available in BAR2: 0x%x > 0x%llx\n",
					ps_size, p2_size - ps_off);
			ps_size = p2_size - ps_off;
		}

	} else { /* XXX Bringup only */
		dev_warn(&dev->dev, "capi vsec not found! Using bringup values!\n");

		nAFUs = 1;
		nIRQs = 3;
		ps_off  = 0x2000000 / 64 / 1024;
		ps_size = 0x2000000 / 64 / 1024;
	}
	/* FIXME workaround for build11_20140512_p015_r181_mcp000d.rbf only */
	ps_off  = 0x2000000 / 64 / 1024;
	ps_size = 0x2000000 / 64 / 1024;

	err_hwirq = alloc_hwirqs(dev, 1);

	if ((rc = capi_init_adapter(adapter, &capi_pci_driver_ops, nAFUs, 0, p1_base, p1_size, p2_base, p2_size, err_hwirq))) {
		dev_err(&dev->dev, "capi_alloc_adapter failed: %i\n", rc);
		goto err3;
	}

	for (slice = 0; slice < nAFUs; slice++) {
		struct capi_afu_t *afu = &(adapter->slice[slice]);
		u64 afu_desc, p1n_base, p2n_base, psn_base;

		const u64 p1n_size = 0x100;
		const u64 p2n_size = 0x1000;

		p1n_base = p1_base + 0x10000 + (slice * p1n_size);
		p2n_base = p2_base + (slice * p2n_size);
		psn_base = p2_base + (ps_off + (slice * ps_size)) * 64 * 1024;

		if (vsec) {
			afu_desc = (afu_desc_off + (slice * afu_desc_size)) * 64 * 1024;

			/* XXX TODO: Read num_ints_per_process from AFU descriptor */
		}

		afu_irq_base = alloc_hwirqs(dev, nIRQs + 1);

		if ((rc = capi_init_afu(adapter, afu, slice, 0,
			      p1n_base, p1n_size,
			      p2n_base, p2n_size,
			      psn_base, ps_size * 64 * 1024,
			      afu_irq_base, nIRQs + 1))) {
			dev_err(&dev->dev, "capi_init_afu failed: %i\n", rc);
			goto err4;
		}
	}

	return 0;
err4:
	/* FIXME: Cleanup AFUs */
err3:
	pci_release_region(dev, 0);
err2:
	pci_release_region(dev, 2);
err1:
	kfree(wrap);
	return rc;
}

static int capi_probe(struct pci_dev *dev, const struct pci_device_id *id)
{
	int rc;

	dev_info(&dev->dev, "pci probe\n");

	dump_capi_config_space(dev);

	reassign_capi_bars(dev);

	if ((rc = enable_capi_protocol(dev))) {
		dev_err(&dev->dev, "enable_capi_protocol failed: %i\n", rc);
		return rc;
	}
	dev_info(&dev->dev, "capi protocol enabled\n");

	dump_capi_config_space(dev);

	/* FIXME: I should wait for PHB to come back in CAPI mode and re-probe */
	if ((rc = pci_enable_device(dev))) {
		dev_err(&dev->dev, "pci_enable_device failed: %i\n", rc);
		return rc;
	}

	if ((rc = init_capi_pci(dev))) {
		dev_err(&dev->dev, "init_capi_pci failed: %i\n", rc);
		return rc;
	}

	return 0;
}

static void capi_early_fixup(struct pci_dev *dev)
{
#if 0
	/* Just trying to understand how setting up BARs work in Linux */
	dump_capi_config_space(dev);

	pci_write_config_dword(dev, PCI_BASE_ADDRESS_4, 0x00020000);
	pci_write_config_dword(dev, PCI_BASE_ADDRESS_5, 0x00000000);

	dump_capi_config_space(dev);
#endif
}
DECLARE_PCI_FIXUP_EARLY(PCI_VENDOR_ID_IBM, 0x0477, capi_early_fixup);

static void capi_remove(struct pci_dev *dev)
{
	dev_warn(&dev->dev, "pci remove\n");

	/* FIXME: Free allocated adapters */

	/* TODO: Implement everything from Documentation/PCI/pci.txt */

}

static struct pci_driver capi_pci_driver = {
	.name = "capi-pci",
	.id_table = capi_pci_tbl,
	.probe = capi_probe,
	.remove = capi_remove,
#if 0
#ifdef CONFIG_PM
	.suspend = ...,
	.resume = ...,
#endif
#endif
};

module_driver(capi_pci_driver, pci_register_driver, pci_unregister_driver);

MODULE_DESCRIPTION("IBM Coherent Accelerator");
MODULE_AUTHOR("Ian Munsie <imunsie@au1.ibm.com>");
MODULE_LICENSE("GPL");
