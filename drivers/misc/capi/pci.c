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

#define CAPI_PROTOCOL_MASK	(7ull << 21)
#define CAPI_PROTOCOL_256TB	(1ull << 23) /* Power 8 uses this */
#define CAPI_PROTOCOL_512TB	(1ull << 22)
#define CAPI_PROTOCOL_1024TB	(1ull << 21)
#define CAPI_PROTOCOL_ENABLE	(1ull << 16)

#define CAPI_VSEC_LENGTH(vsec)		(vsec + 0x6) /* WORD */
#define CAPI_VSEC_NAFUS(vsec)		(vsec + 0x8) /* BYTE */
#define CAPI_VSEC_AFU_DESC_OFF(vsec)	(vsec + 0x20)
#define CAPI_VSEC_AFU_DESC_SIZE(vsec)	(vsec + 0x24)
#define CAPI_VSEC_PS_OFF(vsec)		(vsec + 0x28)
#define CAPI_VSEC_PS_SIZE(vsec)		(vsec + 0x2c)

DEFINE_PCI_DEVICE_TABLE(capi_pci_tbl) = {
	{ PCI_DEVICE(PCI_VENDOR_ID_IBM, 0x0477), },
	{ PCI_DEVICE(PCI_VENDOR_ID_IBM, 0x044b), },
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
	dev_info(&dev->dev, "capi vsec: %30s: %#x\n", "Reserved",	(val >> 24) & 0xff);
	pci_read_config_dword(dev, vsec + 0xc, &val);
	dev_info(&dev->dev, "capi vsec: %30s: %#x\n", "PSL Rev",	(val >>  0) & 0xffff);
	dev_info(&dev->dev, "capi vsec: %30s: %#x\n", "CAIA Ver",	(val >> 16) & 0xffff);
	pci_read_config_dword(dev, vsec + 0x10, &val);
	dev_info(&dev->dev, "capi vsec: %30s: %#x\n", "Base Image Rev",	(val >>  0) & 0xffff);
	dev_info(&dev->dev, "capi vsec: %30s: %#x\n", "Reserved",	(val >> 16) & 0x0fff);
	dev_info(&dev->dev, "capi vsec: %30s: %#x\n", "Image Control",	(val >> 28) & 0x3);
	dev_info(&dev->dev, "capi vsec: %30s: %#x\n", "Reserved",	(val >> 30) & 0x1);
	dev_info(&dev->dev, "capi vsec: %30s: %#x\n", "Image Loaded",	(val >> 31) & 0x1);
	pci_read_config_dword(dev, vsec + 0x14, &val);
	dev_info(&dev->dev, "capi vsec: %30s: %#x\n", "Reserved",	val);

	pci_read_config_dword(dev, vsec + 0x18, &val);
	dev_info(&dev->dev, "capi vsec: %30s: %#x\n", "Reserved", val);
	pci_read_config_dword(dev, vsec + 0x1c, &val);
	dev_info(&dev->dev, "capi vsec: %30s: %#x\n", "Reserved", val);

	pci_read_config_dword(dev, vsec + 0x20, &val);
	dev_info(&dev->dev, "capi vsec: %30s: %#x\n", "AFU Descriptor Offset", val);
	pci_read_config_dword(dev, vsec + 0x24, &val);
	dev_info(&dev->dev, "capi vsec: %30s: %#x\n", "AFU Descriptor Size", val);
	pci_read_config_dword(dev, vsec + 0x28, &val);
	dev_info(&dev->dev, "capi vsec: %30s: %#x\n", "Problem State Offset", val);
	pci_read_config_dword(dev, vsec + 0x2c, &val);
	dev_info(&dev->dev, "capi vsec: %30s: %#x\n", "Problem State Size", val);

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
	dev_info(&dev->dev, "capi vsec: %30s: %#x\n", "Reserved", val);
	pci_read_config_dword(dev, vsec + 0x4c, &val);
	dev_info(&dev->dev, "capi vsec: %30s: %#x\n", "Reserved", val);
	pci_read_config_dword(dev, vsec + 0x50, &val);
	dev_info(&dev->dev, "capi vsec: %30s: %#x\n", "Flash Address Register", val);
	pci_read_config_dword(dev, vsec + 0x54, &val);
	dev_info(&dev->dev, "capi vsec: %30s: %#x\n", "Flash Size Register", val);

	pci_read_config_dword(dev, vsec + 0x58, &val);
	dev_info(&dev->dev, "capi vsec: %30s: %#x\n", "Flash Status/Control Register", val);
	pci_read_config_dword(dev, vsec + 0x58, &val);
	dev_info(&dev->dev, "capi vsec: %30s: %#x\n", "Flash Data Port", val);

	/* TODO: Dump AFU Descriptor & AFU Configuration Record if present */
}

static void __maybe_unused dump_afu_descriptor(struct pci_dev *dev, void __iomem *afu_desc)
{
	u64 val;

	val = _capi_reg_read(afu_desc + 0x0);
	dev_info(&dev->dev, "afu desc: %30s: %#llx\n", "num_ints_per_process", ((val & 0xffff000000000000ULL) >> (63-15)));
	dev_info(&dev->dev, "afu desc: %30s: %#llx\n", "num_of_processes",     ((val & 0x0000ffff00000000ULL) >> (63-31)));
	dev_info(&dev->dev, "afu desc: %30s: %#llx\n", "num_of_afu_CRs",       ((val & 0x00000000ffff0000ULL) >> (63-48)));
	dev_info(&dev->dev, "afu desc: %30s: %#llx\n", "req_prog_model",       ((val & 0x000000000000ffffULL)));

	val = _capi_reg_read(afu_desc + 0x8);
	dev_info(&dev->dev, "afu desc: %30s: %#llx\n", "Reserved", val);
	val = _capi_reg_read(afu_desc + 0x10);
	dev_info(&dev->dev, "afu desc: %30s: %#llx\n", "Reserved", val);
	val = _capi_reg_read(afu_desc + 0x18);
	dev_info(&dev->dev, "afu desc: %30s: %#llx\n", "Reserved", val);

	val = _capi_reg_read(afu_desc + 0x20);
	dev_info(&dev->dev, "afu desc: %30s: %#llx\n", "AFU_CR_format (v0.11)", ((val & 0xff00000000000000ULL) >> (63-7))); /* Reserved >= 0.12 */
	dev_info(&dev->dev, "afu desc: %30s: %#llx\n", "AFU_CR_len",            (val & 0x00ffffffffffffffULL));

	val = _capi_reg_read(afu_desc + 0x28);
	dev_info(&dev->dev, "afu desc: %30s: %#llx\n", "AFU_CR_offset", val);

	val = _capi_reg_read(afu_desc + 0x30);
	dev_info(&dev->dev, "afu desc: %30s: %#llx\n", "PerProcessPSA_control", ((val & 0xff00000000000000ULL) >> (63-7)));
	dev_info(&dev->dev, "afu desc: %30s: %#llx\n", "PerProcessPSA_length",  (val & 0x00ffffffffffffffULL));

	val = _capi_reg_read(afu_desc + 0x38);
	dev_info(&dev->dev, "afu desc: %30s: %#llx\n", "PerProcessPSA_offset", val);

	val = _capi_reg_read(afu_desc + 0x40);
	dev_info(&dev->dev, "afu desc: %30s: %#llx\n", "Reserved",   (val & (0xff00000000000000ULL) >> (63-7)));
	dev_info(&dev->dev, "afu desc: %30s: %#llx\n", "AFU_EB_len", (val & 0x00ffffffffffffffULL));

	val = _capi_reg_read(afu_desc + 0x48);
	dev_info(&dev->dev, "afu desc: %30s: %#llx\n", "AFU_EB_offset", val);

	/* TODO: Dump AFU Configuration record if it exists */
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

extern struct device_node * pnv_pci_to_phb_node(struct pci_dev *dev);

static int init_implementation_adapter_regs(struct capi_t *adapter)
{
	struct pci_dev *dev = container_of(adapter, struct capi_pci_t, adapter)->pdev;
	struct device_node *np;
	const __be32 *prop;
	u64 psl_dsnctl;
	u64 chipid;

	dev_info(&dev->dev, "capi: **** Setup PSL Implementation Specific Registers ****\n");

	if (!(np = pnv_pci_to_phb_node(dev)))
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
	psl_dsnctl = 0x02E890000E000000ULL | (chipid << (63-5));

	capi_p1_write(adapter, CAPI_PSL_DSNDCTL, psl_dsnctl); /* Tell PSL where to route data to */
	capi_p1_write(adapter, CAPI_PSL_RESLCKTO, 0x20000000200);
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

	return 0;
}

static int init_implementation_afu_regs(struct capi_afu_t *afu)
{
	capi_p1n_write(afu, CAPI_PSL_APCALLOC_A, 0xFFFFFFFEFEFEFEFEULL); /* read/write masks for this slice */
	capi_p1n_write(afu, CAPI_PSL_COALLOC_A, 0xFF000000FEFEFEFEULL); /* APC read/write masks for this slice */

	/* changes recommended per JT and Yoanna 11/15/2013 */
	capi_p1n_write(afu, CAPI_PSL_SLICE_TRACE, 0x0000FFFF00000000ULL); /* for debugging with trace arrays */

	capi_p1n_write(afu, CAPI_PSL_RXCTL_A, 0xF000000000000000ULL);

	return 0;
}

/* Defined in powernv pci-ioda.c */
extern int pnv_capi_ioda_msi_setup(struct pnv_phb *phb, struct pci_dev *dev,
		unsigned int hwirq, unsigned int virq);

static int setup_capi_msi(struct capi_t *adapter, unsigned int hwirq, unsigned int virq)
{
	struct capi_pci_t *wrap = container_of(adapter, struct capi_pci_t, adapter);
	struct pci_dev *dev = wrap->pdev;
	struct pci_controller *hose = pci_bus_to_host(dev->bus);
	struct pnv_phb *phb = hose->private_data;

	return pnv_capi_ioda_msi_setup(phb, dev, hwirq, virq);
}

static int _alloc_hwirqs(struct pci_dev *dev, int num)
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

static int alloc_hwirq_ranges(struct capi_irq_ranges *irqs, struct pci_dev *dev, int num)
{
	struct pci_controller *hose = pci_bus_to_host(dev->bus);
	struct pnv_phb *phb = hose->private_data;
	int range = 0;
	int hwirq;
	int try;

	memset(irqs, 0, sizeof(struct capi_irq_ranges));

	for (range = 0; range < 4 && num; range++) {
		try = num;
		while (try) {
			hwirq = msi_bitmap_alloc_hwirqs(&phb->msi_bmp, num);
			if (hwirq >= 0)
				break;
			try /= 2;
		}
		if (!try)
			goto fail;

		irqs->offset[range] = phb->msi_base + hwirq;
		irqs->range[range] = try;
		dev_info(&dev->dev, "capi alloc irq range 0x%x: offset: 0x%x  limit: %i\n",
			 range, irqs->offset[range], irqs->range[range]);
		num -= try;
	}
	if (num)
		goto fail;

	return 0;
fail:
	for (range--; range >= 0; range--) {
		hwirq = irqs->offset[range] - phb->msi_base;
		msi_bitmap_free_hwirqs(&phb->msi_bmp, hwirq,
				       irqs->range[range]);
	}
	return -ENOSPC;
}

static int alloc_hwirqs(struct capi_irq_ranges *irqs, struct capi_t *adapter, unsigned int num)
{
	struct pci_dev *dev = container_of(adapter, struct capi_pci_t, adapter)->pdev;
	return alloc_hwirq_ranges(irqs, dev, num);
}

static void release_hwirqs(struct capi_irq_ranges *irqs, struct capi_t *adapter)
{
	struct pci_dev *dev = container_of(adapter, struct capi_pci_t, adapter)->pdev;
	struct pci_controller *hose = pci_bus_to_host(dev->bus);
	struct pnv_phb *phb = hose->private_data;
	int range = 0;
	int hwirq;

	for (range = 0; range < 4; range++) {
		hwirq = irqs->offset[range] - phb->msi_base;
		if (irqs->range[range]) {
			dev_info(&dev->dev, "capi release irq range 0x%x: offset: %i  limit: %i\n",
				 range, irqs->offset[range],
				 irqs->range[range]);
			msi_bitmap_free_hwirqs(&phb->msi_bmp, hwirq,
					       irqs->range[range]);
		}
	}
}

static struct capi_driver_ops capi_pci_driver_ops = {
	.init_adapter = init_implementation_adapter_regs,
	.init_afu = init_implementation_afu_regs,
	.alloc_irqs = alloc_hwirqs,
	.release_irqs = release_hwirqs,
	.setup_irq = setup_capi_msi,
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

	if (!(np = pnv_pci_to_phb_node(dev))) {
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
	pci_write_config_dword(dev, PCI_BASE_ADDRESS_4, 0x00000000);
	pci_write_config_dword(dev, PCI_BASE_ADDRESS_5, 0x00020000);
	dev_info(&dev->dev, "wrote BAR4/5\n");
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
	val &= ~CAPI_PROTOCOL_MASK;
	val |= CAPI_PROTOCOL_256TB | CAPI_PROTOCOL_ENABLE;
	if ((rc = pci_write_config_dword(dev, vsec + 0x8, val))) {
		dev_err(&dev->dev, "failed to enable capi protocol: %i", rc);
		return rc;
	}

	return 0;
}

extern int pnv_phb_to_capi(struct pci_dev *dev);

int enable_capi_protocol(struct pci_dev *dev)
{
	int rc;

	if ((rc = switch_card_to_capi(dev)))
		return rc;

	if ((rc = pnv_phb_to_capi(dev)))
		return rc;

	return rc;
}

extern int afu_reset(struct capi_afu_t *afu); // FIXME remove

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
	int err_hwirq;

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
		pci_read_config_dword(dev, CAPI_VSEC_AFU_DESC_OFF(vsec), &afu_desc_off);
		pci_read_config_dword(dev, CAPI_VSEC_AFU_DESC_SIZE(vsec), &afu_desc_size);
		pci_read_config_dword(dev, CAPI_VSEC_PS_OFF(vsec), &ps_off);
		pci_read_config_dword(dev, CAPI_VSEC_PS_SIZE(vsec), &ps_size);

		ps_off  *= 64 * 1024;
		ps_size *= 64 * 1024;
		afu_desc_off *= 64 * 1024;
		afu_desc_size *= 64 * 1024;

		if (ps_size > p2_size - ps_off) {
			dev_warn(&dev->dev, "WARNING: Problem state size larger than available in BAR2: 0x%x > 0x%llx\n",
					ps_size, p2_size - ps_off);
			ps_size = p2_size - ps_off;
		}

	} else { /* XXX Bringup only */
		dev_warn(&dev->dev, "capi vsec not found! Using bringup values!\n");

		nAFUs = 1;
		nIRQs = 3;
		ps_off  = 0x2000000;
		ps_size = 0x2000000;
	}

	err_hwirq = _alloc_hwirqs(dev, 1);

	if ((rc = capi_init_adapter(adapter, &capi_pci_driver_ops, nAFUs, 0, p1_base, p1_size, p2_base, p2_size, err_hwirq))) {
		dev_err(&dev->dev, "capi_alloc_adapter failed: %i\n", rc);
		goto err3;
	}

	for (slice = 0; slice < nAFUs; slice++) {
		struct capi_afu_t *afu = &(adapter->slice[slice]);
		u64 p1n_base, p2n_base, psn_base, afu_desc = 0;

		const u64 p1n_size = 0x100;
		const u64 p2n_size = 0x1000;

		p1n_base = p1_base + 0x10000 + (slice * p1n_size);
		p2n_base = p2_base + (slice * p2n_size);
		psn_base = p2_base + (ps_off + (slice * ps_size));
		if (vsec) {
			afu_desc = p2_base + afu_desc_off + (slice * afu_desc_size);
		}


		if ((rc = capi_map_slice_regs(afu,
				p1n_base, p1n_size,
				p2n_base, p2n_size,
				psn_base, ps_size,
				afu_desc, afu_desc_size))) {
			return rc;
		}


#if 1 /* PSL bug doesn't allow us to read the AFU descriptor until the AFU is enabled, supposed to be fixed in PSL 185 */
		if (afu->afu_desc_mmio) {
			u64 val;

			pr_devel("afu_desc_mmio: %p\n", afu->afu_desc_mmio);

			/* FIXME: mask the MMIO timeout for
			   now.  need to * fix this long term */
//			capi_p1n_write(afu, CAPI_PSL_SERR_An, 0x0000000000000000);
			capi_p1n_write(afu, CAPI_PSL_SERR_An, 0x0000000000000000);
			afu_reset(afu);
			dump_afu_descriptor(dev, afu->afu_desc_mmio);
			val = _capi_reg_read(afu->afu_desc_mmio + 0x0);
			afu->pp_irqs = (val & 0xffff000000000000ULL) >> (63-15);
			afu->num_procs = (val & 0x0000ffff00000000ULL) >> (63-31);
			if (val & (1ull << (63-61))) {
				afu->afu_directed_mode = true;
			} else if (val & (1ull << (63-59))) {
				afu->afu_directed_mode = false;
			} else {
				afu->afu_directed_mode = false;
				pr_err("No programing mode found in AFU desc\n");
				WARN_ON(1);
			}

			// FIXME : check req_prog_model and bugon

			val = _capi_reg_read(afu->afu_desc_mmio + 0x30);
			afu->pp_size = (val & 0x00ffffffffffffffULL) * 4096;
			if (val & (1ull << (63 - 6)))
				afu->pp_mmio = true;
			else {
				pr_devel("AFU doesn't support per process mmio space\n");
				afu->pp_mmio = false;
			}
			if (val & (1ull << (63 - 7)))
				afu->mmio = true;
			else {
				pr_devel("AFU doesn't support mmio space\n");
				afu->mmio = false;
			}

			val = _capi_reg_read(afu->afu_desc_mmio + 0x38);
			afu->pp_offset = val;
			/* FIXME check PerProcessPSA_control to see if above
			 * needed */
			WARN_ON(afu->psn_size < (afu->pp_offset +
						afu->pp_size*afu->num_procs));
			WARN_ON(afu->pp_mmio && (afu->pp_size < PAGE_SIZE));

			/* XXX TODO: Read num_ints_per_process from AFU descriptor */
		} else
			BUG(); /* no afu descriptor */
#endif

		err_hwirq = _alloc_hwirqs(dev, 1);

		if ((rc = capi_init_afu(adapter, afu, slice, 0, err_hwirq))) {
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

//	dump_capi_config_space(dev);

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
