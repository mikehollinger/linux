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
#include <linux/delay.h>
#include <asm/opal.h>

#include <asm/msi_bitmap.h>
#include <asm/pci-bridge.h> /* for struct pci_controller */
#include "../arch/powerpc/platforms/powernv/pci.h" /* FIXME - for struct pnv_phb */

#include "cxl.h"

#define CXL_PCI_VSEC_ID	0x1280

#define CXL_PROTOCOL_MASK	(7ull << 21)
#define CXL_PROTOCOL_256TB	(1ull << 23) /* Power 8 uses this */
#define CXL_PROTOCOL_512TB	(1ull << 22)
#define CXL_PROTOCOL_1024TB	(1ull << 21)
#define CXL_PROTOCOL_ENABLE	(1ull << 16)
#define CXL_PERST_RELOAD	(1ull << 29)
#define CXL_USER_IMAGE		(1ull << 28)

#define CXL_VSEC_LENGTH(vsec)		(vsec + 0x6) /* WORD */
#define CXL_VSEC_NAFUS(vsec)		(vsec + 0x8) /* BYTE */
#define CXL_VSEC_AFU_DESC_OFF(vsec)	(vsec + 0x20)
#define CXL_VSEC_AFU_DESC_SIZE(vsec)	(vsec + 0x24)
#define CXL_VSEC_PS_OFF(vsec)		(vsec + 0x28)
#define CXL_VSEC_PS_SIZE(vsec)		(vsec + 0x2c)

/* This works a little different than the p1/p2 register accesses to make it
 * easier to pull out individual fields */
#define AFUD_READ(afu, off)		_cxl_reg_read(afu->afu_desc_mmio + off)
#define EXTRACT_PPC_BIT(val, bit)	(!!(val & PPC_BIT(bit)))
#define EXTRACT_PPC_BITS(val, bs, be)	((val & PPC_BITMASK(bs, be)) >> PPC_BITLSHIFT(be))

#define AFUD_READ_INFO(afu)		AFUD_READ(afu, 0x0)
#define   AFUD_NUM_INTS_PER_PROC(val)	EXTRACT_PPC_BITS(val,  0, 15)
#define   AFUD_NUM_PROCS(val)		EXTRACT_PPC_BITS(val, 16, 31)
#define   AFUD_NUM_CRS(val)		EXTRACT_PPC_BITS(val, 32, 47)
#define   AFUD_MULTIMODE(val)		EXTRACT_PPC_BIT(val, 48)
#define   AFUD_PUSH_BLOCK_TRANSFER(val)	EXTRACT_PPC_BIT(val, 55)
#define   AFUD_DEDICATED_PROCESS(val)	EXTRACT_PPC_BIT(val, 59)
#define   AFUD_AFU_DIRECTED(val)	EXTRACT_PPC_BIT(val, 61)
#define   AFUD_TIME_SLICED(val)		EXTRACT_PPC_BIT(val, 63)
#define AFUD_READ_CR(afu)		AFUD_READ(afu, 0x20)
#define   AFUD_CR_LEN(val)		EXTRACT_PPC_BITS(val, 8, 63)
#define AFUD_READ_CR_OFF(afu)		AFUD_READ(afu, 0x28)
#define AFUD_READ_PPPSA(afu)		AFUD_READ(afu, 0x30)
#define   AFUD_PPPSA_PP(val)		EXTRACT_PPC_BIT(val, 6)
#define   AFUD_PPPSA_PSA(val)		EXTRACT_PPC_BIT(val, 7)
#define   AFUD_PPPSA_LEN(val)		EXTRACT_PPC_BITS(val, 8, 63)
#define AFUD_READ_PPPSA_OFF(afu)	AFUD_READ(afu, 0x38)
#define AFUD_READ_EB(afu)		AFUD_READ(afu, 0x40)
#define   AFUD_EB_LEN(val)		EXTRACT_PPC_BITS(val, 8, 63)
#define AFUD_READ_EB_OFF(afu)		AFUD_READ(afu, 0x48)

DEFINE_PCI_DEVICE_TABLE(cxl_pci_tbl) = {
	{ PCI_DEVICE(PCI_VENDOR_ID_IBM, 0x0477), },
	{ PCI_DEVICE(PCI_VENDOR_ID_IBM, 0x044b), },
	{ PCI_DEVICE(PCI_VENDOR_ID_IBM, 0x04cf), },
	{ PCI_DEVICE_CLASS(0x120000, ~0), },

	{ }
};
MODULE_DEVICE_TABLE(pci, cxl_pci_tbl);

static int find_cxl_vsec(struct pci_dev *dev)
{
	int vsec = 0;
	u16 val;

	while ((vsec = pci_find_next_ext_capability(dev, vsec, PCI_EXT_CAP_ID_VNDR))) {
		pci_read_config_word(dev, vsec + 0x4, &val);
		if (val == CXL_PCI_VSEC_ID)
			return vsec;
	}
	return 0;

}

static void dump_cxl_config_space(struct pci_dev *dev)
{
	int vsec;
	u32 val;

	dev_info(&dev->dev, "dump_cxl_config_space\n");

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

	if (!(vsec = find_cxl_vsec(dev)))
		return;

	pci_read_config_dword(dev, vsec + 0x0, &val);
	dev_info(&dev->dev, "cxl vsec: %30s: %#x\n", "Cap ID",		(val >>  0) & 0xffff);
	dev_info(&dev->dev, "cxl vsec: %30s: %#x\n", "Cap Ver",	(val >> 16) & 0xf);
	dev_info(&dev->dev, "cxl vsec: %30s: %#x\n", "Next Cap Ptr",	(val >> 20) & 0xfff);
	pci_read_config_dword(dev, vsec + 0x4, &val);
	dev_info(&dev->dev, "cxl vsec: %30s: %#x\n", "VSEC ID",	(val >>  0) & 0xffff);
	dev_info(&dev->dev, "cxl vsec: %30s: %#x\n", "VSEC Rev",	(val >> 16) & 0xf);
	dev_info(&dev->dev, "cxl vsec: %30s: %#x\n", "VSEC Length",	(val >> 20) & 0xfff);
	pci_read_config_dword(dev, vsec + 0x8, &val);
	dev_info(&dev->dev, "cxl vsec: %30s: %#x\n", "Num AFUs",	(val >>  0) & 0xff);
	dev_info(&dev->dev, "cxl vsec: %30s: %#x\n", "Status",		(val >>  8) & 0xff);
	dev_info(&dev->dev, "cxl vsec: %30s: %#x\n", "Mode Control",	(val >> 16) & 0xff);
	dev_info(&dev->dev, "cxl vsec: %30s: %#x\n", "Reserved",	(val >> 24) & 0xff);
	pci_read_config_dword(dev, vsec + 0xc, &val);
	dev_info(&dev->dev, "cxl vsec: %30s: %#x\n", "PSL Rev",	(val >>  0) & 0xffff);
	dev_info(&dev->dev, "cxl vsec: %30s: %#x\n", "CAIA Ver",	(val >> 16) & 0xffff);
	pci_read_config_dword(dev, vsec + 0x10, &val);
	dev_info(&dev->dev, "cxl vsec: %30s: %#x\n", "Base Image Rev",	(val >>  0) & 0xffff);
	dev_info(&dev->dev, "cxl vsec: %30s: %#x\n", "Reserved",	(val >> 16) & 0x0fff);
	dev_info(&dev->dev, "cxl vsec: %30s: %#x\n", "Image Control",	(val >> 28) & 0x3);
	dev_info(&dev->dev, "cxl vsec: %30s: %#x\n", "Reserved",	(val >> 30) & 0x1);
	dev_info(&dev->dev, "cxl vsec: %30s: %#x\n", "Image Loaded",	(val >> 31) & 0x1);
	pci_read_config_dword(dev, vsec + 0x14, &val);
	dev_info(&dev->dev, "cxl vsec: %30s: %#x\n", "Reserved",	val);

	pci_read_config_dword(dev, vsec + 0x18, &val);
	dev_info(&dev->dev, "cxl vsec: %30s: %#x\n", "Reserved", val);
	pci_read_config_dword(dev, vsec + 0x1c, &val);
	dev_info(&dev->dev, "cxl vsec: %30s: %#x\n", "Reserved", val);

	pci_read_config_dword(dev, vsec + 0x20, &val);
	dev_info(&dev->dev, "cxl vsec: %30s: %#x\n", "AFU Descriptor Offset", val);
	pci_read_config_dword(dev, vsec + 0x24, &val);
	dev_info(&dev->dev, "cxl vsec: %30s: %#x\n", "AFU Descriptor Size", val);
	pci_read_config_dword(dev, vsec + 0x28, &val);
	dev_info(&dev->dev, "cxl vsec: %30s: %#x\n", "Problem State Offset", val);
	pci_read_config_dword(dev, vsec + 0x2c, &val);
	dev_info(&dev->dev, "cxl vsec: %30s: %#x\n", "Problem State Size", val);

	pci_read_config_dword(dev, vsec + 0x30, &val);
	dev_info(&dev->dev, "cxl vsec: %30s: %#x\n", "Reserved", val);
	pci_read_config_dword(dev, vsec + 0x34, &val);
	dev_info(&dev->dev, "cxl vsec: %30s: %#x\n", "Reserved", val);
	pci_read_config_dword(dev, vsec + 0x38, &val);
	dev_info(&dev->dev, "cxl vsec: %30s: %#x\n", "Reserved", val);
	pci_read_config_dword(dev, vsec + 0x3c, &val);
	dev_info(&dev->dev, "cxl vsec: %30s: %#x\n", "Reserved", val);

	pci_read_config_dword(dev, vsec + 0x40, &val);
	dev_info(&dev->dev, "cxl vsec: %30s: %#x\n", "PSL Programming Port", val);
	pci_read_config_dword(dev, vsec + 0x44, &val);
	dev_info(&dev->dev, "cxl vsec: %30s: %#x\n", "PSL Programming Control", val);
	pci_read_config_dword(dev, vsec + 0x48, &val);
	dev_info(&dev->dev, "cxl vsec: %30s: %#x\n", "Reserved", val);
	pci_read_config_dword(dev, vsec + 0x4c, &val);
	dev_info(&dev->dev, "cxl vsec: %30s: %#x\n", "Reserved", val);
	pci_read_config_dword(dev, vsec + 0x50, &val);
	dev_info(&dev->dev, "cxl vsec: %30s: %#x\n", "Flash Address Register", val);
	pci_read_config_dword(dev, vsec + 0x54, &val);
	dev_info(&dev->dev, "cxl vsec: %30s: %#x\n", "Flash Size Register", val);

	pci_read_config_dword(dev, vsec + 0x58, &val);
	dev_info(&dev->dev, "cxl vsec: %30s: %#x\n", "Flash Status/Control Register", val);
	pci_read_config_dword(dev, vsec + 0x58, &val);
	dev_info(&dev->dev, "cxl vsec: %30s: %#x\n", "Flash Data Port", val);
}

static void __maybe_unused dump_afu_descriptor(struct pci_dev *dev, struct cxl_afu_t *afu)
{
	u64 val;

	val = AFUD_READ_INFO(afu);
	dev_info(&dev->dev, "afu desc: %30s: %#llx\n", "num_ints_per_process", AFUD_NUM_INTS_PER_PROC(val));
	dev_info(&dev->dev, "afu desc: %30s: %#llx\n", "num_of_processes",     AFUD_NUM_PROCS(val));
	dev_info(&dev->dev, "afu desc: %30s: %#llx\n", "num_of_afu_CRs",       AFUD_NUM_CRS(val));
	dev_info(&dev->dev, "afu desc: %30s: %#llx\n", "req_prog_model",       ((val & 0x000000000000ffffULL)));

	val = AFUD_READ(afu, 0x8);
	dev_info(&dev->dev, "afu desc: %30s: %#llx\n", "Reserved", val);
	val = AFUD_READ(afu, 0x10);
	dev_info(&dev->dev, "afu desc: %30s: %#llx\n", "Reserved", val);
	val = AFUD_READ(afu, 0x18);
	dev_info(&dev->dev, "afu desc: %30s: %#llx\n", "Reserved", val);

	val = AFUD_READ_CR(afu);
	dev_info(&dev->dev, "afu desc: %30s: %#llx\n", "AFU_CR_format (v0.11)", ((val & 0xff00000000000000ULL) >> (63-7))); /* Reserved >= 0.12 */
	dev_info(&dev->dev, "afu desc: %30s: %#llx\n", "AFU_CR_len",            AFUD_CR_LEN(val));

	val = AFUD_READ_CR_OFF(afu);
	dev_info(&dev->dev, "afu desc: %30s: %#llx\n", "AFU_CR_offset", val);

	val = AFUD_READ_PPPSA(afu);
	dev_info(&dev->dev, "afu desc: %30s: %#llx\n", "PerProcessPSA_control", ((val & 0xff00000000000000ULL) >> (63-7)));
	dev_info(&dev->dev, "afu desc: %30s: %#llx\n", "PerProcessPSA_control", AFUD_PPPSA_LEN(val));

	val = AFUD_READ_PPPSA_OFF(afu);
	dev_info(&dev->dev, "afu desc: %30s: %#llx\n", "PerProcessPSA_offset", val);

	val = AFUD_READ_EB(afu);
	dev_info(&dev->dev, "afu desc: %30s: %#llx\n", "Reserved",   (val & (0xff00000000000000ULL) >> (63-7)));
	dev_info(&dev->dev, "afu desc: %30s: %#llx\n", "AFU_EB_len", AFUD_EB_LEN(val));

	val = AFUD_READ_EB_OFF(afu);
	dev_info(&dev->dev, "afu desc: %30s: %#llx\n", "AFU_EB_offset", val);
}

static int cmpbar(const void *p1, const void *p2)
{
	struct resource *r1 = *(struct resource **)p1;
	struct resource *r2 = *(struct resource **)p2;
	resource_size_t l1 = r1->end - r1->start;
	resource_size_t l2 = r2->end - r2->start;

	pr_warn("cxl %#.16llx <> %#.16llx : %#llx\n", l1, l2, l1 - l2);

	return l1 - l2;
}

extern struct device_node * pnv_pci_to_phb_node(struct pci_dev *dev);

static int init_implementation_adapter_regs(struct cxl_t *adapter)
{
	struct pci_dev *dev = to_pci_dev(adapter->device.parent);
	struct device_node *np;
	const __be32 *prop;
	u64 psl_dsnctl;
	u64 chipid;

	dev_info(&dev->dev, "cxl: **** Setup PSL Implementation Specific Registers ****\n");

	if (!(np = pnv_pci_to_phb_node(dev)))
		return -ENODEV;

	while (np && !(prop = of_get_property(np, "ibm,chip-id", NULL)))
		np = of_get_next_parent(np);
	if (!np)
		return -ENODEV;
	chipid = be32_to_cpup(prop);
	of_node_put(np);

	dev_info(&dev->dev, "cxl: Found ibm,chip-id: %#llx\n", chipid);

	/* cappid 0:2 nodeid 3:5 chipid */
	/* psl_dsnctl = 0x02e8100000000000ULL | (node << (63-2)) | (pos << (63-5)); */
	psl_dsnctl = 0x02E8900002000000ULL | (chipid << (63-5));

	cxl_p1_write(adapter, CXL_PSL_DSNDCTL, psl_dsnctl); /* Tell PSL where to route data to */
	cxl_p1_write(adapter, CXL_PSL_RESLCKTO, 0x20000000200);
	cxl_p1_write(adapter, CXL_PSL_SNWRALLOC, 0x00000000FFFFFFFFULL); /* snoop write mask */
	cxl_p1_write(adapter, CXL_PSL_FIR_CNTL, 0x0800000000000000ULL); /* set fir_accum */

#if 0
	cxl_p1_write(adapter, CXL_PSL_TRACERD, 0x0000F0FC00000000ULL); /* for debugging with trace arrays */
#else
	/* changes recommended per JT and Yoanna 11/15/2013 */
	cxl_p1_write(adapter, CXL_PSL_TRACE, 0x0000FF7C00000000ULL); /* for debugging with trace arrays */
#endif

	dev_info(&dev->dev, "cxl: **** Workaround to disable PSL QuickTag to fix miscompares - PSL_SNWRALLOC - HW249157 ****\n");
	cxl_p1_write(adapter, CXL_PSL_SNWRALLOC, 0x80000000FFFFFFFFULL); /* HW249157 */

	return 0;
}

static int init_implementation_afu_regs(struct cxl_afu_t *afu)
{
	cxl_p1n_write(afu, CXL_PSL_APCALLOC_A, 0xFFFFFFFEFEFEFEFEULL); /* read/write masks for this slice */
	cxl_p1n_write(afu, CXL_PSL_COALLOC_A, 0xFF000000FEFEFEFEULL); /* APC read/write masks for this slice */

	/* changes recommended per JT and Yoanna 11/15/2013 */
	cxl_p1n_write(afu, CXL_PSL_SLICE_TRACE, 0x0000FFFF00000000ULL); /* for debugging with trace arrays */

	cxl_p1n_write(afu, CXL_PSL_RXCTL_A, 0xF000000000000000ULL);

	return 0;
}

/* Defined in powernv pci-ioda.c */
extern int pnv_cxl_ioda_msi_setup(struct pnv_phb *phb, struct pci_dev *dev,
		unsigned int hwirq, unsigned int virq);

static int setup_cxl_msi(struct cxl_t *adapter, unsigned int hwirq, unsigned int virq)
{
	struct pci_dev *dev = to_pci_dev(adapter->device.parent);
	struct pci_controller *hose = pci_bus_to_host(dev->bus);
	struct pnv_phb *phb = hose->private_data;

	return pnv_cxl_ioda_msi_setup(phb, dev, hwirq, virq);
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

static int alloc_one_hwirq(struct cxl_t *adapter)
{
	struct pci_dev *dev = to_pci_dev(adapter->device.parent);
	return _alloc_hwirqs(dev, 1);
}

static void _release_hwirqs(struct pci_dev *dev, int hwirq, int num)
{
	struct pci_controller *hose = pci_bus_to_host(dev->bus);
	struct pnv_phb *phb = hose->private_data;
	msi_bitmap_free_hwirqs(&phb->msi_bmp, hwirq - phb->msi_base, num);
}

static void release_one_hwirq(struct cxl_t *adapter, int hwirq)
{
	struct pci_dev *dev = to_pci_dev(adapter->device.parent);
	return _release_hwirqs(dev, hwirq, 1);
}

static int _alloc_hwirq_ranges(struct cxl_irq_ranges *irqs, struct pci_dev *dev, int num)
{
	struct pci_controller *hose = pci_bus_to_host(dev->bus);
	struct pnv_phb *phb = hose->private_data;
	int range = 0;
	int hwirq;
	int try;

	memset(irqs, 0, sizeof(struct cxl_irq_ranges));

	for (range = 1; range < CXL_IRQ_RANGES && num; range++) {
		try = num;
		while (try) {
			hwirq = msi_bitmap_alloc_hwirqs(&phb->msi_bmp, try);
			if (hwirq >= 0)
				break;
			try /= 2;
		}
		if (!try)
			goto fail;

		irqs->offset[range] = phb->msi_base + hwirq;
		irqs->range[range] = try;
		dev_info(&dev->dev, "cxl alloc irq range 0x%x: offset: 0x%lx  limit: %li\n",
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

static int alloc_hwirq_ranges(struct cxl_irq_ranges *irqs, struct cxl_t *adapter, unsigned int num)
{
	struct pci_dev *dev = to_pci_dev(adapter->device.parent);
	return _alloc_hwirq_ranges(irqs, dev, num);
}

static void release_hwirq_ranges(struct cxl_irq_ranges *irqs, struct cxl_t *adapter)
{
	struct pci_dev *dev = to_pci_dev(adapter->device.parent);
	struct pci_controller *hose = pci_bus_to_host(dev->bus);
	struct pnv_phb *phb = hose->private_data;
	int range = 0;
	int hwirq;

	for (range = 0; range < 4; range++) {
		hwirq = irqs->offset[range] - phb->msi_base;
		if (irqs->range[range]) {
			dev_info(&dev->dev, "cxl release irq range 0x%x: offset: 0x%lx  limit: %ld\n",
				 range, irqs->offset[range],
				 irqs->range[range]);
			msi_bitmap_free_hwirqs(&phb->msi_bmp, hwirq,
					       irqs->range[range]);
		}
	}
}

static void cxl_release_adapter(struct cxl_t *adapter)
{
	struct pci_dev *dev = to_pci_dev(adapter->device.parent);

	_release_hwirqs(dev, adapter->err_hwirq, 1);
}

static void cxl_release_afu(struct cxl_afu_t *afu)
{
	struct pci_dev *dev = to_pci_dev(afu->adapter->device.parent);

	cxl_unmap_slice_regs(afu);
	_release_hwirqs(dev, afu->err_hwirq, 1);
	_release_hwirqs(dev, afu->psl_hwirq, 1);
}

static int cxl_reset(struct cxl_t *adapter);
static struct cxl_driver_ops cxl_pci_driver_ops = {
	.module = THIS_MODULE,
	.init_adapter = init_implementation_adapter_regs,
	.init_afu = init_implementation_afu_regs,
	.alloc_one_irq = alloc_one_hwirq,
	.release_one_irq = release_one_hwirq,
	.alloc_irq_ranges = alloc_hwirq_ranges,
	.release_irq_ranges = release_hwirq_ranges,
	.setup_irq = setup_cxl_msi,
	.release_adapter = cxl_release_adapter,
	.release_afu = cxl_release_afu,
	.reset = cxl_reset,
};



static void reassign_cxl_bars(struct pci_dev *dev)
{
	const u32 *window_prop;
	LIST_HEAD(head);
	u64 window, size;
	u64 off, addr;
	int bar, i;
	struct resource * bars[2];
	resource_size_t len;
	struct device_node *np;

	dev_warn(&dev->dev, "Reassign CXL BARs\n");

	if (!(np = pnv_pci_to_phb_node(dev))) {
		dev_warn(&dev->dev, "WARNING: Unable to get cxl phb node, using BAR assignment from Linux\n");
		return;
	}

	/*
	 * CXL requires the m64 address space for BAR assignment. Our PHB code
	 * in Linux doesn't use it yet, and Linux will have assigned BARs from
	 * the m32 space. This code reassigns the BARs from the m64 space,
	 * which is OK since the CAPI card can be the only thing behind the
	 * PHB so it won't ever be assigned to anything else. Later when Linux
	 * can assign BARs from the m64 space we can use that instead.
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

	/* BAR 4/5 is for the CXL protocol. Bits[48:49] must be set to 10 */
	pci_write_config_dword(dev, PCI_BASE_ADDRESS_4, 0x00000000);
	pci_write_config_dword(dev, PCI_BASE_ADDRESS_5, 0x00020000);
	dev_info(&dev->dev, "wrote BAR4/5\n");
}

/*
 *  pciex node: ibm,opal-m64-window = <0x3d058 0x0 0x3d058 0x0 0x8 0x0>;
 */

static int switch_card_to_cxl(struct pci_dev *dev)
{
	int vsec;
	u32 val;
	int rc;

	dev_info(&dev->dev, "switch card to cxl\n");

	if (!(vsec = find_cxl_vsec(dev))) {
		dev_err(&dev->dev, "cxl: WARNING: CXL VSEC not found, assuming card is already in CXL mode!\n");
		/* return -ENODEV; */
		return 0;
	}

	dev_info(&dev->dev, "vsec found at offset %#x\n", vsec);

	if ((rc = pci_read_config_dword(dev, vsec + 0x8, &val))) {
		dev_err(&dev->dev, "failed to read current mode control: %i", rc);
		return rc;
	}
	val &= ~CXL_PROTOCOL_MASK;
	val |= CXL_PROTOCOL_256TB | CXL_PROTOCOL_ENABLE;
	if ((rc = pci_write_config_dword(dev, vsec + 0x8, val))) {
		dev_err(&dev->dev, "failed to enable cxl protocol: %i", rc);
		return rc;
	}

	return 0;
}

extern int pnv_phb_to_cxl(struct pci_dev *dev);

int enable_cxl_protocol(struct pci_dev *dev)
{
	int rc;

	if ((rc = switch_card_to_cxl(dev)))
		return rc;

	if ((rc = pnv_phb_to_cxl(dev)))
		return rc;

	return rc;
}

static int init_slice(struct cxl_t *adapter,
		      u64 p1_base, u64 p2_base,
		      u64 ps_off, u64 ps_size,
		      u64 afu_desc_off, u64 afu_desc_size,
		      int slice, struct pci_dev *dev)
{
	int rc;
	struct cxl_afu_t *afu = &(adapter->slice[slice]);
	u64 p1n_base, p2n_base, psn_base, afu_desc = 0;
	int err_hwirq;
	u64 val;

	const u64 p1n_size = 0x100;
	const u64 p2n_size = 0x1000;

	p1n_base = p1_base + 0x10000 + (slice * p1n_size);
	p2n_base = p2_base + (slice * p2n_size);
	psn_base = p2_base + (ps_off + (slice * ps_size));
	afu_desc = p2_base + afu_desc_off + (slice * afu_desc_size);

	if ((rc = cxl_map_slice_regs(afu,
				      p1n_base, p1n_size,
				      p2n_base, p2n_size,
				      psn_base, ps_size,
				      afu_desc, afu_desc_size))) {
		return rc;
	}

	pr_devel("afu_desc_mmio: %p\n", afu->afu_desc_mmio);

	/* FIXME: mask the MMIO timeout for
	   now.  need to * fix this long term */
	cxl_p1n_write(afu, CXL_PSL_SERR_An, 0x0000000000000000);
	cxl_ops->afu_reset(afu);
	dump_afu_descriptor(dev, afu);

	val = AFUD_READ_INFO(afu);
	afu->pp_irqs = AFUD_NUM_INTS_PER_PROC(val);
	afu->num_procs = AFUD_NUM_PROCS(val);
	afu->afu_directed_mode = AFUD_AFU_DIRECTED(val);
	afu->afu_dedicated_mode = AFUD_DEDICATED_PROCESS(val);
	if (afu->afu_directed_mode)
		pr_devel("AFU in directed mode\n");
	else if (afu->afu_dedicated_mode)
		pr_devel("AFU in dedicated mode\n");
	else {
		pr_err("No supported AFU programing models available\n");
		rc = -ENODEV;
		goto out;
	}

	val = AFUD_READ_PPPSA(afu);
	afu->pp_size = AFUD_PPPSA_LEN(val) * 4096;
	afu->mmio = AFUD_PPPSA_PSA(val);
	if (!afu->mmio)
		pr_devel("AFU doesn't support mmio space\n");
	afu->pp_mmio = AFUD_PPPSA_PP(val);
	if (afu->pp_mmio) {
		afu->pp_offset = AFUD_READ_PPPSA_OFF(afu);
	} else {
		pr_devel("AFU doesn't support per process mmio space\n");
		afu->pp_offset = 0;
	}

	WARN_ON(afu->mmio && afu->psn_size < (afu->pp_offset +
				 afu->pp_size*afu->num_procs));
	WARN_ON(afu->pp_mmio && (afu->pp_size < PAGE_SIZE));

	err_hwirq = _alloc_hwirqs(dev, 1);
	if (err_hwirq < 0) {
		rc = err_hwirq;
		goto out;
	}

	if ((rc = cxl_init_afu(afu, 0, err_hwirq))) {
		dev_err(&dev->dev, "cxl_init_afu failed: %i\n", rc);
		goto out1;
	}

	return 0;

out1:
	_release_hwirqs(dev, err_hwirq, 1);
out:
	cxl_unmap_slice_regs(afu);
	return rc;
}

int init_cxl_pci(struct pci_dev *dev)
{
	u64 p1_base, p1_size;
	u64 p2_base, p2_size;
	int vsec = find_cxl_vsec(dev);
	struct cxl_t *adapter;
	u32 afu_desc_off, afu_desc_size;
	u32 ps_off, ps_size;
	u16 vseclen;
	u8 nAFUs;
	int slice;
	int rc = -EBUSY;
	int err_hwirq;
	struct cxl_native_data backend_data;

	if (!(adapter = kzalloc(sizeof(struct cxl_t), GFP_KERNEL))) {
		rc = -ENOMEM;
		goto err;
	}

	pci_set_drvdata(dev, adapter);

	if (pci_request_region(dev, 2, "priv 2 regs"))
		goto err1;
	if (pci_request_region(dev, 0, "priv 1 regs"))
		goto err2;

	p1_base = pci_resource_start(dev, 2);
	p1_size = pci_resource_len(dev, 2);
	p2_base = pci_resource_start(dev, 0);
	p2_size = pci_resource_len(dev, 0);

	if (!vsec) {
		dev_err(&dev->dev, "no cxl vsec found\n");
		goto err3;
	}

	dev_info(&dev->dev, "cxl vsec found at offset %#x\n", vsec);
	pci_read_config_word(dev, CXL_VSEC_LENGTH(vsec), &vseclen);
	vseclen = vseclen >> 4;
	pci_read_config_byte(dev, CXL_VSEC_NAFUS(vsec), &nAFUs);
	pci_read_config_dword(dev, CXL_VSEC_AFU_DESC_OFF(vsec), &afu_desc_off);
	pci_read_config_dword(dev, CXL_VSEC_AFU_DESC_SIZE(vsec), &afu_desc_size);
	pci_read_config_dword(dev, CXL_VSEC_PS_OFF(vsec), &ps_off);
	pci_read_config_dword(dev, CXL_VSEC_PS_SIZE(vsec), &ps_size);

	ps_off  *= 64 * 1024;
	ps_size *= 64 * 1024;
	afu_desc_off *= 64 * 1024;
	afu_desc_size *= 64 * 1024;

	if (ps_size > p2_size - ps_off) {
		dev_warn(&dev->dev, "WARNING: Problem state size larger than available in BAR2: 0x%x > 0x%llx\n",
			 ps_size, p2_size - ps_off);
		ps_size = p2_size - ps_off;
	}

	err_hwirq = _alloc_hwirqs(dev, 1);
	if (err_hwirq < 0) {
		rc = err_hwirq;
		goto err3;
	}

	backend_data.p1_base = p1_base;
	backend_data.p1_size = p1_size;
	backend_data.p2_base = p2_base;
	backend_data.p2_size = p2_size;
	backend_data.err_hwirq = err_hwirq;
	if ((rc = cxl_init_adapter(adapter, &cxl_pci_driver_ops, &dev->dev, nAFUs, &backend_data))) {
		dev_err(&dev->dev, "cxl_alloc_adapter failed: %i\n", rc);
		goto err4;
	}

	BUG_ON(!afu_desc_off || !afu_desc_size);
	for (slice = 0; slice < nAFUs; slice++)
		if ((rc = init_slice(adapter, p1_base, p2_base, ps_off, ps_size, afu_desc_off, afu_desc_size, slice, dev)))
			goto err5;

	return 0;
err5:
	for (slice--; slice >= 0; slice--)
		cxl_unregister_afu(&adapter->slice[slice]);
	/* FIXME: Calling this is going to double call a bunch of crap, like
	 * cxl_unregister_afu and _release_hwirqs - I need to take a good long
	 * hard look at our error paths and convince myself that they actually
	 * do the right thing */
	cxl_unregister_adapter(adapter);
err4:
	_release_hwirqs(dev, err_hwirq, 1);
err3:
	pci_release_region(dev, 0);
err2:
	pci_release_region(dev, 2);
err1:
	kfree(adapter);
err:
	return rc;
}

bool pci_bus_read_dev_vendor_id(struct pci_bus *bus, int devfn, u32 *pl,
				int crs_timeout);

static int cxl_reset(struct cxl_t *adapter)
{
	struct pci_dev *pdev = to_pci_dev(adapter->device.parent);
	int vsec;
	int rc;
	u32 val;

	dev_info(&pdev->dev, "pci reset\n");

	if (!(vsec = find_cxl_vsec(pdev))) {
		dev_err(&pdev->dev, "cxl: WARNING: CXL VSEC not found, assuming card is already in CXL mode!\n");
		/* return -ENODEV; */
		return 0;
	}
	if ((rc = pci_read_config_dword(pdev, vsec + 0x10, &val))) {
		dev_err(&pdev->dev, "failed to read vsec offset 10 (for image control): %i", rc);
		return rc;
	}
	val |= CXL_PERST_RELOAD | CXL_USER_IMAGE;
	if (adapter->reset_image_factory)
		val &= ~CXL_USER_IMAGE;

	if ((rc = pci_write_config_dword(pdev, vsec + 0x10, val))) {
		dev_err(&pdev->dev, "failed to enable perst reload: %i", rc);
		return rc;
	}


	pci_cfg_access_lock(pdev);

	pci_set_pcie_reset_state(pdev, pcie_warm_reset);
	msleep(10);
	pci_set_pcie_reset_state(pdev, pcie_deassert_reset);
	msleep(1000);
	pci_bus_read_dev_vendor_id(pdev->bus, pdev->devfn, &val, 60*1000);
	dev_info(&pdev->dev, "v = %08x\n", val);

	/* Now lets setup the device again.. stolen from cxl_probe() */
	dump_cxl_config_space(pdev);
	reassign_cxl_bars(pdev);

	/* just do the card as the CAPP unit should still be in CXL mode */
	if ((rc = switch_card_to_cxl(pdev))){
		dev_err(&pdev->dev, "enable_cxl_protocol failed: %i\n", rc);
		goto out;
	}
	dev_info(&pdev->dev, "cxl protocol enabled\n");

/*	if ((rc = pci_enable_device(dev))) {
		dev_err(&dev->dev, "pci_enable_device failed: %i\n", rc);
		return rc;
	}
*/
/*	if ((rc = init_cxl_pci(dev))) {
		dev_err(&dev->dev, "init_cxl_pci failed: %i\n", rc);
		return rc;
	}
*/
out:
	pci_cfg_access_unlock(pdev);
	return rc;

}

static int cxl_probe(struct pci_dev *dev, const struct pci_device_id *id)
{
	int rc;

	dev_info(&dev->dev, "pci probe\n");
	pci_dev_get(dev);
	dump_cxl_config_space(dev);

	reassign_cxl_bars(dev);

	if ((rc = enable_cxl_protocol(dev))) {
		dev_err(&dev->dev, "enable_cxl_protocol failed: %i\n", rc);
		return rc;
	}
	dev_info(&dev->dev, "cxl protocol enabled\n");

	if ((rc = pci_enable_device(dev))) {
		dev_err(&dev->dev, "pci_enable_device failed: %i\n", rc);
		return rc;
	}

	if ((rc = init_cxl_pci(dev))) {
		dev_err(&dev->dev, "init_cxl_pci failed: %i\n", rc);
		return rc;
	}

	return 0;
}

static void cxl_remove(struct pci_dev *dev)
{
	struct cxl_t *adapter = pci_get_drvdata(dev);

	dev_warn(&dev->dev, "pci remove\n");
	cxl_unregister_adapter(adapter);
	pci_release_region(dev, 0);
	pci_release_region(dev, 2);
	kfree(adapter);
	pci_disable_device(dev);

	/* TODO: Implement everything from Documentation/PCI/pci.txt */

}

static struct pci_driver cxl_pci_driver = {
	.name = "cxl-pci",
	.id_table = cxl_pci_tbl,
	.probe = cxl_probe,
	.remove = cxl_remove,

	/* TODO:
	 * #ifdef CONFIG_PM
	 *	.suspend = ...,
	 *	.resume = ...,
	 * #endif */
};

module_driver(cxl_pci_driver, pci_register_driver, pci_unregister_driver);

MODULE_DESCRIPTION("IBM Coherent Accelerator");
MODULE_AUTHOR("Ian Munsie <imunsie@au1.ibm.com>");
MODULE_LICENSE("GPL");
