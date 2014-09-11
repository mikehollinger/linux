/*
 * Copyright 2014 IBM Corp.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#undef DEBUG

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
#include <asm/pnv-pci.h>

#include "cxl.h"

#define CXL_PCI_VSEC_ID	0x1280

#define CXL_PROTOCOL_MASK	(7ull << 21)
#define CXL_PROTOCOL_256TB	(1ull << 23) /* Power 8 uses this */
#define CXL_PROTOCOL_512TB	(1ull << 22)
#define CXL_PROTOCOL_1024TB	(1ull << 21)
#define CXL_PROTOCOL_ENABLE	(1ull << 16)
#define CXL_PERST_RELOAD	(1ull << 29)
#define CXL_USER_IMAGE		(1ull << 28)

#define CXL_VSEC_MIN_SIZE		0x80
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
#define   AFUD_MULTIMODEL(val)		EXTRACT_PPC_BIT(val, 48)
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

static DEFINE_PCI_DEVICE_TABLE(cxl_pci_tbl) = {
	{ PCI_DEVICE(PCI_VENDOR_ID_IBM, 0x0477), },
	{ PCI_DEVICE(PCI_VENDOR_ID_IBM, 0x044b), },
	{ PCI_DEVICE(PCI_VENDOR_ID_IBM, 0x04cf), },
	{ PCI_DEVICE_CLASS(0x120000, ~0), },

	{ }
};
MODULE_DEVICE_TABLE(pci, cxl_pci_tbl);


/* Mostly using these wrappers to avoid confusion:
 * priv 1 is BAR2, while priv 2 is BAR0 */
static inline resource_size_t p1_base(struct pci_dev *dev)
{
	return pci_resource_start(dev, 2);
}

static inline resource_size_t p1_size(struct pci_dev *dev)
{
	return pci_resource_len(dev, 2);
}

static inline resource_size_t p2_base(struct pci_dev *dev)
{
	return pci_resource_start(dev, 0);
}

static inline resource_size_t p2_size(struct pci_dev *dev)
{
	return pci_resource_len(dev, 0);
}

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

	if (!cxl_verbose)
		return;

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

	dev_info(&dev->dev, "p1 regs: %#llx, len: %#llx\n",
		p1_base(dev), p1_size(dev));
	dev_info(&dev->dev, "p2 regs: %#llx, len: %#llx\n",
		p1_base(dev), p2_size(dev));
	dev_info(&dev->dev, "BAR 4/5: %#llx, len: %#llx\n",
		pci_resource_start(dev, 4), pci_resource_len(dev, 4));

	if (!(vsec = find_cxl_vsec(dev)))
		return;

#define show_reg(name, what) \
	dev_info(&dev->dev, "cxl vsec: %30s: %#x\n", name, what)

	pci_read_config_dword(dev, vsec + 0x0, &val);
	show_reg("Cap ID", (val >> 0) & 0xffff);
	show_reg("Cap Ver", (val >> 16) & 0xf);
	show_reg("Next Cap Ptr", (val >> 20) & 0xfff);
	pci_read_config_dword(dev, vsec + 0x4, &val);
	show_reg("VSEC ID", (val >> 0) & 0xffff);
	show_reg("VSEC Rev", (val >> 16) & 0xf);
	show_reg("VSEC Length",	(val >> 20) & 0xfff);
	pci_read_config_dword(dev, vsec + 0x8, &val);
	show_reg("Num AFUs", (val >> 0) & 0xff);
	show_reg("Status", (val >> 8) & 0xff);
	show_reg("Mode Control", (val >> 16) & 0xff);
	show_reg("Reserved", (val >> 24) & 0xff);
	pci_read_config_dword(dev, vsec + 0xc, &val);
	show_reg("PSL Rev", (val >> 0) & 0xffff);
	show_reg("CAIA Ver", (val >> 16) & 0xffff);
	pci_read_config_dword(dev, vsec + 0x10, &val);
	show_reg("Base Image Rev", (val >> 0) & 0xffff);
	show_reg("Reserved", (val >> 16) & 0x0fff);
	show_reg("Image Control", (val >> 28) & 0x3);
	show_reg("Reserved", (val >> 30) & 0x1);
	show_reg("Image Loaded", (val >> 31) & 0x1);

	pci_read_config_dword(dev, vsec + 0x14, &val);
	show_reg("Reserved", val);
	pci_read_config_dword(dev, vsec + 0x18, &val);
	show_reg("Reserved", val);
	pci_read_config_dword(dev, vsec + 0x1c, &val);
	show_reg("Reserved", val);

	pci_read_config_dword(dev, vsec + 0x20, &val);
	show_reg("AFU Descriptor Offset", val);
	pci_read_config_dword(dev, vsec + 0x24, &val);
	show_reg("AFU Descriptor Size", val);
	pci_read_config_dword(dev, vsec + 0x28, &val);
	show_reg("Problem State Offset", val);
	pci_read_config_dword(dev, vsec + 0x2c, &val);
	show_reg("Problem State Size", val);

	pci_read_config_dword(dev, vsec + 0x30, &val);
	show_reg("Reserved", val);
	pci_read_config_dword(dev, vsec + 0x34, &val);
	show_reg("Reserved", val);
	pci_read_config_dword(dev, vsec + 0x38, &val);
	show_reg("Reserved", val);
	pci_read_config_dword(dev, vsec + 0x3c, &val);
	show_reg("Reserved", val);

	pci_read_config_dword(dev, vsec + 0x40, &val);
	show_reg("PSL Programming Port", val);
	pci_read_config_dword(dev, vsec + 0x44, &val);
	show_reg("PSL Programming Control", val);

	pci_read_config_dword(dev, vsec + 0x48, &val);
	show_reg("Reserved", val);
	pci_read_config_dword(dev, vsec + 0x4c, &val);
	show_reg("Reserved", val);

	pci_read_config_dword(dev, vsec + 0x50, &val);
	show_reg("Flash Address Register", val);
	pci_read_config_dword(dev, vsec + 0x54, &val);
	show_reg("Flash Size Register", val);
	pci_read_config_dword(dev, vsec + 0x58, &val);
	show_reg("Flash Status/Control Register", val);
	pci_read_config_dword(dev, vsec + 0x58, &val);
	show_reg("Flash Data Port", val);

#undef show_reg
}

static void dump_afu_descriptor(struct pci_dev *dev, struct cxl_afu_t *afu)
{
	u64 val;

	if (!cxl_verbose)
		return;

#define show_reg(name, what) \
	dev_info(&dev->dev, "afu desc: %30s: %#llx\n", name, what)

	val = AFUD_READ_INFO(afu);
	show_reg("num_ints_per_process", AFUD_NUM_INTS_PER_PROC(val));
	show_reg("num_of_processes", AFUD_NUM_PROCS(val));
	show_reg("num_of_afu_CRs", AFUD_NUM_CRS(val));
	show_reg("req_prog_model", val & 0xffffULL);

	val = AFUD_READ(afu, 0x8);
	show_reg("Reserved", val);
	val = AFUD_READ(afu, 0x10);
	show_reg("Reserved", val);
	val = AFUD_READ(afu, 0x18);
	show_reg("Reserved", val);

	val = AFUD_READ_CR(afu);
	show_reg("Reserved", (val >> (63-7)) & 0xff);
	show_reg("AFU_CR_len", AFUD_CR_LEN(val));

	val = AFUD_READ_CR_OFF(afu);
	show_reg("AFU_CR_offset", val);

	val = AFUD_READ_PPPSA(afu);
	show_reg("PerProcessPSA_control", (val >> (63-7)) & 0xff);
	show_reg("PerProcessPSA Length", AFUD_PPPSA_LEN(val));

	val = AFUD_READ_PPPSA_OFF(afu);
	show_reg("PerProcessPSA_offset", val);

	val = AFUD_READ_EB(afu);
	show_reg("Reserved", (val >> (63-7)) & 0xff);
	show_reg("AFU_EB_len", AFUD_EB_LEN(val));

	val = AFUD_READ_EB_OFF(afu);
	show_reg("AFU_EB_offset", val);

#undef show_reg
}

extern struct device_node *pnv_pci_to_phb_node(struct pci_dev *dev);

static int init_implementation_adapter_regs(struct cxl_t *adapter, struct pci_dev *dev)
{
	struct device_node *np;
	const __be32 *prop;
	u64 psl_dsnctl;
	u64 chipid;

	if (!(np = pnv_pci_to_phb_node(dev)))
		return -ENODEV;

	while (np && !(prop = of_get_property(np, "ibm,chip-id", NULL)))
		np = of_get_next_parent(np);
	if (!np)
		return -ENODEV;
	chipid = be32_to_cpup(prop);
	of_node_put(np);

	psl_dsnctl = 0x02E8900002000000ULL | (chipid << (63-5));

	cxl_p1_write(adapter, CXL_PSL_DSNDCTL, psl_dsnctl); /* Tell PSL where to route data to */
	cxl_p1_write(adapter, CXL_PSL_RESLCKTO, 0x20000000200ULL);
	cxl_p1_write(adapter, CXL_PSL_SNWRALLOC, 0x00000000FFFFFFFFULL); /* snoop write mask */
	cxl_p1_write(adapter, CXL_PSL_FIR_CNTL, 0x0800000000000000ULL); /* set fir_accum */
	cxl_p1_write(adapter, CXL_PSL_TRACE, 0x0000FF7C00000000ULL); /* for debugging with trace arrays */

	return 0;
}

static int setup_cxl_msi(struct cxl_t *adapter, unsigned int hwirq,
			 unsigned int virq)
{
	struct pci_dev *dev = to_pci_dev(adapter->device.parent);

	return pnv_cxl_ioda_msi_setup(dev, hwirq, virq);
}

static int alloc_one_hwirq(struct cxl_t *adapter)
{
	struct pci_dev *dev = to_pci_dev(adapter->device.parent);

	return pnv_cxl_alloc_hwirqs(dev, 1);
}

static void release_one_hwirq(struct cxl_t *adapter, int hwirq)
{
	struct pci_dev *dev = to_pci_dev(adapter->device.parent);

	return pnv_cxl_release_hwirqs(dev, hwirq, 1);
}

static int alloc_hwirq_ranges(struct cxl_irq_ranges *irqs, struct cxl_t *adapter, unsigned int num)
{
	struct pci_dev *dev = to_pci_dev(adapter->device.parent);

	return pnv_cxl_alloc_hwirq_ranges(irqs, dev, num);
}

static void release_hwirq_ranges(struct cxl_irq_ranges *irqs, struct cxl_t *adapter)
{
	struct pci_dev *dev = to_pci_dev(adapter->device.parent);

	pnv_cxl_release_hwirq_ranges(irqs, dev);

}


static void cxl_release_afu(struct cxl_afu_t *afu)
{
	struct pci_dev *dev = to_pci_dev(afu->adapter->device.parent);

	cxl_unmap_slice_regs(afu);
	pnv_cxl_release_hwirqs(dev, afu->err_hwirq, 1);
	pnv_cxl_release_hwirqs(dev, afu->psl_hwirq, 1);
}

static struct cxl_driver_ops cxl_pci_driver_ops = {
	.module = THIS_MODULE,
	.alloc_one_irq = alloc_one_hwirq,
	.release_one_irq = release_one_hwirq,
	.alloc_irq_ranges = alloc_hwirq_ranges,
	.release_irq_ranges = release_hwirq_ranges,
	.setup_irq = setup_cxl_msi,
	.release_afu = cxl_release_afu,
};

static int setup_cxl_bars(struct pci_dev *dev)
{
	/* Safety check in case we get backported to < 3.17 without M64 */
	if ((p1_base(dev) < 0x100000000ULL) ||
	    (p2_base(dev) < 0x100000000ULL)) {
		dev_err(&dev->dev, "ABORTING: M32 BAR assignment incompatible with CXL\n");
		return -ENODEV;
	}

	/* BAR 4/5 has a special meaning for CXL and must be programmed with a
	 * special value corresponding to the CXL protocol address range.
	 * For POWER 8 that means bits 48:49 must be set to 10 */
	pci_write_config_dword(dev, PCI_BASE_ADDRESS_4, 0x00000000);
	pci_write_config_dword(dev, PCI_BASE_ADDRESS_5, 0x00020000);

	return 0;
}

/*
 *  pciex node: ibm,opal-m64-window = <0x3d058 0x0 0x3d058 0x0 0x8 0x0>;
 */

static int switch_card_to_cxl(struct pci_dev *dev)
{
	int vsec;
	u32 val;
	int rc;

	dev_info(&dev->dev, "switch card to CXL\n");

	if (!(vsec = find_cxl_vsec(dev))) {
		dev_warn(&dev->dev, "WARNING: CXL VSEC not found, assuming card is already in CXL mode!\n");
		return 0;
	}

	if ((rc = pci_read_config_dword(dev, vsec + 0x8, &val))) {
		dev_err(&dev->dev, "failed to read current mode control: %i", rc);
		return rc;
	}
	val &= ~CXL_PROTOCOL_MASK;
	val |= CXL_PROTOCOL_256TB | CXL_PROTOCOL_ENABLE;
	if ((rc = pci_write_config_dword(dev, vsec + 0x8, val))) {
		dev_err(&dev->dev, "failed to enable CXL protocol: %i", rc);
		return rc;
	}

	return 0;
}

static int enable_cxl_protocol(struct pci_dev *dev)
{
	int rc;

	if ((rc = switch_card_to_cxl(dev)))
		return rc;

	if ((rc = pnv_phb_to_cxl(dev)))
		return rc;

	return rc;
}

static int init_slice(struct cxl_t *adapter,
		      u64 ps_off, u64 ps_size,
		      u64 afu_desc_off, u64 afu_desc_size,
		      int slice, struct pci_dev *dev)
{
	struct cxl_afu_t *afu = &(adapter->slice[slice]);
	u64 p1n_base, p2n_base, psn_base, afu_desc = 0;
	u64 val;
	int rc;
	int err_hwirq;

	const u64 p1n_size = 0x100;
	const u64 p2n_size = 0x1000;

	p1n_base = p1_base(dev) + 0x10000 + (slice * p1n_size);
	p2n_base = p2_base(dev) + (slice * p2n_size);
	psn_base = p2_base(dev) + (ps_off + (slice * ps_size));
	afu_desc = p2_base(dev) + afu_desc_off + (slice * afu_desc_size);

	if ((rc = cxl_map_slice_regs(afu,
				      p1n_base, p1n_size,
				      p2n_base, p2n_size,
				      psn_base, ps_size,
				      afu_desc, afu_desc_size))) {
		return rc;
	}

	cxl_p1n_write(afu, CXL_PSL_SERR_An, 0x0000000000000000);
	cxl_ops->afu_reset(afu);
	dump_afu_descriptor(dev, afu);

	afu->prefault_mode = CXL_PREFAULT_NONE;
	/* Total - 1 PSL ERROR - #AFU*(1 slice error + 1 DSI) */
	afu->user_irqs = pnv_cxl_get_irq_count(dev) - 1 - 2*adapter->slices;
	afu->irqs_max = afu->user_irqs;
	val = AFUD_READ_INFO(afu);
	afu->pp_irqs = AFUD_NUM_INTS_PER_PROC(val);
	afu->num_procs = AFUD_NUM_PROCS(val);

	afu->models_supported = 0;
	if (AFUD_AFU_DIRECTED(val))
		afu->models_supported |= CXL_MODEL_DIRECTED;
	if (AFUD_DEDICATED_PROCESS(val))
		afu->models_supported |= CXL_MODEL_DEDICATED;
	if (AFUD_TIME_SLICED(val))
		afu->models_supported |= CXL_MODEL_TIME_SLICED;

	if (afu->models_supported & CXL_MODEL_DIRECTED) {
		afu->current_model = CXL_MODEL_DIRECTED;
		pr_devel("AFU in AFU directed model\n");
	} else if (afu->models_supported & CXL_MODEL_DEDICATED) {
		afu->current_model = CXL_MODEL_DEDICATED;
		pr_devel("AFU in dedicated process model\n");
	} else {
		pr_err("No supported AFU programing models available\n");
		rc = -ENODEV;
		goto out;
	}

	val = AFUD_READ_PPPSA(afu);
	afu->pp_size = AFUD_PPPSA_LEN(val) * 4096;
	afu->mmio = AFUD_PPPSA_PSA(val);
	if (!afu->mmio)
		pr_devel("AFU doesn't support problem state area\n");
	afu->pp_mmio = AFUD_PPPSA_PP(val);
	if (afu->pp_mmio) {
		afu->pp_offset = AFUD_READ_PPPSA_OFF(afu);
	} else {
		pr_devel("AFU doesn't support per process problem state area\n");
		afu->pp_offset = 0;
	}

	WARN_ON(afu->mmio && afu->psn_size < (afu->pp_offset +
				 afu->pp_size*afu->num_procs));
	WARN_ON(afu->pp_mmio && (afu->pp_size < PAGE_SIZE));

	err_hwirq = pnv_cxl_alloc_hwirqs(dev, 1);
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
	pnv_cxl_release_hwirqs(dev, err_hwirq, 1);
out:
	cxl_unmap_slice_regs(afu);
	return rc;
}


static int cxl_map_adapter_regs(struct cxl_t *adapter, struct pci_dev *dev)
{
	if (pci_request_region(dev, 2, "priv 2 regs"))
		goto err1;
	if (pci_request_region(dev, 0, "priv 1 regs"))
		goto err2;

	pr_devel("cxl_map_adapter_regs: p1: %#.16llx %#llx, p2: %#.16llx %#llx",
			p1_base(dev), p1_size(dev), p2_base(dev), p2_size(dev));

	if (!(adapter->p1_mmio = ioremap(p1_base(dev), p1_size(dev))))
		goto err3;

	if (!(adapter->p2_mmio = ioremap(p2_base(dev), p2_size(dev))))
		goto err4;

	return 0;

err4:
	iounmap(adapter->p1_mmio);
	adapter->p1_mmio = NULL;
err3:
	pci_release_region(dev, 0);
err2:
	pci_release_region(dev, 2);
err1:
	return -ENOMEM;
}

static void cxl_unmap_adapter_regs(struct cxl_t *adapter)
{
	if (adapter->p1_mmio)
		iounmap(adapter->p1_mmio);
	if (adapter->p2_mmio)
		iounmap(adapter->p2_mmio);
}

static int cxl_read_vsec(struct cxl_t *adapter, struct pci_dev *dev)
{
	int vsec_off;
	u32 afu_desc_off, afu_desc_size;
	u32 ps_off, ps_size;
	u16 vseclen;

	if (!(vsec_off = find_cxl_vsec(dev))) {
		dev_err(&dev->dev, "ABORTING: CXL VSEC not found!\n");
		return -ENODEV;
	}

	pci_read_config_word(dev, CXL_VSEC_LENGTH(vsec_off), &vseclen);
	vseclen = vseclen >> 4;
	if (vseclen < CXL_VSEC_MIN_SIZE) {
		pr_err("ABORTING: CXL VSEC too short\n");
		return -EINVAL;
	}

	pci_read_config_byte(dev, CXL_VSEC_NAFUS(vsec_off), &adapter->slices);
	pci_read_config_dword(dev, CXL_VSEC_AFU_DESC_OFF(vsec_off), &afu_desc_off);
	pci_read_config_dword(dev, CXL_VSEC_AFU_DESC_SIZE(vsec_off), &afu_desc_size);
	pci_read_config_dword(dev, CXL_VSEC_PS_OFF(vsec_off), &ps_off);
	pci_read_config_dword(dev, CXL_VSEC_PS_SIZE(vsec_off), &ps_size);

	/* Convert everything to bytes, because there is NO WAY I'd look at the
	 * code a month later and forget what units these are in ;-) */
	adapter->ps_off = ps_off * 64 * 1024;
	adapter->ps_size = ps_size * 64 * 1024;
	adapter->afu_desc_off = afu_desc_off * 64 * 1024;
	adapter->afu_desc_size = afu_desc_size *64 * 1024;

	return 0;
}

static int cxl_vsec_looks_ok(struct cxl_t *adapter, struct pci_dev *dev)
{
	if (!adapter->slices) {
		/* Once we support dynamic reprogramming we can use the card if
		 * it supports loadable AFUs */
		dev_err(&dev->dev, "ABORTING: Device has no AFUs\n");
		return -EINVAL;
	}

	if (!adapter->afu_desc_off || !adapter->afu_desc_size) {
		dev_err(&dev->dev, "ABORTING: VSEC shows no AFU descriptors\n");
		return -EINVAL;
	}

	if (adapter->ps_size > p2_size(dev) - adapter->ps_off) {
		dev_err(&dev->dev, "ABORTING: Problem state size larger than "
				   "available in BAR2: 0x%llx > 0x%llx\n",
			 adapter->ps_size, p2_size(dev) - adapter->ps_off);
		return -EINVAL;
	}

	return 0;
}

static void cxl_release_adapter(struct device *dev)
{
	struct cxl_t *adapter = to_cxl_adapter(dev);
	struct pci_dev *pdev = to_pci_dev(adapter->device.parent);

	pr_devel("cxl_release_adapter\n");

	cxl_debugfs_adapter_remove(adapter);
	cxl_release_psl_err_irq(adapter);
	cxl_unmap_adapter_regs(adapter);
	pci_release_region(pdev, 0);
	pci_release_region(pdev, 2);
	cxl_remove_adapter_nr(adapter);
	kfree(adapter);

	pci_disable_device(pdev);
}

static struct cxl_t *cxl_alloc_adapter(struct pci_dev *dev)
{
	struct cxl_t *adapter;

	if (!(adapter = kzalloc(sizeof(struct cxl_t), GFP_KERNEL)))
		return NULL;

	adapter->device.parent = &dev->dev;
	adapter->device.release = cxl_release_adapter;
	adapter->driver = &cxl_pci_driver_ops;
	pci_set_drvdata(dev, adapter);

	return adapter;
}

static struct cxl_t *cxl_init_adapter(struct pci_dev *dev)
{
	struct cxl_t *adapter;
	int rc;

	if (!(adapter = cxl_alloc_adapter(dev)))
		return ERR_PTR(-ENOMEM);

	if ((rc = cxl_read_vsec(adapter, dev)))
		goto err1;

	if ((rc = cxl_vsec_looks_ok(adapter, dev)))
		goto err1;

	if ((rc = cxl_map_adapter_regs(adapter, dev)))
		goto err1;

	/* TODO: cxl_ops->sanitise_adapter_regs(adapter); */

	if ((rc = init_implementation_adapter_regs(adapter, dev)))
		goto err2;

	if ((rc = cxl_register_psl_err_irq(adapter)))
		goto err2;

	if ((rc = cxl_alloc_adapter_nr(adapter)))
		goto err3;

	/* Don't care if this one fails: */
	cxl_debugfs_adapter_add(adapter);

	/* After we call this function we must not free the adapter directly,
	 * even if it returns an error! */
	if ((rc = cxl_register_adapter(adapter)))
		goto err_put1;

	return adapter;

err_put1:
	device_unregister(&adapter->device);
	return ERR_PTR(rc);

	/* If you add more error paths before cxl_register_adapter remember:
err4:
	cxl_debugfs_adapter_remove(adapter);
	cxl_remove_adapter_nr(adapter);
	*/
err3:
	cxl_release_psl_err_irq(adapter);
err2:
	cxl_unmap_adapter_regs(adapter);
err1:
	kfree(adapter);
	return ERR_PTR(rc);
}

static void afu_t_init(struct cxl_t *adapter, int slice)
{
	struct cxl_afu_t *afu = &adapter->slice[slice];

	afu->adapter = adapter;
	afu->slice = slice;
	idr_init(&afu->contexts_idr);
	spin_lock_init(&afu->contexts_lock);
	spin_lock_init(&afu->afu_cntl_lock);
	mutex_init(&afu->spa_mutex);
}

static int cxl_probe(struct pci_dev *dev, const struct pci_device_id *id)
{
	struct cxl_t *adapter;
	int slice;
	int rc;

	pci_dev_get(dev);
	dump_cxl_config_space(dev);

	if ((rc = setup_cxl_bars(dev)))
		return rc;

	if ((rc = enable_cxl_protocol(dev))) {
		dev_err(&dev->dev, "enable_cxl_protocol failed: %i\n", rc);
		return rc;
	}
	dev_info(&dev->dev, "CXL protocol enabled\n");

	if ((rc = pci_enable_device(dev))) {
		dev_err(&dev->dev, "pci_enable_device failed: %i\n", rc);
		return rc;
	}

	adapter = cxl_init_adapter(dev);
	if (IS_ERR(adapter)) {
		dev_err(&dev->dev, "cxl_init_adapter failed: %li\n", PTR_ERR(adapter));
		return PTR_ERR(adapter);
	}

	for (slice = 0; slice < adapter->slices; slice++) {
		afu_t_init(adapter, slice);
		if ((rc = init_slice(adapter, adapter->ps_off, adapter->ps_size,
				     adapter->afu_desc_off, adapter->afu_desc_size,
				     slice, dev))) {
			dev_warn(&dev->dev, "AFU %i failed to initialise: %i\n", slice, rc);
		}
	}

	return 0;
}

static void cxl_remove(struct pci_dev *dev)
{
	struct cxl_t *adapter = pci_get_drvdata(dev);
	int afu;

	dev_warn(&dev->dev, "pci remove\n");

	/* FIXME: Test this!!! */
	for (afu = 0; afu < adapter->slices; afu++)
		cxl_unregister_afu(&adapter->slice[afu]);
	device_unregister(&adapter->device);
}

static struct pci_driver cxl_pci_driver = {
	.name = "cxl-pci",
	.id_table = cxl_pci_tbl,
	.probe = cxl_probe,
	.remove = cxl_remove,
};

module_driver(cxl_pci_driver, pci_register_driver, pci_unregister_driver);

MODULE_DESCRIPTION("IBM Coherent Accelerator");
MODULE_AUTHOR("Ian Munsie <imunsie@au1.ibm.com>");
MODULE_LICENSE("GPL");
