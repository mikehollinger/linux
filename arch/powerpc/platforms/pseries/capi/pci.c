#define DEBUG

#include <linux/pci_regs.h>
#include <linux/pci_ids.h>
#include <linux/device.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/of.h>
#include <asm/opal.h>

#include "capi.h"

#define CAPI_PCI_VSEC_ID	0x1280

#define CAPI_PROTOCOL_256TB	(1ull << 7)
#define CAPI_PROTOCOL_ENABLE	(1ull << 16)

#define CAPI_VSEC_NAFUS(vsec)		(vsec + 0x8) /* BYTE */
#define CAPI_VSEC_AFU_DESC_OFF(vsec)	(vsec + 0x20)
#define CAPI_VSEC_AFU_DESC_SIZE(vsec)	(vsec + 0x24)
#define CAPI_VSEC_PS_OFF(vsec)		(vsec + 0x28)
#define CAPI_VSEC_PS_SIZE(vsec)		(vsec + 0x2c)

DEFINE_PCI_DEVICE_TABLE(capi_pci_tbl) = {
	{ PCI_DEVICE(PCI_VENDOR_ID_IBM, 0x0477), },
	{ PCI_DEVICE_CLASS(0x120000, ~0), },

	{ }
};
MODULE_DEVICE_TABLE(pci, capi_pci_tbl);

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

	pr_devel("dump_capi_config_space\n");

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
	pr_devel("capi vsec: %30s: %#x\n", "Cap ID",		(val >>  0) & 0xffff);
	pr_devel("capi vsec: %30s: %#x\n", "Cap Ver",		(val >> 16) & 0xf);
	pr_devel("capi vsec: %30s: %#x\n", "Next Cap Ptr",	(val >> 20) & 0xfff);
	pci_read_config_dword(dev, vsec + 0x4, &val);
	pr_devel("capi vsec: %30s: %#x\n", "VSEC ID",		(val >>  0) & 0xffff);
	pr_devel("capi vsec: %30s: %#x\n", "VSEC Rev",		(val >> 16) & 0xf);
	pr_devel("capi vsec: %30s: %#x\n", "VSEC Length",	(val >> 20) & 0xfff);
	pci_read_config_dword(dev, vsec + 0x8, &val);
	pr_devel("capi vsec: %30s: %#x\n", "Num AFUs",		(val >>  0) & 0xff);
	pr_devel("capi vsec: %30s: %#x\n", "Status",		(val >>  8) & 0xff);
	pr_devel("capi vsec: %30s: %#x\n", "Mode Control",	(val >> 16) & 0xff);
	pr_devel("capi vsec: %30s: %#x\n", "PS_area_size",	(val >> 24) & 0xff);
	pci_read_config_dword(dev, vsec + 0xc, &val);
	pr_devel("capi vsec: %30s: %#x\n", "PSL Rev",		(val >>  0) & 0xffff);
	pr_devel("capi vsec: %30s: %#x\n", "CAIA Ver",		(val >> 16) & 0xffff);
	pci_read_config_dword(dev, vsec + 0x10, &val);
	pr_devel("capi vsec: %30s: %#x\n", "Base Image Rev",	(val >>  0) & 0xffff); /* Reserved < 0.11 */
	pr_devel("capi vsec: %30s: %#x\n", "Reserved",		(val >> 16) & 0xffff);
	pci_read_config_dword(dev, vsec + 0x14, &val);
	pr_devel("capi vsec: %30s: %#x\n", "Reserved",		val);

	pci_read_config_dword(dev, vsec + 0x18, &val);
	pr_devel("capi vsec: %30s: %#x\n", "PSL Programming Port", val); /* Reserved >= 0.11 */
	pci_read_config_dword(dev, vsec + 0x1c, &val);
	pr_devel("capi vsec: %30s: %#x\n", "PSL Programming Control", val); /* Reserved >= 0.11 */

	pr_devel("capi vsec: end of v0.09 defintion");

	pci_read_config_dword(dev, vsec + 0x20, &val);
	pr_devel("capi vsec: %30s: %#x\n", "Flash Address Register (v0.10) / AFU Descriptor Offset (v0.11)", val);
	pci_read_config_dword(dev, vsec + 0x24, &val);
	pr_devel("capi vsec: %30s: %#x\n", "Flash Size Register (v0.10) / AFU Descriptor Size (v0.11)", val);
	pci_read_config_dword(dev, vsec + 0x28, &val);
	pr_devel("capi vsec: %30s: %#x\n", "Flash Status/Control Register (v0.10) / Problem State Offset (v0.11)", val);
	pci_read_config_dword(dev, vsec + 0x2c, &val);
	pr_devel("capi vsec: %30s: %#x\n", "Flash Data Port (v0.10) / Problem State Size (v0.11)", val);

	pr_devel("capi vsec: end of v0.10 defintion");

	pci_read_config_dword(dev, vsec + 0x30, &val);
	pr_devel("capi vsec: %30s: %#x\n", "Reserved", val);
	pci_read_config_dword(dev, vsec + 0x34, &val);
	pr_devel("capi vsec: %30s: %#x\n", "Reserved", val);
	pci_read_config_dword(dev, vsec + 0x38, &val);
	pr_devel("capi vsec: %30s: %#x\n", "Reserved", val);
	pci_read_config_dword(dev, vsec + 0x3c, &val);
	pr_devel("capi vsec: %30s: %#x\n", "Reserved", val);

	pci_read_config_dword(dev, vsec + 0x40, &val);
	pr_devel("capi vsec: %30s: %#x\n", "PSL Programming Port", val);
	pci_read_config_dword(dev, vsec + 0x44, &val);
	pr_devel("capi vsec: %30s: %#x\n", "PSL Programming Control", val);
	pci_read_config_dword(dev, vsec + 0x48, &val);
	pr_devel("capi vsec: %30s: %#x\n", "Flash Address Register", val);
	pci_read_config_dword(dev, vsec + 0x4c, &val);
	pr_devel("capi vsec: %30s: %#x\n", "Flash Size Register", val);
	pci_read_config_dword(dev, vsec + 0x50, &val);
	pr_devel("capi vsec: %30s: %#x\n", "Flash Status/Control Register", val);
	pci_read_config_dword(dev, vsec + 0x54, &val);
	pr_devel("capi vsec: %30s: %#x\n", "Flash Data Port", val);

	/* TODO: Dump AFU Descriptor & AFU Configuration Record if present */
}

static int switch_phb_to_capi(struct pci_dev *dev)
{
	struct device_node *np;
	struct property *prop = NULL;
	u64 phb_id;
	int rc = -ENODEV;

	dev_info(&dev->dev, "switch phb to capi\n");

	np = of_node_get(pci_device_to_OF_node(dev));

	/* Scan up the tree looking for the PHB node */
	while (np) {
		if ((prop = of_find_property(np, "ibm,opal-phbid", NULL)))
			break;
		np = of_get_next_parent(np);
	}

	if (!np || !prop)
		goto out;

	dev_info(&dev->dev, "device tree name: %s\n", np->name);
	phb_id = be64_to_cpup(prop->value);
	dev_info(&dev->dev, "PHB-ID  : 0x%016llx\n", phb_id);

	rc = opal_phb_to_capi(phb_id);
	dev_info(&dev->dev, "opal_phb_to_capi: %i", rc);

out:
	of_node_put(np);
	return rc;
}

static int switch_card_to_capi(struct pci_dev *dev)
{
	int vsec;
	u32 val;
	int rc;

	dev_info(&dev->dev, "switch card to capi\n");

#if 1
	pci_write_config_dword(dev, PCI_BASE_ADDRESS_4, 0x00020000);
	pci_write_config_dword(dev, PCI_BASE_ADDRESS_5, 0x00000000);
#endif

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

int init_capi_pci(struct pci_dev *dev)
{
	u64 p1_base = pci_resource_start(dev, 2);
	u64 p1_size = pci_resource_len(dev, 2);
	u64 p2_base = pci_resource_start(dev, 0);
	u64 p2_size = pci_resource_len(dev, 0);
	int vsec = find_capi_vsec(dev);
	struct capi_t *adapter;
	u32 afu_desc_off, afu_desc_size;
	u32 ps_off, ps_size;
	u32 nIRQs;
	u8 nAFUs;
	int slice;
	int rc;

	/* TODO: Upload PSL */

	if (vsec) {
		dev_info(&dev->dev, "capi vsec found at offset %#x\n", vsec);

		pci_read_config_byte(dev, CAPI_VSEC_NAFUS(vsec), &nAFUs);
		pci_read_config_dword(dev, CAPI_VSEC_AFU_DESC_OFF(vsec), &afu_desc_off);
		pci_read_config_dword(dev, CAPI_VSEC_AFU_DESC_SIZE(vsec), &afu_desc_size);
		pci_read_config_dword(dev, CAPI_VSEC_PS_OFF(vsec), &ps_off);
		pci_read_config_dword(dev, CAPI_VSEC_PS_SIZE(vsec), &ps_size);

	} else { /* XXX Bringup only */
		dev_warn(&dev->dev, "capi vsec not found! Using bringup values!\n");

		nAFUs = 1;
		nIRQs = 3;
		ps_off  = 0x2000000 / 64 / 1024;
		ps_size = 0x2000000 / 64 / 1024;
	}

	if ((rc = capi_alloc_adapter(&adapter, nAFUs, 0, p1_base, p1_size, p2_base, p2_size, 0))) {
		dev_err(&dev->dev, "capi_alloc_adapter failed: %i\n", rc);
		return rc;
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

		if ((rc = capi_init_afu(adapter, afu, slice, 0,
			      p1n_base, p1n_size,
			      p2n_base, p2n_size,
			      psn_base, ps_size,
			      0, 0))) { /* XXX Interrupts - I need to hook into the phb code for these */
			dev_err(&dev->dev, "capi_init_afu failed: %i\n", rc);
			return rc;
		}
	}

	return 0;
}

static int capi_probe(struct pci_dev *dev, const struct pci_device_id *id)
{
	int rc;

	dev_info(&dev->dev, "pci probe\n");

	dump_capi_config_space(dev);

	if ((rc = enable_capi_protocol(dev))) {
		dev_err(&dev->dev, "enable_capi_protocol failed: %i\n", rc);
		return rc;
	}

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
	/* Just trying to understand how setting up BARs work in Linux */
	dump_capi_config_space(dev);

#if 0
	pci_write_config_dword(dev, PCI_BASE_ADDRESS_4, 0x00020000);
	pci_write_config_dword(dev, PCI_BASE_ADDRESS_5, 0x00000000);
#endif

	dump_capi_config_space(dev);
}
DECLARE_PCI_FIXUP_EARLY(PCI_VENDOR_ID_IBM, 0x0477, capi_early_fixup);

static void capi_remove(struct pci_dev *dev)
{
	dev_warn(&dev->dev, "pci remove\n");

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
