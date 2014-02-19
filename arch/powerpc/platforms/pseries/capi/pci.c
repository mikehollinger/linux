#include <linux/pci_ids.h>
#include <linux/device.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/of.h>
#include <asm/opal.h>

#define CAPI_PCI_VSEC_ID	0xb

#define CAPI_PROTOCOL_256TB	(1ull << (23-7))
#define CAPI_PROTOCOL_ENABLE	(1ull << (23-16))

DEFINE_PCI_DEVICE_TABLE(capi_pci_tbl) = {
	{ PCI_DEVICE(PCI_VENDOR_ID_IBM, 0x0477), },
	{ PCI_DEVICE_CLASS(0x1200FF, ~0), },

	{ }
};
MODULE_DEVICE_TABLE(pci, capi_pci_tbl);

static int switch_phb_to_capi(struct pci_dev *dev)
{
	struct device_node *np;
	struct property *prop = NULL;
	u64 phb_id;
	int rc = -ENODEV;

	pr_info("capi: switch phb to capi\n");

	np = of_node_get(pci_device_to_OF_node(dev));

	/* Scan up the tree looking for the PHB node */
	while (np) {
		if ((prop = of_find_property(np, "ibm,opal-phbid", NULL)))
			break;
		np = of_get_next_parent(np);
	}

	if (!np || !prop)
		goto out;

	pr_info("capi: device tree name: %s\n", np->name);
	phb_id = be64_to_cpup(prop->value);
	pr_info("capi:  PHB-ID  : 0x%016llx\n", phb_id);

	rc = opal_phb_to_capi(phb_id);
	pr_info("capi: opal_phb_to_capi: %i", rc);

out:
	of_node_put(np);
	return rc;
}

static int switch_card_to_capi(struct pci_dev *dev)
{
	int vsec;
	u32 val;
	int rc;

	pr_info("capi: switch card to capi\n");

	if ((vsec = pci_find_ext_capability(dev, CAPI_PCI_VSEC_ID)) == 0) {
		pr_err("capi: No CAPI VSEC found!\n");
		return -ENODEV;
	}

	pr_info("capi vsec found at offset %#x\n", vsec);

	/* FIXME: Can probably just read/write one byte and not worry about the
	 * number of AFUs and status fields */
	if ((rc = pci_read_config_dword(dev, vsec + 0x8, &val))) {
		pr_err("capi: failed to read current mode control: %i", rc);
		return rc;
	}
	/* FIXME: Clear other protocol size bits */
	val |= CAPI_PROTOCOL_256TB | CAPI_PROTOCOL_ENABLE;
	if ((rc = pci_write_config_dword(dev, vsec + 0x8, val))) {
		pr_err("capi: failed to enable capi protocol: %i", rc);
		return rc;
	}

	return 0;
}

int enable_capi_protocol(struct pci_dev *dev)
{
	int rc;

	/* XXX: Which needs to happen first? */

	if ((rc = switch_phb_to_capi(dev)))
		return rc;

	return switch_card_to_capi(dev);
}

int capi_probe(struct pci_dev *dev, const struct pci_device_id *id)
{
	int rc;

	pr_info("capi pci probe\n");

	if ((rc = enable_capi_protocol(dev))) {
		pr_err("capi-pci: enable_capi_protocol failed: %i\n", rc);
		return rc;
	}

	/* FIXME: Should I wait for PHB to come back in CAPI mode and re-probe? */
	if ((rc = pci_enable_device(dev))) {
		pr_err("capi-pci: pci_enable_device failed: %i\n", rc);
		return rc;
	}

	/* XXX: Do I need any of these?
	 * pci_set_master()
	 * pci_set_mwi()
	 * etc?
	 */

	return 0;
}

void capi_remove(struct pci_dev *dev)
{
	pr_warn("capi pci remove\n");

	/* TODO: Implement everything from Documentation/PCI/pci.txt */

}

static struct pci_driver capi_pci_driver = {
	.name = "capi",
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
