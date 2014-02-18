#include <linux/pci_ids.h>
#include <linux/device.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/of.h>
#include <asm/opal.h>

DEFINE_PCI_DEVICE_TABLE(capi_pci_tbl) = {
	{ PCI_DEVICE(PCI_VENDOR_ID_IBM, 0x0477), },
	{ PCI_DEVICE_CLASS(0x120000, ~0), },

	{ }
};
MODULE_DEVICE_TABLE(pci, capi_pci_tbl);

int switch_to_capi(struct pci_dev *dev)
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

int capi_probe(struct pci_dev *dev, const struct pci_device_id *id)
{
	int rc;

	pr_info("capi pci probe\n");

	switch_to_capi(dev);

	/* FIXME: Should wait for PHB to come back in CAPI mode and re-probe */
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
