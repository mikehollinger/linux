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
	pr_info("switch to capi\n");

	return 0;
}

int capi_probe(struct pci_dev *dev, const struct pci_device_id *id)
{
	int result;
	struct device_node *np;

	pr_info("capi pci probe\n");

	np = pci_device_to_OF_node(dev);

	if (np)
		pr_info("device tree name: %s\n", np->name);

	if ((result = pci_enable_device(dev))) {
		pr_err("capi-pci: pci_enable_device failed: %i\n", result);
		return result;
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
