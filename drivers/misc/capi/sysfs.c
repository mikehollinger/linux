#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/sysfs.h>

#include "capi.h"

#define to_afu(d) container_of(d, struct capi_afu_t, device)
#define to_adapter(d) container_of(d, struct capi_t, device)
#define master_to_afu(d) container_of(d, struct capi_afu_t, device_master)

static ssize_t reset_store(struct device *device, struct device_attribute *attr,
		   const char *buf, size_t count)
{
	struct capi_t *adapter = to_adapter(device);
	int rc;

	/* TODO: support various types of reset */
	if ((rc = adapter->driver->reset(adapter)))
		return rc;
	return count;
}

static ssize_t reset_image_select_store(struct device *device,
					struct device_attribute *attr,
					const char *buf, size_t count)
{
	struct capi_t *adapter = to_adapter(device);
	int ret;

	ret = strncmp(buf, "factory", 7);
	if (ret == 0) {
		adapter->reset_image_factory = true;
		return count;
	}
	ret = strncmp(buf, "user", 4);
	if (ret == 0) {
		adapter->reset_image_factory = false;
		return count;
	}
	return -EINVAL;
}

static ssize_t reset_image_select_show(struct device *device,
				       struct device_attribute *attr,
				       char *buf)
{
	struct capi_t *adapter = to_adapter(device);

	if (adapter->reset_image_factory)
		return scnprintf(buf, PAGE_SIZE, "factory\n");
	return scnprintf(buf, PAGE_SIZE, "user\n");
}

static struct device_attribute adapter_attrs[] = {
	__ATTR_WO(reset),
	__ATTR_RW(reset_image_select),
};

static ssize_t mmio_size_show_master(struct device *device,
				     struct device_attribute *attr,
				     char *buf)
{
	struct capi_afu_t *afu = master_to_afu(device);

	return scnprintf(buf, PAGE_SIZE, "%llu\n", afu->psn_size);
}
static ssize_t mmio_size_show(struct device *device,
			      struct device_attribute *attr,
			      char *buf)
{
	struct capi_afu_t *afu = to_afu(device);

	if (afu->pp_size)
		return scnprintf(buf, PAGE_SIZE, "%llu\n", afu->pp_size);
	return scnprintf(buf, PAGE_SIZE, "%llu\n", afu->psn_size);
}

static ssize_t reset_store_afu(struct device *device,
			       struct device_attribute *attr,
			       const char *buf, size_t count)
{
	struct capi_afu_t *afu = to_afu(device);
	int rc;

	if ((rc = capi_ops->afu_reset(afu)))
		return rc;
	return count;
}

static struct device_attribute afu_master_attrs[] = {
	__ATTR(mmio_size, S_IRUGO, mmio_size_show_master, NULL),
	//__ATTR_RO(pp_mmio_off),
	//__ATTR_RO(pp_mmio_len),
};

static struct device_attribute afu_attrs[] = {
	__ATTR_RO(mmio_size),
	//__ATTR_RO(min_irqs),
	//__ATTR_RO(supported_modes),
	//__ATTR_RW(mode),
	__ATTR(reset, S_IWUGO, NULL, reset_store_afu),
};

int capi_sysfs_adapter_add(struct capi_t *adapter)
{
	int i, rc;

	for (i = 0; i < ARRAY_SIZE(adapter_attrs); i++) {
		if ((rc = device_create_file(&adapter->device, &adapter_attrs[i])))
			goto err;
	}
	return 0;
err:
	for (i--; i >= 0; i--)
		device_remove_file(&adapter->device, &adapter_attrs[i]);
	return rc;
}
void capi_sysfs_adapter_remove(struct capi_t *adapter)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(adapter_attrs); i++)
		device_remove_file(&adapter->device, &adapter_attrs[i]);
}

int capi_sysfs_afu_add(struct capi_afu_t *afu)
{
	int afu_attr, mstr_attr, rc = 0;

	for (afu_attr = 0; afu_attr < ARRAY_SIZE(afu_attrs); afu_attr++) {
		if ((rc = device_create_file(&afu->device, &afu_attrs[afu_attr])))
			goto err;
	}
	for (mstr_attr = 0; mstr_attr < ARRAY_SIZE(afu_master_attrs); mstr_attr++) {
		if ((rc = device_create_file(&afu->device_master, &afu_master_attrs[mstr_attr])))
			goto err1;
	}
	return 0;

err1:
	for (mstr_attr--; mstr_attr >= 0; mstr_attr--)
		device_remove_file(&afu->device, &afu_master_attrs[mstr_attr]);
err:
	for (afu_attr--; afu_attr >= 0; afu_attr--)
		device_remove_file(&afu->device, &afu_attrs[afu_attr]);
	return rc;
}
void capi_sysfs_afu_remove(struct capi_afu_t *afu)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(afu_master_attrs); i++)
		device_remove_file(&afu->device, &afu_master_attrs[i]);
	for (i = 0; i < ARRAY_SIZE(afu_attrs); i++)
		device_remove_file(&afu->device, &afu_attrs[i]);
}
