/*
 * Copyright 2014 IBM Corp.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/sysfs.h>

#include "cxl.h"

#define to_afu_chardev_m(d) dev_get_drvdata(d)

/*********  Adapter attributes  **********************************************/

static ssize_t caia_version_show(struct device *device,
				 struct device_attribute *attr,
				 char *buf)
{
	struct cxl_t *adapter = to_cxl_adapter(device);

	return scnprintf(buf, PAGE_SIZE, "%i.%i\n", adapter->caia_major,
			 adapter->caia_minor);
}

static ssize_t psl_revision_show(struct device *device,
				 struct device_attribute *attr,
				 char *buf)
{
	struct cxl_t *adapter = to_cxl_adapter(device);

	return scnprintf(buf, PAGE_SIZE, "%i\n", adapter->psl_rev);
}

static ssize_t base_image_show(struct device *device,
			       struct device_attribute *attr,
			       char *buf)
{
	struct cxl_t *adapter = to_cxl_adapter(device);

	return scnprintf(buf, PAGE_SIZE, "%i\n", adapter->base_image);
}

static ssize_t image_loaded_show(struct device *device,
				 struct device_attribute *attr,
				 char *buf)
{
	struct cxl_t *adapter = to_cxl_adapter(device);

	if (adapter->user_image_loaded)
		return scnprintf(buf, PAGE_SIZE, "user\n");
	return scnprintf(buf, PAGE_SIZE, "factory\n");
}

static struct device_attribute adapter_attrs[] = {
	__ATTR_RO(caia_version),
	__ATTR_RO(psl_revision),
	__ATTR_RO(base_image),
	__ATTR_RO(image_loaded),
	/* __ATTR_RW(reset_loads_image); */
	/* __ATTR_RW(reset_image_select); */
};


/*********  AFU master specific attributes  **********************************/

static ssize_t mmio_size_show_master(struct device *device,
				     struct device_attribute *attr,
				     char *buf)
{
	struct cxl_afu_t *afu = to_afu_chardev_m(device);

	return scnprintf(buf, PAGE_SIZE, "%llu\n", afu->adapter->ps_size);
}

static ssize_t pp_mmio_off_show(struct device *device,
				struct device_attribute *attr,
				char *buf)
{
	struct cxl_afu_t *afu = to_afu_chardev_m(device);

	return scnprintf(buf, PAGE_SIZE, "%llu\n", afu->pp_offset);
}

static ssize_t pp_mmio_len_show(struct device *device,
				struct device_attribute *attr,
				char *buf)
{
	struct cxl_afu_t *afu = to_afu_chardev_m(device);

	return scnprintf(buf, PAGE_SIZE, "%llu\n", afu->pp_size);
}

static struct device_attribute afu_master_attrs[] = {
	__ATTR(mmio_size, S_IRUGO, mmio_size_show_master, NULL),
	__ATTR_RO(pp_mmio_off),
	__ATTR_RO(pp_mmio_len),
};


/*********  AFU attributes  **************************************************/

static ssize_t mmio_size_show(struct device *device,
			      struct device_attribute *attr,
			      char *buf)
{
	struct cxl_afu_t *afu = to_cxl_afu(device);

	if (afu->pp_size)
		return scnprintf(buf, PAGE_SIZE, "%llu\n", afu->pp_size);
	return scnprintf(buf, PAGE_SIZE, "%llu\n", afu->adapter->ps_size);
}

static ssize_t reset_store_afu(struct device *device,
			       struct device_attribute *attr,
			       const char *buf, size_t count)
{
	struct cxl_afu_t *afu = to_cxl_afu(device);
	int rc;

	if ((rc = cxl_ops->afu_reset(afu)))
		return rc;
	return count;
}

static ssize_t irqs_min_show(struct device *device,
			     struct device_attribute *attr,
			     char *buf)
{
	struct cxl_afu_t *afu = to_cxl_afu(device);

	return scnprintf(buf, PAGE_SIZE, "%i\n", afu->pp_irqs);
}

static ssize_t irqs_max_show(struct device *device,
				  struct device_attribute *attr,
				  char *buf)
{
	struct cxl_afu_t *afu = to_cxl_afu(device);

	return scnprintf(buf, PAGE_SIZE, "%i\n", afu->irqs_max);
}

static ssize_t irqs_max_store(struct device *device,
				  struct device_attribute *attr,
				  const char *buf, size_t count)
{
	struct cxl_afu_t *afu = to_cxl_afu(device);
	ssize_t ret;
	int irqs_max;

	ret = sscanf(buf, "%i", &irqs_max);
	if (ret != 1)
		return -EINVAL;

	if (irqs_max < afu->pp_irqs)
		return -EINVAL;

	if (irqs_max > afu->adapter->user_irqs)
		return -EINVAL;

	afu->irqs_max = irqs_max;
	return count;
}

static ssize_t models_supported_show(struct device *device,
				    struct device_attribute *attr,
				    char *buf)
{
	struct cxl_afu_t *afu = to_cxl_afu(device);
	char *p = buf, *end = buf + PAGE_SIZE;

	if (afu->models_supported & CXL_MODEL_DEDICATED)
		p += scnprintf(p, end - p, "dedicated_process\n");
	if (afu->models_supported & CXL_MODEL_DIRECTED)
		p += scnprintf(p, end - p, "afu_directed\n");
	return (p - buf);
}

static ssize_t prefault_mode_show(struct device *device,
				  struct device_attribute *attr,
				  char *buf)
{
	struct cxl_afu_t *afu = to_cxl_afu(device);

	switch (afu->prefault_mode) {
	case CXL_PREFAULT_WED:
		return scnprintf(buf, PAGE_SIZE, "wed\n");
	case CXL_PREFAULT_ALL:
		return scnprintf(buf, PAGE_SIZE, "all\n");
	default:
		return scnprintf(buf, PAGE_SIZE, "none\n");
	}
}

static ssize_t prefault_mode_store(struct device *device,
			  struct device_attribute *attr,
			  const char *buf, size_t count)
{
	struct cxl_afu_t *afu = to_cxl_afu(device);
	enum prefault_modes mode = -1;

	if (!strncmp(buf, "wed", 3))
		mode = CXL_PREFAULT_WED;
	if (!strncmp(buf, "all", 3))
		mode = CXL_PREFAULT_ALL;
	if (!strncmp(buf, "none", 4))
		mode = CXL_PREFAULT_NONE;

	if (mode == -1)
		return -EINVAL;

	afu->prefault_mode = mode;
	return count;
}

static ssize_t model_show(struct device *device,
			 struct device_attribute *attr,
			 char *buf)
{
	struct cxl_afu_t *afu = to_cxl_afu(device);

	if (afu->current_model == CXL_MODEL_DEDICATED)
		return scnprintf(buf, PAGE_SIZE, "dedicated_process\n");
	if (afu->current_model == CXL_MODEL_DIRECTED)
		return scnprintf(buf, PAGE_SIZE, "afu_directed\n");
	return scnprintf(buf, PAGE_SIZE, "none\n");
}

static ssize_t model_store(struct device *device,
			   struct device_attribute *attr,
			   const char *buf, size_t count)
{
	struct cxl_afu_t *afu = to_cxl_afu(device);
	int old_model, model = -1;
	int rc = -EBUSY;

	/* can't change this if we have a user */
	spin_lock(&afu->contexts_lock);
	if (!idr_is_empty(&afu->contexts_idr))
		goto err;

	if (!strncmp(buf, "dedicated_process", 17))
		model = CXL_MODEL_DEDICATED;
	if (!strncmp(buf, "afu_directed", 12))
		model = CXL_MODEL_DIRECTED;
	if (!strncmp(buf, "none", 4))
		model = 0;

	if (model == -1) {
		rc = -EINVAL;
		goto err;
	}

	/* cxl_afu_deactivate_model needs to be done outside the lock, prevent
	 * other contexts coming in before we are ready: */
	old_model = afu->current_model;
	afu->current_model = 0;
	afu->num_procs = 0;

	spin_unlock(&afu->contexts_lock);

	if ((rc = _cxl_afu_deactivate_model(afu, old_model)))
		return rc;
	if ((rc = cxl_afu_activate_model(afu, model)))
		return rc;

	return count;
err:
	spin_unlock(&afu->contexts_lock);
	return rc;
}

static struct device_attribute afu_attrs[] = {
	__ATTR_RO(mmio_size),
	__ATTR_RO(irqs_min),
	__ATTR_RW(irqs_max),
	__ATTR_RO(models_supported),
	__ATTR_RW(model),
	__ATTR_RW(prefault_mode),
	__ATTR(reset, S_IWUSR, NULL, reset_store_afu),
};



int cxl_sysfs_adapter_add(struct cxl_t *adapter)
{
	int i, rc;

	for (i = 0; i < ARRAY_SIZE(adapter_attrs); i++) {
		if ((rc = device_create_file(&adapter->dev, &adapter_attrs[i])))
			goto err;
	}
	return 0;
err:
	for (i--; i >= 0; i--)
		device_remove_file(&adapter->dev, &adapter_attrs[i]);
	return rc;
}
EXPORT_SYMBOL(cxl_sysfs_adapter_add);
void cxl_sysfs_adapter_remove(struct cxl_t *adapter)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(adapter_attrs); i++)
		device_remove_file(&adapter->dev, &adapter_attrs[i]);
}
EXPORT_SYMBOL(cxl_sysfs_adapter_remove);

int cxl_sysfs_afu_add(struct cxl_afu_t *afu)
{
	int afu_attr, mstr_attr, rc = 0;

	for (afu_attr = 0; afu_attr < ARRAY_SIZE(afu_attrs); afu_attr++) {
		if ((rc = device_create_file(&afu->dev, &afu_attrs[afu_attr])))
			goto err;
	}
	for (mstr_attr = 0; mstr_attr < ARRAY_SIZE(afu_master_attrs); mstr_attr++) {
		if ((rc = device_create_file(afu->chardev_m, &afu_master_attrs[mstr_attr])))
			goto err1;
	}

	return 0;

err1:
	for (mstr_attr--; mstr_attr >= 0; mstr_attr--)
		device_remove_file(afu->chardev_m, &afu_master_attrs[mstr_attr]);
err:
	for (afu_attr--; afu_attr >= 0; afu_attr--)
		device_remove_file(&afu->dev, &afu_attrs[afu_attr]);
	return rc;
}
EXPORT_SYMBOL(cxl_sysfs_afu_add);

void cxl_sysfs_afu_remove(struct cxl_afu_t *afu)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(afu_master_attrs); i++)
		device_remove_file(afu->chardev_m, &afu_master_attrs[i]);
	for (i = 0; i < ARRAY_SIZE(afu_attrs); i++)
		device_remove_file(&afu->dev, &afu_attrs[i]);
}
EXPORT_SYMBOL(cxl_sysfs_afu_remove);
