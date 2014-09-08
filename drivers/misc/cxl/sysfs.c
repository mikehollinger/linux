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

#define to_afu(d) container_of(d, struct cxl_afu_t, device)
#define master_to_afu(d) container_of(d, struct cxl_afu_t, device_master)


/*********  AFU master specific attributes  **********************************/

static ssize_t mmio_size_show_master(struct device *device,
				     struct device_attribute *attr,
				     char *buf)
{
	struct cxl_afu_t *afu = master_to_afu(device);

	return scnprintf(buf, PAGE_SIZE, "%llu\n", afu->psn_size);
}

static ssize_t pp_mmio_off_show(struct device *device,
				struct device_attribute *attr,
				char *buf)
{
	struct cxl_afu_t *afu = master_to_afu(device);

	return scnprintf(buf, PAGE_SIZE, "%llu\n", afu->pp_offset);
}

static ssize_t pp_mmio_len_show(struct device *device,
				struct device_attribute *attr,
				char *buf)
{
	struct cxl_afu_t *afu = master_to_afu(device);

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
	struct cxl_afu_t *afu = to_afu(device);

	if (afu->pp_size)
		return scnprintf(buf, PAGE_SIZE, "%llu\n", afu->pp_size);
	return scnprintf(buf, PAGE_SIZE, "%llu\n", afu->psn_size);
}

static ssize_t reset_store_afu(struct device *device,
			       struct device_attribute *attr,
			       const char *buf, size_t count)
{
	struct cxl_afu_t *afu = to_afu(device);
	int rc;

	if ((rc = cxl_ops->afu_reset(afu)))
		return rc;
	return count;
}

static ssize_t irqs_min_show(struct device *device,
			     struct device_attribute *attr,
			     char *buf)
{
	struct cxl_afu_t *afu = to_afu(device);

	return scnprintf(buf, PAGE_SIZE, "%i\n", afu->pp_irqs);
}

static ssize_t irqs_max_show(struct device *device,
				  struct device_attribute *attr,
				  char *buf)
{
	struct cxl_afu_t *afu = to_afu(device);

	return scnprintf(buf, PAGE_SIZE, "%i\n", afu->irqs_max);
}

static ssize_t irqs_max_store(struct device *device,
				  struct device_attribute *attr,
				  const char *buf, size_t count)
{
	struct cxl_afu_t *afu = to_afu(device);
	ssize_t ret;
	int irqs_max;

	ret = sscanf(buf, "%i", &irqs_max);
	if (ret != 1)
		return -EINVAL;

	if (irqs_max < afu->pp_irqs)
		return -EINVAL;

	if (irqs_max > afu->user_irqs)
		return -EINVAL;

	afu->irqs_max = irqs_max;
	return count;
}

static ssize_t supported_modes_show(struct device *device,
				    struct device_attribute *attr,
				    char *buf)
{
	struct cxl_afu_t *afu = to_afu(device);
	char *p = buf, *end = buf + PAGE_SIZE;

	if (afu->afu_dedicated_mode)
		p += scnprintf(p, end - p, "dedicated_process\n");
	if (afu->afu_directed_mode)
		p += scnprintf(p, end - p, "afu_directed\n");
	return (p - buf);
}

static ssize_t mode_show(struct device *device,
			 struct device_attribute *attr,
			 char *buf)
{
	struct cxl_afu_t *afu = to_afu(device);

	if (afu->afu_dedicated_mode)
		return scnprintf(buf, PAGE_SIZE, "dedicated_process\n");
	if (afu->afu_directed_mode)
		return scnprintf(buf, PAGE_SIZE, "afu_directed\n");
	return -EINVAL;
}

static ssize_t mode_store(struct device *device,
			  struct device_attribute *attr,
			  const char *buf, size_t count)
{
	if (!strncmp(buf, "dedicated_process", 17))
		pr_warn("cxl: switching to dedicated mode live not implemented yet\n");
	if (!strncmp(buf, "afu_directed", 12))
		pr_warn("cxl: switching to directed mode live not implemented yet\n");
	return -EINVAL;
}

static struct device_attribute afu_attrs[] = {
	__ATTR_RO(mmio_size),
	__ATTR_RO(irqs_min),
	__ATTR_RW(irqs_max),
	__ATTR_RO(supported_modes),
	__ATTR_RW(mode),
	__ATTR(reset, S_IWUSR, NULL, reset_store_afu),
};

int cxl_sysfs_afu_add(struct cxl_afu_t *afu)
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
void cxl_sysfs_afu_remove(struct cxl_afu_t *afu)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(afu_master_attrs); i++)
		device_remove_file(&afu->device, &afu_master_attrs[i]);
	for (i = 0; i < ARRAY_SIZE(afu_attrs); i++)
		device_remove_file(&afu->device, &afu_attrs[i]);
}
