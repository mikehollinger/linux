/*
 * Copyright 2014 IBM Corp.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <linux/debugfs.h>
#include <linux/kernel.h>
#include <linux/slab.h>

#include "cxl.h"

struct dentry *cxl_debugfs;

int cxl_debugfs_init(void)
{
	struct dentry *ent;
	ent = debugfs_create_dir("cxl", NULL);
	if (IS_ERR(ent))
		return PTR_ERR(ent);
	cxl_debugfs = ent;

	return 0;
}

void cxl_debugfs_exit(void)
{
	debugfs_remove_recursive(cxl_debugfs);
}

void cxl_stop_trace(struct cxl_t *cxl)
{
	int slice;

	/* Stop the trace */
	cxl_p1_write(cxl, CXL_PSL_TRACE, 0x8000000000000017LL);

	/* Stop the slice traces */
	for (slice = 0; slice < cxl->slices; slice++)
		cxl_p1n_write(&cxl->slice[slice], CXL_PSL_SLICE_TRACE, 0x8000000000000000LL);
}

int cxl_debugfs_adapter_add(struct cxl_t *adapter)
{
	if (!cxl_debugfs)
		return -ENODEV;

	debugfs_create_x64("fir1",     S_IRUSR, cxl_debugfs, _cxl_p1_addr(adapter, CXL_PSL_FIR1));
	debugfs_create_x64("fir2",     S_IRUSR, cxl_debugfs, _cxl_p1_addr(adapter, CXL_PSL_FIR2));
	debugfs_create_x64("fir_cntl", S_IRUSR, cxl_debugfs, _cxl_p1_addr(adapter, CXL_PSL_FIR_CNTL));
	debugfs_create_x64("err_ivte", S_IRUSR, cxl_debugfs, _cxl_p1_addr(adapter, CXL_PSL_ErrIVTE));

	debugfs_create_x64("trace", S_IRUSR | S_IWUSR, cxl_debugfs, _cxl_p1_addr(adapter, CXL_PSL_TRACE));

	return 0;
}

int cxl_debugfs_afu_add(struct cxl_afu_t *afu)
{
	struct dentry *dir;
	char buf[32];

	if (!cxl_debugfs)
		return -ENODEV;

	snprintf(buf, 32, "psl%i.%i", afu->adapter->adapter_num, afu->slice);
	dir = debugfs_create_dir(buf, cxl_debugfs);
	if (IS_ERR(dir))
		return PTR_ERR(dir);

	debugfs_create_x64("fir",       S_IRUSR, dir, _cxl_p1n_addr(afu, CXL_PSL_FIR_SLICE_An));
	debugfs_create_x64("fir_recov", S_IRUSR, dir, _cxl_p1n_addr(afu, CXL_PSL_R_FIR_SLICE_An));
	debugfs_create_x64("serr",      S_IRUSR, dir, _cxl_p1n_addr(afu, CXL_PSL_SERR_An));
	debugfs_create_x64("sr",        S_IRUSR, dir, _cxl_p1n_addr(afu, CXL_PSL_SR_An));

	debugfs_create_x64("dsisr",     S_IRUSR, dir, _cxl_p2n_addr(afu, CXL_PSL_DSISR_An));
	debugfs_create_x64("dar",       S_IRUSR, dir, _cxl_p2n_addr(afu, CXL_PSL_DAR_An));
	debugfs_create_x64("sstp0",     S_IRUSR, dir, _cxl_p2n_addr(afu, CXL_SSTP0_An));
	debugfs_create_x64("sstp1",     S_IRUSR, dir, _cxl_p2n_addr(afu, CXL_SSTP1_An));
	debugfs_create_x64("err_stat",  S_IRUSR, dir, _cxl_p2n_addr(afu, CXL_PSL_ErrStat_An));

	debugfs_create_x64("trace", S_IRUSR | S_IWUSR, dir, _cxl_p1n_addr(afu, CXL_PSL_SLICE_TRACE));

	return 0;
}
