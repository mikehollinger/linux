#include <linux/debugfs.h>
#include <linux/kernel.h>
#include <linux/slab.h>

#include "cxl.h"

struct dentry *cxl_debugfs;

int cxl_debugfs_init(void)
{
	struct dentry *ent;
	ent = debugfs_create_dir("cxl", NULL);
	if (IS_ERR(ent)) {
		return PTR_ERR(ent);
	}
	cxl_debugfs = ent;

	return 0;
}

void cxl_debugfs_exit(void)
{
	debugfs_remove_recursive(cxl_debugfs);
}

struct trcdsc {
	unsigned char name[8];
	unsigned int slice;
	unsigned int readsperline;
	unsigned int traceid;
	unsigned int addr;
};

static struct trcdsc descriptors[] = {
	{ "ahctr  ", 1, 0x3, 0x0, 512 } ,
	{ "ersptr ", 1, 0x1, 0x3, 512 } ,
	{ "twdatr ", 1, 0x9, 0xa, 512 } ,
	{ "crsptr ", 1, 0x1, 0x2, 512 } ,
	{ "hartr  ", 1, 0x1, 0x1, 512 } ,
	{ "twtr   ", 1, 0x3, 0x7, 512 } ,
	{ "rtwtr  ", 1, 0x2, 0x8, 512 } ,
	{ "ssprot ", 0, 0x3, 0xc, 512 } ,
	{ "datr   ", 0, 0x6, 0xf, 4096 } ,
	{ "r0tiftr", 1, 0x3, 0xd, 512 } ,
	{ "b0rvalt", 1, 0x9, 0x4, 512 } ,
	{ "b0wvalt", 1, 0x9, 0x5, 512 } ,
	{ "rwtiftr", 0, 0x3, 0x9, 512 } ,
	{ "rqinftr", 0, 0x4, 0x8, 512 } ,
	{ "rqinft2", 0, 0x4, 0xa, 512 } ,
	{ "pslcmd ", 0, 0x3, 0x3, 512 } ,
	{ "pslsndt", 0, 0x2, 0xd, 512 } ,
	{ "rdintr ", 0, 0x9, 0x4, 512 } ,
	{ "wrrdy  ", 0, 0x1, 0x5, 512 } ,
	{ "wdoutr ", 0, 0x9, 0x6, 512 } ,
	{ "rxdcdtr", 0, 0x3, 0x0, 512 } ,
	{ "rxsnp  ", 0, 0x2, 0x1, 512 } ,
	{ "apcrspt", 0, 0x2, 0x2, 512 } ,
	{ "dsisrtr", 1, 0x1, 0x6, 512 } ,
	{ "jmcmdtr", 1, 0x2, 0xe, 512 } ,
	{ "tbtr   ", 0, 0x3, 0xb, 512 } ,
	{ {0x0}, 0, 0, 0, 0 },
};

static u64 dump_size(void)
{
	struct trcdsc *dsc = &descriptors[0];
	u64 size = 2*8;

	while (dsc->addr) {
		size += 2*8;
		size += 8*(dsc->addr*dsc->readsperline);
		dsc++;
	}

	return size;
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

static void dump_trace(unsigned long long *buffer, struct cxl_t *cxl)
{
	struct trcdsc *dsc = &descriptors[0];

	cxl_stop_trace(cxl);

	/* Get read write machine state */
	*buffer++ = cxl_p1_read(cxl, CXL_PSL_TRACE);

	while (dsc->addr) {
		unsigned long long namev = 0;
		unsigned long long sv = 64-8;
		int i, j;

		/* Init trace engine */
		if (dsc->slice)
			cxl_p1n_write(&cxl->slice[0], CXL_PSL_SLICE_TRACE,
				       0x8000000000000000LL |
				       dsc->readsperline << 4 |
				       dsc->traceid);
		else
			cxl_p1_write(cxl, CXL_PSL_TRACE,
				      0x8000000000000000LL |
				      dsc->readsperline << 4 |
				      dsc->traceid);

		/* Write descriptor record */
		*buffer++ = 0xb0f0000000000000LL | (dsc->addr * dsc->readsperline);

		for (i = 0; i < 8; i++)	{
			namev |= (unsigned long long)(dsc->name[i]) << sv;
			sv -= 8;
		}
		*buffer++ = namev;

		/* Read out trace */
		for (i = 0; i < dsc->addr; i++)
			for (j = 0; j < dsc->readsperline; j++) {
				*buffer++ = (dsc->slice) ?
					cxl_p1n_read(&cxl->slice[0], CXL_PSL_SLICE_TRACE) :
					cxl_p1_read(cxl, CXL_PSL_TRACE);
			}

		dsc++;
	}

	*buffer++ = 0xE0F0000000000000LL;
}

static unsigned long long *trace_buffer;

static ssize_t read_trace(struct file *file, char __user *userbuf,
			 size_t count, loff_t *ppos)
{
	u64 size = dump_size();
	struct cxl_t *cxl = file->private_data;

	if (!trace_buffer)
		trace_buffer = kzalloc(size, GFP_KERNEL);

	if (!trace_buffer)
		return -ENOMEM;

	dump_trace(trace_buffer, cxl);
	return simple_read_from_buffer(userbuf, count, ppos, trace_buffer, size);
}

static int open_trace(struct inode *inode, struct file *file)
{
	file->private_data = inode->i_private;

	return 0;
}

static const struct file_operations trace_fops = {
	.open = open_trace,
	.read = read_trace,
};



int cxl_debugfs_adapter_add(struct cxl_t *adapter)
{
	char buf[32];

	/* FIXME: This assumes AFU 0 */
	pr_devel("Creating CXL debugfs entries\n");
	snprintf(buf, 32, "psl%i_trace", adapter->adapter_num);
	adapter->trace = debugfs_create_file(buf, 0444, cxl_debugfs, adapter, &trace_fops);

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

	snprintf(buf, 32, "psl%i.%i", afu->adapter->adapter_num, afu->slice);
	dir = debugfs_create_dir(buf, cxl_debugfs);

	debugfs_create_x64("fir",       S_IRUSR, dir, _cxl_p1n_addr(afu, CXL_PSL_FIR_SLICE_An));
	debugfs_create_x64("fir_recov", S_IRUSR, dir, _cxl_p1n_addr(afu, CXL_PSL_R_FIR_SLICE_An));
	debugfs_create_x64("serr",      S_IRUSR, dir, _cxl_p1n_addr(afu, CXL_PSL_SERR_An));
	debugfs_create_x64("sr",        S_IRUSR, dir, _cxl_p1n_addr(afu, CXL_PSL_SR_An));

	debugfs_create_x64("dsisr",     S_IRUSR, dir, _cxl_p2n_addr(afu, CXL_PSL_DSISR_An));
	debugfs_create_x64("dar",       S_IRUSR, dir, _cxl_p2n_addr(afu, CXL_PSL_DAR_An));
	debugfs_create_x64("sstp0",     S_IRUSR, dir, _cxl_p2n_addr(afu, CXL_SSTP0_An));
	debugfs_create_x64("sstp1",     S_IRUSR, dir, _cxl_p2n_addr(afu, CXL_SSTP1_An));
	debugfs_create_x64("err_stat",  S_IRUSR, dir, _cxl_p2n_addr(afu, CXL_PSL_ErrStat_An));

	debugfs_create_x64("trace", S_IRUSR | S_IWUSR, dir, _cxl_p2n_addr(afu, CXL_PSL_SLICE_TRACE));

	return 0;
}
