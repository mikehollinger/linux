#ifndef _CXL_HCALLS_
#define _CXL_HCALLS_

#include <linux/compiler.h>
#include <linux/types.h>
#include <asm/hvcall.h>
#include <asm/byteorder.h>

/* Select RIT version when different to PAPR */
#define RIT

#define CXL_HCALL_TIMEOUT 5000

#define H_ATTACH_CA_PROCESS    0x344
#define H_CONTROL_CA_FUNCTION  0x348
#define H_CONTROL_CA_FUNCTION_FULL_RESET                     1
#ifndef RIT
#define H_CONTROL_CA_FUNCTION_NORMAL_RESET                   2
#define H_CONTROL_CA_FUNCTION_DISABLE                        3
#define H_CONTROL_CA_FUNCTION_ENABLE                         4
#define H_CONTROL_CA_FUNCTION_READ_ERR                       5
#define H_CONTROL_CA_FUNCTION_GET_ERR                        6
#define H_CONTROL_CA_FUNCTION_GET_CONFIG                     7
#define H_CONTROL_CA_FUNCTION_GET_DOWNLOAD_STATE             8
#if 0 /* Operation value missing in PAPR */
#define H_CONTROL_CA_FUNCTION_RESET_DOWNLOAD_STATE           ???
#endif
#define H_CONTROL_CA_FUNCTION_SET_FUNCTION_CONFIG_CORRELATOR 9
#define H_CONTROL_CA_FUNCTION_GET_FUNCTION_CONFIG_CORRELATOR 10
#endif
#define H_DETACH_CA_PROCESS    0x34C
#define H_COLLECT_CA_INT_INFO  0x350
#define H_CONTROL_CA_FAULTS    0x354

#if 0 /* STILL TBD */
#define H_DOWNLOAD_CA_FUNCTION ???
#endif

/*
 * This is straight out of PAPR, but replacing some of the compound fields with
 * a single field, where they were identical to the register layout.
 */
/*
 * FIXME: Delete the bitfields - their packing order is undefined, and will
 * probably bite us when running little endian or after upgrading gcc!!
 *
 * I've disabled most with preprocessor where their order matched another
 * variable, but I'll need to handle the last one specially.
 */
#define CXL_PROCESS_ELEMENT_VERSION 1
struct cxl_process_element_hcall {
	__be64 version;
#if 1 /* FIXME: Replace this bitfield! */
	__be64 csrpValid:1,
	       problemState:1,
	       secondarySegmentTableSearchEnabled:1,
	       tagsActive:1,
	       userState:1,
	       translationEnabled:1,
	       sixtyFourBit:1,
	       isPrivilegedProcess:1,
	       reservedFlags:56;
#endif
	u8     reserved0[12];
	__be32 pslVirtualIsn;
	u8     applicationVirtualIsnBitmap[256];
	u8     reserved1[144];
	struct cxl_process_element_common common;
	u8     reserved4[12];
} __packed;

#define CXL_H_WAIT_UNTIL_DONE(rc, ret, fn, ...)                             \
{                                                                            \
        unsigned long retbuf[PLPAR_HCALL_BUFSIZE];                           \
	unsigned int delay, total_delay = 0;                                 \
	u64 token = 0;                                                       \
        while (1) {                                                          \
                rc = plpar_hcall(fn, retbuf, __VA_ARGS__, token);            \
                token = retbuf[0];                                           \
                if (rc != H_BUSY && !H_IS_LONG_BUSY(rc))                     \
			break;                                               \
		                                                             \
		if (rc == H_BUSY)                                            \
			delay = 10; /* FIXME - just count time elapsed, maybe schedule() */ \
		else                                                         \
			delay = get_longbusy_msecs(rc);                      \
		total_delay += delay;                                        \
		if (total_delay > CXL_HCALL_TIMEOUT) {                      \
			WARN(1, "Warning: Giving up waiting for CXL hcall " \
				"%#x after %u msec\n", fn, total_delay);     \
			return -EBUSY;                                       \
		}                                                            \
                mdelay(delay);                                               \
        }                                                                    \
	*ret = retbuf[0];                                                    \
}


static inline long
_cxl_h_attach_process(u64 unit_address, struct cxl_process_element_hcall *element,
		       u64 *process_token)
{
	long rc;
#if 0
	CXL_H_WAIT_UNTIL_DONE(rc, process_token,  H_ATTACH_CA_PROCESS,
			       unit_address, virt_to_phys(element));
	/* XXX This is just an assertion - I noticed PAPR states this is 4 bytes: */
	WARN_ON_ONCE(*process_token & 0xffffffff00000000);
#else
	u64 token = 0;
	unsigned long retbuf[PLPAR_HCALL_BUFSIZE];
	unsigned int delay, total_delay = 0;
	memset(retbuf, 0, sizeof(retbuf));

	while (1) {
		rc = plpar_hcall(H_ATTACH_CA_PROCESS, retbuf, unit_address, virt_to_phys(element), token);
		pr_devel_ratelimited("H_ATTACH_CA_PROCESS(%#.16llx, elem:%#.16lx, ct:%#llx): %li retbuf:[%#lx, %#lx, %#lx, %#lx]\n",
				unit_address, virt_to_phys(element), token, rc, retbuf[0], retbuf[1], retbuf[2], retbuf[3]);
		token = retbuf[0];

                if (rc != H_BUSY && !H_IS_LONG_BUSY(rc))
			break;

		if (rc == H_BUSY)
			delay = 10;
		else
			delay = get_longbusy_msecs(rc);
		total_delay += delay;
		if (total_delay > CXL_HCALL_TIMEOUT) {
			WARN(1, "Warning: Giving up waiting for "
				"H_ATTACH_CA_PROCESS after %u msec\n",
				total_delay);
			return -EBUSY;
		}
		mdelay(delay);
	}
	*process_token = retbuf[0];
#endif

	return rc;
}

/* NOTE: element must be a logical real address, and must be pinned */
static inline long
cxl_h_attach_process(u64 unit_address, struct cxl_process_element_hcall *element,
		      u64 *process_token)
{
	long rc;
	int i;
	u32 *buf;

	pr_devel("---\ncxl_h_attach_process(%#.16llx, %#.16lx) Process Element Structure:\n",
			unit_address, virt_to_phys(element));

	buf = (u32*)element;
	for (i = 0; i*4 < sizeof(struct cxl_process_element_hcall); i += 4) {
		if ((i+3)*4 < sizeof(struct cxl_process_element_hcall))
			pr_devel("%.8x %.8x %.8x %.8x\n", buf[i], buf[i + 1], buf[i + 2], buf[i + 3]);
		else if ((i+2)*4 < sizeof(struct cxl_process_element_hcall))
			pr_devel("%.8x %.8x %.8x\n", buf[i], buf[i + 1], buf[i + 2]);
		else if ((i+1)*4 < sizeof(struct cxl_process_element_hcall))
			pr_devel("%.8x %.8x\n", buf[i], buf[i + 1]);
		else
			pr_devel("%.8x\n", buf[i]);
	}

	rc = _cxl_h_attach_process(unit_address, element, process_token);

	pr_devel("rc: %li token: 0x%.8llx\n", rc, *process_token);
	pr_devel("---\n");

	switch(rc) {
		case H_SUCCESS:
			return 0;
		case H_PARAMETER:
		case H_FUNCTION:
			return -EINVAL;
		case H_RESOURCE:
		case H_HARDWARE:
		case H_STATE:
			return -EBUSY;
		default:
			WARN(1, "Unexpected return code: %lx", rc);
			return -EINVAL;
	}
}

static inline long
cxl_h_detach_process(u64 unit_address, u64 process_token)
{
	long rc;
#if 0
	unsigned long dummy;
	CXL_H_WAIT_UNTIL_DONE(rc, &dummy,  H_DETACH_CA_PROCESS, unit_address,
			       process_token);
#else
	u64 token = 0;
	unsigned long retbuf[PLPAR_HCALL_BUFSIZE];
	unsigned int delay, total_delay = 0;
	memset(retbuf, 0, sizeof(retbuf));

	while (1) {
		rc = plpar_hcall(H_DETACH_CA_PROCESS, retbuf, unit_address, process_token, token);
		pr_devel_ratelimited("H_DETACH_CA_PROCESS(%#.16llx, %#.16llx, ct:%#llx): %li retbuf:[%#lx, %#lx, %#lx, %#lx]\n",
				unit_address, process_token, token, rc, retbuf[0], retbuf[1], retbuf[2], retbuf[3]);
		token = retbuf[0];

                if (rc != H_BUSY && !H_IS_LONG_BUSY(rc))
			break;

		if (rc == H_BUSY)
			delay = 10;
		else
			delay = get_longbusy_msecs(rc);
		total_delay += delay;
		if (total_delay > CXL_HCALL_TIMEOUT) {
			WARN(1, "Warning: Giving up waiting for "
				"H_DETACH_CA_PROCESS after %u msec\n",
				total_delay);
			return -EIO;
		}
		mdelay(delay);
	}
#endif

	pr_devel("cxl_h_detach_process(%#.16llx, 0x%.8llx): %li\n",
			unit_address, process_token, rc);

	switch(rc) {
		case H_SUCCESS:
			return 0;
		case H_PARAMETER:
			return -EINVAL;
		case H_HARDWARE:
		case H_STATE:
			return -EBUSY;
		default:
			WARN(1, "Unexpected return code: %lx", rc);
			return -EINVAL;
	}
}

static inline long
cxl_h_control_function(u64 unit_address, u64 op, u64 p1, u64 p2, u64 p3)
{
	long rc;
#if 0
	unsigned long dummy;
	CXL_H_WAIT_UNTIL_DONE(rc, &dummy, H_CONTROL_CA_FUNCTION, unit_address,
			       op, p1, p2, p3);
#else
	u64 token = 0;
        unsigned long retbuf[PLPAR_HCALL_BUFSIZE];
	unsigned int delay, total_delay = 0;
	memset(retbuf, 0, sizeof(retbuf));
        while (1) {
                rc = plpar_hcall(H_CONTROL_CA_FUNCTION, retbuf, unit_address, op, p1, p2, p3, token);
		pr_devel_ratelimited("H_CONTROL_CA_FUNCTION(%#.16llx, op:%#llx, p1:%#llx, p2:%#llx, p3:%#llx, ct:%#llx): %li retbuf:[%#lx, %#lx, %#lx, %#lx]\n",
				unit_address, op, p1, p2, p3, token, rc, retbuf[0], retbuf[1], retbuf[2], retbuf[3]);
                token = retbuf[0];
                if (rc != H_BUSY && !H_IS_LONG_BUSY(rc))
			break;

		if (rc == H_BUSY)
			delay = 10;
		else
			delay = get_longbusy_msecs(rc);
		total_delay += delay;
		if (total_delay > CXL_HCALL_TIMEOUT) {
			WARN(1, "Warning: Giving up waiting for "
				"H_CONTROL_CA_FUNCTION after %u msec\n",
				total_delay);
			return -EBUSY;
		}
		mdelay(delay);
        }
#endif

	pr_devel("cxl_h_control_function(%#.16llx, %#llx(%#llx, %#llx, %#llx)): %li\n",
			unit_address, op, p1, p2, p3, rc);

	switch(rc) {
		case H_SUCCESS:
			return 0;
		case H_AUTHORITY:
			return -EPERM;
		case H_PARAMETER:
		case H_NOT_FOUND:
			return -EINVAL;
		case H_HARDWARE:
		case H_STATE:
			return -EBUSY;
		default:
			WARN(1, "Unexpected return code: %lx", rc);
			return -EINVAL;
	}
}

static inline long
cxl_h_full_reset(u64 unit_address)
{
	return cxl_h_control_function(unit_address,
				       H_CONTROL_CA_FUNCTION_FULL_RESET,
				       0, 0, 0);
}

#ifndef RIT
static inline long
cxl_h_normal_reset(u64 unit_address, u64 process_token)
{
	return cxl_h_control_function(unit_address,
				       H_CONTROL_CA_FUNCTION_NORMAL_RESET,
				       process_token, 0, 0);
}

static inline long
cxl_h_disable_process(u64 unit_address, u64 process_token)
{
	return cxl_h_control_function(unit_address,
				       H_CONTROL_CA_FUNCTION_DISABLE,
				       process_token, 0, 0);
}

static inline long
cxl_h_enable_process(u64 unit_address, u64 process_token)
{
	return cxl_h_control_function(unit_address,
				       H_CONTROL_CA_FUNCTION_ENABLE,
				       process_token, 0, 0);
}

static inline long
cxl_h_read_error_state(u64 unit_address)
{
	return cxl_h_control_function(unit_address,
				       H_CONTROL_CA_FUNCTION_READ_ERR,
				       0, 0, 0);
}

static inline long
cxl_h_get_error_info(u64 unit_address, unsigned long *buf, u64 len)
{
	return cxl_h_control_function(unit_address,
				       H_CONTROL_CA_FUNCTION_GET_ERR,
				       buf, len, 0);
}

static inline long
cxl_h_get_error_info(u64 unit_address, unsigned long *buf, u64 len)
{
	return cxl_h_control_function(unit_address,
				       H_CONTROL_CA_FUNCTION_GET_CONFIG,
				       buf, len, 0);
}

static inline long
cxl_h_get_fn_download_status(u64 unit_address)
{
	return cxl_h_control_function(unit_address,
				       H_CONTROL_CA_FUNCTION_GET_DOWNLOAD_STATE,
				       0, 0, 0);
}

#if 0 /* Operation value missing in PAPR */
static inline long
cxl_h_reset_fn_download_status(u64 unit_address)
{
	return cxl_h_control_function(unit_address,
			H_CONTROL_CA_FUNCTION_RESET_DOWNLOAD_STATE,
			0, 0, 0);
}
#endif

static inline long
cxl_h_set_fn_config_correlator(u64 unit_address, unsigned long *buf, u64 len)
{
	return cxl_h_control_function(unit_address,
			H_CONTROL_CA_FUNCTION_SET_FUNCTION_CONFIG_CORRELATOR,
			buf, len, 0);
}

static inline long
cxl_h_get_fn_config_correlator(u64 unit_address, unsigned long *buf, u64 len)
{
	return cxl_h_control_function(unit_address,
			H_CONTROL_CA_FUNCTION_GET_FUNCTION_CONFIG_CORRELATOR,
			buf, len, 0);
}
#endif

static inline long
cxl_h_collect_int_info(u64 unit_address, u64 process_token,
			struct cxl_irq_info *info)
{
	long rc;

	BUG_ON(sizeof(*info) != sizeof(unsigned long[PLPAR_HCALL9_BUFSIZE]));

	rc = plpar_hcall9(H_COLLECT_CA_INT_INFO, (unsigned long *)info,
			unit_address, process_token);

	pr_devel("cxl_h_collect_int_info(%#.16llx, 0x%llx): %li\n",
			unit_address, process_token, rc);

	switch(rc) {
		case H_SUCCESS:
			return 0;
		case H_PARAMETER:
			return -EINVAL;
		case H_HARDWARE:
		case H_STATE:
			return -EBUSY;
		default:
			WARN(1, "Unexpected return code: %lx", rc);
			return -EINVAL;
	}
}

/*
 * control_mask looks like PSL_TFC_An shifted >> 32
 * Set reset_mask = 1 to reset PSL errors
 */
static inline long
cxl_h_control_faults(u64 unit_address, u64 process_token, u64 control_mask,
		      u64 reset_mask, u64 *ret)
{
	long rc;
	CXL_H_WAIT_UNTIL_DONE(rc, ret,  H_CONTROL_CA_FAULTS, unit_address,
			       process_token, control_mask, reset_mask);

	pr_devel("cxl_h_control_faults(%#.16llx, 0x%llx, %#llx, %#llx): %li %#llx\n",
			unit_address, process_token, control_mask, reset_mask, rc, *ret);

	switch(rc) {
		case H_SUCCESS:
			return 0;
		case H_PARAMETER:
			return -EINVAL;
		case H_HARDWARE:
		case H_STATE:
			return -EBUSY;
		default:
			WARN(1, "Unexpected return code: %lx", rc);
			return -EINVAL;
	}
}

#if 0 /* Details still TBD */
static inline long
cxl_h_download_function(u64 unit_address, u64 block_list_address,
			 u64 num_block_list_entries, u64 total_image_size)
{
	long rc;
	CXL_H_WAIT_UNTIL_DONE(rc, ret,  H_DOWNLOAD_CA_FUNCTION, unit_address,
			       block_list_address, num_block_list_entries,
			       total_image_size);

	switch(rc) {
		case H_SUCCESS:
			return 0;
		case H_PARAMETER:
		case H_SG_LIST: /* XXX print specific error? */
		case H_TOO_BIG: /* XXX print specific error? */
		case H_BAD_DATA: /* XXX print specific error? */
			return -EINVAL;
		case H_HARDWARE:
		case H_STATE:
		case H_RESOURCE:
			return -EBUSY;
		case H_AUTHORITY:
			return -EPERM;
		case H_PARTIAL:
			WARN(1, "FIXME: Handle H_PARTIAL from AFU download\n");
			return -EAGAIN;
		default:
			WARN(1, "Unexpected return code: %lx", rc);
			return -EINVAL;
	}
}
#endif

#endif
