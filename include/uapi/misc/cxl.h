/*
 * Copyright 2014 IBM Corp.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#ifndef _UAPI_ASM_CXL_H
#define _UAPI_ASM_CXL_H

#include <linux/types.h>
#include <linux/ioctl.h>

/* structs for IOCTLS for userspace to talk to the kernel */
struct cxl_ioctl_start_work {
	__u64 flags;
	__u64 wed;
	__u64 amr;
	__s16 num_interrupts;
	__s16 reserved1;
	__s32 reserved2;
	__u64 reserved3;
	__u64 reserved4;
	__u64 reserved5;
	__u64 reserved6;
};
#define CXL_START_WORK_AMR		0x0000000000000001UUL
#define CXL_START_WORK_NUM_IRQS		0x0000000000000002UUL
#define CXL_START_WORK_ALL		(CXL_START_WORK_AMR |\
					CXL_START_WORK_NUM_IRQS

struct cxl_ioctl_get_info {
	__u64 flags;
	__u32 api_version_compatible;
	__u32 api_version;
	__u16 process_element;
	__s16 reserved1;
	__s32 reserved2;
	__u64 reserved3;
};

/* IOCTL numbers */
#define CXL_MAGIC 0xCA
#define CXL_IOCTL_START_WORK      _IOW(CXL_MAGIC, 0x00, struct cxl_ioctl_start_work)
#define CXL_IOCTL_GET_INFO	  _IOR(CXL_MAGIC, 0x01, struct cxl_ioctl_get_info)
#define CXL_IOCTL_CHECK_ERROR     _IO(CXL_MAGIC, 0x02)


/* Events from read() */
enum cxl_event_type {
	CXL_EVENT_RESERVED      = 0,
	CXL_EVENT_AFU_INTERRUPT = 1,
	CXL_EVENT_DATA_STORAGE  = 2,
	CXL_EVENT_AFU_ERROR     = 3,
};

struct cxl_event_header {
	__u16 type;
	__u16 size;
	__u16 process_element;
	__u16 reserved1;
};

struct cxl_event_afu_interrupt {
	__u16 flags;
	__u16 irq; /* Raised AFU interrupt number */
	__u32 reserved1;
};

struct cxl_event_data_storage {
	__u16 flags;
	__u16 dsisr;
	__u32 reserved1;
	__u64 addr;
};
#define CXL_EVENT_DSISR_STORAGE_RW	0x0001
#define CXL_EVENT_DSISR_SEGMENT		0x0002
#define CXL_EVENT_DSISR_PAGE		0x0004
#define CXL_EVENT_DSISR_PROTECTION	0x0008
#define CXL_EVENT_DSISR_MANDITORY	(CXL_EVENT_DSISR_RW |\
					 CXL_EVENT_DSISR_SEGMENT |\
					 CXL_EVENT_DSISR_PAGE |
					 CXL_EVENT_DSISR_PROTECTION)

struct cxl_event_afu_error {
	__u16 flags;
	__u16 reserved1;
	__u32 reserved2;
	__u64 err;
};

struct cxl_event {
	struct cxl_event_header header;
	union {
		struct cxl_event_afu_interrupt irq;
		struct cxl_event_data_storage fault;
		struct cxl_event_afu_error afu_err;
	};
};

#ifdef __KERNEL__
/*
 * If these change we really need to update API.  Either change some
 * flags or update API version numbers.
 */
BUILD_BUG_ON(sizeof(struct cxl_event_header) == 64);
BUILD_BUG_ON(sizeof(struct cxl_event_afu_interrupt) == 64);
BUILD_BUG_ON(sizeof(struct cxl_event_data_storage) == 128);
BUILD_BUG_ON(sizeof(struct cxl_event_afu_error) == 128);

#endif

#endif
