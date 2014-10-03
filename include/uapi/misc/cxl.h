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

/* ioctls */
struct cxl_ioctl_start_work {
	__u64 wed;
	__u64 amr;
	__u64 reserved1;
	__u32 reserved2;
	__s16 num_interrupts; /* -1 = use value from afu descriptor */
	__u16 process_element; /* returned from kernel */
	__u64 reserved3;
	__u64 reserved4;
	__u64 reserved5;
	__u64 reserved6;
};

#define CXL_MAGIC 0xCA
#define CXL_IOCTL_START_WORK      _IOWR(CXL_MAGIC, 0x00, struct cxl_ioctl_start_work)
#define CXL_IOCTL_CHECK_ERROR     _IO(CXL_MAGIC,   0x01)

/* events from read() */

#define CXL_READ_MIN_SIZE 0x1000 /* 4K */

enum cxl_event_type {
	CXL_EVENT_RESERVED      = 0,
	CXL_EVENT_AFU_INTERRUPT = 1,
	CXL_EVENT_DATA_STORAGE  = 2,
	CXL_EVENT_AFU_ERROR     = 3,
};

struct cxl_event_header {
	__u32 type;
	__u16 size;
	__u16 process_element;
	__u64 reserved1;
	__u64 reserved2;
	__u64 reserved3;
};

struct cxl_event_afu_interrupt {
	__u16 irq; /* Raised AFU interrupt number */
	__u16 reserved1;
	__u32 reserved2;
	__u64 reserved3;
	__u64 reserved4;
	__u64 reserved5;
};

struct cxl_event_data_storage {
	__u64 addr;
	__u64 reserved1;
	__u64 reserved2;
	__u64 reserved3;
};

struct cxl_event_afu_error {
	__u64 err;
	__u64 reserved1;
	__u64 reserved2;
	__u64 reserved3;
};

struct cxl_event {
	struct cxl_event_header header;
	union {
		struct cxl_event_afu_interrupt irq;
		struct cxl_event_data_storage fault;
		struct cxl_event_afu_error afu_err;
	};
};

#endif
