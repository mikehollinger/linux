#ifndef _UAPI_ASM_CXL_H
#define _UAPI_ASM_CXL_H

#include <linux/types.h>

/* ioctls */

/* Argument is a pointer to a struct cxl_ioctl_start_work */
#define CXL_IOCTL_START_WORK      0
#define CXL_IOCTL_CHECK_ERROR     2

struct cxl_ioctl_start_work {
	__u64 wed;
	__u64 amr;
	__u64 ctx_save_ptr; /* Ignored in dedicated process model */
	__u32 ctx_save_size; /* In bytes */
	__s16 num_interrupts; /* -1 = use value from afu descriptor */
	__u16 process_element; /* returned from kernel */
	__u64 reserved1;
	__u64 reserved2;
	__u64 reserved3;
	__u64 reserved4;
};

/* events from read() */

enum cxl_event_type {
	CXL_EVENT_READ_FAIL     = -1,
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

#if 0
/*
 * This was an old convenience structure guaranteed to be the same size as the
 * largest event, so userspace could use one of these as the buffer to receive
 * an event and then cast it into the specific event structure from
 * header->type.
 *
 * This has been deprecated in favour of using struct cxl_event with each
 * possible event type in a union.
 */
struct cxl_event_uncast {
	struct cxl_event_header header;
	__u64 reserved1;
	__u64 reserved2;
	__u64 reserved3;
	__u64 reserved4;
};
#endif

struct cxl_event_afu_interrupt {
	struct cxl_event_header header;
	__u16 irq; /* Raised AFU interrupt number */
	__u16 reserved1;
	__u32 reserved2;
	__u64 reserved3;
	__u64 reserved4;
	__u64 reserved5;
};

struct cxl_event_data_storage {
	struct cxl_event_header header;
	__u64 addr;
	__u64 reserved1;
	__u64 reserved2;
	__u64 reserved3;
};

struct cxl_event_afu_error {
	struct cxl_event_header header;
	__u64 err;
	__u64 reserved1;
	__u64 reserved2;
	__u64 reserved3;
};

struct cxl_event {
	union {
		struct cxl_event_header header;
		struct cxl_event_afu_interrupt irq;
		struct cxl_event_data_storage fault;
		struct cxl_event_afu_error afu_err;
	};
};

#endif
