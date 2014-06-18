#ifndef _UAPI_ASM_CAPI_H
#define _UAPI_ASM_CAPI_H

#include <linux/types.h>

/* ioctls */

/* Argument is a pointer to a struct capi_ioctl_start_work */
#define CAPI_IOCTL_START_WORK      0
#define CAPI_IOCTL_LOAD_AFU_IMAGE  1

struct capi_ioctl_start_work {
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

struct capi_ioctl_load_afu_image {
	__u64 vaddress;
	__u64 length;
};

/* events from read() */

enum capi_event_type {
	CAPI_EVENT_READ_FAIL     = -1,
	CAPI_EVENT_RESERVED      = 0,
	CAPI_EVENT_AFU_INTERRUPT = 1,
	CAPI_EVENT_DATA_STORAGE  = 2,
	CAPI_EVENT_AFU_ERROR     = 3,
};

struct capi_event_header {
	__u32 type;
	__u16 size;
	__u16 process_element;
	__u64 reserved1;
	__u64 reserved2;
	__u64 reserved3;
};

/* Keep this large enough to fit any event for convenience */
struct capi_event_uncast {
	struct capi_event_header header;
	__u64 reserved1;
	__u64 reserved2;
	__u64 reserved3;
	__u64 reserved4;
};

struct capi_event_afu_interrupt {
	struct capi_event_header header;
	__u16 irq; /* Raised AFU interrupt number */
	__u16 reserved1;
	__u32 reserved2;
	__u64 reserved3;
	__u64 reserved4;
	__u64 reserved5;
};

struct capi_event_data_storage {
	struct capi_event_header header;
	__u64 address;
	__u64 reserved1;
	__u64 reserved2;
	__u64 reserved3;
};

struct capi_event_afu_error {
	struct capi_event_header header;
	__u64 afu_err;
	__u64 reserved1;
	__u64 reserved2;
	__u64 reserved3;
};

#endif
