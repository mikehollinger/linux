#ifndef _UAPI_ASM_CAPI_H
#define _UAPI_ASM_CAPI_H

#include <linux/types.h>

#define AFU_PS_REGS_SIZE 0x2000000

/* ioctls */

/* Argument *is* WED (DEPRECATED: 32bit applications cannot set full 64bit WED) */
#define CAPI_OPEN_AND_RUN 0
#define CAPI_IOCTL_OPEN_AND_RUN 0
/* Argument is a pointer to a struct capi_ioctl_start_work */
#define CAPI_IOCTL_START_WORK   1

struct capi_ioctl_start_work {
	__u64 wed;
	__u64 amr;
	__u64 ctx_save_ptr; /* Ignored in dedicated process model */
	__u32 ctx_save_size; /* In bytes */
	__u32 reserved1;
	__u64 reserved2;
};

/* events from read() */

enum capi_event_type {
	CAPI_EVENT_READ_FAIL = -1,
	CAPI_EVENT_RESERVED = 0,
	CAPI_EVENT_AFU_INTERRUPT = 1,
	CAPI_EVENT_DATA_STORAGE = 2,
	CAPI_EVENT_AFU_ERROR = 3,
};

struct capi_event_header {
	__u32 type;
	__u16 size;
	__u16 reserved;
};

/* Keep this large enough to fit any event for convenience */
struct capi_event_uncast {
	struct capi_event_header header;
	__u8 data[8];
};

#define AFU_IRQ_LEVEL_1 0x01
#define AFU_IRQ_LEVEL_2 0x02
#define AFU_IRQ_LEVEL_3 0x04
struct capi_event_afu_interrupt {
	struct capi_event_header header;
	__u8 level; /* Raised AFU interrupt level(s) */
};

struct capi_event_data_storage {
	struct capi_event_header header;
	__u64 address;
};

struct capi_event_afu_error {
	struct capi_event_header header;
	__u64 afu_err;
};

#endif
