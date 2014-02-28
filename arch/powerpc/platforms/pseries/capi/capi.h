#ifndef _CAPI_H_
#define _CAPI_H_

#include <linux/interrupt.h>
#include <linux/semaphore.h>
#include <linux/device.h>
#include <linux/types.h>
#include <linux/cdev.h>
#include <linux/pid.h>
#include <asm/byteorder.h>
#include <asm/cputable.h>
#include <asm/mmu.h>
#include <asm/reg.h>
#include <asm/io.h>

#include <uapi/asm/capi.h>

/* Valid setting for this are 7 and 11 */
/* FIXME do this dynamically, or just only support 11 and above */
#define CAIA_VERSION 7

/* Opaque types to avoid accidentally passing registers for the wrong MMIO
 *
 * At the end of the day, I'm not married to using typedef here, but it might
 * (and has!) help avoid bugs like mixing up CAPI_PSL_CtxTime and
 * CAPI_PSL_CtxTime_An, or calling capi_p1n_write instead of capi_p1_write.
 *
 * I'm quite happy if these are changed back to #defines before upstreaming, it
 * should be little more than a regexp search+replace operation in this file.
 */
typedef struct {
	const int x;
} capi_p1_reg_t;
typedef struct {
	const int x;
} capi_p1n_reg_t;
typedef struct {
	const int x;
} capi_p2n_reg_t;
#define capi_reg_off(reg) \
	(reg.x)

/* Memory maps. Ref CAPI Appendix A */

/* PSL Privilege 1 Memory Map */
/* Configuration and Control area */
static const capi_p1_reg_t CAPI_PSL_CtxTime = {0x0000};
static const capi_p1_reg_t CAPI_PSL_ErrIVTE = {0x0008};
static const capi_p1_reg_t CAPI_PSL_KEY1    = {0x0010};
static const capi_p1_reg_t CAPI_PSL_KEY2    = {0x0018};
static const capi_p1_reg_t CAPI_PSL_Control = {0x0020};
/* Downloading */
static const capi_p1_reg_t CAPI_PSL_DLCNTL  = {0x0060};
static const capi_p1_reg_t CAPI_PSL_DLADDR  = {0x0068};

/* PSL Lookaside Buffer Management Area */
static const capi_p1_reg_t CAPI_PSL_LBISEL  = {0x0080};
static const capi_p1_reg_t CAPI_PSL_SLBIE   = {0x0088};
static const capi_p1_reg_t CAPI_PSL_SLBIA   = {0x0090};
static const capi_p1_reg_t CAPI_PSL_TLBIE   = {0x00A0};
static const capi_p1_reg_t CAPI_PSL_TLBIA   = {0x00A8};
static const capi_p1_reg_t CAPI_PSL_AFUSEL  = {0x00B0};

/* 0x00C0:7EFF Implementation dependent area */
static const capi_p1_reg_t CAPI_PSL_FIR1      = {0x0100};
static const capi_p1_reg_t CAPI_PSL_FIR2      = {0x0108};
static const capi_p1_reg_t CAPI_PSL_FIR_CNTL  = {0x0148};
static const capi_p1_reg_t CAPI_PSL_DSNDCTL   = {0x0150};
static const capi_p1_reg_t CAPI_PSL_SNWRALLOC = {0x0158};
static const capi_p1_reg_t CAPI_PSL_TRACE     = {0x0170};
/* 0x7F00:7FFF Reserved PCIe MSI-X Pending Bit Array area */
/* 0x8000:FFFF Reserved PCIe MSI-X Table Area */

/* PSL Slice Privilege 1 Memory Map */
/* Configuration Area */
static const capi_p1n_reg_t CAPI_PSL_SR_An          = {0x00};
static const capi_p1n_reg_t CAPI_PSL_LPID_An        = {0x08};
static const capi_p1n_reg_t CAPI_PSL_AMBAR_An       = {0x10};
static const capi_p1n_reg_t CAPI_PSL_SPOffset_An    = {0x18};
static const capi_p1n_reg_t CAPI_PSL_PSL_ID_An      = {0x20};
/* Memory Management and Lookaside Buffer Management */
static const capi_p1n_reg_t CAPI_PSL_SDR_An         = {0x30};
static const capi_p1n_reg_t CAPI_PSL_AMOR_An        = {0x38};
/* Pointer Area */
static const capi_p1n_reg_t CAPI_HAURP_An           = {0x80};
static const capi_p1n_reg_t CAPI_PSL_SPAP_An        = {0x88};
static const capi_p1n_reg_t CAPI_PSL_LLCMD_An       = {0x90};
/* Control Area */
static const capi_p1n_reg_t CAPI_PSL_CNTL_An        = {0xA0};
static const capi_p1n_reg_t CAPI_PSL_CtxTime_An     = {0xA8};
static const capi_p1n_reg_t CAPI_PSL_IVTE_Offset_An = {0xB0};
static const capi_p1n_reg_t CAPI_PSL_IVTE_Limit_An  = {0xB8};
/* 0xC0:FF Implementation Dependent Area */
static const capi_p1n_reg_t CAPI_PSL_FIR_SLICE_An   = {0xC0};
static const capi_p1n_reg_t CAPI_PSL_R_FIR_SLICE_An = {0xC8};
static const capi_p1n_reg_t CAPI_PSL_APCALLOC_A     = {0xD0};
static const capi_p1n_reg_t CAPI_PSL_COALLOC_A      = {0xD8};
static const capi_p1n_reg_t CAPI_PSL_RXCTL_A        = {0xE0};
static const capi_p1n_reg_t CAPI_PSL_SLICE_TRACE    = {0xE8};

/* PSL Slice Privilege 2 Memory Map */
/* Configuration and Control Area */
static const capi_p2n_reg_t CAPI_PSL_PID_TID_An = {0x000};
static const capi_p2n_reg_t CAPI_CSRP_An        = {0x008};
static const capi_p2n_reg_t CAPI_AURP0_An       = {0x010};
static const capi_p2n_reg_t CAPI_AURP1_An       = {0x018};
static const capi_p2n_reg_t CAPI_SSTP0_An       = {0x020};
static const capi_p2n_reg_t CAPI_SSTP1_An       = {0x028};
static const capi_p2n_reg_t CAPI_PSL_AMR_An     = {0x030};
/* Segment Lookaside Buffer Management */
static const capi_p2n_reg_t CAPI_SLBIE_An       = {0x040};
static const capi_p2n_reg_t CAPI_SLBIA_An       = {0x048};
static const capi_p2n_reg_t CAPI_SLBI_Select_An = {0x050};
/* Interrupt Registers */
static const capi_p2n_reg_t CAPI_PSL_DSISR_An   = {0x060};
static const capi_p2n_reg_t CAPI_PSL_DAR_An     = {0x068};
static const capi_p2n_reg_t CAPI_PSL_DSR_An     = {0x070};
static const capi_p2n_reg_t CAPI_PSL_TFC_An     = {0x078};
static const capi_p2n_reg_t CAPI_PSL_PEHandle_An = {0x080};
static const capi_p2n_reg_t CAPI_PSL_ErrStat_An = {0x088};
/* AFU Registers */
static const capi_p2n_reg_t CAPI_AFU_Cntl_An    = {0x090};
static const capi_p2n_reg_t CAPI_AFU_ERR_An     = {0x098};
/* Work Element Descriptor */
static const capi_p2n_reg_t CAPI_PSL_WED_An     = {0x0A0};
/* 0x0C0:FFF Implementation Dependent Area */

/****** CAPI_PSL_SR_An ******************************************************/
#define CAPI_PSL_SR_An_SF  MSR_SF            /* 64bit */
#define CAPI_PSL_SR_An_TA  (1ull << (63-1))  /* Tags active,   GA1: 0 */
#define CAPI_PSL_SR_An_HV  MSR_HV            /* Hypervisor,    GA1: 0 */
#define CAPI_PSL_SR_An_PR  MSR_PR            /* Problem state, GA1: 1 */
#define CAPI_PSL_SR_An_ISL (1ull << (63-53)) /* Ignore Segment Large Page */
#define CAPI_PSL_SR_An_TC  (1ull << (63-54)) /* Page Table secondary hash */
#define CAPI_PSL_SR_An_US  (1ull << (63-56)) /* User state,    GA1: X */
#define CAPI_PSL_SR_An_SC  (1ull << (63-58)) /* Segment Table secondary hash */
#define CAPI_PSL_SR_An_R   MSR_DR            /* Relocate,      GA1: 1 */

/****** CAPI_PSL_CNTL_An *****************************************************/
/* Programming Mode: */
#define CAPI_PSL_CNTL_An_PM_MASK     (0x3ull << (63-31))
#define CAPI_PSL_CNTL_An_PM_Shared   (0x0ull << (63-31))
#define CAPI_PSL_CNTL_An_PM_OS       (0x1ull << (63-31))
#define CAPI_PSL_CNTL_An_PM_Process  (0x2ull << (63-31))
#define CAPI_PSL_CNTL_An_PM_Address  (0x3ull << (63-31))
/* Purge Status (ro) */
#define CAPI_PSL_CNTL_An_Ps_MASK     (0x3ull << (63-39))
#define CAPI_PSL_CNTL_An_Ps_Pending  (0x1ull << (63-39))
#define CAPI_PSL_CNTL_An_Ps_Complete (0x3ull << (63-39))
/* Purge */
#define CAPI_PSL_CNTL_An_Pc          (0x1ull << (63-48))
/* Suspend Status (ro) */
#define CAPI_PSL_CNTL_An_Ss_MASK     (0x3ull << (63-55))
#define CAPI_PSL_CNTL_An_Ss_Pending  (0x1ull << (63-55))
#define CAPI_PSL_CNTL_An_Ss_Complete (0x3ull << (63-55))
/* Suspend Control */
#define CAPI_PSL_CNTL_An_Sc          (0x1ull << (63-63))

/* AFU Slice Enable Status (ro) */
#define CAPI_AFU_Cntl_An_ES_MASK     (0x3ull << (63-1))
#define CAPI_AFU_Cntl_An_ES_Disabled (0x0ull << (63-1))
#define CAPI_AFU_Cntl_An_ES_Pending  (0x1ull << (63-1))
#define CAPI_AFU_Cntl_An_ES_Enabled  (0x2ull << (63-1))
/* AFU Slice Enable */
#define CAPI_AFU_Cntl_An_E           (0x1ull << (63-3))
/* AFU Slice Reset status (ro) */
#define CAPI_AFU_Cntl_An_RS_MASK     (0x3ull << (63-5))
#define CAPI_AFU_Cntl_An_RS_Pending  (0x1ull << (63-5))
#define CAPI_AFU_Cntl_An_RS_Complete (0x2ull << (63-5))
/* AFU Slice Reset */
#define CAPI_AFU_Cntl_An_RA          (0x1ull << (63-7))

/****** CAPI_SSTP0/1_An ******************************************************/
/* These top bits are for the segment that CONTAINS the segment table */
#define CAPI_SSTP0_An_B_SHIFT    SLB_VSID_SSIZE_SHIFT
#define CAPI_SSTP0_An_KS             (1ull << (63-2))
#define CAPI_SSTP0_An_KP             (1ull << (63-3))
#define CAPI_SSTP0_An_N              (1ull << (63-4))
#define CAPI_SSTP0_An_L              (1ull << (63-5))
#define CAPI_SSTP0_An_C              (1ull << (63-6))
#define CAPI_SSTP0_An_TA             (1ull << (63-7))
#define CAPI_SSTP0_An_LP_SHIFT                (63-9)  /* 2 Bits */
/* And finally, the virtual address & size of the segment table: */
#define CAPI_SSTP0_An_SegTableSize_SHIFT      (63-31) /* 12 Bits */
#define CAPI_SSTP0_An_SegTableSize_MASK \
	(((1ull << 12) - 1) << CAPI_SSTP0_An_SegTableSize_SHIFT)
#define CAPI_SSTP0_An_STVA_U_MASK   ((1ull << (63-49))-1)
#define CAPI_SSTP1_An_STVA_L_MASK (~((1ull << (63-55))-1))
#define CAPI_SSTP1_An_V              (1ull << (63-63))

/****** CAPI_PSL_DSISR_An ****************************************************/
#define CAPI_PSL_DSISR_An_DS (1ull << (63-0))  /* Segment not found */
#define CAPI_PSL_DSISR_An_DM (1ull << (63-1))  /* PTE not found (See also: M) or protection fault */
#define CAPI_PSL_DSISR_An_ST (1ull << (63-2))  /* Segment Table PTE not found */
#define CAPI_PSL_DSISR_An_UR (1ull << (63-3))  /* AURP PTE not found */
#define CAPI_PSL_DSISR_TRANS (CAPI_PSL_DSISR_An_DS | CAPI_PSL_DSISR_An_DM | CAPI_PSL_DSISR_An_ST | CAPI_PSL_DSISR_An_UR)
#define CAPI_PSL_DSISR_An_PE (1ull << (63-4))  /* PSL Error (implementation specific) */
#define CAPI_PSL_DSISR_An_AE (1ull << (63-5))  /* AFU Error */
#define CAPI_PSL_DSISR_An_OC (1ull << (63-6))  /* OS Context Warning */
#define CAPI_PSL_DSISR_An_PC (1ull << (63-7))  /* Process Complete XXX TODO: Notify application */
/* NOTE: Bits 32:63 are undefined if DSISR[DS] = 1 */
#define CAPI_PSL_DSISR_An_M  DSISR_NOHPTE      /* PTE not found */
#define CAPI_PSL_DSISR_An_P  DSISR_PROTFAULT   /* Storage protection violation */
#define CAPI_PSL_DSISR_An_A  (1ull << (63-37)) /* AFU lock access to write through or cache inhibited storage */
#define CAPI_PSL_DSISR_An_S  DSISR_ISSTORE     /* Access was afu_wr or afu_zero */
#define CAPI_PSL_DSISR_An_K  DSISR_KEYFAULT    /* Access not permitted by virtual page class key protection */

/****** CAPI_PSL_R_FIR_SLICE_An (XXX: PSL IMPLEMENTATION SPECIFIC REGISTER ***/
#define CAPI_PSL_R_FIR_AFUTO  (1ull << (63-0)) /* AFU did not respond to MMIO */
#define CAPI_PSL_R_FIR_AFUDIS (1ull << (63-1)) /* MMIO to disabled AFU */
#define CAPI_PSL_R_FIR_AFUOV  (1ull << (63-2)) /* AFU issued > 64 outstanding commands */

/****** CAPI_PSL_TFC_An ******************************************************/
#define CAPI_PSL_TFC_An_A  (1ull << (63-28)) /* Acknowledge non-translation fault */
#define CAPI_PSL_TFC_An_C  (1ull << (63-29)) /* Continue (abort transaction) */
#define CAPI_PSL_TFC_An_AE (1ull << (63-30)) /* Restart PSL with address error */
#define CAPI_PSL_TFC_An_R  (1ull << (63-31)) /* Restart PSL transaction */

#define CAPI_MAX_SLICES 4
#define CAPI_SLICE_IRQS 4
#define MAX_AFU_MMIO_REGS 3

/* CAPI character device info */
extern dev_t capi_dev;
extern struct bus_type capi_bus_type;
#define CAPI_NUM_MINORS 256 /* Total to reserve */
#define CAPI_DEV_MINORS 8   /* 1 control, up to 4 AFUs, 3 reserved for now */

#if CAIA_VERSION < 11
struct capi_sste {
	u64 vsid_data;
	u64 esid_data;
};
#else
struct capi_sste {
	u64 esid_data;
	u64 vsid_data;
};
#endif

/* TODO: Pack structure */
struct capi_afu_t {
	union {
		void __iomem *p1n_mmio;
		u64 handle;
	};
	void __iomem *p2n_mmio;
	void __iomem *psn_mmio;
	phys_addr_t psn_phys;
	u64 psn_size;
	u32 irq_count;
	irq_hw_number_t hwirq[CAPI_SLICE_IRQS];
	unsigned int virq[CAPI_SLICE_IRQS];
	struct capi_t *adapter;
	struct device device;

	/* FIXME: Below items should be in a separate context struct for virtualisation */

	struct capi_sste *sstp;
	unsigned int sst_size, sst_lru;

	/* XXX: Is it possible to need multiple work items at once? */
	struct work_struct work;
	u64 dsisr;
	u64 dar;

	u64 enabled;

	wait_queue_head_t wq;

	struct pid *pid;

	spinlock_t lock; /* Protects pending_irq_mask, pending_fault and fault_addr */
	u8 pending_irq_mask; /* Accessed from IRQ context */
	bool pending_fault;
	u64 fault_addr;
	u64 afu_err;
	bool pending_afu_err;

	/* Only used in PR mode */
	u64 process_token;
};


struct capi_driver_ops;

struct capi_t {
	union {
		struct { /* hv */
			void __iomem *p1_mmio;
			void __iomem *p2_mmio;
			irq_hw_number_t err_hwirq;
			unsigned int err_virq;
		};
		u64 handle;
	};
	struct capi_driver_ops *driver;
	struct capi_afu_t slice[CAPI_MAX_SLICES];
	struct cdev cdev;
	struct cdev afu_cdev;
	struct device device;
	int slices;
	struct dentry *trace;
	struct dentry *psl_err_chk;
	struct dentry *afx_chk;
	struct list_head list;
};

struct capi_driver_ops {
	int (*init_adapter) (struct capi_t *adapter);
	int (*init_afu) (struct capi_afu_t *afu);
};

struct capi_ivte_ranges {
	__be32 offsets[4];
	__be32 ranges[4];
};

struct capi_process_element_common {
	__be32 threadId;
	__be32 processId;
	__be64 csrp;
	__be64 aurp0;
	__be64 aurp1;
	__be64 sstp0;
	__be64 sstp1;
	__be64 amr;
	u8     reserved3[4];
	__be64 workElementDescriptor;
	u8     reserved4[4];
} __packed;

struct capi_process_element {
	__be64 sr;
	__be64 SPOffset;
	__be64 sdr;
	__be64 haurp;
	__be32 ctxtime;
	struct capi_ivte_ranges ivte;
	__be32 lpid;
	struct capi_process_element_common common;
} __packed;

#define _capi_reg_write(addr, val) \
	out_be64((u64 __iomem *)(addr), val)
#define _capi_reg_read(addr) \
	in_be64((u64 __iomem *)(addr))

static inline void __iomem * _capi_p1_addr(struct capi_t *capi, capi_p1_reg_t reg)
{
	WARN_ON(!cpu_has_feature(CPU_FTR_HVMODE));
	return capi->p1_mmio + capi_reg_off(reg);
}
#define capi_p1_write(capi, reg, val) \
	_capi_reg_write(_capi_p1_addr(capi, reg), val)
#define capi_p1_read(capi, reg) \
	_capi_reg_read(_capi_p1_addr(capi, reg))

static inline void __iomem * _capi_p1n_addr(struct capi_afu_t *afu, capi_p1n_reg_t reg)
{
	WARN_ON(!cpu_has_feature(CPU_FTR_HVMODE));
	return afu->p1n_mmio + capi_reg_off(reg);
}
#define capi_p1n_write(afu, reg, val) \
	_capi_reg_write(_capi_p1n_addr(afu, reg), val)
#define capi_p1n_read(afu, reg) \
	_capi_reg_read(_capi_p1n_addr(afu, reg))

static inline void __iomem * _capi_p2n_addr(struct capi_afu_t *afu, capi_p2n_reg_t reg)
{
	return afu->p2n_mmio + capi_reg_off(reg);
}
#define capi_p2n_write(afu, reg, val) \
	_capi_reg_write(_capi_p2n_addr(afu, reg), val)
#define capi_p2n_read(afu, reg) \
	_capi_reg_read(_capi_p2n_addr(afu, reg))

/* TODO: Move PS out of kernel */
static inline void __iomem * _capi_afu_ps_addr(struct capi_afu_t *afu, int reg)
{
	return afu->psn_mmio + reg;
}
#define capi_afu_ps_write(afu, reg, val) \
	_capi_reg_write(_capi_afu_ps_addr(afu, reg), val)
#define capi_afu_ps_read(afu, reg) \
	_capi_reg_read(_capi_afu_ps_addr(afu, reg))

/* TODO: Clean up the alloc/init process */
int capi_init_adapter(struct capi_t *adapter,
		      struct capi_driver_ops *driver,
		      int slices, u64 handle,
		      u64 p1_base, u64 p1_size,
		      u64 p2_base, u64 p2_size,
		      irq_hw_number_t err_hwirq);
int capi_init_afu(struct capi_t *adapter, struct capi_afu_t *afu,
		  int slice, u64 handle,
		  u64 p1n_base, u64 p1n_size,
		  u64 p2n_base, u64 p2n_size,
		  u64 psn_base, u64 psn_size,
		  irq_hw_number_t irq_start, irq_hw_number_t irq_count);

int register_capi_dev(void);
void unregister_capi_dev(void);
int add_capi_dev(struct capi_t *capi, int adapter_num);
void del_capi_dev(struct capi_t *capi, int adapter_num);

unsigned int
capi_map_irq(irq_hw_number_t hwirq, irq_handler_t handler, void *cookie);
void capi_unmap_irq(unsigned int virq, void *cookie);
void afu_register_irqs(struct capi_afu_t *afu, u32 start, u32 count);
void afu_enable_irqs(struct capi_afu_t *afu);
void afu_disable_irqs(struct capi_afu_t *afu);
void afu_release_irqs(struct capi_afu_t *afu);
irqreturn_t capi_irq_err(int irq, void *data);

int capi_handle_segment_miss(struct capi_afu_t *afu, u64 ea);
void capi_handle_page_fault(struct work_struct *work);
void capi_prefault(struct capi_afu_t *afu, u64 wed);

struct capi_t * get_capi_adapter(int num);
int capi_alloc_sst(struct capi_afu_t *afu, u64 *sstp0, u64 *sstp1);

void init_capi_hv(void);
void init_capi_native(void);

/* This matches the layout of the H_COLLECT_CA_INT_INFO retbuf */
struct capi_irq_info {
	u64 dsisr;
	u64 dar;
	u64 dsr;
#ifdef __BIG_ENDIAN
	/* These are written as one 64bit value, but read as 32bit values */
	u32 pid;
	u32 tid;
#elif defined(__LITTLE_ENDIAN)
	u32 tid;
	u32 pid;
#else
#error Unknown endian - missing byteorder.h?
#endif
	u64 afu_err;
	u64 fir_r_slice;
	u64 padding[3]; /* to match the expected retbuf size for plpar_hcall9 */
};

struct capi_backend_ops {
	int (*init_adapter) (struct capi_t *adapter, u64 handle,
			     u64 p1_base, u64 p1_size,
			     u64 p2_base, u64 p2_size,
			     irq_hw_number_t err_hwirq);
	/* FIXME: Clean this up */
	int (*init_afu) (struct capi_afu_t *afu, u64 handle,
			 u64 p1n_base, u64 p1n_size,
			 u64 p2n_base, u64 p2n_size,
			 u64 psn_base, u64 psn_size,
			 irq_hw_number_t irq_start, irq_hw_number_t irq_count);

	int (*init_dedicated_process) (struct capi_afu_t *afu, bool kernel,
			               u64 wed, u64 amr);
	int (*detach_process) (struct capi_afu_t *afu);

	int (*get_irq) (struct capi_afu_t *afu, struct capi_irq_info *info);
	int (*ack_irq) (struct capi_afu_t *afu, u64 tfc, u64 psl_reset_mask);

	void (*release_adapter) (struct capi_t *adapter);
	void (*release_afu) (struct capi_afu_t *afu);
};
extern const struct capi_backend_ops *capi_ops;

/* XXX: LAB DEBUGGING */
void capi_stop_trace(struct capi_t *capi);

/* XXX: Wrong place for this */
static inline u64 slbfee(u64 ea)
{
	u64 rb = ea & ESID_MASK;
	u64 rt = 0;

	/* asm volatile("slbfee. %0,%1" : "=r"(rt) : "r"(rb) : ); */
	asm volatile(".long ( 31 << (31 -  5)"
		         " |  %0 << (31 - 10)"
			 " |  %1 << (31 - 20)"
			 " | 979 << (31 - 30)"
			 " | 1)" : "=r"(rt) : "r"(rb) : );
	return rt;
}

#endif
