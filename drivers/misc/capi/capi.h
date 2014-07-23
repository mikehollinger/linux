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

#include <uapi/misc/capi.h>

/* Valid setting for this are 7 and 11 */
/* FIXME do this dynamically, or just only support 11 and above */
#define CAIA_VERSION 12

#define CAPI_TIMEOUT 5

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
static const capi_p1_reg_t CAPI_PSL_VERSION   = {0x0118};
static const capi_p1_reg_t CAPI_PSL_RESLCKTO  = {0x0128};
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
static const capi_p1n_reg_t CAPI_PSL_ID_An	    = {0x20};
static const capi_p1n_reg_t CAPI_PSL_SERR_An	    = {0x28};
/* Memory Management and Lookaside Buffer Management */
static const capi_p1n_reg_t CAPI_PSL_SDR_An         = {0x30};
static const capi_p1n_reg_t CAPI_PSL_AMOR_An        = {0x38};
/* Pointer Area */
static const capi_p1n_reg_t CAPI_HAURP_An           = {0x80};
static const capi_p1n_reg_t CAPI_PSL_SPAP_An        = {0x88};
static const capi_p1n_reg_t CAPI_PSL_LLCMD_An       = {0x90};
/* Control Area */
static const capi_p1n_reg_t CAPI_PSL_SCNTL_An       = {0xA0};
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
static const capi_p2n_reg_t CAPI_PSL_ErrStat_An = {0x088}; /* TODO: Print out this register on PSL error */
/* AFU Registers */
static const capi_p2n_reg_t CAPI_AFU_Cntl_An    = {0x090};
static const capi_p2n_reg_t CAPI_AFU_ERR_An     = {0x098};
/* Work Element Descriptor */
static const capi_p2n_reg_t CAPI_PSL_WED_An     = {0x0A0};
/* 0x0C0:FFF Implementation Dependent Area */

#define CAPI_PSL_SPAP_Addr 0x0ffffffffffff000ULL
#define CAPI_PSL_SPAP_Size 0x0000000000000ff0ULL
#define CAPI_PSL_SPAP_Size_Shift 4
#define CAPI_PSL_SPAP_V    0x0000000000000001ULL

/****** CAPI_PSL_DLCNTL *****************************************************/
#define CAPI_PSL_DLCNTL_D (0x1ull << (63-28))
#define CAPI_PSL_DLCNTL_C (0x1ull << (63-29))
#define CAPI_PSL_DLCNTL_E (0x1ull << (63-30))
#define CAPI_PSL_DLCNTL_S (0x1ull << (63-31))
#define CAPI_PSL_DLCNTL_CE ( CAPI_PSL_DLCNTL_C | CAPI_PSL_DLCNTL_E )
#define CAPI_PSL_DLCNTL_DCES ( CAPI_PSL_DLCNTL_D | CAPI_PSL_DLCNTL_CE | CAPI_PSL_DLCNTL_S)

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
#define CAPI_PSL_SR_An_MP  (1ull << (63-62)) /* Master Process */

/****** CAPI_PSL_LLCMD_An ****************************************************/
#define CAPI_LLCMD_TERMINATE   0x0001000000000000ULL
#define CAPI_LLCMD_REMOVE      0x0002000000000000ULL
#define CAPI_LLCMD_SUSPEND     0x0003000000000000ULL
#define CAPI_LLCMD_RESUME      0x0004000000000000ULL
#define CAPI_LLCMD_ADD         0x0005000000000000ULL
#define CAPI_LLCMD_UPDATE      0x0006000000000000ULL
#define CAPI_LLCMD_HANDLE_MASK 0x000000000000ffffULL

/****** CAPI_PSL_ID_An ****************************************************/
#define CAPI_PSL_ID_An_F	(1ull << (63-31))
#define CAPI_PSL_ID_An_L	(1ull << (63-30))

/****** CAPI_PSL_SCNTL_An ****************************************************/
#define CAPI_PSL_SCNTL_An_CR          (0x1ull << (63-15))
/* Programming Mode: */
#define CAPI_PSL_SCNTL_An_PM_MASK     (0xffffull << (63-31))
#define CAPI_PSL_SCNTL_An_PM_Shared   (0x0000ull << (63-31))
#define CAPI_PSL_SCNTL_An_PM_OS       (0x0001ull << (63-31))
#define CAPI_PSL_SCNTL_An_PM_Process  (0x0002ull << (63-31))
#define CAPI_PSL_SCNTL_An_PM_AFU      (0x0004ull << (63-31))
#define CAPI_PSL_SCNTL_An_PM_AFU_PBT  (0x0104ull << (63-31))
/* Purge Status (ro) */
#define CAPI_PSL_SCNTL_An_Ps_MASK     (0x3ull << (63-39))
#define CAPI_PSL_SCNTL_An_Ps_Pending  (0x1ull << (63-39))
#define CAPI_PSL_SCNTL_An_Ps_Complete (0x3ull << (63-39))
/* Purge */
#define CAPI_PSL_SCNTL_An_Pc          (0x1ull << (63-48))
/* Suspend Status (ro) */
#define CAPI_PSL_SCNTL_An_Ss_MASK     (0x3ull << (63-55))
#define CAPI_PSL_SCNTL_An_Ss_Pending  (0x1ull << (63-55))
#define CAPI_PSL_SCNTL_An_Ss_Complete (0x3ull << (63-55))
/* Suspend Control */
#define CAPI_PSL_SCNTL_An_Sc          (0x1ull << (63-63))

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

/****** CAPI_SLBIA ******************************************************/
#define CAPI_SLBIA_IQ_ALL		(0ull) /* Inv qualifier (write) */
#define CAPI_SLBIA_IQ_LPID		(1ull) /* Inv qualifier (write) */
#define CAPI_SLBIA_IQ_LPIDPID		(3ull) /* Inv qualifier (write) */
#define CAPI_SLBIA_P			(1ull) /* Pending (read) */

/****** CAPI_PSL_DSISR_An ****************************************************/
#define CAPI_PSL_DSISR_An_DS (1ull << (63-0))  /* Segment not found */
#define CAPI_PSL_DSISR_An_DM (1ull << (63-1))  /* PTE not found (See also: M) or protection fault */
#define CAPI_PSL_DSISR_An_ST (1ull << (63-2))  /* Segment Table PTE not found */
#define CAPI_PSL_DSISR_An_UR (1ull << (63-3))  /* AURP PTE not found */
#define CAPI_PSL_DSISR_TRANS (CAPI_PSL_DSISR_An_DS | CAPI_PSL_DSISR_An_DM | CAPI_PSL_DSISR_An_ST | CAPI_PSL_DSISR_An_UR)
#define CAPI_PSL_DSISR_An_PE (1ull << (63-4))  /* PSL Error (implementation specific) */
#define CAPI_PSL_DSISR_An_AE (1ull << (63-5))  /* AFU Error */
#define CAPI_PSL_DSISR_An_OC (1ull << (63-6))  /* OS Context Warning */
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

/* capi_process_element->software_status */
#define CAPI_PE_SOFTWARE_STATE_V (1ul << (31 -  0)) /* Valid */
#define CAPI_PE_SOFTWARE_STATE_C (1ul << (31 - 29)) /* Complete */
#define CAPI_PE_SOFTWARE_STATE_S (1ul << (31 - 30)) /* Suspend */
#define CAPI_PE_SOFTWARE_STATE_T (1ul << (31 - 31)) /* Terminate */

/* SPA->sw_command_status */
#define CAPI_SPA_SW_CMD_MASK         0xffff000000000000ULL
#define CAPI_SPA_SW_CMD_TERMINATE    0x0001000000000000ULL
#define CAPI_SPA_SW_CMD_REMOVE       0x0002000000000000ULL
#define CAPI_SPA_SW_CMD_SUSPEND      0x0003000000000000ULL
#define CAPI_SPA_SW_CMD_RESUME       0x0004000000000000ULL
#define CAPI_SPA_SW_CMD_ADD          0x0005000000000000ULL
#define CAPI_SPA_SW_CMD_UPDATE       0x0006000000000000ULL
#define CAPI_SPA_SW_STATE_MASK       0x0000ffff00000000ULL
#define CAPI_SPA_SW_STATE_TERMINATED 0x0000000100000000ULL
#define CAPI_SPA_SW_STATE_REMOVED    0x0000000200000000ULL
#define CAPI_SPA_SW_STATE_SUSPENDED  0x0000000300000000ULL
#define CAPI_SPA_SW_STATE_RESUMED    0x0000000400000000ULL
#define CAPI_SPA_SW_STATE_ADDED      0x0000000500000000ULL
#define CAPI_SPA_SW_STATE_UPDATED    0x0000000600000000ULL
#define CAPI_SPA_SW_PSL_ID_MASK      0x00000000ffff0000ULL
#define CAPI_SPA_SW_LINK_MASK        0x000000000000ffffULL

#define CAPI_MAX_SLICES 4
#define CAPI_IRQ_RANGES 4
#define MAX_AFU_MMIO_REGS 3

/* CAPI character device info */
extern dev_t capi_dev;
extern struct bus_type capi_bus_type;
#define CAPI_NUM_MINORS 256 /* Total to reserve */
#define CAPI_DEV_MINORS 9   /* 1 control + 4 AFUs * 2 (master/slave) */

#if CAIA_VERSION < 11
struct capi_sste {
	__be64 vsid_data;
	__be64 esid_data;
};
#else
struct capi_sste {
	__be64 esid_data;
	__be64 vsid_data;
};
#endif

/* TODO: Pack structure */
struct capi_afu_t {
	union {
		struct { /* hv */
			void __iomem *p1n_mmio;
			irq_hw_number_t err_hwirq;
			unsigned int err_virq;
		};
		u64 handle;
	};
	void __iomem *p2n_mmio;
	void __iomem *psn_mmio;
	phys_addr_t psn_phys;
	u64 psn_size;
	int pp_irqs;
	int num_procs;
	u64 pp_offset;
	u64 pp_size;
	void __iomem *afu_desc_mmio;
	u64 afu_desc_size;
	int slice;
	struct capi_t *adapter;
	struct device device, device_master;
	bool afu_directed_mode;
	bool afu_dedicated_mode;
	bool mmio;
	bool pp_mmio;

	u64 enabled;

	/* Only the first part of the SPA is used for the process element
	 * linked list. The only other part that software needs to worry about
	 * is sw_command_status, which we store a separate pointer to.
	 * Everything else in the SPA is only used by hardware */
	struct capi_process_element *spa;
	unsigned int spa_size;
	int spa_max_procs;
	__be64 *sw_command_status;

	/* FIXME: Below items should be in a separate context struct for virtualisation */

	struct ida pe_index_ida;
	spinlock_t spa_lock;
};

struct capi_irq_ranges {
	irq_hw_number_t offset[CAPI_IRQ_RANGES];
	irq_hw_number_t range[CAPI_IRQ_RANGES];
};


/* This is a capi context.  If the PSL is in dedicated mode, there will be one
 * of these per AFU.  If in AFU directed there can be lots of these. */
struct capi_context_t {
	struct capi_afu_t *afu;

	bool master;

	int ph; /* process handle/process element index */

	/* Problem state MMIO */
	phys_addr_t psn_phys;
	u64 psn_size;

	struct capi_sste *sstp;
	unsigned int sst_size, sst_lru;

	wait_queue_head_t wq;
	struct pid *pid;
	spinlock_t lock; /* Protects pending_irq_mask, pending_fault and fault_addr */
	/* Only used in PR mode */
	u64 process_token;

	bool pending_irq;
	unsigned long *irq_bitmap; /* Accessed from IRQ context */
	struct capi_irq_ranges irqs;
	bool pending_fault;
	u64 fault_addr;
	u64 afu_err;
	bool pending_afu_err;

	u32 irq_count;

	/* XXX: Is it possible to need multiple work items at once? */
	struct work_struct work;
	u64 dsisr;
	u64 dar;

	struct capi_process_element *elem;
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
	struct cdev afu_master_cdev;
	struct device device;
	int adapter_num;
	int slices;
	struct dentry *trace;
	struct dentry *psl_err_chk;
	struct dentry *afx_chk;
	struct list_head list;
	struct bin_attribute capi_attr;
	struct kobject *afu_kobj;
};

struct capi_driver_ops {
	int (*init_adapter) (struct capi_t *adapter);
	int (*init_afu) (struct capi_afu_t *afu);
	int (*alloc_irqs) (struct capi_irq_ranges *irqs, struct capi_t *adapter, unsigned int num);
	void (*release_irqs) (struct capi_irq_ranges *irqs, struct capi_t *adapter);
	int (*setup_irq) (struct capi_t *adapter, unsigned int hwirq, unsigned int virq);
	void (*release_adapter) (struct capi_t *adapter);
	void (*release_afu) (struct capi_afu_t *afu);
};

/* common == phyp + powernv */
struct capi_process_element_common {
	__be32 tid;
	__be32 pid;
	__be64 csrp;
	__be64 aurp0;
	__be64 aurp1;
	__be64 sstp0;
	__be64 sstp1;
	__be64 amr;
	u8     reserved3[4];
	__be64 wed;
} __packed;

/* just powernv */
struct capi_process_element {
	__be64 sr;
	__be64 SPOffset;
	__be64 sdr;
	__be64 haurp;
	__be32 ctxtime;
	__be16 ivte_offsets[4];
	__be16 ivte_ranges[4];
	__be32 lpid;
	struct capi_process_element_common common;
	__be32 software_state;
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
		      struct device *parent,
		      int slices,
		      void *backend_data);
int capi_map_slice_regs(struct capi_afu_t *afu,
		  u64 p1n_base, u64 p1n_size,
		  u64 p2n_base, u64 p2n_size,
		  u64 psn_base, u64 psn_size,
		  u64 afu_desc, u64 afu_desc_size);
void capi_unmap_slice_regs(struct capi_afu_t *afu);
int capi_init_afu(struct capi_t *adapter, struct capi_afu_t *afu,
		  int slice, u64 handle,
		  irq_hw_number_t err_irq);
void capi_unregister_adapter(struct capi_t *adapter);
void capi_unregister_afu(struct capi_afu_t *afu);

int register_capi_dev(void);
void unregister_capi_dev(void);
int add_capi_dev(struct capi_t *capi, int adapter_num);
void del_capi_dev(struct capi_t *capi, int adapter_num);
int add_capi_afu_dev(struct capi_afu_t *afu, int slice);
void del_capi_afu_dev(struct capi_afu_t *afu);

int capi_sysfs_adapter_add(struct capi_t *adapter);
void capi_sysfs_adapter_remove(struct capi_t *adapter);
int capi_sysfs_afu_add(struct capi_afu_t *afu);
void capi_sysfs_afu_remove(struct capi_afu_t *afu);


unsigned int
capi_map_irq(struct capi_t *adapter, irq_hw_number_t hwirq, irq_handler_t handler, void *cookie);
void capi_unmap_irq(unsigned int virq, void *cookie);
int afu_register_irqs(struct capi_context_t *ctx, u32 count);
void afu_enable_irqs(struct capi_context_t *ctx);
void afu_disable_irqs(struct capi_context_t *ctx);
void afu_release_irqs(struct capi_context_t *ctx);
irqreturn_t capi_irq_err(int irq, void *data);
irqreturn_t capi_slice_irq_err(int irq, void *data);

int capi_handle_segment_miss(struct capi_context_t *ctx, u64 ea);
void capi_handle_page_fault(struct work_struct *work);
void capi_prefault(struct capi_context_t *ctx, u64 wed);

struct capi_t * get_capi_adapter(int num);
int capi_alloc_sst(struct capi_context_t *ctx, u64 *sstp0, u64 *sstp1);

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
	int (*init_adapter) (struct capi_t *adapter, void *backend_data);
	/* FIXME: Clean this up */
	int (*init_afu) (struct capi_afu_t *afu, u64 handle);

	int (*init_process) (struct capi_context_t *ctx, bool kernel,
			               u64 wed, u64 amr);
	int (*detach_process) (struct capi_context_t *ctx);

	int (*get_irq) (struct capi_context_t *ctx, struct capi_irq_info *info);
	int (*ack_irq) (struct capi_context_t *ctx, u64 tfc, u64 psl_reset_mask);

	void (*release_adapter) (struct capi_t *adapter);
	void (*release_afu) (struct capi_afu_t *afu);
	int (*load_afu_image) (struct capi_afu_t *afu, u64 vaddress, u64 length);
	int (*check_error) (struct capi_afu_t *afu);
	int (*afu_reset) (struct capi_afu_t *afu);
};
extern const struct capi_backend_ops *capi_ops;

struct capi_native_data {
	u64 p1_base;
	u64 p1_size;
	u64 p2_base;
	u64 p2_size;
	irq_hw_number_t err_hwirq;
};

struct capi_hv_data {
	u64 handle;
};

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
