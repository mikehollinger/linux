
#ifndef _CXLFLASH_CXL_STUB_H
#define _CXLFLASH_CXL_STUB_H

#include <linux/types.h>
#include <linux/interrupt.h>

#define CXL_START_WORK_NUM_IRQS 0x0000000000000002ULL

struct cxl_ioctl_start_work {
        __u64 flags;
        __u64 work_element_descriptor;
        __u64 amr;
        __s16 num_interrupts;
        __s16 reserved1;
        __s32 reserved2;
        __u64 reserved3;
        __u64 reserved4;
        __u64 reserved5;
        __u64 reserved6;
};

struct cxl_context {
        bool kernelapi;
};

void cxl_psa_unmap(void *);

int cxl_stop_context(struct cxl_context *);

void cxl_unmap_afu_irq(struct cxl_context *, int, void *);

void cxl_free_afu_irqs(struct cxl_context *);

int cxl_start_context(struct cxl_context *, u64, struct task_struct *);

int cxl_process_element(struct cxl_context *);

struct cxl_context *cxl_get_context(struct pci_dev *);

void cxl_set_master(struct cxl_context *);

int cxl_afu_reset(struct cxl_context *);

int cxl_allocate_afu_irqs(struct cxl_context *, int);

int cxl_map_afu_irq(struct cxl_context *, int, irq_handler_t, void *, char *);

void __iomem *cxl_psa_map(struct cxl_context *);

struct device *cxl_get_phys_dev(struct pci_dev *);

struct cxl_afu *cxl_pci_to_afu(struct pci_dev *);

struct cxl_context *cxl_fops_get_context(struct file *file);

int cxl_fd_release(struct inode *inode, struct file *file);

int cxl_fd_mmap(struct file *file, struct vm_area_struct *vm);

struct cxl_context *cxl_dev_context_init(struct pci_dev *dev);

struct file *cxl_get_fd(struct cxl_context *ctx, struct file_operations *fops,
                        int *fd);

int cxl_start_work(struct cxl_context *ctx,
                   struct cxl_ioctl_start_work *work);

int cxl_release_context(struct cxl_context *ctx);

#endif /* ifndef _CXLFLASH_COMMON_H */
