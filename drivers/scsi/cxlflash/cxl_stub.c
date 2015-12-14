#include <linux/pci.h>

#include "main.h"
#include "sislite.h"
#include "common.h"
#include "cxl_stub.h"

void cxl_psa_unmap(void *addr)
{
   return;
}

int cxl_stop_context(struct cxl_context *ctx)
{
        return 0;
}

void cxl_unmap_afu_irq(struct cxl_context *ctx, int num, void *cookie)
{
    return;
}

void cxl_free_afu_irqs(struct cxl_context *ctx)
{
    return;
}

int cxl_start_context(struct cxl_context *ctx, u64 wed,
                      struct task_struct *task)
{
        return 0;
}

int cxl_process_element(struct cxl_context *ctx)
{
     return 0;
}

struct cxl_context *cxl_get_context(struct pci_dev *dev)
{
        return ((struct cxl_context *)(dev));
}

void cxl_set_master(struct cxl_context *ctx)
{
    return;
}

int cxl_afu_reset(struct cxl_context *ctx)
{
     return 0;
}

int cxl_allocate_afu_irqs(struct cxl_context *ctx, int num)
{
     return 0;
}

int cxl_map_afu_irq(struct cxl_context *ctx, int num,
                    irq_handler_t handler, void *cookie, char *name)
{
     return 0;
}

void __iomem *cxl_psa_map(struct cxl_context *ctx)
{
     return ((void __iomem *)(ctx));
}

struct device *cxl_get_phys_dev(struct pci_dev *dev)
{
     return ((struct device *)(dev));
}

struct cxl_afu *cxl_pci_to_afu(struct pci_dev *dev)
{
     return ((struct cxl_afu *)(dev));
}

struct cxl_context *cxl_fops_get_context(struct file *file)
{
     return ((struct cxl_context *)(file));
}

int cxl_fd_release(struct inode *inode, struct file *file)
{
     return 0;
}

int cxl_fd_mmap(struct file *file, struct vm_area_struct *vm)
{
     return 0;
}

struct cxl_context *cxl_dev_context_init(struct pci_dev *dev)
{
     return ((struct cxl_context *)(dev));
}

struct file *cxl_get_fd(struct cxl_context *ctx, struct file_operations *fops,
                        int *fd)
{
     return ((struct file *)(ctx));
}

int cxl_start_work(struct cxl_context *ctx,
                   struct cxl_ioctl_start_work *work)
{
     return 0;
}

int cxl_release_context(struct cxl_context *ctx)
{
     return 0;
}
