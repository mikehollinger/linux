/*
 * Copyright 2015 IBM Corp.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#ifndef _MISC_CXL_H
#define _MISC_CXL_H

#include <linux/pci.h>
#include <linux/poll.h>
#include <linux/interrupt.h>
#include <uapi/misc/cxl.h>

/*
 * Get the AFU and configuration record number associated with a particular
 * PCI_dev.  NULL may be pased to cfg_record if it's not required.
 */
struct cxl_afu *cxl_pci_to_afu(struct pci_dev *dev, unsigned int *cfg_record);

/* Get default context associated with this pci_dev */
struct cxl_context *cxl_get_context(struct pci_dev *dev);

/*
 * Get the physical device which the AFU is attached.  We return a device here
 * not a pci_dev.
 */
struct device *cxl_get_phys_dev(struct pci_dev *dev);

/* Initalise a context from a AFU PCI device */
extern struct cxl_context *cxl_dev_context_init(struct pci_dev *dev);

/*
 * Cleanup context and free it
 */
int cxl_release_context(struct cxl_context *ctx);

/*
 * Allocate AFU interrupts for this context. num=0 will allocate the default
 * for this AFU as given in the AFU descriptor.  Each interrupt to be used must
 * register a handler with cxl_register_afu_irq.  Must be freed after.
 */
int cxl_allocate_afu_irqs(struct cxl_context *cxl, int num);
void cxl_free_afu_irqs(struct cxl_context *cxl);

/*
 * Map a handler for an AFU interrupt associated with a particular
 * context. AFU interrupt numbers start from 1. cookie is private data is that
 * will be provided to the interrupt handler.  Each irq must be unmapped.
 * FIXME: do we want a single unmap call here to free all IRQs at once?
 */
int cxl_map_afu_irq(struct cxl_context *cxl, int num,
		    irq_handler_t handler, void *cookie, char *name);
void cxl_unmap_afu_irq(struct cxl_context *cxl, int num, void *cookie);

/*
 * Start work on the AFU.  This starts an cxl context and associates it with a
 * task.  task == NULL will attach to the kernel context.
 */
int cxl_start_context(struct cxl_context *ctx, u64 wed,
		      struct task_struct *task);

/*
 * Get the process element for this context.  May return a error code if the
 * context is not currently valid.
 */
int cxl_process_element(struct cxl_context *ctx);

/*
 * Stop a context and remove it from the PSL
 * Returns 0 on success, or negative errno.
 */
int cxl_stop_context(struct cxl_context *ctx);

/*
 * Set a context as a master context
 * NOTE: no way to degrade back to slave, but do we need this?
 */
void cxl_set_master(struct cxl_context *ctx);

/* Attach an fd to a context. */
/* Export all the existing fops so drivers can use them */
int cxl_fd_open(struct inode *inode, struct file *file);
int cxl_fd_release(struct inode *inode, struct file *file);
long cxl_fd_ioctl(struct file *file, unsigned int cmd, unsigned long arg);
int cxl_fd_mmap(struct file *file, struct vm_area_struct *vm);
unsigned int cxl_fd_poll(struct file *file, struct poll_table_struct *poll);
ssize_t cxl_fd_read(struct file *file, char __user *buf, size_t count,
			   loff_t *off);

struct file *cxl_get_fd(struct cxl_context *ctx, struct file_operations *fops,
			int *fd);
int cxl_start_work(struct cxl_context *ctx,
		   struct cxl_ioctl_start_work *work);

/* Map and unmap the AFU Problem Space area */
void __iomem *cxl_psa_map(struct cxl_context *ctx);
void cxl_psa_unmap(void __iomem *addr);
int cxl_afu_reset(struct cxl_context *ctx);

#endif
