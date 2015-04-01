/*
 * CAPI Flash Device Driver
 *
 * Written by: Manoj N. Kumar <manoj@linux.vnet.ibm.com>, IBM Corporation
 *             Matthew R. Ochs <mrochs@linux.vnet.ibm.com>, IBM Corporation
 *
 * Copyright (C) 2015 IBM Corporation
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <linux/pci.h>
#include <linux/module.h>
#include <linux/semaphore.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/cdev.h>
#include <linux/delay.h>
#include <linux/list.h>
#include <linux/syscalls.h>
#include <uapi/misc/cxl.h>
#include <misc/cxl.h>
#include <linux/unistd.h>
#include <linux/kernel.h>
#include <asm/unistd.h>

#include <scsi/scsi.h>
#include <scsi/scsi_host.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_tcq.h>
#include <scsi/scsi_eh.h>
#include <scsi/scsi_cmnd.h>

#include "sislite.h"
#include "cflash.h"
#include "cflash_mc.h"
#include "cflash_ba.h"
#include "cflash_ioctl.h"
#include "cflash_util.h"
#include "afu_fc.h"
#include "mserv.h"



/* Mask off the low nibble of the length to ensure 16 byte multiple */
#define SISLITE_LEN_MASK 0xFFFFFFF0

int cflash_afu_attach(struct cflash *p_cflash, u64 context_id)
{
	struct afu *p_afu = p_cflash->p_afu;
	struct ctx_info *p_ctx_info = &p_afu->ctx_info[context_id];
	int rc = 0;
	u64 reg;

	/* This code reads the mbox w/o knowing if the requester is
	 * the true owner of the context it wants to register. The
	 * read has no side effect and does not affect the true
	 * owner if this is a fraudulent registration attempt.
	 */
	reg = read_64(&p_ctx_info->p_ctrl_map->mbox_r);

	/* zeroed mbox is a locked mbox */
	if (reg == 0) {
		cflash_err("zero mbox reg 0x%llx", reg);
	}

	/* This context is not duped and is in a group by
	 * itself.
	 */
	p_ctx_info->p_next = p_ctx_info;
	p_ctx_info->p_forw = p_ctx_info;

	/* restrict user to read/write cmds in translated
	 * mode. User has option to choose read and/or write
	 * permissions again in mc_open.
	 */
	write_64(&p_ctx_info->p_ctrl_map->ctx_cap,
		 SISL_CTX_CAP_READ_CMD | SISL_CTX_CAP_WRITE_CMD);

	asm volatile ("eieio"::);
	reg = read_64(&p_ctx_info->p_ctrl_map->ctx_cap);

	/* if the write failed, the ctx must have been
	 * closed since the mbox read and the ctx_cap
	 * register locked up.  fail the registration
	 */
	if (reg != (SISL_CTX_CAP_READ_CMD | SISL_CTX_CAP_WRITE_CMD)) {
		cflash_err("ctx may be closed reg=%llx", reg);
		rc = -EAGAIN;
		goto out;
	}

	/* the context gets a dedicated RHT tbl unless it
	 * is dup'ed later.
	 */
	p_ctx_info->p_rht_info = &p_afu->rht_info[context_id];
	p_ctx_info->p_rht_info->ref_cnt = 1;
	memset(p_ctx_info->p_rht_info->rht_start, 0,
	       sizeof(struct sisl_rht_entry) * MAX_RHT_PER_CONTEXT);
	/* make clearing of the RHT visible to AFU before
	 * MMIO
	 */
	asm volatile ("lwsync"::);

	/* set up MMIO registers pointing to the RHT */
	write_64(&p_ctx_info->p_ctrl_map->rht_start,
		 (u64) p_ctx_info->p_rht_info->rht_start);
	write_64(&p_ctx_info->p_ctrl_map->rht_cnt_id,
		 SISL_RHT_CNT_ID((u64) MAX_RHT_PER_CONTEXT,
				 (u64) (p_afu->ctx_hndl)));
	p_ctx_info->ref_cnt = 1;
out:
	cflash_info("returning rc=%d", rc);
	return rc;

}

static int cflash_init_ba(struct lun_info *p_lun_info)
{
	int rc = 0;
	struct blka *p_blka = &p_lun_info->blka;

	memset(p_blka, 0, sizeof(*p_blka));
	mutex_init(&p_blka->mutex);

	p_blka->ba_lun.lun_id = p_lun_info->lun_id;
	p_blka->ba_lun.lsize = p_lun_info->max_lba + 1;
	p_blka->ba_lun.lba_size = p_lun_info->blk_len;

	p_blka->ba_lun.au_size = MC_CHUNK_SIZE;
	p_blka->nchunk = p_blka->ba_lun.lsize / MC_CHUNK_SIZE;

	rc = ba_init(&p_blka->ba_lun);
	if (rc) {
		cflash_err("cannot init block_alloc, rc=%d", rc);
		goto cflash_init_ba_exit;
	}

cflash_init_ba_exit:
	cflash_info("returning rc=%d p_lun_info=%p", rc, p_lun_info);
	return rc;
}

/**
 * cflash_scan_luns - Scans For all LUNs on all Ports
 * @p_cflash:    struct cflash config struct
 *
 * Description: This will be deprecated when the kernel services
 * are ready.
 *
 * Return value:
 *      none
 **/
void cflash_scan_luns(struct cflash *p_cflash)
{
	int j, rc;

	for (j = 0; j < NUM_FC_PORTS; j++) {	/* discover on each port */
		if ((rc = find_lun(p_cflash, 1u << j)) == 0) {
			cflash_info("Found valid lun on port=%d", j);
		} else {
			cflash_err("find_lun returned rc=%d on port=%d", rc, j);
		}
	}
}

/*
 * NAME:        cflash_disk_attach
 *
 * FUNCTION:    attach a LUN to context
 *
 * INPUTS:
 *              sdev       - Pointer to scsi device structure
 *              arg        - Pointer to ioctl specific structure
 *
 * OUTPUTS:
 *              context_id - Unique context index
 *              adap_fd    - New file descriptor for user
 *
 * RETURNS:
 *              0           - Success
 *              errno       - Failure
 *
 * NOTES:
 *              When successful:
 *               a. initialize AFU for this context
 *
 */
int cflash_disk_attach(struct scsi_device *sdev, void __user * arg)
{
	struct cflash *p_cflash = (struct cflash *)sdev->host->hostdata;
	struct afu *p_afu = p_cflash->p_afu;
	struct lun_info *p_lun_info = sdev->hostdata;
	struct cxl_ioctl_start_work *p_work;
	int rc = 0;
	struct file *file;

	struct dk_capi_attach *parg = (struct dk_capi_attach *)arg;
	struct cxl_context *ctx;

	int fd = -1;

	if (fullqc) {
	if (p_lun_info->max_lba == 0) {
		cflash_info("No capacity info yet for this LUN (%016llX)",
			    p_lun_info->lun_id);
		read_cap16(p_afu, p_lun_info, sdev->channel + 1);
		cflash_info("LBA = %016llX", p_lun_info->max_lba);
		cflash_info("BLK_LEN = %08X", p_lun_info->blk_len);
		rc = cflash_init_ba(p_lun_info);
		if (rc) {
			cflash_err("call to cflash_init_ba failed rc=%d!", rc);
			rc = -ENOMEM;
			goto out;
		}
		}
	}

	ctx = cxl_dev_context_init(p_cflash->p_dev);
	if (!ctx) {
		cflash_err("Could not initialize context");
		rc = -ENODEV;
		goto out;
	}

	parg->context_id = (u64) cxl_process_element(ctx);
	if (parg->context_id > MAX_CONTEXT) {
		cflash_err("context_id (%llu) is too large!", parg->context_id);
		rc = -EPERM;
		goto out;
	}

	//BUG_ON(p_cflash->per_context[parg->context_id].lfd != -1);
	//BUG_ON(p_cflash->per_context[parg->context_id].pid != 0);

	/*
	 * Create and attach a new file descriptor. This must be the last
	 * statement as once this is run, the file descritor is visible to
	 * userspace and can't be undone. No error paths after this as we
	 * can't free the fd safely.
	 */
	p_work = &p_cflash->per_context[parg->context_id].work;
	memset(p_work, 0, sizeof(*p_work));
	p_work->num_interrupts = 4;
	p_work->flags = CXL_START_WORK_NUM_IRQS;

	file = cxl_get_fd(ctx, NULL, &fd);
	if (fd < 0) {
		rc = -ENODEV;
		cxl_release_context(ctx);
		cflash_err("Could not get file descriptor");
		goto out;
	}

	rc = cxl_start_work(ctx, p_work);
	if (rc) {
		cflash_err("Could not start context rc=%d", rc);
		cxl_release_context(ctx);
		fput(file);
		put_unused_fd(fd);
		fd = -1;
		goto out;
	}

	rc = cflash_afu_attach(p_cflash, parg->context_id);
	if (rc) {
		cflash_err("Could not attach AFU rc %d", rc);
		cxl_release_context(ctx);
		fput(file);
		put_unused_fd(fd);
		fd = -1;
		goto out;
	}

	/* No error paths after installing the fd */
	fd_install(fd, file);

	p_cflash->per_context[parg->context_id].lfd = fd;
	p_cflash->per_context[parg->context_id].pid = current->pid;

	parg->return_flags = 0;
	parg->block_size = p_lun_info->blk_len;
	parg->mmio_size = sizeof(p_afu->p_afu_map->hosts[0].harea);

out:
	parg->adap_fd = fd;

	cflash_info("returning fd=%d bs=%lld rc=%d", fd, parg->block_size, rc);
	return rc;
}

struct ctx_info *
get_validated_context(struct cflash *p_cflash, u64 ctxid, bool clone_path)
{
	struct afu *p_afu = p_cflash->p_afu;
	struct ctx_info *p_ctx_info = NULL;
	bool mc_override = ctxid == p_afu->ctx_hndl;
	pid_t pid = current->pid,
	      ctxpid = 0;

	if (unlikely(clone_path))
		pid = current->parent->pid;

	if (likely(ctxid < MAX_CONTEXT)) {
		p_ctx_info = &p_afu->ctx_info[ctxid];

		if (checkpid) {
			ctxpid = p_cflash->per_context[ctxid].pid;

			if ((pid != ctxpid) &&
			     (!mc_override))
				p_ctx_info = NULL;
		}
	}

	cflash_dbg("ctxid=%llu p_ctx_info=%p ctxpid=%u pid=%u clone_path=%d",
		   ctxid, p_ctx_info, ctxpid, pid, clone_path);

	return p_ctx_info;
}

/* Checkout a free/empty RHT entry */
struct sisl_rht_entry *cflash_rhte_cout(struct cflash *p_cflash, 
					u64 context_id)
{
	struct ctx_info *p_ctx_info;
	struct rht_info *p_rht_info = NULL;
	struct sisl_rht_entry *p_rht_entry = NULL;
	int i;

	p_ctx_info = get_validated_context(p_cflash, context_id, FALSE);
	if (p_ctx_info != NULL) {
		p_rht_info = p_ctx_info->p_rht_info;

		cflash_info("ctx 0x%llx ctxinfo %p rhtinfo %p",
			    context_id, p_ctx_info, p_rht_info);

		/* find a free RHT entry */
		for (i = 0; i < MAX_RHT_PER_CONTEXT; i++) {
			if (p_rht_info->rht_start[i].nmask == 0) {
				p_rht_entry = &p_rht_info->rht_start[i];
				break;
			}
		}
		cflash_info("i %d rhti %p rhte %p", 
			    i, p_rht_info, p_rht_entry);

		/* if we did not find a free entry, reached max opens allowed
		 * per context
		 */

		if (p_rht_entry == NULL) {
			goto out;
		}

	} else {
		goto out;
	}
out:
	cflash_info("returning p_rht_entry=%p", p_rht_entry);
	return p_rht_entry;
}

void  cflash_rhte_cin(struct sisl_rht_entry *p_rht_entry)
{
	p_rht_entry->nmask = 0;
	p_rht_entry->fp = 0;
}

void cflash_rht_format1(struct sisl_rht_entry *p_rht_entry, u64 lun_id,
			u32 perm)
{
	/*
	 * Populate the Format 1 RHT entry for direct access (physical
	 * LUN) using the synchronization sequence defined in the
	 * SISLite specification.
	 */
	struct sisl_rht_entry_f1 dummy = { 0 };
	struct sisl_rht_entry_f1 *p_rht_entry_f1 =
		(struct sisl_rht_entry_f1 *)p_rht_entry;
	memset(p_rht_entry_f1, 0, sizeof(struct sisl_rht_entry_f1));
	p_rht_entry_f1->fp = SISL_RHT_FP(1U, 0);
	asm volatile ("lwsync"::);

	p_rht_entry_f1->lun_id = lun_id;
	asm volatile ("lwsync"::);

	/*
	 * Use a dummy RHT Format 1 entry to build the second dword
	 * of the entry that must be populated in a single write when
	 * enabled (valid bit set to TRUE).
	 */
	dummy.valid = 0x80;
	dummy.fp = SISL_RHT_FP(1U, perm);
#if 0	/* XXX - check with Andy/Todd b/c this doesn't work */
	if (internal_lun)
		dummy.port_sel = 0x1;
	else
#endif
		dummy.port_sel = 0x3;
	p_rht_entry_f1->dw = dummy.dw;

	asm volatile ("lwsync"::);

	return;
}

/*
 * NAME:        cflash_disk_open
 *
 * FUNCTION:    open a virtual lun of specified size
 *
 * INPUTS:
 *              sdev       - Pointer to scsi device structure
 *              arg        - Pointer to ioctl specific structure
 *
 * OUTPUTS:
 *              none
 *
 * RETURNS:
 *              0           - Success
 *              errno       - Failure
 *
 * NOTES:
 *              When successful:
 *               a. find a free RHT entry
 *
 */
int cflash_disk_open(struct scsi_device *sdev, void __user * arg,
		     enum open_mode_type mode)
{
	struct cflash *p_cflash = (struct cflash *)sdev->host->hostdata;
	struct afu *p_afu = p_cflash->p_afu;
	struct lun_info *p_lun_info = sdev->hostdata;

	struct dk_capi_uvirtual *pvirt = (struct dk_capi_uvirtual *)arg;
	struct dk_capi_udirect *pphys = (struct dk_capi_udirect *)arg;
	struct dk_capi_resize  resize;

	u32 perm;
	u64 context_id;
	u64 lun_size = 0;
	u64 block_size = 0;
	u64 last_lba = 0;
	u64 rsrc_handle = -1;

	int rc = 0;

	struct ctx_info *p_ctx_info;
	struct rht_info *p_rht_info = NULL;
	struct sisl_rht_entry *p_rht_entry = NULL;

	if (mode == MODE_VIRTUAL) {
		context_id = pvirt->context_id;
		lun_size =  pvirt->lun_size;
		/* Initialize to invalid value */
		pvirt->rsrc_handle = -1;
	} else if (mode == MODE_PHYSICAL) {
		context_id = pphys->context_id;
		/* Initialize to invalid value */
		pphys->rsrc_handle = -1;
	} else {
		cflash_err("unknown mode %d", mode);
		rc = -EINVAL;
		goto out;
	}

	spin_lock(p_lun_info->slock);
	if (p_lun_info->mode == MODE_NONE) {
		p_lun_info->mode = mode;
	} else  if (p_lun_info->mode != mode) {
		cflash_err("disk already opened in mode %d, mode requested %d",
			   p_lun_info->mode, mode);
		rc = -EINVAL;
		spin_unlock(p_lun_info->slock);
		goto out;
	}
	spin_unlock(p_lun_info->slock);

	cflash_info("context=0x%llx ls=0x%llx", context_id, lun_size);

	p_rht_entry = cflash_rhte_cout(p_cflash, context_id);

	if (p_rht_entry == NULL)
	{
		cflash_err("too many opens for this context");
		rc = -EMFILE;	/* too many opens  */
		goto out;
	} else {
		p_ctx_info = get_validated_context(p_cflash, context_id, FALSE);
		if (p_ctx_info) {
			p_rht_info = p_ctx_info->p_rht_info;
		} else {
			cflash_err("in %s context not valid\n", __func__);
			rc = -EINVAL;
			goto out;
		}
	}

	/* Translate read/write O_* flags from fnctl.h to AFU permission bits */
	//perm = ((pvirt->flags + 1) & 0x3);
	perm = 0x3;

	rsrc_handle = (p_rht_entry - p_rht_info->rht_start);
	block_size = p_lun_info->blk_len;

	if (mode == MODE_VIRTUAL) {
		p_rht_entry->nmask = MC_RHT_NMASK;
		p_rht_entry->fp = SISL_RHT_FP(0U, perm);
		/* format 0 & perms */

		if (lun_size != 0) {
			marshall_virt_to_resize (pvirt, &resize);
			rc = cflash_vlun_resize(sdev, &resize);
			if (rc) {
				cflash_err("resize failed rc %d", rc);
				goto out;
			}
			last_lba = resize.last_lba;
		}
		pvirt->return_flags = 0;
		pvirt->block_size = block_size;
		pvirt->last_lba = last_lba;
		pvirt->rsrc_handle = rsrc_handle;
	} else if (mode == MODE_PHYSICAL) {
		cflash_rht_format1(p_rht_entry, p_lun_info->lun_id, perm);
		afu_sync(p_afu, context_id, rsrc_handle, AFU_LW_SYNC);

		last_lba = p_lun_info->max_lba;
		pphys->return_flags = 0;
		pphys->block_size = block_size;
		pphys->last_lba = last_lba;
		pphys->rsrc_handle = rsrc_handle;
	}

out:
	cflash_info("returning handle 0x%llx rc=%d bs %lld llba %lld",
		    rsrc_handle, rc, block_size, last_lba);
	return rc;
}

/*
 * NAME:        cflash_disk_release
 *
 * FUNCTION:    Close a virtual LBA space setting it to 0 size and
 *              marking the res_hndl as free/closed.
 *
 * INPUTS:
 *              sdev       - Pointer to scsi device structure
 *              arg        - Pointer to ioctl specific structure
 *
 * OUTPUTS:
 *              none
 *
 * RETURNS:
 *              0           - Success
 *              errno       - Failure
 *
 * NOTES:
 *              When successful, the RHT entry is cleared.
 */
int cflash_disk_release(struct scsi_device *sdev, void __user * arg)
{
	struct cflash *p_cflash = (struct cflash *)sdev->host->hostdata;
	struct lun_info *p_lun_info = sdev->hostdata;
	struct afu *p_afu = p_cflash->p_afu;

	struct dk_capi_release *prele = (struct dk_capi_release *)arg;
	struct dk_capi_resize size;
	res_hndl_t res_hndl = prele->rsrc_handle;

	int rc = 0;

	struct ctx_info *p_ctx_info;
	struct rht_info *p_rht_info;
	struct sisl_rht_entry *p_rht_entry;

	cflash_info("context=0x%llx res_hndl=0x%llx, challenge=0x%llx",
		    prele->context_id, prele->rsrc_handle, prele->challenge);

	p_ctx_info = get_validated_context(p_cflash, prele->context_id, FALSE);
	if (!p_ctx_info) {
		cflash_err("invalid context!");
		rc = -EINVAL;
		goto out;
	}

	p_rht_info = p_ctx_info->p_rht_info;

	if (res_hndl < MAX_RHT_PER_CONTEXT) {
		p_rht_entry = &p_rht_info->rht_start[res_hndl];
		if (p_rht_entry->nmask == 0) {	/* not open */
			rc = -EINVAL;
			cflash_err("not open");
			goto out;
		}

		/*
		 * Resize to 0 for virtual LUNS by setting the size
		 * to 0. This will clear LXT_START and LXT_CNT fields
		 * in the RHT entry and properly sync with the AFU.
		 * Afterwards we clear the remaining fields.
		 */
		if (p_lun_info->mode ==  MODE_VIRTUAL) {
			marshall_rele_to_resize (prele, &size);
			size.req_size = 0;
			rc = cflash_vlun_resize(sdev, &size);/* p_conn good ? */
			if (rc) {
				cflash_err("resize failed rc %d", rc);
				goto out;
			}			
			cflash_rhte_cin(p_rht_entry);
		} else if (p_lun_info->mode ==  MODE_PHYSICAL) {
			/*
			 * Clear the Format 1 RHT entry for direct access (physical
			 * LUN) using the synchronization sequence defined in the
			 * SISLite specification.
			 */
			struct sisl_rht_entry_f1 *p_rht_entry_f1 =
				(struct sisl_rht_entry_f1 *)p_rht_entry;

			p_rht_entry_f1->valid = 0;
			asm volatile ("lwsync"::);

			p_rht_entry_f1->lun_id = 0ULL;
			asm volatile ("lwsync"::);

			p_rht_entry_f1->dw = 0ULL;
			asm volatile ("lwsync"::);
			afu_sync(p_afu, prele->context_id, res_hndl,
				 AFU_HW_SYNC);
		}

		/* now the RHT entry is all cleared */
		rc = 0;
		p_rht_info->ref_cnt--;
	} else {
		rc = -EINVAL;
		cflash_info("resource handle invalid %d", res_hndl);
	}

out:
	cflash_info("returning rc=%d", rc);
	return rc;
}

/*
 * NAME:        cflash_disk_detach
 *
 * FUNCTION:    Unregister a user AFU context with master.
 *
 * INPUTS:
 *              sdev       - Pointer to scsi device structure
 *              arg        - Pointer to ioctl specific structure
 *
 * OUTPUTS:
 *              none
 *
 * RETURNS:
 *              0           - Success
 *              errno       - Failure
 *
 * NOTES:
 *              When successful:
 *               a. RHT_START, RHT_CNT & CTX_CAP registers for the
 *                  context are cleared
 *               b. There is no need to clear RHT entries since
 *                  RHT_CNT=0.
 */
int cflash_disk_detach(struct scsi_device *sdev, void __user * arg)
{
	struct cflash *p_cflash = (struct cflash *)sdev->host->hostdata;
	struct lun_info *p_lun_info = sdev->hostdata;

	struct dk_capi_detach *pdet = (struct dk_capi_detach *)arg;
	struct dk_capi_release rel;

	struct ctx_info *p_ctx_info;

	int i;
	int rc = 0;

	cflash_info("context=0x%llx", pdet->context_id);

	p_ctx_info = get_validated_context(p_cflash, pdet->context_id, FALSE);
	if (!p_ctx_info) {
		cflash_err("invalid context!");
		rc = -EINVAL;
		goto out;
	}

	if (p_ctx_info->ref_cnt-- == 1) {

		/* close the context */
		/* for any resource still open, deallocate LBAs and close
		 * if nobody else is using it.
		 */

		if (p_ctx_info->p_rht_info->ref_cnt-- == 1) {
			marshall_det_to_rele(pdet, &rel);
			for (i = 0; i < MAX_RHT_PER_CONTEXT; i++) {
				rel.rsrc_handle = i;
				cflash_disk_release(sdev, &rel);
			}
		}

		/* clear RHT registers for this context */
		write_64(&p_ctx_info->p_ctrl_map->rht_start, 0);
		write_64(&p_ctx_info->p_ctrl_map->rht_cnt_id, 0);
		/* drop all capabilities */
		write_64(&p_ctx_info->p_ctrl_map->ctx_cap, 0);
	}
	spin_lock(p_lun_info->slock);
	p_lun_info->mode = MODE_NONE;
	spin_unlock(p_lun_info->slock);

	p_cflash->per_context[pdet->context_id].lfd = -1;
	p_cflash->per_context[pdet->context_id].pid = 0;

out:
	cflash_info("returning rc=%d", rc);
	return rc;
}

/*
 * NAME:	cflash_vlun_resize()
 *
 * FUNCTION:	Resize a resource handle by changing the RHT entry and LXT
 *		Tbl it points to. Synchronize all contexts that refer to
 *		the RHT.
 *
 * INPUTS:
 *              sdev       - Pointer to scsi device structure
 *              arg        - Pointer to ioctl specific structure
 *
 * OUTPUTS:
 *		p_act_new_size	- pointer to actual new size in chunks
 *
 * RETURNS:
 *		0	- Success
 *		errno	- Failure
 *
 * NOTES:
 *		Setting new_size=0 will clear LXT_START and LXT_CNT fields
 *		in the RHT entry.
 */
int cflash_vlun_resize(struct scsi_device *sdev, void __user * arg)
{
	struct cflash *p_cflash = (struct cflash *)sdev->host->hostdata;
	struct lun_info *p_lun_info = sdev->hostdata;
	struct blka *p_blka = &p_lun_info->blka;
	struct afu *p_afu = p_cflash->p_afu;

	struct dk_capi_resize *parg = (struct dk_capi_resize *)arg;
	u64 p_act_new_size = 0;
	res_hndl_t res_hndl = parg->rsrc_handle;
	u64 new_size;
	u64 nsectors;

	struct ctx_info *p_ctx_info;
	struct rht_info *p_rht_info;
	struct sisl_rht_entry *p_rht_entry;

	int rc = 0;

	/* req_size is always assumed to be in 4k blocks. So we have to convert
	 * it from 4k to chunk size
	 */
	nsectors = (parg->req_size * DK_CAPI_BLOCK) / (p_lun_info->blk_len);
	new_size = (nsectors + MC_CHUNK_SIZE - 1) / MC_CHUNK_SIZE;

	cflash_info("context=0x%llx res_hndl=0x%llx, req_size=0x%llx,"
		    "new_size=%llx", parg->context_id,
		    parg->rsrc_handle, parg->req_size, new_size);

	if (p_lun_info->mode != MODE_VIRTUAL) {
		cflash_err("cannot resize lun that is not virtual %d",
			   p_lun_info->mode);
		rc = -EINVAL;
		goto out;

	}

	p_ctx_info = get_validated_context(p_cflash, parg->context_id, FALSE);
	if (!p_ctx_info) {
		cflash_err("invalid context!");
		rc = -EINVAL;
		goto out;
	}

	p_rht_info = p_ctx_info->p_rht_info;

	if (res_hndl < MAX_RHT_PER_CONTEXT) {
		p_rht_entry = &p_rht_info->rht_start[res_hndl];

		if (p_rht_entry->nmask == 0) {	/* not open */
			cflash_err("not open rhti %p rhte %p",
				   p_rht_info, p_rht_entry);
			rc = -EINVAL;
			goto out;
		}

		if (new_size > p_rht_entry->lxt_cnt) {
			grow_lxt(p_afu,
				 p_blka,
				 parg->context_id,
				 res_hndl,
				 p_rht_entry,
				 new_size - p_rht_entry->lxt_cnt,
				 &p_act_new_size);
		} else if (new_size < p_rht_entry->lxt_cnt) {
			shrink_lxt(p_afu,
				   p_blka,
				   parg->context_id,
				   res_hndl,
				   p_rht_entry,
				   p_rht_entry->lxt_cnt - new_size,
				   &p_act_new_size);
		} else {
			p_act_new_size = new_size;
		}
	} else {
		cflash_err("res_hndl %d invalid", res_hndl);
		rc = -EINVAL;
	}
	parg->return_flags = 0;
	parg->last_lba = (p_act_new_size * MC_CHUNK_SIZE *
			  p_lun_info->blk_len) / DK_CAPI_BLOCK;

out:
	cflash_info("resized to %lld returning rc=%d", parg->last_lba, rc);
	return rc;
}

int grow_lxt(struct afu *p_afu,
	     struct blka *p_blka,
	     ctx_hndl_t ctx_hndl_u,
	     res_hndl_t res_hndl_u,
	     struct sisl_rht_entry *p_rht_entry,
	     u64 delta, u64 * p_act_new_size)
{
	struct sisl_lxt_entry *p_lxt = NULL, *p_lxt_old = NULL;
	unsigned int av_size;
	unsigned int ngrps, ngrps_old;
	u64 aun;		/* chunk# allocated by block allocator */
	int i;

	/*
	 * Check what is available in the block allocator before re-allocating
	 * LXT array. This is done up front under the mutex which must not be
	 * released until after allocation is complete.
	 */
	mutex_lock(&p_blka->mutex);
	av_size = ba_space(&p_blka->ba_lun);
	if (av_size < delta)
		delta = av_size;

	p_lxt_old = p_rht_entry->lxt_start;
	ngrps_old = LXT_NUM_GROUPS(p_rht_entry->lxt_cnt);
	ngrps = LXT_NUM_GROUPS(p_rht_entry->lxt_cnt + delta);

	if (ngrps != ngrps_old) {
		/* reallocate to fit new size */
		p_lxt = kzalloc((sizeof(*p_lxt) * LXT_GROUP_SIZE * ngrps),
				GFP_KERNEL);
		if (!p_lxt) {
			mutex_unlock(&p_blka->mutex);
			return -ENOMEM;
		}

		/* copy over all old entries */
		memcpy(p_lxt, p_lxt_old, (sizeof(*p_lxt) *
					  p_rht_entry->lxt_cnt));
	} else {
		p_lxt = p_lxt_old;
	}

	/* nothing can fail from now on */
	*p_act_new_size = p_rht_entry->lxt_cnt + delta;

	/* add new entries to the end */
	for (i = p_rht_entry->lxt_cnt; i < *p_act_new_size; i++) {
		/*
		 * Due to the earlier check of available space, ba_alloc
		 * cannot fail here. If it did due to internal error,
		 * leave a rlba_base of -1u which will likely be a
		 * invalid LUN (too large).
		 */
		aun = ba_alloc(&p_blka->ba_lun);
		if ((aun == -1ULL) || (aun >= p_blka->nchunk)) {
			cflash_err("ba_alloc error: allocated chunk# %llX, "
				   "max %llX", aun, p_blka->nchunk - 1);
		}

		/* lun_indx = 0, select both ports, use r/w perms from RHT */
		p_lxt[i].rlba_base = ((aun << MC_CHUNK_SHIFT) | 0x33);
	}

	mutex_unlock(&p_blka->mutex);

	asm volatile ("lwsync"::);	/* make lxt updates visible */

	/* Now sync up AFU - this can take a while */
	p_rht_entry->lxt_start = p_lxt;	/* even if p_lxt didn't change */
	asm volatile ("lwsync"::);

	p_rht_entry->lxt_cnt = *p_act_new_size;
	asm volatile ("lwsync"::);

	afu_sync(p_afu, ctx_hndl_u, res_hndl_u, AFU_LW_SYNC);

	/* free old lxt if reallocated */
	if (p_lxt != p_lxt_old)
		kfree(p_lxt_old);

	/* XXX - what is the significance of this comment? */
	/* sync up AFU on each context in the doubly linked list */
	cflash_info("returning");
	return 0;
}

int shrink_lxt(struct afu *p_afu,
	       struct blka *p_blka,
	       ctx_hndl_t ctx_hndl_u,
	       res_hndl_t res_hndl_u,
	       struct sisl_rht_entry *p_rht_entry,
	       u64 delta, u64 * p_act_new_size)
{
	struct sisl_lxt_entry *p_lxt, *p_lxt_old;
	unsigned int ngrps, ngrps_old;
	u64 aun;		/* chunk# allocated by block allocator */
	int i;

	p_lxt_old = p_rht_entry->lxt_start;
	ngrps_old = LXT_NUM_GROUPS(p_rht_entry->lxt_cnt);
	ngrps = LXT_NUM_GROUPS(p_rht_entry->lxt_cnt - delta);

	if (ngrps != ngrps_old) {
		/* reallocate to fit new size unless new size is 0 */
		if (ngrps) {
			p_lxt = kzalloc((sizeof(*p_lxt) * LXT_GROUP_SIZE *
					 ngrps), GFP_KERNEL);
			if (!p_lxt)
				return -ENOMEM;

			/* copy over old entries that will remain */
			memcpy(p_lxt, p_lxt_old, (sizeof(*p_lxt) *
						  (p_rht_entry->lxt_cnt -
						   delta)));
		} else {
			p_lxt = NULL;
		}
	} else {
		p_lxt = p_lxt_old;
	}

	/* nothing can fail from now on */
	*p_act_new_size = p_rht_entry->lxt_cnt - delta;

	/* Now sync up AFU - this can take a while */
	p_rht_entry->lxt_cnt = *p_act_new_size;
	asm volatile ("lwsync"::);	/* also makes lxt updates visible */

	p_rht_entry->lxt_start = p_lxt;	/* even if p_lxt didn't change */
	asm volatile ("lwsync"::);

	afu_sync(p_afu, ctx_hndl_u, res_hndl_u, AFU_HW_SYNC);

	/* free LBAs allocated to freed chunks */
	mutex_lock(&p_blka->mutex);
	for (i = delta - 1; i >= 0; i--) {
		aun = (p_lxt_old[*p_act_new_size + i].rlba_base >>
		       MC_CHUNK_SHIFT);
		ba_free(&p_blka->ba_lun, aun);
	}
	mutex_unlock(&p_blka->mutex);

	/* free old lxt if reallocated */
	if (p_lxt != p_lxt_old)
		kfree(p_lxt_old);
	/* XXX - what is the significance of this comment? */
	/* sync up AFU on each context in the doubly linked list!!! */
	cflash_info("returning");
	return 0;
}

int cflash_afu_recover(struct scsi_device *sdev, void __user * arg)
{
	struct cflash *p_cflash = (struct cflash *)sdev->host->hostdata;
	struct afu *p_afu = p_cflash->p_afu;
	struct dk_capi_recover_afu *parg = (struct dk_capi_recover_afu *)arg;
	long reg;
	int rc = 0;

	reg = read_64(&p_afu->p_ctrl_map->mbox_r);	/* Try MMIO */

	/* MMIO returning 0xff, need to reset */
	if (reg == -1) {
		cflash_info("p_afu=%p reason 0x%llx", p_afu, parg->reason);
		afu_reset (p_cflash);

	} else {
		cflash_info("reason 0x%llx MMIO is working, no reset performed",
			    parg->reason);
		rc = -EINVAL;
	}

	return rc;
}

/*
 * NAME:	clone_lxt()
 *
 * FUNCTION:	clone a LXT table
 *
 * INPUTS:
 *		p_afu		- Pointer to afu struct
 *		ctx_hndl_u	- context that owns the destination LXT
 *		res_hndl_u	- res_hndl of the destination LXT
 *		p_rht_entry	- destination RHT to clone into
 *		p_rht_entry_src	- source RHT to clone from
 *
 * OUTPUTS:
 *
 * RETURNS:
 *		0	- Success
 *		errno	- Failure
 *
 * NOTES:
 */
int clone_lxt(struct afu *p_afu,
	      struct blka *p_blka,
	      ctx_hndl_t ctx_hndl_u,
	      res_hndl_t res_hndl_u,
	      struct sisl_rht_entry *p_rht_entry,
	      struct sisl_rht_entry *p_rht_entry_src)
{
	struct sisl_lxt_entry *p_lxt;
	unsigned int ngrps;
	u64 aun;		/* chunk# allocated by block allocator */
	int i, j;

	ngrps = LXT_NUM_GROUPS(p_rht_entry_src->lxt_cnt);

	if (ngrps) {
		/* allocate new LXTs for clone */
		p_lxt = kzalloc((sizeof(*p_lxt) * LXT_GROUP_SIZE * ngrps),
				GFP_KERNEL);
		if (!p_lxt)
			return -ENOMEM;

		/* copy over */
		memcpy(p_lxt, p_rht_entry_src->lxt_start,
		       (sizeof(*p_lxt) * p_rht_entry_src->lxt_cnt));

		/* clone the LBAs in block allocator via ref_cnt */
		mutex_lock(&p_blka->mutex);
		for (i = 0; i < p_rht_entry_src->lxt_cnt; i++) {
			aun = (p_lxt[i].rlba_base >> MC_CHUNK_SHIFT);
			if (ba_clone(&p_blka->ba_lun, aun) == -1ULL) {
				/* free the clones already made */
				for (j = 0; j < i; j++) {
					aun = (p_lxt[j].rlba_base >>
					       MC_CHUNK_SHIFT);
					ba_free(&p_blka->ba_lun, aun);
				}

				mutex_unlock(&p_blka->mutex);
				kfree(p_lxt);
				return -EIO;
			}
		}
		mutex_unlock(&p_blka->mutex);
	} else {
		p_lxt = NULL;
	}

	asm volatile ("lwsync"::);	/* make lxt updates visible */

	/* Now sync up AFU - this can take a while */
	p_rht_entry->lxt_start = p_lxt;	/* even if p_lxt is NULL */
	asm volatile ("lwsync"::);

	p_rht_entry->lxt_cnt = p_rht_entry_src->lxt_cnt;
	asm volatile ("lwsync"::);

	afu_sync(p_afu, ctx_hndl_u, res_hndl_u, AFU_LW_SYNC);

	/* XXX - what is the significance of this comment? */
	/* sync up AFU on each context in the doubly linked list */
	cflash_info("returning");
	return 0;
}

/*
 * NAME:        do_mc_xlate_lba
 *
 * FUNCTION:    Query the physical LBA mapped to a virtual LBA
 *
 * INPUTS:
 *              p_afu       - Pointer to afu struct
 *              p_conn_info - Pointer to connection the request came in
 *              res_hndl    - resource handle to query on
 *              v_lba       - virtual LBA on res_hndl
 *
 * OUTPUTS:
 *              p_p_lba     - pointer to output physical LBA
 *
 * RETURNS:
 *              0           - Success
 *              errno       - Failure
 *
 */
int cflash_xlate_lba(struct scsi_device *sdev, void __user * arg)
{
	/* XXX: Original arguments. */
	u64 v_lba = 0;
	u64 *p_p_lba = NULL;
	u64 rsrc_handle = 0;
	/* XXX: How to determine p_ctx_info? */
	u64 context_id = 0;
	struct ctx_info *p_ctx_info = NULL;

	struct rht_info *p_rht_info = p_ctx_info->p_rht_info;
	struct sisl_rht_entry *p_rht_entry;
	u64 chunk_id, chunk_off, rlba_base;

	cflash_info("rsrc_handle=%lld v_lba=%lld ctx_hdl=%lld",
		    rsrc_handle, v_lba, context_id);

	if (rsrc_handle < MAX_RHT_PER_CONTEXT) {
		p_rht_entry = &p_rht_info->rht_start[rsrc_handle];
		if (p_rht_entry->nmask == 0) {
			/* not open */
			return -EINVAL;
		}

		chunk_id = (v_lba >> MC_CHUNK_SHIFT);
		chunk_off = (v_lba & MC_CHUNK_OFF_MASK);

		if (chunk_id < p_rht_entry->lxt_cnt) {
			rlba_base =
			    (p_rht_entry->lxt_start[chunk_id].rlba_base &
			     (~MC_CHUNK_OFF_MASK));
			*p_p_lba = (rlba_base | chunk_off);
		} else {
			return -EINVAL;
		}
	} else {
		return -EINVAL;
	}

	cflash_info("returning");
	return 0;
}

/*
 * NAME:        cflash_disk_clone
 *
 * FUNCTION:    Clone a context by making a snapshot copy of another, specified
 *		context. This routine effectively performs cflash_disk_open
 *		operations for each in-use virtual resource in the source
 *		context. Note that the destination context must be in pristine
 *		state and cannot have any resource handles open at the time
 *		of the clone.
 *
 * INPUTS:
 *              sdev       - Pointer to scsi device structure
 *              arg        - Pointer to ioctl specific structure
 *
 * OUTPUTS:
 *              None
 *
 * RETURNS:
 *              0           - Success
 *              errno       - Failure
 */
int cflash_disk_clone(struct scsi_device *sdev, void __user * arg)
{
	struct cflash *p_cflash = (struct cflash *)sdev->host->hostdata;
	struct lun_info *p_lun_info = sdev->hostdata;
	struct blka *p_blka = &p_lun_info->blka;
	struct afu *p_afu = p_cflash->p_afu;
	struct dk_capi_clone *pclone = (struct dk_capi_clone *)arg;
	struct dk_capi_release release = { 0 };

	struct ctx_info *p_ctx_info_src,
			*p_ctx_info_dst;
	struct rht_info *p_rht_info_src,
			*p_rht_info_dst;
	u32 perm;
	u64 reg;
	int i, j;
	int rc = 0;

	cflash_info("ctx_hdl_src=%llu ctx_hdl_dst=%llu",
		    pclone->context_id_src, pclone->context_id_dst);

	/* Do not clone yourself */
	if (pclone->context_id_src == pclone->context_id_dst) {
		rc = -EINVAL;
		goto out;
	}

	p_ctx_info_src = get_validated_context(p_cflash, pclone->context_id_src,
					       TRUE);
	p_ctx_info_dst = get_validated_context(p_cflash, pclone->context_id_dst,
					       FALSE);
	if (!p_ctx_info_src || !p_ctx_info_dst) {
		cflash_err("invalid context!");
		rc = -EINVAL;
		goto out;
	}

	p_rht_info_src = p_ctx_info_src->p_rht_info;
	p_rht_info_dst = p_ctx_info_dst->p_rht_info;

	/* Verify there is no open resource handle in the destination context */
	for (i = 0; i < MAX_RHT_PER_CONTEXT; i++)
		if (p_rht_info_dst->rht_start[i].nmask != 0) {
			rc = -EINVAL;
			goto out;
		}

	reg = read_64(&p_ctx_info_src->p_ctrl_map->mbox_r);
	if (reg == 0) {		/* zeroed mbox is a locked mbox */
		rc = -EACCES;	/* return Permission denied */
		goto out;
	}

	/* Translate read/write O_* flags from fnctl.h to AFU permission bits */
	perm = ((pclone->flags + 1) & 0x3);

	/*
	 * This loop is equivalent to cflash_disk_open & cflash_vlun_resize.
	 * Not checking if the source context has anything open or whether
	 * it is even registered. Cleanup when the clone fails.
	 */
	for (i = 0; i < MAX_RHT_PER_CONTEXT; i++) {
		p_rht_info_dst->rht_start[i].nmask =
		    p_rht_info_src->rht_start[i].nmask;
		p_rht_info_dst->rht_start[i].fp =
		    SISL_RHT_FP_CLONE(p_rht_info_src->rht_start[i].fp, perm);

		rc = clone_lxt(p_afu, p_blka, pclone->context_id_dst, i,
			       &p_rht_info_dst->rht_start[i],
			       &p_rht_info_src->rht_start[i]);
		if (rc) {
			marshall_clone_to_rele(pclone, &release);
			for (j = 0; j < i; j++) {
				release.rsrc_handle = j;
				cflash_disk_release(sdev, &release);
			}

			cflash_rhte_cin(&p_rht_info_dst->rht_start[i]);
			goto out;
		}
	}

out:
	cflash_info("returning rc=%d", rc);
	return rc;
}

/*
 * NAME:	do_mc_dup()
 *
 * FUNCTION:	dup 2 contexts by linking their RHTs
 *
 * INPUTS:
 *		p_afu		- Pointer to afu struct
 *		p_conn_info	- Pointer to connection the request came in
 *				  This is the context to dup to (target)
 *		ctx_hndl_cand	- This is the context to dup from source)
 *		challenge	- used to validate access to ctx_hndl_cand
 *
 * OUTPUTS:
 *		None
 *
 * RETURNS:
 *		0	- Success
 *		errno	- Failure
 */
/* XXX - what is the significance of this comment? */
/* dest ctx must be unduped and with no open res_hndls */
int cflash_disk_dup(struct scsi_device *sdev, void __user * arg)
{
	struct cflash *p_cflash = (struct cflash *)sdev->host->hostdata;
	struct afu *p_afu = p_cflash->p_afu;

	/* XXX: Input arguments */
	u64 challenge = 0;
	u64 ctx_hndl_cand = 0;
	u64 context_id = 0;
	struct ctx_info *p_ctx_info = NULL;

	struct rht_info *p_rht_info = p_ctx_info->p_rht_info;

	struct ctx_info *p_ctx_info_cand;
	u64 reg;
	int i;

	cflash_info("challenge=%lld cand=%lld ctx_hdl=%lld",
		    challenge, ctx_hndl_cand, context_id);

	/* verify there is no open resource handle in the target context of the clone */
	for (i = 0; i < MAX_RHT_PER_CONTEXT; i++)
		if (p_rht_info->rht_start[i].nmask != 0)
			return -EINVAL;

	/* do not dup yourself */
	if (context_id == ctx_hndl_cand)
		return -EINVAL;

	if (ctx_hndl_cand < MAX_CONTEXT)
		p_ctx_info_cand = &p_afu->ctx_info[ctx_hndl_cand];
	else
		return -EINVAL;

	reg = read_64(&p_ctx_info_cand->p_ctrl_map->mbox_r);

	/* fyi, zeroed mbox is a locked mbox */
	if ((reg == 0) || (challenge != reg))
		return -EACCES;	/* return Permission denied */

	/* XXX - what does this mean? */
	cflash_info("returning");
	return -EIO;		/* todo later!!! */
}

/*
 * NAME:	do_mc_stat()
 *
 * FUNCTION:	Query the current information on a resource handle
 *
 * INPUTS:
 *		p_afu		- Pointer to afu struct
 *		p_conn_info	- Pointer to connection the request came in
 *		res_hndl	- resource handle to query
 *
 * OUTPUTS:
 *		p_mc_stat	- pointer to output stat information
 *
 * RETURNS:
 *		0		- Success
 *		errno		- Failure
 *
 */
int cflash_disk_stat(struct scsi_device *sdev, void __user * arg)
{
	struct lun_info *p_lun_info = sdev->hostdata;
	struct blka *p_blka = &p_lun_info->blka;

	/* XXX: Input arguments; */
	mc_stat_t *p_mc_stat = NULL;
	struct ctx_info *p_ctx_info = NULL;
	u64 context_id = 0;
	u64 rsrc_handle = 0;

	struct rht_info *p_rht_info = p_ctx_info->p_rht_info;
	struct sisl_rht_entry *p_rht_entry;

	cflash_info("context_id=%lld", context_id);

	if (rsrc_handle < MAX_RHT_PER_CONTEXT) {
		p_rht_entry = &p_rht_info->rht_start[rsrc_handle];

		/* not open */
		if (p_rht_entry->nmask == 0)
			return -EINVAL;

		p_mc_stat->blk_len = p_blka->ba_lun.lba_size;
		p_mc_stat->nmask = p_rht_entry->nmask;
		p_mc_stat->size = p_rht_entry->lxt_cnt;
		p_mc_stat->flags = SISL_RHT_PERM(p_rht_entry->fp);
	} else {
		return -EINVAL;
	}

	cflash_info("returning");
	return 0;
}

int read_cap16(struct afu *p_afu, struct lun_info *p_lun_info, u32 port_sel)
{

	u32 *p_u32;
	u64 *p_u64;
	struct afu_cmd *p_cmd;
	int rc=0;

	p_cmd = cflash_cmd_cout(p_afu);
	if (!p_cmd) {
		cflash_err("could not get a free command");
		return -1;
	}

	p_cmd->rcb.req_flags = (SISL_REQ_FLAGS_PORT_LUN_ID |
				SISL_REQ_FLAGS_SUP_UNDERRUN |
				SISL_REQ_FLAGS_HOST_READ);

	p_cmd->rcb.port_sel = port_sel;
	p_cmd->rcb.lun_id = p_lun_info->lun_id;
	p_cmd->rcb.data_len = CMD_BUFSIZE;
	p_cmd->rcb.data_ea = (u64) p_cmd->buf;
	p_cmd->rcb.timeout = MC_DISCOVERY_TIMEOUT;

	p_cmd->rcb.cdb[0] = 0x9E;	/* read cap(16) */
	p_cmd->rcb.cdb[1] = 0x10;	/* service action */
	p_u32 = (u32 *) & p_cmd->rcb.cdb[10];
	write_32(p_u32, CMD_BUFSIZE);
	p_cmd->sa.host_use_b[1] = 0;	/* reset retry cnt */

	cflash_info("sending cmd(0x%x) with RCB EA=%p data EA=0x%llx",
		    p_cmd->rcb.cdb[0], &p_cmd->rcb,
		    p_cmd->rcb.data_ea);

	do {
		cflash_send_cmd(p_afu, p_cmd);
		cflash_wait_resp(p_afu, p_cmd);
	} while (check_status(&p_cmd->sa));

	if (p_cmd->sa.host_use_b[0] & B_ERROR) {
		cflash_err("command failed");
		rc = -1;
		goto out;
	}
	/* read cap success  */
	spin_lock(p_lun_info->slock);
	p_u64 = (u64 *) & p_cmd->buf[0];
	p_lun_info->max_lba = read_64(p_u64);

	p_u32 = (u32 *) & p_cmd->buf[8];
	p_lun_info->blk_len = read_32(p_u32);
	spin_unlock(p_lun_info->slock);

out:
	cflash_cmd_cin(p_cmd);

	cflash_info("maxlba=%lld blklen=%d pcmd %p",
		    p_lun_info->max_lba, p_lun_info->blk_len, p_cmd);
	return rc;
}

/* XXX: This is temporary. 
 * The report luns command will be sent be the SCSI stack
 */
int find_lun(struct cflash *p_cflash, u32 port_sel)
{
	u32 *p_u32;
	u32 len;
	u64 *p_u64;
	struct afu *p_afu = p_cflash->p_afu;
	struct afu_cmd *p_cmd;
	struct lun_info *p_lun_info = NULL;
	u64 *p_currid;
	int i = 0;
	int j = 0;
	int rc = 0;
	u64 *lunidarray = NULL;

	p_cmd = cflash_cmd_cout(p_afu);
	if (!p_cmd) {
		cflash_err("could not get a free command");
		return -1;
	}

	p_cmd->rcb.req_flags = (SISL_REQ_FLAGS_PORT_LUN_ID |
				SISL_REQ_FLAGS_SUP_UNDERRUN |
				SISL_REQ_FLAGS_HOST_READ);

	p_cmd->rcb.port_sel = port_sel;
	p_cmd->rcb.lun_id = 0x0;	/* use lun_id=0 w/report luns */
	p_cmd->rcb.data_len = CMD_BUFSIZE;
	p_cmd->rcb.data_ea = (u64) p_cmd->buf;
	p_cmd->rcb.timeout = MC_DISCOVERY_TIMEOUT;

	p_cmd->rcb.cdb[0] = 0xA0;	/* report luns */
	p_u32 = (u32 *) & p_cmd->rcb.cdb[6];
	write_32(p_u32, CMD_BUFSIZE);	/* allocation length */
	p_cmd->sa.host_use_b[1] = 0;	/* reset retry cnt */

	cflash_info("sending cmd(0x%x) with RCB EA=%p data EA=0x%p",
		    p_cmd->rcb.cdb[0], &p_cmd->rcb, (void *)p_cmd->rcb.data_ea);

	do {
		cflash_send_cmd(p_afu, p_cmd);
		cflash_wait_resp(p_afu, p_cmd);
	} while (check_status(&p_cmd->sa));

	if (p_cmd->sa.host_use_b[0] & B_ERROR) {
		cflash_cmd_cin(p_cmd);
		return -1;
	}
	/* report luns success  */
	len = read_32((u32 *) & p_cmd->buf[0]);
	hexdump((void *)p_cmd->buf, len + 8, "report luns data");

	p_u64 = (u64 *) & p_cmd->buf[8];	/* start of lun list */

	p_currid = lunidarray = kzalloc(len, GFP_KERNEL);

	while (len) {
		*p_currid = read_64(p_u64);
		len -= 8;
		p_u64++;
		i++;
		p_currid++;
	}
	cflash_info("found %d luns", i);

	/* Release the CMD only after looking through the response */
	cflash_cmd_cin(p_cmd);

	p_currid = lunidarray;

	for (j = 0; j < i; j++, p_currid++) {
		cflash_info("adding i=%d lun_id %016llx last_index %d",
			    j, *p_currid, p_cflash->last_lun_index);

		/*
		 * XXX - scsi_add_device() will trigger slave_alloc and
		 * slave_configure which will create the lun_info structure
		 * and add it to the front of the AFU's lun list.
		 */
		scsi_add_device(p_cflash->host, port_sel, CFLASH_TARGET,
				*p_currid);
		p_lun_info = list_first_entry(&p_afu->luns, struct lun_info,
					      list);
		p_lun_info->lun_id = *p_currid;

		/* program FC_PORT LUN Tbl */
		write_64(&p_afu->p_afu_map->global.fc_port[port_sel - 1]
			 [p_cflash->last_lun_index], *p_currid);

		read_cap16(p_afu, p_lun_info, port_sel);

		/*
		 * XXX - when we transition to slave_alloc, refactor this into
		 * create_lun_info(), for now it must be called separately after
		 * we obtain the blk_len and lba from cap16.
		 */
		rc = cflash_init_ba(p_lun_info);
		if (rc) {
			cflash_err("call to cflash_init_ba failed rc=%d!", rc);
			list_del(&p_lun_info->list);
			kfree(p_lun_info);
			goto out;
		}

		p_cflash->last_lun_index++;
	}

out:
	if (lunidarray)
		kfree(lunidarray);
	cflash_info("returning rc %d pcmd%p", rc, p_cmd);
	return rc;
}
