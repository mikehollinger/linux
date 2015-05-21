/*
 * CXL Flash Device Driver
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

#include <linux/delay.h>
#include <linux/file.h>
#include <linux/moduleparam.h>
#include <linux/syscalls.h>
#include <misc/cxl.h>
#include <asm/unaligned.h>

#include <scsi/scsi_host.h>
#include <uapi/scsi/cxlflash_ioctl.h>

#include "sislite.h"
#include "common.h"
#include "superpipe.h"

struct cxlflash_global global;

static void marshall_det_to_rele(struct dk_cxlflash_detach *detach,
				 struct dk_cxlflash_release *release)
{
	release->hdr = detach->hdr;
	release->context_id = detach->context_id;
}

static void marshall_clone_to_rele(struct dk_cxlflash_clone *clone,
				   struct dk_cxlflash_release *release)
{
	release->hdr = clone->hdr;
	release->context_id = clone->context_id_dst;
}

static struct lun_info *create_lun_info(struct scsi_device *sdev)
{
	struct lun_info *lun_info = NULL;

	lun_info = kzalloc(sizeof(*lun_info), GFP_KERNEL);
	if (unlikely(!lun_info)) {
		cxlflash_err("could not allocate lun_info");
		goto create_lun_info_exit;
	}

	lun_info->sdev = sdev;

	spin_lock_init(&lun_info->slock);

create_lun_info_exit:
	return lun_info;
}

static struct lun_info *lookup_lun(struct scsi_device *sdev, __u8 *wwid)
{
	struct lun_info *lun_info, *temp;
	unsigned long flags = 0UL;

	if (wwid)
		list_for_each_entry_safe(lun_info, temp, &global.luns, list) {
			if (!memcmp(lun_info->wwid, wwid,
				    DK_CXLFLASH_MANAGE_LUN_WWID_LEN))
				return lun_info;
		}

	lun_info = create_lun_info(sdev);
	if (unlikely(!lun_info))
		goto out;

	spin_lock_irqsave(&global.slock, flags);
	if (wwid)
		memcpy(lun_info->wwid, wwid, DK_CXLFLASH_MANAGE_LUN_WWID_LEN);
	list_add(&lun_info->list, &global.luns);
	spin_unlock_irqrestore(&global.slock, flags);

out:
	cxlflash_dbg("returning %p", lun_info);
	return lun_info;
}

/**
 * cxlflash_slave_alloc - Allocate a per LUN structure
 * @sdev:       struct scsi_device device to configure
 *
 * Returns:
 *      0 on success / -ENOMEM when memory allocation fails
 **/
int cxlflash_slave_alloc(struct scsi_device *sdev)
{
	int rc = 0;
	struct lun_info *lun_info = NULL;

	lun_info = lookup_lun(sdev, NULL);
	if (unlikely(!lun_info)) {
		rc = -ENOMEM;
		goto out;
	}

	sdev->hostdata = lun_info;

out:
	cxlflash_dbg("returning sdev %p rc=%d", sdev, rc);
	return rc;
}

/**
 * cxlflash_slave_configure - Configure the device
 * @sdev:       struct scsi_device device to configure
 *
 * Store the lun_id field, and program the LUN mapping table on the AFU.
 *
 * Returns:
 *      0
 **/
int cxlflash_slave_configure(struct scsi_device *sdev)
{
	struct Scsi_Host *shost = sdev->host;
	struct lun_info *lun_info = sdev->hostdata;
	struct cxlflash *cxlflash = shost_priv(shost);
	struct afu *afu = cxlflash->afu;

	cxlflash_info("id = %d/%d/%d/%llu", shost->host_no, sdev->channel,
		      sdev->id, sdev->lun);

	/* Store off lun in unpacked, AFU-friendly format */
	lun_info->lun_id = lun_to_lunid(sdev->lun);
	lun_info->lun_index = cxlflash->last_lun_index[sdev->channel];

	writeq_be(lun_info->lun_id,
		  &afu->afu_map->global.fc_port[sdev->channel]
		  [cxlflash->last_lun_index[sdev->channel]++]);

	return 0;
}

void cxlflash_slave_destroy(struct scsi_device *sdev)
{
	void *lun_info = (void *)sdev->hostdata;

	cxlflash_dbg("lun_info=%p", lun_info);
}

void cxlflash_list_init(void)
{
	INIT_LIST_HEAD(&global.luns);
	spin_lock_init(&global.slock);
	global.err_page = NULL;
}

void cxlflash_list_terminate(void)
{
	struct lun_info *lun_info, *temp;
	unsigned long flags = 0;

	spin_lock_irqsave(&global.slock, flags);
	list_for_each_entry_safe(lun_info, temp, &global.luns, list) {
		list_del(&lun_info->list);
		ba_terminate(&lun_info->blka.ba_lun);
		kfree(lun_info);
	}

	if (global.err_page) {
		__free_page(global.err_page);
		global.err_page = NULL;
	}
	spin_unlock_irqrestore(&global.slock, flags);
}

/*
 * NOTE: despite the name pid, in linux, current->pid actually refers
 * to the lightweight process id (tid) and can change if the process is
 * multithreaded. The tgid remains constant for the process and only changes
 * when the process of fork. For all intents and purposes, think of tgid
 * as a pid in the traditional sense.
 */
struct ctx_info *cxlflash_get_context(struct cxlflash *cxlflash,
				      u64 ctxid,
				      struct lun_info *lun_info,
				      bool clone_path)
{
	struct ctx_info *ctx_info = NULL;
	struct lun_access *lun_access = NULL;
	bool found = false;
	pid_t pid = current->tgid, ctxpid = 0;
	unsigned long flags = 0;

	if (unlikely(clone_path))
		pid = current->parent->tgid;

	if (likely(ctxid < MAX_CONTEXT)) {
		spin_lock_irqsave(&cxlflash->ctx_tbl_slock, flags);
		ctx_info = cxlflash->ctx_tbl[ctxid];
		if (unlikely(!ctx_info)) {
			spin_unlock_irqrestore(&cxlflash->ctx_tbl_slock, flags);
			goto out;
		}

		/*
		 * Increment the reference count under lock so the context
		 * is not yanked from under us on a removal thread.
		 */
		atomic_inc(&ctx_info->nrefs);
		spin_unlock_irqrestore(&cxlflash->ctx_tbl_slock, flags);

		ctxpid = ctx_info->pid;
		if (pid != ctxpid)
			goto denied;

		if (likely(lun_info)) {
			list_for_each_entry(lun_access, &ctx_info->luns, list)
				if (lun_access->lun_info == lun_info) {
					found = true;
					break;
				}

			if (!found)
				goto denied;
		}
	}

out:
	cxlflash_dbg("ctxid=%llu ctxinfo=%p ctxpid=%u pid=%u clone=%d found=%d",
		     ctxid, ctx_info, ctxpid, pid, clone_path, found);

	return ctx_info;

denied:
	atomic_dec(&ctx_info->nrefs);
	ctx_info = NULL;
	goto out;
}

static int cxlflash_afu_attach(struct cxlflash *cxlflash,
			       struct ctx_info *ctx_info)
{
	struct afu *afu = cxlflash->afu;
	int rc = 0;
	u64 reg;

	/* restrict user to read/write cmds in translated
	 * mode. User has option to choose read and/or write
	 * permissions again in mc_open.
	 */
	(void)readq_be(&ctx_info->ctrl_map->mbox_r);	/* unlock ctx_cap */
	writeq_be((SISL_CTX_CAP_READ_CMD | SISL_CTX_CAP_WRITE_CMD),
		  &ctx_info->ctrl_map->ctx_cap);

	reg = readq_be(&ctx_info->ctrl_map->ctx_cap);

	/* if the write failed, the ctx must have been
	 * closed since the mbox read and the ctx_cap
	 * register locked up.  fail the registration
	 */
	if (reg != (SISL_CTX_CAP_READ_CMD | SISL_CTX_CAP_WRITE_CMD)) {
		cxlflash_err("ctx may be closed reg=%llx", reg);
		rc = -EAGAIN;
		goto out;
	}

	/* set up MMIO registers pointing to the RHT */
	writeq_be((u64)ctx_info->rht_start, &ctx_info->ctrl_map->rht_start);
	writeq_be(SISL_RHT_CNT_ID((u64)MAX_RHT_PER_CONTEXT,
				  (u64)(afu->ctx_hndl)),
		  &ctx_info->ctrl_map->rht_cnt_id);
out:
	cxlflash_info("returning rc=%d", rc);
	return rc;

}

/**
 * cxlflash_check_status() - evaluates the status of an AFU command
 * @ioasa:	The IOASA of an AFU command.
 *
 * Return:
 *	TRUE (1) when the IOASA contains an error
 *	FALSE (0) when the IOASA does not contain an error
 */
int cxlflash_check_status(struct sisl_ioasa *ioasa)
{
	/* do we need to retry AFU_CMDs (sync) on afu_rc = 0x30 ? */
	/* can we not avoid that ? */
	/* not retrying afu timeouts (B_TIMEOUT) */
	/* returns 1 if the cmd should be retried, 0 otherwise */
	/* sets B_ERROR flag based on IOASA */

	if (ioasa->ioasc == 0)
		return 0;

	ioasa->host_use_b[0] |= B_ERROR;

	if (!(ioasa->host_use_b[1]++ < MC_RETRY_CNT))
		return 0;

	switch (ioasa->rc.afu_rc) {
	case SISL_AFU_RC_NO_CHANNELS:
	case SISL_AFU_RC_OUT_OF_DATA_BUFS:
		msleep(1);	/* 1 msec */
		return 1;

	case 0:
		/* no afu_rc, but either scsi_rc and/or fc_rc is set */
		/* retry all scsi_rc and fc_rc after a small delay */
		msleep(1);	/* 1 msec */
		return 1;
	}

	return 0;
}

static int read_cap16(struct afu *afu, struct lun_info *lun_info, u32 port_sel)
{
	struct afu_cmd *cmd;
	int rc = 0;

	cmd = cxlflash_cmd_checkout(afu);
	if (unlikely(!cmd)) {
		cxlflash_err("could not get a free command");
		return -1;
	}

	cmd->rcb.req_flags = (SISL_REQ_FLAGS_PORT_LUN_ID |
				SISL_REQ_FLAGS_SUP_UNDERRUN |
				SISL_REQ_FLAGS_HOST_READ);

	cmd->rcb.port_sel = port_sel;
	cmd->rcb.lun_id = lun_info->lun_id;
	cmd->rcb.data_len = CMD_BUFSIZE;
	cmd->rcb.data_ea = (u64) cmd->buf;
	cmd->rcb.timeout = MC_DISCOVERY_TIMEOUT;
	cmd->internal = true;

	cmd->rcb.cdb[0] = 0x9E;	/* read cap(16) */
	cmd->rcb.cdb[1] = 0x10;	/* service action */
	put_unaligned_be32(CMD_BUFSIZE, &cmd->rcb.cdb[10]);

	cmd->sa.host_use_b[1] = 0;	/* reset retry cnt */

	cxlflash_info("sending cmd(0x%x) with RCB EA=%p data EA=0x%llx",
		      cmd->rcb.cdb[0], &cmd->rcb, cmd->rcb.data_ea);

	do {
		rc = cxlflash_send_cmd(afu, cmd);
		if (!rc)
			cxlflash_wait_resp(afu, cmd);
		else
			break;
	} while (cxlflash_check_status(&cmd->sa));

	if (cmd->sa.host_use_b[0] & B_ERROR) {
		cxlflash_err("command failed");
		rc = -1;
		goto out;
	}

	/*
	 * Read cap was successful, grab values from the buffer;
	 * note that we don't need to worry about unaligned access
	 * as the buffer is allocated on an aligned boundary.
	 */
	spin_lock(&lun_info->slock);
	lun_info->max_lba = swab64(*((u64 *)&cmd->buf[0]));
	lun_info->blk_len = swab32(*((u32 *)&cmd->buf[8]));
	spin_unlock(&lun_info->slock);

out:
	cxlflash_info("maxlba=%lld blklen=%d pcmd %p",
		      lun_info->max_lba, lun_info->blk_len, cmd);
	return rc;
}

struct sisl_rht_entry *cxlflash_get_rhte(struct ctx_info *ctx_info,
					 res_hndl_t res_hndl,
					 struct lun_info *lun_info)
{
	struct sisl_rht_entry *rhte = NULL;

	if (unlikely(!ctx_info->rht_start)) {
		cxlflash_err("Context does not have an allocated RHT!");
		goto out;
	}

	if (unlikely(res_hndl >= MAX_RHT_PER_CONTEXT)) {
		cxlflash_err("Invalid resource handle! (%d)", res_hndl);
		goto out;
	}

	if (unlikely(ctx_info->rht_lun[res_hndl] != lun_info)) {
		cxlflash_err("Resource handle invalid for LUN! (%d)", res_hndl);
		goto out;
	}

	rhte = &ctx_info->rht_start[res_hndl];
	if (unlikely(rhte->nmask == 0)) {
		cxlflash_err("Unopened resource handle! (%d)", res_hndl);
		rhte = NULL;
		goto out;
	}

out:
	return rhte;
}

/* Checkout a free/empty RHT entry */
struct sisl_rht_entry *rhte_checkout(struct ctx_info *ctx_info,
				     struct lun_info *lun_info)
{
	struct sisl_rht_entry *rht_entry = NULL;
	int i;

	/* Find a free RHT entry */
	for (i = 0; i < MAX_RHT_PER_CONTEXT; i++)
		if (ctx_info->rht_start[i].nmask == 0) {
			rht_entry = &ctx_info->rht_start[i];
			ctx_info->rht_out++;
			break;
		}

	if (likely(rht_entry))
		ctx_info->rht_lun[i] = lun_info;

	cxlflash_dbg("returning rht_entry=%p (%d)", rht_entry, i);
	return rht_entry;
}

void rhte_checkin(struct ctx_info *ctx_info,
		  struct sisl_rht_entry *rht_entry)
{
	rht_entry->nmask = 0;
	rht_entry->fp = 0;
	ctx_info->rht_out--;
	ctx_info->rht_lun[rht_entry - ctx_info->rht_start] = NULL;
}

static void rht_format1(struct sisl_rht_entry *rht_entry, u64 lun_id, u32 perm)
{
	/*
	 * Populate the Format 1 RHT entry for direct access (physical
	 * LUN) using the synchronization sequence defined in the
	 * SISLite specification.
	 */
	struct sisl_rht_entry_f1 dummy = { 0 };
	struct sisl_rht_entry_f1 *rht_entry_f1 =
	    (struct sisl_rht_entry_f1 *)rht_entry;
	memset(rht_entry_f1, 0, sizeof(struct sisl_rht_entry_f1));
	rht_entry_f1->fp = SISL_RHT_FP(1U, 0);
	smp_wmb();

	rht_entry_f1->lun_id = lun_id;
	smp_wmb();

	/*
	 * Use a dummy RHT Format 1 entry to build the second dword
	 * of the entry that must be populated in a single write when
	 * enabled (valid bit set to TRUE).
	 */
	dummy.valid = 0x80;
	dummy.fp = SISL_RHT_FP(1U, perm);
	dummy.port_sel = BOTH_PORTS;
	rht_entry_f1->dw = dummy.dw;

	smp_wmb();
}

int cxlflash_lun_attach(struct lun_info *lun_info, enum lun_mode mode)
{
	int rc = 0;

	spin_lock(&lun_info->slock);
	if (lun_info->mode == MODE_NONE)
		lun_info->mode = mode;
	else if (lun_info->mode != mode) {
		cxlflash_err("LUN operating in mode %d, requested mode %d",
			     lun_info->mode, mode);
		rc = -EINVAL;
		goto out;
	}

	lun_info->users++;
	BUG_ON(lun_info->users < 0);
out:
	cxlflash_dbg("Returning rc=%d li_mode=%u li_users=%u", rc,
		     lun_info->mode, lun_info->users);
	spin_unlock(&lun_info->slock);
	return rc;
}

void cxlflash_lun_detach(struct lun_info *lun_info)
{
	spin_lock(&lun_info->slock);
	if (--lun_info->users == 0)
		lun_info->mode = MODE_NONE;
	cxlflash_dbg("li_users=%u", lun_info->users);
	BUG_ON(lun_info->users < 0);
	spin_unlock(&lun_info->slock);
}

/*
 * NAME:        cxlflash_disk_release
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
static int cxlflash_disk_release(struct scsi_device *sdev,
				 struct dk_cxlflash_release *release)
{
	struct cxlflash *cxlflash = (struct cxlflash *)sdev->host->hostdata;
	struct lun_info *lun_info = sdev->hostdata;
	struct afu *afu = cxlflash->afu;

	struct dk_cxlflash_resize size;
	res_hndl_t res_hndl = release->rsrc_handle;

	int rc = 0;
	u64 ctxid = release->context_id;

	struct ctx_info *ctx_info = NULL;
	struct sisl_rht_entry *rht_entry;

	cxlflash_info("ctxid=%llu res_hndl=0x%llx li->mode=%u li->users=%u",
		      ctxid, release->rsrc_handle, lun_info->mode,
		      lun_info->users);

	ctx_info = cxlflash_get_context(cxlflash, ctxid, lun_info, false);
	if (unlikely(!ctx_info)) {
		cxlflash_err("Invalid context! (%llu)", ctxid);
		rc = -EINVAL;
		goto out;
	}

	rht_entry = cxlflash_get_rhte(ctx_info, res_hndl, lun_info);
	if (unlikely(!rht_entry)) {
		cxlflash_err("Invalid resource handle! (%d)", res_hndl);
		rc = -EINVAL;
		goto out;
	}

	/*
	 * Resize to 0 for virtual LUNS by setting the size
	 * to 0. This will clear LXT_START and LXT_CNT fields
	 * in the RHT entry and properly sync with the AFU.
	 * Afterwards we clear the remaining fields.
	 */
	if (lun_info->mode == MODE_VIRTUAL) {
		marshall_rele_to_resize(release, &size);
		size.req_size = 0;
		rc = cxlflash_vlun_resize(sdev, &size);
		if (rc) {
			cxlflash_err("resize failed rc %d", rc);
			goto out;
		}
		rhte_checkin(ctx_info, rht_entry);
	} else if (lun_info->mode == MODE_PHYSICAL) {
		/*
		 * Clear the Format 1 RHT entry for direct access
		 * (physical LUN) using the synchronization sequence
		 * defined in the SISLite specification.
		 */
		struct sisl_rht_entry_f1 *rht_entry_f1 =
			    (struct sisl_rht_entry_f1 *)rht_entry;

		rht_entry_f1->valid = 0;
		smp_wmb();

		rht_entry_f1->lun_id = 0;
		smp_wmb();

		rht_entry_f1->dw = 0;
		smp_wmb();
		cxlflash_afu_sync(afu, ctxid, res_hndl, AFU_HW_SYNC);
		rhte_checkin(ctx_info, rht_entry);
	}

	cxlflash_lun_detach(lun_info);

out:
	if (likely(ctx_info))
		atomic_dec(&ctx_info->nrefs);
	cxlflash_info("returning rc=%d", rc);
	return rc;
}

static void destroy_context(struct cxlflash *cxlflash,
			    struct ctx_info *ctx_info)
{
	BUG_ON(!list_empty(&ctx_info->luns));

	/* Clear RHT registers and drop all capabilities for this context */
	writeq_be(0, &ctx_info->ctrl_map->rht_start);
	writeq_be(0, &ctx_info->ctrl_map->rht_cnt_id);
	writeq_be(0, &ctx_info->ctrl_map->ctx_cap);

	/* Free the RHT memory */
	free_page((unsigned long)ctx_info->rht_start);

	/* Free the context; note that rht_lun was allocated at same time */
	kfree(ctx_info);
	cxlflash->num_user_contexts--;
}

static struct ctx_info *create_context(struct cxlflash *cxlflash,
				       struct cxl_context *ctx, int ctxid,
				       int adap_fd, u32 perms)
{
	char *tmp = NULL;
	size_t size;
	struct afu *afu = cxlflash->afu;
	struct ctx_info *ctx_info = NULL;
	struct sisl_rht_entry *rht;

	size = ((MAX_RHT_PER_CONTEXT * sizeof(*ctx_info->rht_lun)) +
		sizeof(*ctx_info));

	tmp = kzalloc(size, GFP_KERNEL);
	if (unlikely(!tmp)) {
		cxlflash_err("Unable to allocate context! (%ld)", size);
		goto out;
	}

	rht = (struct sisl_rht_entry *)get_zeroed_page(GFP_KERNEL);
	if (unlikely(!rht)) {
		cxlflash_err("Unable to allocate RHT!");
		goto err;
	}

	ctx_info = (struct ctx_info *)tmp;
	ctx_info->rht_lun = (struct lun_info **)(tmp + sizeof(*ctx_info));
	ctx_info->rht_start = rht;
	ctx_info->rht_perms = perms;

	ctx_info->ctrl_map = &afu->afu_map->ctrls[ctxid].ctrl;
	ctx_info->ctxid = ctxid;
	ctx_info->lfd = adap_fd;
	ctx_info->pid = current->pid;
	ctx_info->ctx = ctx;
	INIT_LIST_HEAD(&ctx_info->luns);
	atomic_set(&ctx_info->nrefs, 1);

	cxlflash->num_user_contexts++;

out:
	return ctx_info;

err:
	kfree(tmp);
	goto out;
}

/*
 * NAME:        cxlflash_disk_detach
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
static int cxlflash_disk_detach(struct scsi_device *sdev,
				struct dk_cxlflash_detach *detach)
{
	struct cxlflash *cxlflash = (struct cxlflash *)sdev->host->hostdata;
	struct lun_info *lun_info = sdev->hostdata;
	struct lun_access *lun_access, *t;
	struct dk_cxlflash_release rel;
	struct ctx_info *ctx_info = NULL;

	int i;
	int rc = 0;
	int lfd;
	u64 ctxid = detach->context_id;
	unsigned long flags = 0;

	cxlflash_info("ctxid=%llu", ctxid);

	ctx_info = cxlflash_get_context(cxlflash, ctxid, lun_info, false);
	if (unlikely(!ctx_info)) {
		cxlflash_err("Invalid context! (%llu)", ctxid);
		rc = -EINVAL;
		goto out;
	}

	/* Cleanup outstanding resources tied to this LUN */
	if (ctx_info->rht_out) {
		marshall_det_to_rele(detach, &rel);
		for (i = 0; i < MAX_RHT_PER_CONTEXT; i++) {
			if (ctx_info->rht_lun[i] == lun_info) {
				rel.rsrc_handle = i;
				cxlflash_disk_release(sdev, &rel);
			}

			/* No need to loop further if we're done */
			if (ctx_info->rht_out == 0)
				break;
		}
	}

	/* Take our LUN out of context, free the node */
	list_for_each_entry_safe(lun_access, t, &ctx_info->luns, list)
		if (lun_access->lun_info == lun_info) {
			list_del(&lun_access->list);
			kfree(lun_access);
			lun_access = NULL;
			break;
		}

	/* Tear down context following last LUN cleanup */
	if (list_empty(&ctx_info->luns)) {
		spin_lock_irqsave(&cxlflash->ctx_tbl_slock, flags);
		cxlflash->ctx_tbl[ctxid] = NULL;
		spin_unlock_irqrestore(&cxlflash->ctx_tbl_slock, flags);

		while (atomic_read(&ctx_info->nrefs) > 1) {
			cxlflash_dbg("waiting on threads... (%d)",
				     atomic_read(&ctx_info->nrefs));
			cpu_relax();
		}

		lfd = ctx_info->lfd;
		destroy_context(cxlflash, ctx_info);
		ctx_info = NULL;

		/*
		 * As a last step, clean up external resources when not
		 * already on an external cleanup thread, ie: close(adap_fd).
		 *
		 * NOTE: this will free up the context from the CXL services,
		 * allowing it to dole out the same context_id on a future
		 * (or even currently in-flight) disk_attach operation.
		 */
		if (lfd != -1)
			sys_close(lfd);
	}

out:
	if (likely(ctx_info))
		atomic_dec(&ctx_info->nrefs);
	cxlflash_info("returning rc=%d", rc);
	return rc;
}

/*
 * This routine is the release handler for the fops registered with
 * the CXL services on an initial attach for a context. It is called
 * when a close is performed on the adapter file descriptor returned
 * to the user. Programmatically, the user is not required to perform
 * the close, as it is handled internally via the detach ioctl when
 * a context is being removed. Note that nothing prevents the user
 * from performing a close, but the user should be aware that doing
 * so is considered catastrophic and subsequent usage of the superpipe
 * API with previously saved off tokens will fail.
 *
 * When initiated from an external close (either by the user or via
 * a process tear down), the routine derives the context reference
 * and calls detach for each LUN associated with the context. The
 * final detach operation will cause the context itself to be freed.
 * Note that the saved off lfd is reset prior to calling detach to
 * signify that the final detach should not perform a close.
 *
 * When initiated from a detach operation as part of the tear down
 * of a context, the context is first completely freed and then the
 * close is performed. This routine will fail to derive the context
 * reference (due to the context having already been freed) and then
 * call into the CXL release entry point.
 *
 * Thus, with exception to when the CXL process element (context id)
 * lookup fails (a case that should theoretically never occur), every
 * call into this routine results in a complete freeing of a context.
 */
int cxlflash_cxl_release(struct inode *inode, struct file *file)
{
	struct cxl_context *ctx = cxl_fops_get_context(file);
	struct cxlflash *cxlflash = container_of(file->f_op, struct cxlflash,
						   cxl_fops);
	struct ctx_info *ctx_info = NULL;
	struct dk_cxlflash_detach detach = { { 0 }, 0 };
	struct lun_access *lun_access, *t;
	int ctxid;

	ctxid = cxl_process_element(ctx);
	if (unlikely(ctxid < 0)) {
		cxlflash_err("Context %p was closed! (%d)", ctx, ctxid);
		BUG(); /* XXX - remove me before submission */
		goto out;
	}

	ctx_info = cxlflash_get_context(cxlflash, ctxid, NULL, false);
	if (unlikely(!ctx_info)) {
		ctx_info = cxlflash_get_context(cxlflash, ctxid, NULL, true);
		if (!ctx_info) {
			cxlflash_dbg("Context %d already free!", ctxid);
			goto out_release;
		}

		cxlflash_dbg("Another process owns context %d!", ctxid);
		goto out;
	}

	cxlflash_info("close(%d) for context %d", ctx_info->lfd, ctxid);

	/* Reset the file descriptor to indicate we're on a close() thread */
	ctx_info->lfd = -1;
	detach.context_id = ctxid;
	atomic_dec(&ctx_info->nrefs); /* fix up reference count */
	list_for_each_entry_safe(lun_access, t, &ctx_info->luns, list)
		cxlflash_disk_detach(lun_access->sdev, &detach);

	/*
	 * Don't reference lun_access, or t (or ctx_info for that matter, even
	 * though it's invalidated to appease the reference counting code.
	 */
	ctx_info = NULL;

out_release:
	cxl_fd_release(inode, file);
out:
	if (likely(ctx_info))
		atomic_dec(&ctx_info->nrefs);
	cxlflash_dbg("returning");
	return 0;
}

static void cxlflash_unmap_context(struct ctx_info *ctx_info)
{
	unmap_mapping_range(ctx_info->mapping, 0, 0, 1);
}

static struct page *get_err_page(void)
{
	struct page *err_page = global.err_page;
	unsigned long flags = 0;

	if (unlikely(!err_page)) {
		err_page = alloc_page(GFP_KERNEL);
		if (unlikely(!err_page)) {
			pr_err("%s: Unable to allocate err_page!\n", __func__);
			goto out;
		}

		memset(page_address(err_page), -1, PAGE_SIZE);

		/* Serialize update w/ other threads to avoid a leak */
		spin_lock_irqsave(&global.slock, flags);
		if (likely(!global.err_page))
			global.err_page = err_page;
		else {
			__free_page(err_page);
			err_page = global.err_page;
		}
		spin_unlock_irqrestore(&global.slock, flags);
	}

out:
	pr_debug("%s: returning err_page=%p\n", __func__, err_page);
	return err_page;
}

static int cxlflash_mmap_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	struct file *file = vma->vm_file;
	struct cxl_context *ctx = cxl_fops_get_context(file);
	struct cxlflash *cxlflash = container_of(file->f_op, struct cxlflash,
						   cxl_fops);
	struct ctx_info *ctx_info = NULL;
	struct page *err_page = NULL;
	int rc = 0;
	int ctxid;

	ctxid = cxl_process_element(ctx);
	if (unlikely(ctxid < 0)) {
		pr_err("%s: Context %p was closed! (%d)\n",
		       __func__, ctx, ctxid);
		BUG(); /* XXX - remove me before submission */
		goto err;
	}

	ctx_info = cxlflash_get_context(cxlflash, ctxid, NULL, false);
	if (unlikely(!ctx_info)) {
		pr_err("%s: Invalid context! (%d)\n", __func__, ctxid);
		goto err;
	}

	pr_debug("%s: fault(%d) for context %d\n",
		 __func__, ctx_info->lfd, ctxid);

	if (likely(!cxlflash->err_recovery_active))
		rc = ctx_info->cxl_mmap_vmops->fault(vma, vmf);
	else {
		pr_debug("%s: err recovery active, use err_page!\n", __func__);

		err_page = get_err_page();
		if (unlikely(!err_page)) {
			pr_err("%s: Could not obtain error page!\n", __func__);
			rc = VM_FAULT_RETRY;
			goto out;
		}

		vmf->page = err_page;
	}

out:
	if (likely(ctx_info))
		atomic_dec(&ctx_info->nrefs);
	pr_debug("%s: returning rc=%d\n", __func__, rc);
	return rc;

err:
	rc = VM_FAULT_SIGBUS;
	goto out;
}

static const struct vm_operations_struct cxlflash_mmap_vmops = {
	.fault = cxlflash_mmap_fault,
};

int cxlflash_cxl_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct cxl_context *ctx = cxl_fops_get_context(file);
	struct cxlflash *cxlflash = container_of(file->f_op, struct cxlflash,
						   cxl_fops);
	struct ctx_info *ctx_info = NULL;
	int ctxid;
	int rc = 0;

	ctxid = cxl_process_element(ctx);
	if (unlikely(ctxid < 0)) {
		cxlflash_err("Context %p was closed! (%d)", ctx, ctxid);
		BUG(); /* XXX - remove me before submission */
		rc = -EIO;
		goto out;
	}

	ctx_info = cxlflash_get_context(cxlflash, ctxid, NULL, false);
	if (unlikely(!ctx_info)) {
		cxlflash_err("Invalid context! (%d)", ctxid);
		rc = -EIO;
		goto out;
	}

	cxlflash_info("mmap(%d) for context %d", ctx_info->lfd, ctxid);

	rc = cxl_fd_mmap(file, vma);
	if (!rc) {
		/*
		 * Insert ourself in the mmap fault handler path and save off
		 * the address space for toggling the mapping on error context.
		 * */
		ctx_info->cxl_mmap_vmops = vma->vm_ops;
		vma->vm_ops = &cxlflash_mmap_vmops;

		ctx_info->mapping = file->f_inode->i_mapping;
	}

out:
	if (likely(ctx_info))
		atomic_dec(&ctx_info->nrefs);
	return rc;
}

const struct file_operations cxlflash_cxl_fops = {
	.owner = THIS_MODULE,
	.mmap = cxlflash_cxl_mmap,
	.release = cxlflash_cxl_release,
};

/*
 * NAME:        cxlflash_disk_attach
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
static int cxlflash_disk_attach(struct scsi_device *sdev,
				struct dk_cxlflash_attach *attach)
{
	struct cxlflash *cxlflash = (struct cxlflash *)sdev->host->hostdata;
	struct afu *afu = cxlflash->afu;
	struct lun_info *lun_info = sdev->hostdata;
	struct cxl_ioctl_start_work *work;
	struct ctx_info *ctx_info = NULL;
	struct lun_access *lun_access = NULL;
	int rc = 0;
	u32 perms;
	int ctxid = -1;
	struct file *file;

	struct cxl_context *ctx;

	int fd = -1;

	/* On first attach set fileops */
	if (cxlflash->num_user_contexts == 0)
		cxlflash->cxl_fops = cxlflash_cxl_fops;

	if (attach->num_interrupts > 4) {
		cxlflash_err("Cannot support this many interrupts %llu",
			     attach->num_interrupts);
		rc = -EINVAL;
		goto out;
	}

	if (lun_info->max_lba == 0) {
		cxlflash_info("No capacity info yet for this LUN "
			      "(%016llX)", lun_info->lun_id);
		read_cap16(afu, lun_info, sdev->channel + 1);
		cxlflash_info("LBA = %016llX", lun_info->max_lba);
		cxlflash_info("BLK_LEN = %08X", lun_info->blk_len);
	}

	if (attach->hdr.flags & DK_CXLFLASH_ATTACH_REUSE_CONTEXT) {
		ctxid = attach->context_id;
		ctx_info = cxlflash_get_context(cxlflash, ctxid, NULL, false);
		if (!ctx_info) {
			cxlflash_err("Invalid context! (%d)", ctxid);
			rc = -EINVAL;
			goto out;
		}

		list_for_each_entry(lun_access, &ctx_info->luns, list)
			if (lun_access->lun_info == lun_info) {
				cxlflash_err("Context already attached!");
				rc = -EINVAL;
				goto out;
			}
	}

	lun_access = kzalloc(sizeof(*lun_access), GFP_KERNEL);
	if (unlikely(!lun_access)) {
		cxlflash_err("Unable to allocate lun_access!");
		rc = -ENOMEM;
		goto out;
	}

	lun_access->lun_info = lun_info;
	lun_access->sdev = sdev;

	/* Non-NULL context indicates reuse */
	if (ctx_info) {
		cxlflash_dbg("Reusing context for LUN! (%d)", ctxid);
		list_add(&lun_access->list, &ctx_info->luns);
		goto out;
	}

	ctx = cxl_dev_context_init(cxlflash->dev);
	if (!ctx) {
		cxlflash_err("Could not initialize context");
		rc = -ENODEV;
		goto err0;
	}

	ctxid = cxl_process_element(ctx);
	if ((ctxid > MAX_CONTEXT) || (ctxid < 0)) {
		cxlflash_err("ctxid (%d) invalid!", ctxid);
		rc = -EPERM;
		goto err1;
	}

	file = cxl_get_fd(ctx, &cxlflash->cxl_fops, &fd);
	if (fd < 0) {
		rc = -ENODEV;
		cxlflash_err("Could not get file descriptor");
		goto err1;
	}

	/* Translate read/write O_* flags from fnctl.h to AFU permission bits */
	perms = SISL_RHT_PERM(attach->hdr.flags + 1);

	ctx_info = create_context(cxlflash, ctx, ctxid, fd, perms);
	if (unlikely(!ctx_info)) {
		cxlflash_err("Failed to create context! (%d)", ctxid);
		goto err2;
	}

	work = &ctx_info->work;
	work->num_interrupts = attach->num_interrupts;
	work->flags = CXL_START_WORK_NUM_IRQS;

	rc = cxl_start_work(ctx, work);
	if (rc) {
		cxlflash_err("Could not start context rc=%d", rc);
		goto err3;
	}

	rc = cxlflash_afu_attach(cxlflash, ctx_info);
	if (rc) {
		cxlflash_err("Could not attach AFU rc %d", rc);
		goto err4;
	}

	/*
	 * No error paths after this point. Once the fd is installed it's
	 * visible to userspace and can't be undone safely on this thread.
	 */
	list_add(&lun_access->list, &ctx_info->luns);
	cxlflash->ctx_tbl[ctxid] = ctx_info;
	fd_install(fd, file);

	attach->hdr.return_flags = 0;
	attach->context_id = ctxid;
	attach->block_size = lun_info->blk_len;
	attach->mmio_size = sizeof(afu->afu_map->hosts[0].harea);
	attach->last_lba = lun_info->max_lba;
	attach->max_xfer = sdev->host->max_sectors;

out:
	attach->adap_fd = fd;

	if (likely(ctx_info))
		atomic_dec(&ctx_info->nrefs);

	cxlflash_info("returning ctxid=%d fd=%d bs=%lld rc=%d llba=%lld",
		      ctxid, fd, attach->block_size, rc, attach->last_lba);
	return rc;

err4:
	cxl_stop_context(ctx);
err3:
	destroy_context(cxlflash, ctx_info);
err2:
	fput(file);
	put_unused_fd(fd);
	fd = -1;
err1:
	cxl_release_context(ctx);
err0:
	kfree(lun_access);
	goto out;
}

static int cxlflash_manage_lun(struct scsi_device *sdev,
			       struct dk_cxlflash_manage_lun *manage)
{
	struct lun_info *lun_info = NULL;

	lun_info = lookup_lun(sdev, manage->wwid);
	cxlflash_info("ENTER: WWID = %016llX%016llX, flags = %016llX li = %p",
		      get_unaligned_le64(&manage->wwid[0]),
		      get_unaligned_le64(&manage->wwid[8]),
		      manage->hdr.flags,
		      lun_info);
	return 0;
}

static int cxlflash_afu_recover(struct scsi_device *sdev,
				struct dk_cxlflash_recover_afu *recover)
{
	struct cxlflash *cxlflash = (struct cxlflash *)sdev->host->hostdata;
	struct lun_info *lun_info = sdev->hostdata;
	struct afu *afu = cxlflash->afu;
	struct ctx_info *ctx_info = NULL;
	u64 ctxid = recover->context_id;
	long reg;
	int rc = 0;

	/* Ensure that this process is attached to the context */
	ctx_info = cxlflash_get_context(cxlflash, ctxid, lun_info, false);
	if (unlikely(!ctx_info)) {
		cxlflash_err("Invalid context! (%llu)", ctxid);
		rc = -EINVAL;
		goto out;
	}

	reg = readq_be(&afu->ctrl_map->mbox_r);	/* Try MMIO */
	/* MMIO returning 0xff, need to reset */
	if (reg == -1) {
		cxlflash_info("afu=%p reason 0x%llx", afu, recover->reason);
		cxlflash_afu_reset(cxlflash);

	} else {
		cxlflash_info
		    ("reason 0x%llx MMIO is working, no reset performed",
		     recover->reason);
		rc = -EINVAL;
	}

out:
	if (likely(ctx_info))
		atomic_dec(&ctx_info->nrefs);
	return rc;
}

/*
 * NAME:        cxlflash_disk_clone
 *
 * FUNCTION:    Clone a context by making a snapshot copy of another, specified
 *		context. This routine effectively performs cxlflash_disk_open
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
static int cxlflash_disk_clone(struct scsi_device *sdev,
			       struct dk_cxlflash_clone *clone)
{
	struct cxlflash *cxlflash = (struct cxlflash *)sdev->host->hostdata;
	struct lun_info *lun_info = sdev->hostdata;
	struct blka *blka = &lun_info->blka;
	struct afu *afu = cxlflash->afu;
	struct dk_cxlflash_release release = { { 0 }, 0 };

	struct ctx_info *ctx_info_src = NULL,
			*ctx_info_dst = NULL;
	struct lun_access *lun_access_src, *lun_access_dst;
	u32 perms;
	u64 ctxid_src = clone->context_id_src,
	    ctxid_dst = clone->context_id_dst;
	int adap_fd_src = clone->adap_fd_src;
	int i, j;
	int rc = 0;
	bool found;
	LIST_HEAD(sidecar);

	cxlflash_info("ctxid_src=%llu ctxid_dst=%llu adap_fd_src=%d",
		      ctxid_src, ctxid_dst, adap_fd_src);

	/* Do not clone yourself */
	if (unlikely(ctxid_src == ctxid_dst)) {
		rc = -EINVAL;
		goto out;
	}

	ctx_info_src = cxlflash_get_context(cxlflash, ctxid_src, lun_info,
					    true);
	ctx_info_dst = cxlflash_get_context(cxlflash, ctxid_dst, lun_info,
					    false);
	if (unlikely(!ctx_info_src || !ctx_info_dst)) {
		cxlflash_err("Invalid context! (%llu,%llu)",
			     ctxid_src, ctxid_dst);
		rc = -EINVAL;
		goto out;
	}

	if (unlikely(adap_fd_src != ctx_info_src->lfd)) {
		cxlflash_err("Invalid source adapter fd! (%d)", adap_fd_src);
		rc = -EINVAL;
		goto out;
	}

	/* Verify there is no open resource handle in the destination context */
	for (i = 0; i < MAX_RHT_PER_CONTEXT; i++)
		if (ctx_info_dst->rht_start[i].nmask != 0) {
			rc = -EINVAL;
			goto out;
		}

	/* Clone LUN access list */
	list_for_each_entry(lun_access_src, &ctx_info_src->luns, list) {
		found = false;
		list_for_each_entry(lun_access_dst, &ctx_info_dst->luns, list)
			if (lun_access_dst->sdev == lun_access_src->sdev) {
				found = true;
				break;
			}

		if (!found) {
			lun_access_dst = kzalloc(sizeof(*lun_access_dst),
						 GFP_KERNEL);
			if (unlikely(!lun_access_dst)) {
				cxlflash_err("Unable to allocate lun_access!");
				rc = -ENOMEM;
				goto out;
			}

			*lun_access_dst = *lun_access_src;
			list_add(&lun_access_dst->list, &sidecar);
		}
	}

	if (unlikely(!ctx_info_src->rht_out)) {
		cxlflash_info("Nothing to clone!");
		goto out_success;
	}

	/* User specified permission on attach */
	perms = ctx_info_dst->rht_perms;

	/*
	 * Copy over checked-out RHT (and their associated LXT) entries by
	 * hand, stopping after we've copied all outstanding entries and
	 * cleaning up if the clone fails.
	 *
	 * Note: This loop is equivalent to performing cxlflash_disk_open and
	 * cxlflash_vlun_resize. As such, LUN accounting needs to be taken into
	 * account by attaching after each successful RHT entry clone. In the
	 * event that a clone failure is experienced, the LUN detach is handled
	 * via the cleanup performed by cxlflash_disk_release.
	 */
	for (i = 0; i < MAX_RHT_PER_CONTEXT; i++) {
		if (ctx_info_src->rht_out == ctx_info_dst->rht_out)
			break;
		if (ctx_info_src->rht_start[i].nmask == 0)
			continue;

		/* Consume a destination RHT entry */
		ctx_info_dst->rht_out++;
		ctx_info_dst->rht_start[i].nmask =
		    ctx_info_src->rht_start[i].nmask;
		ctx_info_dst->rht_start[i].fp =
		    SISL_RHT_FP_CLONE(ctx_info_src->rht_start[i].fp, perms);
		ctx_info_dst->rht_lun[i] = ctx_info_src->rht_lun[i];

		rc = cxlflash_clone_lxt(afu, blka, ctxid_dst, i,
					&ctx_info_dst->rht_start[i],
					&ctx_info_src->rht_start[i]);
		if (rc) {
			marshall_clone_to_rele(clone, &release);
			for (j = 0; j < i; j++) {
				release.rsrc_handle = j;
				cxlflash_disk_release(sdev, &release);
			}

			/* Put back the one we failed on */
			rhte_checkin(ctx_info_dst, &ctx_info_dst->rht_start[i]);
			goto err;
		}

		cxlflash_lun_attach(lun_info, lun_info->mode);
	}

out_success:
	list_splice(&sidecar, &ctx_info_dst->luns);
	sys_close(adap_fd_src);

	/* fall thru */
out:
	if (likely(ctx_info_src))
		atomic_dec(&ctx_info_src->nrefs);
	if (likely(ctx_info_dst))
		atomic_dec(&ctx_info_dst->nrefs);
	cxlflash_info("returning rc=%d", rc);
	return rc;

err:
	list_for_each_entry_safe(lun_access_src, lun_access_dst, &sidecar, list)
		kfree(lun_access_src);
	goto out;
}

static int process_sense(struct scsi_device *sdev,
			 struct dk_cxlflash_verify *verify)
{
	struct request_sense_data *sense_data = (struct request_sense_data *)
		&verify->sense_data;
	struct lun_info *lun_info = sdev->hostdata;
	struct cxlflash *cxlflash = (struct cxlflash *)sdev->host->hostdata;
	struct afu *afu = cxlflash->afu;
	u64 prev_lba = lun_info->max_lba;
	int rc = 0;

	switch (sense_data->sense_key) {
	case NO_SENSE:
	case RECOVERED_ERROR:
		/* Fall through */
	case NOT_READY:
		break;
	case UNIT_ATTENTION:
		switch (sense_data->add_sense_key) {
		case 0x29: /* Power on Reset or Device Reset */
			/* Fall through */
		case 0x2A: /* Device settings/capacity changed */
			read_cap16(afu, lun_info, sdev->channel + 1);
			verify->last_lba = lun_info->max_lba;
			if (prev_lba != lun_info->max_lba)
				cxlflash_dbg("Capacity changed old=%lld "
					     "new=%lld", prev_lba,
					     lun_info->max_lba);
			break;
		case 0x3F: /* Report LUNs changed, Rescan. */
			scsi_scan_host(cxlflash->host);
			break;
		default:
			rc = -EIO;
			break;
		}
		break;
	default:
		rc = -EIO;
		break;
	}
	cxlflash_dbg("sense_key %x asc %x rc %d", sense_data->sense_key,
		      sense_data->add_sense_key, rc);
	return rc;
}

/*
 * NAME:        cxlflash_disk_verify
 *
 * FUNCTION:    Verify that the LUN is the same, whether its size has changed
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
static int cxlflash_disk_verify(struct scsi_device *sdev,
				struct dk_cxlflash_verify *verify)
{
	int rc = 0;
	struct ctx_info *ctx_info = NULL;
	struct cxlflash *cxlflash = (struct cxlflash *)sdev->host->hostdata;
	struct lun_info *lun_info = sdev->hostdata;
	u64 ctxid = verify->context_id;

	cxlflash_info("ctxid=%llu res_hndl=0x%llx, hint=0x%llx",
		      ctxid, verify->rsrc_handle, verify->hint);

	ctx_info = cxlflash_get_context(cxlflash, ctxid, lun_info, false);
	if (unlikely(!ctx_info)) {
		cxlflash_err("Invalid context! (%llu)", ctxid);
		rc = -EINVAL;
		goto out;
	}

	/* XXX: We would have to look at the hint/sense to see if it
	 * requires us to redrive inquiry (i.e. the Unit attention is
	 * due to the WWN changing).
	 */
	if (verify->hint & DK_CXLFLASH_VERIFY_HINT_SENSE)
		rc = process_sense(sdev, verify);

out:
	if (likely(ctx_info))
		atomic_dec(&ctx_info->nrefs);
	cxlflash_info("returning rc=%d llba=%lld", rc, verify->last_lba);
	return rc;
}

static char *decode_ioctl(int cmd)
{
#define _CASE2STR(_x) case _x: return #_x

	switch (cmd) {
		_CASE2STR(DK_CXLFLASH_ATTACH);
		_CASE2STR(DK_CXLFLASH_USER_DIRECT);
		_CASE2STR(DK_CXLFLASH_USER_VIRTUAL);
		_CASE2STR(DK_CXLFLASH_DETACH);
		_CASE2STR(DK_CXLFLASH_VLUN_RESIZE);
		_CASE2STR(DK_CXLFLASH_RELEASE);
		_CASE2STR(DK_CXLFLASH_CLONE);
		_CASE2STR(DK_CXLFLASH_VERIFY);
	}

	return "UNKNOWN";
}

/* NAME:	cxlflash_disk_direct_open
 *
 * FUNCTION:	open a virtual lun of specified size
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
 *		When successful:
 *		a. find a free RHT entry
 *		b. Program it with FORMAT1
 *
 */
static int cxlflash_disk_direct_open(struct scsi_device *sdev, void *arg)
{
	struct cxlflash *cxlflash = (struct cxlflash *)sdev->host->hostdata;
	struct afu *afu = cxlflash->afu;
	struct lun_info *lun_info = sdev->hostdata;

	struct dk_cxlflash_udirect *pphys = (struct dk_cxlflash_udirect *)arg;

	u64 ctxid = pphys->context_id;
	u64 lun_size = 0;
	u64 last_lba = 0;
	u64 rsrc_handle = -1;

	int rc = 0;

	struct ctx_info *ctx_info = NULL;
	struct sisl_rht_entry *rht_entry = NULL;

	cxlflash_info("ctxid=%llu ls=0x%llx", ctxid, lun_size);

	rc = cxlflash_lun_attach(lun_info, MODE_PHYSICAL);
	if (unlikely(rc)) {
		cxlflash_err("Failed to attach to LUN! mode=%u", MODE_PHYSICAL);
		goto out;
	}

	ctx_info = cxlflash_get_context(cxlflash, ctxid, lun_info, false);
	if (unlikely(!ctx_info)) {
		cxlflash_err("Invalid context! (%llu)", ctxid);
		rc = -EINVAL;
		goto err1;
	}

	rht_entry = rhte_checkout(ctx_info, lun_info);
	if (unlikely(!rht_entry)) {
		cxlflash_err("too many opens for this context");
		rc = -EMFILE;	/* too many opens  */
		goto err1;
	}

	rsrc_handle = (rht_entry - ctx_info->rht_start);

	rht_format1(rht_entry, lun_info->lun_id, ctx_info->rht_perms);
	cxlflash_afu_sync(afu, ctxid, rsrc_handle, AFU_LW_SYNC);

	last_lba = lun_info->max_lba;
	pphys->hdr.return_flags = 0;
	pphys->last_lba = last_lba;
	pphys->rsrc_handle = rsrc_handle;

out:
	if (likely(ctx_info))
		atomic_dec(&ctx_info->nrefs);
	cxlflash_info("returning handle 0x%llx rc=%d llba %lld",
		      rsrc_handle, rc, last_lba);
	return rc;

err1:
	cxlflash_lun_detach(lun_info);
	goto out;
}

/**
 * cxlflash_ioctl - IOCTL handler
 * @sdev:       scsi device struct
 * @cmd:        IOCTL cmd
 * @arg:        IOCTL arg
 *
 * Return value:
 *      0 on success / other on failure
 **/
int cxlflash_ioctl(struct scsi_device *sdev, int cmd, void __user *arg)
{
	typedef int (*sioctl) (struct scsi_device *, void *);

	struct cxlflash *cxlflash = (struct cxlflash *)sdev->host->hostdata;
	struct afu *afu = cxlflash->afu;
	struct dk_cxlflash_hdr *hdr;
	char buf[MAX_CXLFLASH_IOCTL_SZ];
	size_t size = 0;
	int idx;
	int rc = 0;
	struct Scsi_Host *shost = sdev->host;
	sioctl do_ioctl = NULL;
	u64 ctxid;
	struct ctx_info *ctx_info;
#define IOCTE(_s, _i) sizeof(struct _s), (sioctl)(_i)
	static const struct {
		size_t size;
		sioctl ioctl;
	} ioctl_tbl[] = {	/* NOTE: order matters here */
		{
		IOCTE(dk_cxlflash_attach, cxlflash_disk_attach)}, {
		IOCTE(dk_cxlflash_udirect, cxlflash_disk_direct_open)}, {
		IOCTE(dk_cxlflash_uvirtual, cxlflash_disk_virtual_open)}, {
		IOCTE(dk_cxlflash_resize, cxlflash_vlun_resize)}, {
		IOCTE(dk_cxlflash_release, cxlflash_disk_release)}, {
		IOCTE(dk_cxlflash_detach, cxlflash_disk_detach)}, {
		IOCTE(dk_cxlflash_verify, cxlflash_disk_verify)}, {
		IOCTE(dk_cxlflash_clone, cxlflash_disk_clone)}, {
		IOCTE(dk_cxlflash_recover_afu, cxlflash_afu_recover)}, {
		IOCTE(dk_cxlflash_manage_lun, cxlflash_manage_lun)}
	};

	/* Restrict command set to physical support only for internal LUN */
	if (afu->internal_lun)
		switch (cmd) {
		case DK_CXLFLASH_USER_VIRTUAL:
		case DK_CXLFLASH_VLUN_RESIZE:
		case DK_CXLFLASH_RELEASE:
		case DK_CXLFLASH_CLONE:
			cxlflash_err("%s not supported for lun_mode=%d",
				     decode_ioctl(cmd), afu->internal_lun);
			rc = -EINVAL;
			goto cxlflash_ioctl_exit;
		}

	switch (cmd) {
	case 0x4711:	/* XXX - remove case and assoc. vars before upstream */
		ctxid = ((struct dk_cxlflash_detach *)arg)->context_id;
		ctx_info = cxlflash_get_context(cxlflash, ctxid, NULL, false);
		cxlflash_unmap_context(ctx_info);
		goto cxlflash_ioctl_exit;
	case DK_CXLFLASH_ATTACH:
	case DK_CXLFLASH_USER_DIRECT:
	case DK_CXLFLASH_USER_VIRTUAL:
	case DK_CXLFLASH_VLUN_RESIZE:
	case DK_CXLFLASH_RELEASE:
	case DK_CXLFLASH_DETACH:
	case DK_CXLFLASH_VERIFY:
	case DK_CXLFLASH_CLONE:
	case DK_CXLFLASH_RECOVER_AFU:
	case DK_CXLFLASH_MANAGE_LUN:
		idx = _IOC_NR(cmd) - _IOC_NR(DK_CXLFLASH_ATTACH);
		size = ioctl_tbl[idx].size;
		do_ioctl = ioctl_tbl[idx].ioctl;

		if (likely(do_ioctl))
			break;

		/* fall thru */
	default:
		rc = -EINVAL;
		goto cxlflash_ioctl_exit;
	}

	if (unlikely(copy_from_user(&buf, arg, size))) {
		cxlflash_err("copy_from_user() fail! "
			     "size=%lu cmd=%d (%s) arg=%p",
			     size, cmd, decode_ioctl(cmd), arg);
		rc = -EFAULT;
		goto cxlflash_ioctl_exit;
	}

	hdr = (struct dk_cxlflash_hdr *)&buf;
	if (hdr->version != 0) {
		cxlflash_err("Version %u not supported for %s",
			     hdr->version, decode_ioctl(cmd));
		rc = -EINVAL;
		goto cxlflash_ioctl_exit;
	}

	rc = do_ioctl(sdev, (void *)&buf);
	if (likely(!rc))
		if (unlikely(copy_to_user(arg, &buf, size))) {
			cxlflash_err("copy_to_user() fail! "
				     "size=%lu cmd=%d (%s) arg=%p",
				     size, cmd, decode_ioctl(cmd), arg);
			rc = -EFAULT;
		}

	/* fall thru to exit */

cxlflash_ioctl_exit:
	if (rc)
		cxlflash_err("ioctl %s (%08X) on dev(%d/%d/%d/%llu) "
			     "returned rc %d",
			     decode_ioctl(cmd), cmd, shost->host_no,
			     sdev->channel, sdev->id, sdev->lun, rc);
	else
		cxlflash_dbg("ioctl %s (%08X) on dev(%d/%d/%d/%llu) "
			     "returned rc %d",
			     decode_ioctl(cmd), cmd, shost->host_no,
			     sdev->channel, sdev->id, sdev->lun, rc);
	return rc;
}
