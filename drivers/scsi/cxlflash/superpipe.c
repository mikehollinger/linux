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

/**
 * marshall_rele_to_resize() - translate release to resize structure
 * @rele:	Source structure from which to translate/copy.
 * @resize:	Destination structure for the translate/copy.
 */
static void marshall_rele_to_resize(struct dk_cxlflash_release *release,
				    struct dk_cxlflash_resize *resize)
{
	resize->hdr = release->hdr;
	resize->context_id = release->context_id;
	resize->rsrc_handle = release->rsrc_handle;
}

static void marshall_det_to_rele(struct dk_cxlflash_detach *detach,
				 struct dk_cxlflash_release *release)
{
	release->hdr = detach->hdr;
	release->context_id = detach->context_id;
}

static struct lun_info *create_lun_info(struct scsi_device *sdev)
{
	struct lun_info *lun_info = NULL;

	lun_info = kzalloc(sizeof(*lun_info), GFP_KERNEL);
	if (unlikely(!lun_info)) {
		pr_err("%s: could not allocate lun_info\n", __func__);
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
	ulong flags = 0UL;

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
	pr_debug("%s: returning %p\n", __func__, lun_info);
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
	pr_debug("%s: returning sdev %p rc=%d\n", __func__, sdev, rc);
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
	struct cxlflash_cfg *cfg = shost_priv(shost);
	struct afu *afu = cfg->afu;

	pr_info("%s: id = %d/%d/%d/%llu\n", __func__, shost->host_no,
		sdev->channel, sdev->id, sdev->lun);

	/* Store off lun in unpacked, AFU-friendly format */
	lun_info->lun_id = lun_to_lunid(sdev->lun);
	lun_info->lun_index = cfg->last_lun_index[sdev->channel];

	writeq_be(lun_info->lun_id,
		  &afu->afu_map->global.fc_port[sdev->channel]
		  [cfg->last_lun_index[sdev->channel]++]);

	return 0;
}

void cxlflash_slave_destroy(struct scsi_device *sdev)
{
	void *lun_info = (void *)sdev->hostdata;

	pr_debug("%s: lun_info=%p\n", __func__, lun_info);
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
	ulong flags = 0;

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
struct ctx_info *cxlflash_get_context(struct cxlflash_cfg *cfg,
				      u64 ctxid,
				      struct lun_info *lun_info,
				      bool clone_path)
{
	struct ctx_info *ctx_info = NULL;
	struct lun_access *lun_access = NULL;
	bool found = false;
	pid_t pid = current->tgid, ctxpid = 0;
	ulong flags = 0;

	if (unlikely(clone_path))
		pid = current->parent->tgid;

	if (likely(ctxid < MAX_CONTEXT)) {
		spin_lock_irqsave(&cfg->ctx_tbl_slock, flags);
		ctx_info = cfg->ctx_tbl[ctxid];
		if (unlikely(!ctx_info)) {
			spin_unlock_irqrestore(&cfg->ctx_tbl_slock, flags);
			goto out;
		}

		/*
		 * Increment the reference count under lock so the context
		 * is not yanked from under us on a removal thread.
		 */
		atomic_inc(&ctx_info->nrefs);
		spin_unlock_irqrestore(&cfg->ctx_tbl_slock, flags);

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
	pr_debug("%s: ctxid=%llu ctxinfo=%p ctxpid=%u pid=%u clone=%d "
		 "found=%d\n", __func__, ctxid, ctx_info, ctxpid, pid,
		 clone_path, found);

	return ctx_info;

denied:
	atomic_dec(&ctx_info->nrefs);
	ctx_info = NULL;
	goto out;
}

static int cxlflash_afu_attach(struct cxlflash_cfg *cfg,
			       struct ctx_info *ctx_info)
{
	struct afu *afu = cfg->afu;
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
		pr_err("%s: ctx may be closed reg=%llx\n", __func__, reg);
		rc = -EAGAIN;
		goto out;
	}

	/* set up MMIO registers pointing to the RHT */
	writeq_be((u64)ctx_info->rht_start, &ctx_info->ctrl_map->rht_start);
	writeq_be(SISL_RHT_CNT_ID((u64)MAX_RHT_PER_CONTEXT,
				  (u64)(afu->ctx_hndl)),
		  &ctx_info->ctrl_map->rht_cnt_id);
out:
	pr_info("%s: returning rc=%d\n", __func__, rc);
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
int cxlflash_check_status(struct afu_cmd *cmd)
{
	struct sisl_ioasa *ioasa = &cmd->sa;
	ulong lock_flags;

	/* do we need to retry AFU_CMDs (sync) on afu_rc = 0x30 ? */
	/* can we not avoid that ? */
	/* not retrying afu timeouts (B_TIMEOUT) */
	/* returns 1 if the cmd should be retried, 0 otherwise */
	/* sets B_ERROR flag based on IOASA */

	if (ioasa->ioasc == 0)
		return 0;

	spin_lock_irqsave(&cmd->slock, lock_flags);
	ioasa->host_use_b[0] |= B_ERROR;
	spin_unlock_irqrestore(&cmd->slock, lock_flags);

	if (!(ioasa->host_use_b[1]++ < MC_RETRY_CNT))
		return 0;

	switch (ioasa->rc.afu_rc) {
	case SISL_AFU_RC_NO_CHANNELS:
	case SISL_AFU_RC_OUT_OF_DATA_BUFS:
		msleep(20);
		return 1;

	case 0:
		/* no afu_rc, but either scsi_rc and/or fc_rc is set */
		/* retry all scsi_rc and fc_rc after a small delay */
		msleep(20);
		return 1;
	}

	return 0;
}

static int read_cap16(struct afu *afu, struct lun_info *lun_info, u32 port_sel)
{
	struct afu_cmd *cmd = NULL;
	int rc = 0;

	cmd = cxlflash_cmd_checkout(afu);
	if (unlikely(!cmd)) {
		pr_err("%s: could not get a free command\n", __func__);
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

	cmd->rcb.cdb[0] = 0x9E;	/* read cap(16) */
	cmd->rcb.cdb[1] = 0x10;	/* service action */
	put_unaligned_be32(CMD_BUFSIZE, &cmd->rcb.cdb[10]);

	pr_info("%s: sending cmd(0x%x) with RCB EA=%p data EA=0x%llx\n",
		__func__, cmd->rcb.cdb[0], &cmd->rcb, cmd->rcb.data_ea);

	do {
		rc = cxlflash_send_cmd(afu, cmd);
		if (unlikely(rc))
			goto out;
		cxlflash_wait_resp(afu, cmd);
	} while (cxlflash_check_status(cmd));

	if (unlikely(cmd->sa.host_use_b[0] & B_ERROR)) {
		pr_err("%s: command failed\n", __func__);
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
	if (cmd)
		cxlflash_cmd_checkin(cmd);
	pr_info("%s: maxlba=%lld blklen=%d pcmd %p\n",
		__func__, lun_info->max_lba, lun_info->blk_len, cmd);
	return rc;
}

struct sisl_rht_entry *cxlflash_get_rhte(struct ctx_info *ctx_info,
					 res_hndl_t res_hndl,
					 struct lun_info *lun_info)
{
	struct sisl_rht_entry *rhte = NULL;

	if (unlikely(!ctx_info->rht_start)) {
		pr_err("%s: Context does not have an allocated RHT!\n",
		       __func__);
		goto out;
	}

	if (unlikely(res_hndl >= MAX_RHT_PER_CONTEXT)) {
		pr_err("%s: Invalid resource handle! (%d)\n",
		       __func__, res_hndl);
		goto out;
	}

	if (unlikely(ctx_info->rht_lun[res_hndl] != lun_info)) {
		pr_err("%s: Resource handle invalid for LUN! (%d)\n",
		       __func__, res_hndl);
		goto out;
	}

	rhte = &ctx_info->rht_start[res_hndl];
	if (unlikely(rhte->nmask == 0)) {
		pr_err("%s: Unopened resource handle! (%d)\n",
		       __func__, res_hndl);
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

	pr_debug("%s: returning rht_entry=%p (%d)\n", __func__, rht_entry, i);
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
	smp_wmb(); /* Make setting of format bit visible */

	rht_entry_f1->lun_id = lun_id;
	smp_wmb(); /* Make setting of LUN id visible */

	/*
	 * Use a dummy RHT Format 1 entry to build the second dword
	 * of the entry that must be populated in a single write when
	 * enabled (valid bit set to TRUE).
	 */
	dummy.valid = 0x80;
	dummy.fp = SISL_RHT_FP(1U, perm);
	dummy.port_sel = BOTH_PORTS;
	rht_entry_f1->dw = dummy.dw;

	smp_wmb(); /* Make remaining RHT entry fields visible */
}

int cxlflash_lun_attach(struct lun_info *lun_info, enum lun_mode mode)
{
	int rc = 0;

	spin_lock(&lun_info->slock);
	if (lun_info->mode == MODE_NONE)
		lun_info->mode = mode;
	else if (lun_info->mode != mode) {
		pr_err("%s: LUN operating in mode %d, requested mode %d\n",
		       __func__, lun_info->mode, mode);
		rc = -EINVAL;
		goto out;
	}

	lun_info->users++;
	BUG_ON(lun_info->users < 0);
out:
	pr_debug("%s: Returning rc=%d li_mode=%u li_users=%u\n",
		 __func__, rc, lun_info->mode, lun_info->users);
	spin_unlock(&lun_info->slock);
	return rc;
}

void cxlflash_lun_detach(struct lun_info *lun_info)
{
	spin_lock(&lun_info->slock);
	BUG_ON(lun_info->mode == MODE_NONE); /* XXX - remove me before submit */
	if (--lun_info->users == 0)
		lun_info->mode = MODE_NONE;
	pr_debug("%s: li_users=%u\n", __func__, lun_info->users);
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
int cxlflash_disk_release(struct scsi_device *sdev,
			  struct dk_cxlflash_release *release)
{
	struct cxlflash_cfg *cfg = (struct cxlflash_cfg *)sdev->host->hostdata;
	struct lun_info *lun_info = sdev->hostdata;
	struct afu *afu = cfg->afu;

	struct dk_cxlflash_resize size;
	res_hndl_t res_hndl = release->rsrc_handle;

	int rc = 0;
	u64 ctxid = release->context_id;

	struct ctx_info *ctx_info = NULL;
	struct sisl_rht_entry *rht_entry;
	struct sisl_rht_entry_f1 *rht_entry_f1;

	pr_info("%s: ctxid=%llu res_hndl=0x%llx li->mode=%u li->users=%u\n",
		__func__, ctxid, release->rsrc_handle, lun_info->mode,
		lun_info->users);

	ctx_info = cxlflash_get_context(cfg, ctxid, lun_info, false);
	if (unlikely(!ctx_info)) {
		pr_err("%s: Invalid context! (%llu)\n", __func__, ctxid);
		rc = -EINVAL;
		goto out;
	}

	rht_entry = cxlflash_get_rhte(ctx_info, res_hndl, lun_info);
	if (unlikely(!rht_entry)) {
		pr_err("%s: Invalid resource handle! (%d)\n",
		       __func__, res_hndl);
		rc = -EINVAL;
		goto out;
	}

	/*
	 * Resize to 0 for virtual LUNS by setting the size
	 * to 0. This will clear LXT_START and LXT_CNT fields
	 * in the RHT entry and properly sync with the AFU.
	 * Afterwards we clear the remaining fields.
	 */
	switch(lun_info->mode) {
	case MODE_VIRTUAL:
		marshall_rele_to_resize(release, &size);
		size.req_size = 0;
		rc = cxlflash_vlun_resize(sdev, &size);
		if (rc) {
			pr_err("%s: resize failed rc %d\n", __func__, rc);
			goto out;
		}

		break;
	case MODE_PHYSICAL:
		/*
		 * Clear the Format 1 RHT entry for direct access
		 * (physical LUN) using the synchronization sequence
		 * defined in the SISLite specification.
		 */
		rht_entry_f1 = (struct sisl_rht_entry_f1 *)rht_entry;

		rht_entry_f1->valid = 0;
		smp_wmb(); /* Make revoccation of RHT entry visible */

		rht_entry_f1->lun_id = 0;
		smp_wmb(); /* Make clearing of LUN id visible */

		rht_entry_f1->dw = 0;
		smp_wmb(); /* Make RHT entry bottom-half clearing visible */

		cxlflash_afu_sync(afu, ctxid, res_hndl, AFU_HW_SYNC);
		break;
	default:
		BUG();
		goto out;
	}

	rhte_checkin(ctx_info, rht_entry);
	cxlflash_lun_detach(lun_info);

out:
	if (likely(ctx_info))
		atomic_dec(&ctx_info->nrefs);
	pr_info("%s: returning rc=%d\n", __func__, rc);
	return rc;
}

static void destroy_context(struct cxlflash_cfg *cfg,
			    struct ctx_info *ctx_info)
{
	BUG_ON(!list_empty(&ctx_info->luns));

	/* Clear RHT registers and drop all capabilities for this context */
	writeq_be(0, &ctx_info->ctrl_map->rht_start);
	writeq_be(0, &ctx_info->ctrl_map->rht_cnt_id);
	writeq_be(0, &ctx_info->ctrl_map->ctx_cap);

	/* Free the RHT memory */
	free_page((ulong)ctx_info->rht_start);

	/* Free the context; note that rht_lun was allocated at same time */
	kfree(ctx_info);
	cfg->num_user_contexts--;
}

static struct ctx_info *create_context(struct cxlflash_cfg *cfg,
				       struct cxl_context *ctx, int ctxid,
				       int adap_fd, u32 perms)
{
	char *tmp = NULL;
	size_t size;
	struct afu *afu = cfg->afu;
	struct ctx_info *ctx_info = NULL;
	struct sisl_rht_entry *rht;

	size = ((MAX_RHT_PER_CONTEXT * sizeof(*ctx_info->rht_lun)) +
		sizeof(*ctx_info));

	tmp = kzalloc(size, GFP_KERNEL);
	if (unlikely(!tmp)) {
		pr_err("%s: Unable to allocate context! (%ld)\n",
		       __func__, size);
		goto out;
	}

	rht = (struct sisl_rht_entry *)get_zeroed_page(GFP_KERNEL);
	if (unlikely(!rht)) {
		pr_err("%s: Unable to allocate RHT!\n", __func__);
		goto err;
	}

	ctx_info = (struct ctx_info *)tmp;
	ctx_info->rht_lun = (struct lun_info **)(tmp + sizeof(*ctx_info));
	ctx_info->rht_start = rht;
	ctx_info->rht_perms = perms;

	ctx_info->ctrl_map = &afu->afu_map->ctrls[ctxid].ctrl;
	ctx_info->ctxid = ctxid;
	ctx_info->lfd = adap_fd;
	ctx_info->pid = current->tgid; /* tgid = pid */
	ctx_info->ctx = ctx;
	INIT_LIST_HEAD(&ctx_info->luns);
	atomic_set(&ctx_info->nrefs, 1);

	cfg->num_user_contexts++;

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
	struct cxlflash_cfg *cfg = (struct cxlflash_cfg *)sdev->host->hostdata;
	struct lun_info *lun_info = sdev->hostdata;
	struct lun_access *lun_access, *t;
	struct dk_cxlflash_release rel;
	struct ctx_info *ctx_info = NULL;

	int i;
	int rc = 0;
	int lfd;
	u64 ctxid = detach->context_id;
	ulong flags = 0;

	pr_info("%s: ctxid=%llu\n", __func__, ctxid);

	ctx_info = cxlflash_get_context(cfg, ctxid, lun_info, false);
	if (unlikely(!ctx_info)) {
		pr_err("%s: Invalid context! (%llu)\n", __func__, ctxid);
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
		spin_lock_irqsave(&cfg->ctx_tbl_slock, flags);
		cfg->ctx_tbl[ctxid] = NULL;
		spin_unlock_irqrestore(&cfg->ctx_tbl_slock, flags);

		while (atomic_read(&ctx_info->nrefs) > 1) {
			pr_debug("%s: waiting on threads... (%d)\n",
				 __func__, atomic_read(&ctx_info->nrefs));
			cpu_relax();
		}

		lfd = ctx_info->lfd;
		destroy_context(cfg, ctx_info);
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
	pr_info("%s: returning rc=%d\n", __func__, rc);
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
static int cxlflash_cxl_release(struct inode *inode, struct file *file)
{
	struct cxl_context *ctx = cxl_fops_get_context(file);
	struct cxlflash_cfg *cfg = container_of(file->f_op, struct cxlflash_cfg,
						cxl_fops);
	struct ctx_info *ctx_info = NULL;
	struct dk_cxlflash_detach detach = { { 0 }, 0 };
	struct lun_access *lun_access, *t;
	int ctxid;

	ctxid = cxl_process_element(ctx);
	if (unlikely(ctxid < 0)) {
		pr_err("%s: Context %p was closed! (%d)\n",
		       __func__, ctx, ctxid);
		BUG(); /* XXX - remove me before submission */
		goto out;
	}

	ctx_info = cxlflash_get_context(cfg, ctxid, NULL, false);
	if (unlikely(!ctx_info)) {
		ctx_info = cxlflash_get_context(cfg, ctxid, NULL, true);
		if (!ctx_info) {
			pr_debug("%s: Context %d already free!\n",
				 __func__, ctxid);
			goto out_release;
		}

		pr_debug("%s: Another process owns context %d!\n",
			 __func__, ctxid);
		goto out;
	}

	pr_info("%s: close(%d) for context %d\n",
		__func__, ctx_info->lfd, ctxid);

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
	pr_debug("%s: returning\n", __func__);
	return 0;
}

static void cxlflash_unmap_context(struct ctx_info *ctx_info)
{
	unmap_mapping_range(ctx_info->mapping, 0, 0, 1);
}

static struct page *get_err_page(void)
{
	struct page *err_page = global.err_page;
	ulong flags = 0;

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
	struct cxlflash_cfg *cfg = container_of(file->f_op, struct cxlflash_cfg,
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

	ctx_info = cxlflash_get_context(cfg, ctxid, NULL, false);
	if (unlikely(!ctx_info)) {
		pr_err("%s: Invalid context! (%d)\n", __func__, ctxid);
		goto err;
	}

	pr_debug("%s: fault(%d) for context %d\n",
		 __func__, ctx_info->lfd, ctxid);

	if (likely(!cfg->err_recovery_active))
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

static int cxlflash_cxl_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct cxl_context *ctx = cxl_fops_get_context(file);
	struct cxlflash_cfg *cfg = container_of(file->f_op, struct cxlflash_cfg,
						cxl_fops);
	struct ctx_info *ctx_info = NULL;
	int ctxid;
	int rc = 0;

	ctxid = cxl_process_element(ctx);
	if (unlikely(ctxid < 0)) {
		pr_err("%s: Context %p was closed! (%d)\n",
		       __func__, ctx, ctxid);
		BUG(); /* XXX - remove me before submission */
		rc = -EIO;
		goto out;
	}

	ctx_info = cxlflash_get_context(cfg, ctxid, NULL, false);
	if (unlikely(!ctx_info)) {
		pr_err("%s: Invalid context! (%d)\n", __func__, ctxid);
		rc = -EIO;
		goto out;
	}

	pr_info("%s: mmap(%d) for context %d\n",
		__func__, ctx_info->lfd, ctxid);

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

static const struct file_operations cxlflash_cxl_fops = {
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
	struct cxlflash_cfg *cfg = (struct cxlflash_cfg *)sdev->host->hostdata;
	struct afu *afu = cfg->afu;
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
	if (cfg->num_user_contexts == 0)
		cfg->cxl_fops = cxlflash_cxl_fops;

	if (attach->num_interrupts > 4) {
		pr_err("%s: Cannot support this many interrupts %llu\n",
		       __func__, attach->num_interrupts);
		rc = -EINVAL;
		goto out;
	}

	if (lun_info->max_lba == 0) {
		pr_info("%s: No capacity info yet for this LUN "
			"(%016llX)\n", __func__, lun_info->lun_id);
		read_cap16(afu, lun_info, sdev->channel + 1);
		pr_info("%s: LBA = %016llX\n", __func__, lun_info->max_lba);
		pr_info("%s: BLK_LEN = %08X\n", __func__, lun_info->blk_len);
	}

	if (attach->hdr.flags & DK_CXLFLASH_ATTACH_REUSE_CONTEXT) {
		ctxid = attach->context_id;
		ctx_info = cxlflash_get_context(cfg, ctxid, NULL, false);
		if (!ctx_info) {
			pr_err("%s: Invalid context! (%d)\n", __func__, ctxid);
			rc = -EINVAL;
			goto out;
		}

		list_for_each_entry(lun_access, &ctx_info->luns, list)
			if (lun_access->lun_info == lun_info) {
				pr_err("%s: Context already attached!\n",
				       __func__);
				rc = -EINVAL;
				goto out;
			}
	}

	lun_access = kzalloc(sizeof(*lun_access), GFP_KERNEL);
	if (unlikely(!lun_access)) {
		pr_err("%s: Unable to allocate lun_access!\n", __func__);
		rc = -ENOMEM;
		goto out;
	}

	lun_access->lun_info = lun_info;
	lun_access->sdev = sdev;

	/* Non-NULL context indicates reuse */
	if (ctx_info) {
		pr_debug("%s: Reusing context for LUN! (%d)\n",
			 __func__, ctxid);
		list_add(&lun_access->list, &ctx_info->luns);
		fd = ctx_info->lfd;
		goto out_attach;
	}

	ctx = cxl_dev_context_init(cfg->dev);
	if (!ctx) {
		pr_err("%s: Could not initialize context\n", __func__);
		rc = -ENODEV;
		goto err0;
	}

	ctxid = cxl_process_element(ctx);
	if ((ctxid > MAX_CONTEXT) || (ctxid < 0)) {
		pr_err("%s: ctxid (%d) invalid!\n", __func__, ctxid);
		rc = -EPERM;
		goto err1;
	}

	file = cxl_get_fd(ctx, &cfg->cxl_fops, &fd);
	if (fd < 0) {
		rc = -ENODEV;
		pr_err("%s: Could not get file descriptor\n", __func__);
		goto err1;
	}

	/* Translate read/write O_* flags from fnctl.h to AFU permission bits */
	perms = SISL_RHT_PERM(attach->hdr.flags + 1);

	ctx_info = create_context(cfg, ctx, ctxid, fd, perms);
	if (unlikely(!ctx_info)) {
		pr_err("%s: Failed to create context! (%d)\n", __func__, ctxid);
		goto err2;
	}

	work = &ctx_info->work;
	work->num_interrupts = attach->num_interrupts;
	work->flags = CXL_START_WORK_NUM_IRQS;

	rc = cxl_start_work(ctx, work);
	if (rc) {
		pr_err("%s: Could not start context rc=%d\n", __func__, rc);
		goto err3;
	}

	rc = cxlflash_afu_attach(cfg, ctx_info);
	if (rc) {
		pr_err("%s: Could not attach AFU rc %d\n", __func__, rc);
		goto err4;
	}

	/*
	 * No error paths after this point. Once the fd is installed it's
	 * visible to userspace and can't be undone safely on this thread.
	 */
	list_add(&lun_access->list, &ctx_info->luns);
	cfg->ctx_tbl[ctxid] = ctx_info;
	fd_install(fd, file);

out_attach:
	attach->hdr.return_flags = 0;
	attach->context_id = ctxid;
	attach->block_size = lun_info->blk_len;
	attach->mmio_size = sizeof(afu->afu_map->hosts[0].harea);
	attach->last_lba = lun_info->max_lba;
	attach->max_xfer = (sdev->host->max_sectors * 512) / lun_info->blk_len;

out:
	attach->adap_fd = fd;

	if (likely(ctx_info))
		atomic_dec(&ctx_info->nrefs);

	pr_info("%s: returning ctxid=%d fd=%d bs=%lld rc=%d llba=%lld\n",
		__func__, ctxid, fd, attach->block_size, rc, attach->last_lba);
	return rc;

err4:
	cxl_stop_context(ctx);
err3:
	destroy_context(cfg, ctx_info);
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
	pr_info("%s: ENTER: WWID = %016llX%016llX, flags = %016llX li = %p\n",
		__func__, get_unaligned_le64(&manage->wwid[0]),
		get_unaligned_le64(&manage->wwid[8]),
		manage->hdr.flags, lun_info);
	return 0;
}

static int cxlflash_afu_recover(struct scsi_device *sdev,
				struct dk_cxlflash_recover_afu *recover)
{
	struct cxlflash_cfg *cfg = (struct cxlflash_cfg *)sdev->host->hostdata;
	struct lun_info *lun_info = sdev->hostdata;
	struct afu *afu = cfg->afu;
	struct ctx_info *ctx_info = NULL;
	u64 ctxid = recover->context_id;
	long reg;
	int rc = 0;

	/* Ensure that this process is attached to the context */
	ctx_info = cxlflash_get_context(cfg, ctxid, lun_info, false);
	if (unlikely(!ctx_info)) {
		pr_err("%s: Invalid context! (%llu)\n", __func__, ctxid);
		rc = -EINVAL;
		goto out;
	}

	reg = readq_be(&afu->ctrl_map->mbox_r);	/* Try MMIO */
	/* MMIO returning 0xff, need to reset */
	if (reg == -1) {
		pr_info("%s: afu=%p reason 0x%llx\n",
			__func__, afu, recover->reason);
		cxlflash_afu_reset(cfg);

	} else {
		pr_info("%s: reason 0x%llx MMIO working, no reset performed\n",
			__func__, recover->reason);
		rc = -EINVAL;
	}

out:
	if (likely(ctx_info))
		atomic_dec(&ctx_info->nrefs);
	return rc;
}

static int process_sense(struct scsi_device *sdev,
			 struct dk_cxlflash_verify *verify)
{
	struct request_sense_data *sense_data = (struct request_sense_data *)
		&verify->sense_data;
	struct lun_info *lun_info = sdev->hostdata;
	struct cxlflash_cfg *cfg = (struct cxlflash_cfg *)sdev->host->hostdata;
	struct afu *afu = cfg->afu;
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
				pr_debug("%s: Capacity changed old=%lld "
					 "new=%lld\n", __func__, prev_lba,
					 lun_info->max_lba);
			break;
		case 0x3F: /* Report LUNs changed, Rescan. */
			scsi_scan_host(cfg->host);
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
	pr_debug("%s: sense_key %x asc %x rc %d\n", __func__,
		 sense_data->sense_key, sense_data->add_sense_key, rc);
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
	struct cxlflash_cfg *cfg = (struct cxlflash_cfg *)sdev->host->hostdata;
	struct lun_info *lun_info = sdev->hostdata;
	u64 ctxid = verify->context_id;

	pr_info("%s: ctxid=%llu res_hndl=0x%llx, hint=0x%llx\n",
		__func__, ctxid, verify->rsrc_handle, verify->hint);

	ctx_info = cxlflash_get_context(cfg, ctxid, lun_info, false);
	if (unlikely(!ctx_info)) {
		pr_err("%s: Invalid context! (%llu)\n",
		       __func__, ctxid);
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
	pr_info("%s: returning rc=%d llba=%lld\n",
		__func__, rc, verify->last_lba);
	return rc;
}

static char *decode_ioctl(int cmd)
{
	switch (cmd) {
	case DK_CXLFLASH_ATTACH:
		return __stringify_1(DK_CXLFLASH_ATTACH);
	case DK_CXLFLASH_USER_DIRECT:
		return __stringify_1(DK_CXLFLASH_USER_DIRECT);
	case DK_CXLFLASH_USER_VIRTUAL:
		return __stringify_1(DK_CXLFLASH_USER_VIRTUAL);
	case DK_CXLFLASH_VLUN_RESIZE:
		return __stringify_1(DK_CXLFLASH_VLUN_RESIZE);
	case DK_CXLFLASH_RELEASE:
		return __stringify_1(DK_CXLFLASH_RELEASE);
	case DK_CXLFLASH_DETACH:
		return __stringify_1(DK_CXLFLASH_DETACH);
	case DK_CXLFLASH_VERIFY:
		return __stringify_1(DK_CXLFLASH_VERIFY);
	case DK_CXLFLASH_CLONE:
		return __stringify_1(DK_CXLFLASH_CLONE);
	case DK_CXLFLASH_RECOVER_AFU:
		return __stringify_1(DK_CXLFLASH_RECOVER_AFU);
	case DK_CXLFLASH_MANAGE_LUN:
		return __stringify_1(DK_CXLFLASH_MANAGE_LUN);
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
	struct cxlflash_cfg *cfg = (struct cxlflash_cfg *)sdev->host->hostdata;
	struct afu *afu = cfg->afu;
	struct lun_info *lun_info = sdev->hostdata;

	struct dk_cxlflash_udirect *pphys = (struct dk_cxlflash_udirect *)arg;

	u64 ctxid = pphys->context_id;
	u64 lun_size = 0;
	u64 last_lba = 0;
	u64 rsrc_handle = -1;

	int rc = 0;

	struct ctx_info *ctx_info = NULL;
	struct sisl_rht_entry *rht_entry = NULL;

	pr_info("%s: ctxid=%llu ls=0x%llx\n", __func__, ctxid, lun_size);

	rc = cxlflash_lun_attach(lun_info, MODE_PHYSICAL);
	if (unlikely(rc)) {
		pr_err("%s: Failed to attach to LUN! mode=%u\n",
		       __func__, MODE_PHYSICAL);
		goto out;
	}

	ctx_info = cxlflash_get_context(cfg, ctxid, lun_info, false);
	if (unlikely(!ctx_info)) {
		pr_err("%s: Invalid context! (%llu)\n", __func__, ctxid);
		rc = -EINVAL;
		goto err1;
	}

	rht_entry = rhte_checkout(ctx_info, lun_info);
	if (unlikely(!rht_entry)) {
		pr_err("%s: too many opens for this context\n", __func__);
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
	pr_info("%s: returning handle 0x%llx rc=%d llba %lld\n",
		__func__, rsrc_handle, rc, last_lba);
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

	struct cxlflash_cfg *cfg = (struct cxlflash_cfg *)sdev->host->hostdata;
	struct afu *afu = cfg->afu;
	struct dk_cxlflash_hdr *hdr;
	char buf[MAX_CXLFLASH_IOCTL_SZ];
	size_t size = 0;
	bool known_ioctl = false;
	int idx;
	int rc = 0;
	struct Scsi_Host *shost = sdev->host;
	sioctl do_ioctl = NULL;
	u64 ctxid;
	struct ctx_info *ctx_info;

	static const struct {
		size_t size;
		sioctl ioctl;
	} ioctl_tbl[] = {	/* NOTE: order matters here */
	{sizeof(struct dk_cxlflash_attach), (sioctl)cxlflash_disk_attach},
	{sizeof(struct dk_cxlflash_udirect), cxlflash_disk_direct_open},
	{sizeof(struct dk_cxlflash_uvirtual), cxlflash_disk_virtual_open},
	{sizeof(struct dk_cxlflash_resize), (sioctl)cxlflash_vlun_resize},
	{sizeof(struct dk_cxlflash_release), (sioctl)cxlflash_disk_release},
	{sizeof(struct dk_cxlflash_detach), (sioctl)cxlflash_disk_detach},
	{sizeof(struct dk_cxlflash_verify), (sioctl)cxlflash_disk_verify},
	{sizeof(struct dk_cxlflash_clone), (sioctl)cxlflash_disk_clone},
	{sizeof(struct dk_cxlflash_recover_afu), (sioctl)cxlflash_afu_recover},
	{sizeof(struct dk_cxlflash_manage_lun), (sioctl)cxlflash_manage_lun},
	};

	/* Restrict command set to physical support only for internal LUN */
	if (afu->internal_lun)
		switch (cmd) {
		case DK_CXLFLASH_USER_VIRTUAL:
		case DK_CXLFLASH_VLUN_RESIZE:
		case DK_CXLFLASH_RELEASE:
		case DK_CXLFLASH_CLONE:
			pr_err("%s: %s not supported for lun_mode=%d\n",
			       __func__, decode_ioctl(cmd), afu->internal_lun);
			rc = -EINVAL;
			goto cxlflash_ioctl_exit;
		}

	switch (cmd) {
	case 0x4711:	/* XXX - remove case and assoc. vars before upstream */
		ctxid = ((struct dk_cxlflash_detach *)arg)->context_id;
		ctx_info = cxlflash_get_context(cfg, ctxid, NULL, false);
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
		known_ioctl = true;
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
		pr_err("%s: copy_from_user() fail! "
		       "size=%lu cmd=%d (%s) arg=%p\n",
		       __func__, size, cmd, decode_ioctl(cmd), arg);
		rc = -EFAULT;
		goto cxlflash_ioctl_exit;
	}

	hdr = (struct dk_cxlflash_hdr *)&buf;
	if (hdr->version != 0) {
		pr_err("%s: Version %u not supported for %s\n",
		       __func__, hdr->version, decode_ioctl(cmd));
		rc = -EINVAL;
		goto cxlflash_ioctl_exit;
	}

	rc = do_ioctl(sdev, (void *)&buf);
	if (likely(!rc))
		if (unlikely(copy_to_user(arg, &buf, size))) {
			pr_err("%s: copy_to_user() fail! "
			       "size=%lu cmd=%d (%s) arg=%p\n",
			       __func__, size, cmd, decode_ioctl(cmd), arg);
			rc = -EFAULT;
		}

	/* fall thru to exit */

cxlflash_ioctl_exit:
	if (unlikely(rc && known_ioctl))
		pr_err("%s: ioctl %s (%08X) on dev(%d/%d/%d/%llu) "
		       "returned rc %d\n", __func__,
		       decode_ioctl(cmd), cmd, shost->host_no,
		       sdev->channel, sdev->id, sdev->lun, rc);
	else
		pr_debug("%s: ioctl %s (%08X) on dev(%d/%d/%d/%llu) "
			 "returned rc %d\n", __func__, decode_ioctl(cmd),
			 cmd, shost->host_no, sdev->channel, sdev->id,
			 sdev->lun, rc);
	return rc;
}
