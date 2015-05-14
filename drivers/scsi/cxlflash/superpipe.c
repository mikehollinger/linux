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

#include <linux/file.h>
#include <linux/syscalls.h>
#include <misc/cxl.h>
#include <asm/unaligned.h>

#include <scsi/scsi_host.h>
#include <uapi/scsi/cxlflash_ioctl.h>

#include "sislite.h"
#include "superpipe.h"
#include "common.h"

extern struct cxlflash_global global;

static void marshall_virt_to_resize(struct dk_cxlflash_uvirtual *virt,
				    struct dk_cxlflash_resize *resize)
{
	resize->hdr = virt->hdr;
	resize->context_id = virt->context_id;
	resize->rsrc_handle = virt->rsrc_handle;
	resize->req_size = virt->lun_size;
	resize->last_lba = virt->last_lba;
}

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

static void marshall_clone_to_rele(struct dk_cxlflash_clone *clone,
				   struct dk_cxlflash_release *release)
{
	release->hdr = clone->hdr;
	release->context_id = clone->context_id_dst;
}

static int ba_init(struct ba_lun *ba_lun)
{
	struct ba_lun_info *lun_info = NULL;
	int lun_size_au = 0, i = 0;
	int last_word_underflow = 0;
	u64 *lam;

	cxlflash_info("Initializing LUN: lun_id = %llX, "
		      "ba_lun->lsize = %lX, ba_lun->au_size = %lX",
		      ba_lun->lun_id, ba_lun->lsize, ba_lun->au_size);

	/* Calculate bit map size */
	lun_size_au = ba_lun->lsize / ba_lun->au_size;
	if (lun_size_au == 0) {
		cxlflash_err("Requested LUN size of 0!");
		return -EINVAL;
	}

	/* Allocate lun information container */
	lun_info = kzalloc(sizeof(struct ba_lun_info), GFP_KERNEL);
	if (unlikely(!lun_info)) {
		cxlflash_err("Failed to allocate lun_info for lun_id %llX",
			     ba_lun->lun_id);
		return -ENOMEM;
	}

	lun_info->total_aus = lun_size_au;
	lun_info->lun_bmap_size = lun_size_au / 64;

	if (lun_size_au % 64)
		lun_info->lun_bmap_size++;

	/* Allocate bitmap space */
	lun_info->lun_alloc_map = kzalloc((lun_info->lun_bmap_size *
					   sizeof(u64)), GFP_KERNEL);
	if (unlikely(!lun_info->lun_alloc_map)) {
		cxlflash_err("Failed to allocate lun allocation map: "
			     "lun_id = %llX", ba_lun->lun_id);
		kfree(lun_info);
		return -ENOMEM;
	}

	/* Initialize the bit map size and set all bits to '1' */
	lun_info->free_aun_cnt = lun_size_au;

	for (i = 0; i < lun_info->lun_bmap_size; i++)
		lun_info->lun_alloc_map[i] = (u64) ~ 0;

	/* If the last word not fully utilized, mark extra bits as allocated */
	last_word_underflow = (lun_info->lun_bmap_size * 64) -
	    lun_info->free_aun_cnt;
	if (last_word_underflow > 0) {
		lam = &lun_info->lun_alloc_map[lun_info->lun_bmap_size - 1];
		for (i = (63 - last_word_underflow + 1); i < 64; i++)
			clear_bit(i, (ulong *)lam);
	}

	/* Initialize high elevator index, low/curr already at 0 from kzalloc */
	lun_info->free_high_idx = lun_info->lun_bmap_size;

	/* Allocate clone map */
	lun_info->aun_clone_map = kzalloc((lun_info->total_aus *
					   sizeof(u8)), GFP_KERNEL);
	if (unlikely(!lun_info->aun_clone_map)) {
		cxlflash_err("Failed to allocate clone map: lun_id = %llX",
			     ba_lun->lun_id);
		kfree(lun_info->lun_alloc_map);
		kfree(lun_info);
		return -ENOMEM;
	}

	/* Pass the allocated lun info as a handle to the user */
	ba_lun->ba_lun_handle = (void *)lun_info;

	cxlflash_info("Successfully initialized the LUN: "
		      "lun_id = %llX, bitmap size = %X, free_aun_cnt = %llX",
		      ba_lun->lun_id, lun_info->lun_bmap_size,
		      lun_info->free_aun_cnt);
	return 0;
}

static int find_free_range(u32 low,
			   u32 high,
			   struct ba_lun_info *lun_info, int *bit_word)
{
	int i;
	u64 bit_pos = -1;
	ulong *lam;

	for (i = low; i < high; i++)
		if (lun_info->lun_alloc_map[i] != 0) {
			lam = (ulong *)&lun_info->lun_alloc_map[i];
			/* size argument is in number of bits */
			bit_pos = find_first_bit(lam, sizeof(u64)*8);

			cxlflash_dbg("Found free bit %llX in lun "
				     "map entry %llX at bitmap index = %X",
				     bit_pos, lun_info->lun_alloc_map[i], i);

			*bit_word = i;
			lun_info->free_aun_cnt--;
			clear_bit(bit_pos, lam);
			break;
		}

	return bit_pos;
}

static u64 ba_alloc(struct ba_lun *ba_lun)
{
	u64 bit_pos = -1;
	int bit_word = 0;
	struct ba_lun_info *lun_info = NULL;

	lun_info = (struct ba_lun_info *)ba_lun->ba_lun_handle;

	cxlflash_dbg("Received block allocation request: "
		     "lun_id = %llX, free_aun_cnt = %llX",
		     ba_lun->lun_id, lun_info->free_aun_cnt);

	if (lun_info->free_aun_cnt == 0) {
		cxlflash_err("No space left on LUN: lun_id = %llX",
			     ba_lun->lun_id);
		return -1ULL;
	}

	/* Search to find a free entry, curr->high then low->curr */
	bit_pos = find_free_range(lun_info->free_curr_idx,
				  lun_info->free_high_idx, lun_info, &bit_word);
	if (bit_pos == -1) {
		bit_pos = find_free_range(lun_info->free_low_idx,
					  lun_info->free_curr_idx,
					  lun_info, &bit_word);
		if (bit_pos == -1) {
			cxlflash_err
			    ("Could not find an allocation unit on LUN: "
			     "lun_id = %llX", ba_lun->lun_id);
			return -1ULL;
		}
	}

	/* Update the free_curr_idx */
	if (bit_pos == 63)
		lun_info->free_curr_idx = bit_word + 1;
	else
		lun_info->free_curr_idx = bit_word;

	cxlflash_dbg("Allocating AU number %llX, on lun_id %llX, "
		     "free_aun_cnt = %llX", ((bit_word * 64) + bit_pos),
		     ba_lun->lun_id, lun_info->free_aun_cnt);

	return (u64) ((bit_word * 64) + bit_pos);
}

static int validate_alloc(struct ba_lun_info *lun_info, u64 aun)
{
	int idx = 0, bit_pos = 0;

	idx = aun / 64;
	bit_pos = aun % 64;

	if (test_bit(bit_pos, (ulong *)&lun_info->lun_alloc_map[idx]))
		return -1;

	return 0;
}

static int ba_free(struct ba_lun *ba_lun, u64 to_free)
{
	int idx = 0, bit_pos = 0;
	struct ba_lun_info *lun_info = NULL;

	lun_info = (struct ba_lun_info *)ba_lun->ba_lun_handle;

	if (validate_alloc(lun_info, to_free)) {
		cxlflash_err("The AUN %llX is not allocated on lun_id %llX",
			     to_free, ba_lun->lun_id);
		return -1;
	}

	cxlflash_dbg("Received a request to free AU %llX on lun_id %llX, "
		     "free_aun_cnt = %llX", to_free, ba_lun->lun_id,
		     lun_info->free_aun_cnt);

	if (lun_info->aun_clone_map[to_free] > 0) {
		cxlflash_info("AUN %llX on lun_id %llX has been cloned. Clone "
			      "count = %X",
			      to_free, ba_lun->lun_id,
			      lun_info->aun_clone_map[to_free]);
		lun_info->aun_clone_map[to_free]--;
		return 0;
	}

	idx = to_free / 64;
	bit_pos = to_free % 64;

	set_bit(bit_pos, (ulong *)&lun_info->lun_alloc_map[idx]);
	lun_info->free_aun_cnt++;

	if (idx < lun_info->free_low_idx)
		lun_info->free_low_idx = idx;
	else if (idx > lun_info->free_high_idx)
		lun_info->free_high_idx = idx;

	cxlflash_dbg("Successfully freed AU at bit_pos %X, bit map index %X on "
		     "lun_id %llX, free_aun_cnt = %llX", bit_pos, idx,
		     ba_lun->lun_id, lun_info->free_aun_cnt);

	return 0;
}

static int ba_clone(struct ba_lun *ba_lun, u64 to_clone)
{
	struct ba_lun_info *lun_info =
	    (struct ba_lun_info *)ba_lun->ba_lun_handle;

	if (validate_alloc(lun_info, to_clone)) {
		cxlflash_err("AUN %llX is not allocated on lun_id %llX",
			     to_clone, ba_lun->lun_id);
		return -1;
	}

	cxlflash_info("Received a request to clone AUN %llX on lun_id %llX",
		      to_clone, ba_lun->lun_id);

	if (lun_info->aun_clone_map[to_clone] == MAX_AUN_CLONE_CNT) {
		cxlflash_err
		    ("AUN %llX on lun_id %llX has hit max clones already",
		     to_clone, ba_lun->lun_id);
		return -1;
	}

	lun_info->aun_clone_map[to_clone]++;

	return 0;
}

static u64 ba_space(struct ba_lun *ba_lun)
{
	struct ba_lun_info *lun_info =
	    (struct ba_lun_info *)ba_lun->ba_lun_handle;

	return lun_info->free_aun_cnt;
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
	if (unlikely(!lun_info)) {
		goto out;
	}

	spin_lock_irqsave(&global.slock, flags);
	if (wwid)
		memcpy(lun_info->wwid, wwid, DK_CXLFLASH_MANAGE_LUN_WWID_LEN);
	list_add(&lun_info->list, &global.luns);
	spin_unlock_irqrestore(&global.slock, flags);

out:
	cxlflash_info("returning %p", lun_info);
	return lun_info;
}

int cxlflash_alloc_lun(struct scsi_device *sdev)
{
	struct lun_info *lun_info = NULL;
	int rc = 0;

	lun_info = lookup_lun(sdev, NULL);
	if (unlikely(!lun_info)) {
		rc = -ENOMEM;
		goto out;
	}

	sdev->hostdata = lun_info;

out:
	return rc;
}

void cxlflash_init_lun(struct scsi_device *sdev)
{
	struct lun_info *lun_info = sdev->hostdata;
	struct Scsi_Host *shost = sdev->host;
	struct cxlflash *cxlflash = shost_priv(shost);
	struct afu *afu = cxlflash->afu;

	/* Store off lun in unpacked, AFU-friendly format */
	lun_info->lun_id = lun_to_lunid(sdev->lun);

	writeq_be(lun_info->lun_id,
		  &afu->afu_map->global.fc_port[sdev->channel]
		  [cxlflash->last_lun_index++]);

}

static void ba_terminate(struct ba_lun *ba_lun)
{
	struct ba_lun_info *lun_info =
	    (struct ba_lun_info *)ba_lun->ba_lun_handle;

	if (lun_info) {
		if (lun_info->aun_clone_map)
			kfree(lun_info->aun_clone_map);
		if (lun_info->lun_alloc_map)
			kfree(lun_info->lun_alloc_map);
		kfree(lun_info);
		ba_lun->ba_lun_handle = NULL;
	}
}

void cxlflash_lun_terminate(struct cxlflash_global *globalp)
{
	struct lun_info *lun_info, *temp;
	unsigned long flags = 0;

	spin_lock_irqsave(&globalp->slock, flags);
	list_for_each_entry_safe(lun_info, temp, &globalp->luns, list) {
		list_del(&lun_info->list);
		ba_terminate(&lun_info->blka.ba_lun);
		kfree(lun_info);
	}
	spin_unlock_irqrestore(&globalp->slock, flags);
}

static struct ctx_info *get_context(struct cxlflash *cxlflash, u64 ctxid,
				    struct lun_info *lun_info, bool clone_path)
{
	struct ctx_info *ctx_info = NULL;
	struct lun_access *lun_access = NULL;
	bool found = false;
	pid_t pid = current->pid, ctxpid = 0;

	if (unlikely(clone_path))
		pid = current->parent->pid;

	if (likely(ctxid < MAX_CONTEXT)) {
		ctx_info = cxlflash->ctx_info[ctxid];
		if (unlikely(!ctx_info))
			goto out;

		ctxpid = ctx_info->pid;
		if (checkpid && (pid != ctxpid)) {
			ctx_info = NULL;
			goto out;
		}

		if (likely(lun_info)) {
			list_for_each_entry(lun_access, &ctx_info->luns, list)
				if (lun_access->lun_info == lun_info) {
					found = true;
					break;
				}

			if (!found) {
				ctx_info = NULL;
				goto out;
			}
		}
	}

out:
	cxlflash_dbg("ctxid=%llu ctxinfo=%p ctxpid=%u pid=%u clone=%d found=%d",
		     ctxid, ctx_info, ctxpid, pid, clone_path, found);

	return ctx_info;
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

static int cxlflash_init_ba(struct lun_info *lun_info)
{
	int rc = 0;
	struct blka *blka = &lun_info->blka;

	memset(blka, 0, sizeof(*blka));
	mutex_init(&blka->mutex);

	blka->ba_lun.lun_id = lun_info->lun_id;
	blka->ba_lun.lsize = lun_info->max_lba + 1;
	blka->ba_lun.lba_size = lun_info->blk_len;

	blka->ba_lun.au_size = MC_CHUNK_SIZE;
	blka->nchunk = blka->ba_lun.lsize / MC_CHUNK_SIZE;

	rc = ba_init(&blka->ba_lun);
	if (rc) {
		cxlflash_err("cannot init block_alloc, rc=%d", rc);
		goto cxlflash_init_ba_exit;
	}

cxlflash_init_ba_exit:
	cxlflash_info("returning rc=%d lun_info=%p", rc, lun_info);
	return rc;
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

static struct sisl_rht_entry *get_rhte(struct ctx_info *ctx_info,
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
static struct sisl_rht_entry *rhte_checkout(struct ctx_info *ctx_info,
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

static void rhte_checkin(struct ctx_info *ctx_info,
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
	dummy.port_sel = 0x3;
	rht_entry_f1->dw = dummy.dw;

	smp_wmb();

	return;
}

int write_same16(struct afu *afu, struct lun_info *lun_info, u64 lba, u32 nblks)
{
	struct afu_cmd *cmd;
	int rc = 0;

	cmd = cxlflash_cmd_checkout(afu);
	if (unlikely(!cmd)) {
		cxlflash_err("could not get a free command");
		rc = -1;
		goto out;
	}

	cmd->rcb.req_flags = (SISL_REQ_FLAGS_PORT_LUN_ID |
				SISL_REQ_FLAGS_SUP_UNDERRUN |
				SISL_REQ_FLAGS_HOST_READ);

	cmd->rcb.port_sel = 3;
	cmd->rcb.lun_id = lun_info->lun_id;
	cmd->rcb.data_len = CMD_BUFSIZE;
	cmd->rcb.data_ea = (u64) cmd->buf; /* Filled w/ zeros on checkout */
	cmd->rcb.timeout = MC_DISCOVERY_TIMEOUT;
	cmd->internal = true;

	cmd->rcb.cdb[0] = WRITE_SAME_16;
	put_unaligned_be64(lba, &cmd->rcb.cdb[2]);
	put_unaligned_be32(nblks, &cmd->rcb.cdb[10]);

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

out:
	cxlflash_info("returning rc=%d", rc);
	return rc;
}

static int grow_lxt(struct afu *afu,
		    struct lun_info *lun_info,
		    ctx_hndl_t ctx_hndl_u,
		    res_hndl_t res_hndl_u,
		    struct sisl_rht_entry *rht_entry,
		    u64 delta, u64 * act_new_size)
{
	struct sisl_lxt_entry *lxt = NULL, *lxt_old = NULL;
	unsigned int av_size;
	unsigned int ngrps, ngrps_old;
	u64 aun;		/* chunk# allocated by block allocator */
	int i;
	struct blka *blka = &lun_info->blka;

	/*
	 * Check what is available in the block allocator before re-allocating
	 * LXT array. This is done up front under the mutex which must not be
	 * released until after allocation is complete.
	 */
	mutex_lock(&blka->mutex);
	av_size = ba_space(&blka->ba_lun);
	if (av_size < delta)
		delta = av_size;

	lxt_old = rht_entry->lxt_start;
	ngrps_old = LXT_NUM_GROUPS(rht_entry->lxt_cnt);
	ngrps = LXT_NUM_GROUPS(rht_entry->lxt_cnt + delta);

	if (ngrps != ngrps_old) {
		/* reallocate to fit new size */
		lxt = kzalloc((sizeof(*lxt) * LXT_GROUP_SIZE * ngrps),
				GFP_KERNEL);
		if (unlikely(!lxt)) {
			mutex_unlock(&blka->mutex);
			return -ENOMEM;
		}

		/* copy over all old entries */
		memcpy(lxt, lxt_old, (sizeof(*lxt) *
					  rht_entry->lxt_cnt));
	} else
		lxt = lxt_old;

	/* nothing can fail from now on */
	*act_new_size = rht_entry->lxt_cnt + delta;

	/* add new entries to the end */
	for (i = rht_entry->lxt_cnt; i < *act_new_size; i++) {
		/*
		 * Due to the earlier check of available space, ba_alloc
		 * cannot fail here. If it did due to internal error,
		 * leave a rlba_base of -1u which will likely be a
		 * invalid LUN (too large).
		 */
		aun = ba_alloc(&blka->ba_lun);
		if ((aun == -1ULL) || (aun >= blka->nchunk))
			cxlflash_err("ba_alloc error: allocated chunk# %llX, "
				     "max %llX", aun, blka->nchunk - 1);

		/* select both ports, use r/w perms from RHT */
		lxt[i].rlba_base = ((aun << MC_CHUNK_SHIFT) |
				      (lun_info->lun_index <<
				       LXT_LUNIDX_SHIFT) | 0x33);
	}

	mutex_unlock(&blka->mutex);

	smp_wmb();		/* make lxt updates visible */

	/* Now sync up AFU - this can take a while */
	rht_entry->lxt_start = lxt;	/* even if lxt didn't change */
	smp_wmb();

	rht_entry->lxt_cnt = *act_new_size;
	smp_wmb();

	cxlflash_afu_sync(afu, ctx_hndl_u, res_hndl_u, AFU_LW_SYNC);

	/* free old lxt if reallocated */
	if (lxt != lxt_old)
		kfree(lxt_old);
	cxlflash_dbg("returning");
	return 0;
}

static int shrink_lxt(struct afu *afu,
		      struct lun_info *lun_info,
		      ctx_hndl_t ctx_hndl_u,
		      res_hndl_t res_hndl_u,
		      struct sisl_rht_entry *rht_entry,
		      u64 delta, u64 * act_new_size)
{
	struct sisl_lxt_entry *lxt, *lxt_old;
	unsigned int ngrps, ngrps_old;
	u64 aun;		/* chunk# allocated by block allocator */
	int i;
	struct blka *blka = &lun_info->blka;

	lxt_old = rht_entry->lxt_start;
	ngrps_old = LXT_NUM_GROUPS(rht_entry->lxt_cnt);
	ngrps = LXT_NUM_GROUPS(rht_entry->lxt_cnt - delta);

	if (ngrps != ngrps_old) {
		/* reallocate to fit new size unless new size is 0 */
		if (ngrps) {
			lxt = kzalloc((sizeof(*lxt) * LXT_GROUP_SIZE *
					 ngrps), GFP_KERNEL);
			if (unlikely(!lxt))
				return -ENOMEM;

			/* copy over old entries that will remain */
			memcpy(lxt, lxt_old, (sizeof(*lxt) *
						  (rht_entry->lxt_cnt -
						   delta)));
		} else
			lxt = NULL;
	} else
		lxt = lxt_old;

	/* nothing can fail from now on */
	*act_new_size = rht_entry->lxt_cnt - delta;

	/* Now sync up AFU - this can take a while */
	rht_entry->lxt_cnt = *act_new_size;
	smp_wmb();		/* also makes lxt updates visible */

	rht_entry->lxt_start = lxt;	/* even if lxt didn't change */
	smp_wmb();

	cxlflash_afu_sync(afu, ctx_hndl_u, res_hndl_u, AFU_HW_SYNC);

	/* free LBAs allocated to freed chunks */
	mutex_lock(&blka->mutex);
	for (i = delta - 1; i >= 0; i--) {
		/* Mask the higher 48 bits before shifting, even though
		 * it is a noop
		 */
		aun = ((lxt_old[*act_new_size + i].rlba_base &
			SISL_ASTATUS_MASK) >> MC_CHUNK_SHIFT);
		if (ws)
			write_same16(afu, lun_info, aun, MC_CHUNK_SIZE);
		ba_free(&blka->ba_lun, aun);
	}
	mutex_unlock(&blka->mutex);

	/* free old lxt if reallocated */
	if (lxt != lxt_old)
		kfree(lxt_old);
	cxlflash_dbg("returning");
	return 0;
}

/*
 * NAME:	cxlflash_vlun_resize()
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
 *		act_new_size	- pointer to actual new size in chunks
 *
 * RETURNS:
 *		0	- Success
 *		errno	- Failure
 *
 * NOTES:
 *		Setting new_size=0 will clear LXT_START and LXT_CNT fields
 *		in the RHT entry.
 */
static int cxlflash_vlun_resize(struct scsi_device *sdev,
				struct dk_cxlflash_resize *resize)
{
	struct cxlflash *cxlflash = (struct cxlflash *)sdev->host->hostdata;
	struct lun_info *lun_info = sdev->hostdata;
	struct afu *afu = cxlflash->afu;

	u64 act_new_size = 0;
	res_hndl_t res_hndl = resize->rsrc_handle;
	u64 new_size;
	u64 nsectors;

	struct ctx_info *ctx_info;
	struct sisl_rht_entry *rht_entry;

	int rc = 0;

	/* req_size is always assumed to be in 4k blocks. So we have to convert
	 * it from 4k to chunk size
	 */
	nsectors = (resize->req_size * CXLFLASH_BLOCK_SIZE) /
	    (lun_info->blk_len);
	new_size = (nsectors + MC_CHUNK_SIZE - 1) / MC_CHUNK_SIZE;

	cxlflash_info("context=0x%llx res_hndl=0x%llx, req_size=0x%llx,"
		      "new_size=%llx", resize->context_id,
		      resize->rsrc_handle, resize->req_size, new_size);

	if (unlikely(lun_info->mode != MODE_VIRTUAL)) {
		cxlflash_err("LUN mode does not support resize! (%d)",
			     lun_info->mode);
		rc = -EINVAL;
		goto out;

	}

	ctx_info = get_context(cxlflash, resize->context_id, lun_info, false);
	if (unlikely(!ctx_info)) {
		cxlflash_err("Invalid context! (%llu)", resize->context_id);
		rc = -EINVAL;
		goto out;
	}

	rht_entry = get_rhte(ctx_info, res_hndl, lun_info);
	if (unlikely(!rht_entry)) {
		cxlflash_err("Invalid resource handle! (%u)", res_hndl);
		rc = -EINVAL;
		goto out;
	}

	if (new_size > rht_entry->lxt_cnt)
		grow_lxt(afu,
			 lun_info,
			 resize->context_id,
			 res_hndl,
			 rht_entry,
			 new_size - rht_entry->lxt_cnt,
			 &act_new_size);
	else if (new_size < rht_entry->lxt_cnt)
		shrink_lxt(afu,
			   lun_info,
			   resize->context_id,
			   res_hndl,
			   rht_entry,
			   rht_entry->lxt_cnt - new_size,
			   &act_new_size);
	else
		act_new_size = new_size;

	resize->hdr.return_flags = 0;
	resize->last_lba = (((act_new_size * MC_CHUNK_SIZE *
			    lun_info->blk_len) / CXLFLASH_BLOCK_SIZE) - 1);

out:
	cxlflash_info("resized to %lld returning rc=%d", resize->last_lba, rc);
	return rc;
}

static int cxlflash_lun_attach(struct lun_info *lun_info, enum lun_mode mode)
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

static void cxlflash_lun_detach(struct lun_info *lun_info)
{
	spin_lock(&lun_info->slock);
	if (--lun_info->users == 0)
		lun_info->mode = MODE_NONE;
	cxlflash_dbg("li_users=%u", lun_info->users);
	BUG_ON(lun_info->users < 0);
	spin_unlock(&lun_info->slock);
}

/*
 * NAME:        cxlflash_disk_open
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
static int cxlflash_disk_open(struct scsi_device *sdev, void *arg,
			      enum lun_mode mode)
{
	struct cxlflash *cxlflash = (struct cxlflash *)sdev->host->hostdata;
	struct afu *afu = cxlflash->afu;
	struct lun_info *lun_info = sdev->hostdata;

	struct dk_cxlflash_uvirtual *virt = (struct dk_cxlflash_uvirtual *)arg;
	struct dk_cxlflash_udirect *pphys = (struct dk_cxlflash_udirect *)arg;
	struct dk_cxlflash_resize resize;

	u32 perms;
	u64 context_id;
	u64 lun_size = 0;
	u64 last_lba = 0;
	u64 rsrc_handle = -1;

	int rc = 0;

	struct ctx_info *ctx_info;
	struct sisl_rht_entry *rht_entry = NULL;

	switch (mode) {
	case MODE_VIRTUAL:
		context_id = virt->context_id;
		lun_size = virt->lun_size;
		break;
	case MODE_PHYSICAL:
		context_id = pphys->context_id;
		break;
	default:
		cxlflash_err("Unknown mode! (%u)", mode);
		rc = -EINVAL;
		goto out;
	}

	cxlflash_info("context=0x%llx ls=0x%llx", context_id, lun_size);

	rc = cxlflash_lun_attach(lun_info, mode);
	if (unlikely(rc)) {
		cxlflash_err("Failed to attach to LUN! mode=%u", mode);
		goto out;
	}

	ctx_info = get_context(cxlflash, context_id, lun_info, false);
	if (unlikely(!ctx_info)) {
		cxlflash_err("Invalid context! (%llu)", context_id);
		rc = -EINVAL;
		goto err1;
	}

	rht_entry = rhte_checkout(ctx_info, lun_info);
	if (unlikely(!rht_entry)) {
		cxlflash_err("too many opens for this context");
		rc = -EMFILE;	/* too many opens  */
		goto err1;
	}

	/* User specified permission on attach */
	perms = ctx_info->rht_perms;

	rsrc_handle = (rht_entry - ctx_info->rht_start);

	if (mode == MODE_VIRTUAL) {
		rht_entry->nmask = MC_RHT_NMASK;
		rht_entry->fp = SISL_RHT_FP(0U, perms);
		/* format 0 & perms */

		if (lun_size != 0) {
			marshall_virt_to_resize(virt, &resize);
			resize.rsrc_handle = rsrc_handle;
			rc = cxlflash_vlun_resize(sdev, &resize);
			if (rc) {
				cxlflash_err("resize failed rc %d", rc);
				goto err2;
			}
			last_lba = resize.last_lba;
		}
		virt->hdr.return_flags = 0;
		virt->last_lba = last_lba;
		virt->rsrc_handle = rsrc_handle;
	} else if (mode == MODE_PHYSICAL) {
		rht_format1(rht_entry, lun_info->lun_id, perms);
		cxlflash_afu_sync(afu, context_id, rsrc_handle, AFU_LW_SYNC);

		last_lba = lun_info->max_lba;
		pphys->hdr.return_flags = 0;
		pphys->last_lba = last_lba;
		pphys->rsrc_handle = rsrc_handle;
	}

out:
	cxlflash_info("returning handle 0x%llx rc=%d llba %lld",
		      rsrc_handle, rc, last_lba);
	return rc;

err2:
	rhte_checkin(ctx_info, rht_entry);
err1:
	cxlflash_lun_detach(lun_info);
	goto out;
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

	struct ctx_info *ctx_info;
	struct sisl_rht_entry *rht_entry;

	cxlflash_info("context=0x%llx res_hndl=0x%llx li->mode=%u li->users=%u",
		      release->context_id, release->rsrc_handle,
		      lun_info->mode, lun_info->users);

	ctx_info = get_context(cxlflash, release->context_id, lun_info, false);
	if (unlikely(!ctx_info)) {
		cxlflash_err("Invalid context! (%llu)", release->context_id);
		rc = -EINVAL;
		goto out;
	}

	rht_entry = get_rhte(ctx_info, res_hndl, lun_info);
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
		cxlflash_afu_sync(afu, release->context_id, res_hndl,
					  AFU_HW_SYNC);
		rhte_checkin(ctx_info, rht_entry);
	}

	cxlflash_lun_detach(lun_info);

out:
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
	struct ctx_info *ctx_info;

	int i;
	int rc = 0;
	int lfd;

	cxlflash_info("context=0x%llx", detach->context_id);

	ctx_info = get_context(cxlflash, detach->context_id, lun_info, false);
	if (unlikely(!ctx_info)) {
		cxlflash_err("Invalid context! (%llu)", detach->context_id);
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
		lfd = ctx_info->lfd;

		cxlflash->ctx_info[detach->context_id] = NULL;
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
	struct ctx_info *ctx_info;
	struct dk_cxlflash_detach detach = { { 0 }, 0 };
	struct lun_access *lun_access, *t;
	int context_id;

	context_id = cxl_process_element(ctx);
	if (unlikely(context_id < 0)) {
		cxlflash_err("Context %p was closed! (%d)", ctx, context_id);
		BUG(); /* XXX - remove me before submission */
		goto out;
	}

	ctx_info = get_context(cxlflash, context_id, NULL, false);
	if (unlikely(!ctx_info)) {
		ctx_info = get_context(cxlflash, context_id, NULL, true);
		if (!ctx_info) {
			cxlflash_dbg("Context %d already free!", context_id);
			goto out_release;
		}

		cxlflash_dbg("Another process owns context %d!", context_id);
		goto out;
	}

	cxlflash_info("close(%d) for context %d", ctx_info->lfd, context_id);

	/* Reset the file descriptor to indicate we're on a close() thread */
	ctx_info->lfd = -1;
	detach.context_id = context_id;
	list_for_each_entry_safe(lun_access, t, &ctx_info->luns, list)
		cxlflash_disk_detach(lun_access->sdev, &detach);

	/* Don't reference ctx_info, lun_access, or t */

out_release:
	cxl_fd_release(inode, file);
out:
	cxlflash_dbg("returning");
	return 0;
}

const struct file_operations cxlflash_cxl_fops = {
	.owner = THIS_MODULE,
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
	int context_id = -1;
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
		rc = cxlflash_init_ba(lun_info);
		if (rc) {
			cxlflash_err("call to cxlflash_init_ba failed "
				     "rc=%d!", rc);
			rc = -ENOMEM;
			goto out;
		}
	}

	if (attach->hdr.flags & DK_CXLFLASH_ATTACH_REUSE_CONTEXT) {
		context_id = attach->context_id;
		ctx_info = get_context(cxlflash, context_id, NULL, false);
		if (!ctx_info) {
			cxlflash_err("Invalid context! (%d)", context_id);
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
		cxlflash_dbg("Reusing context for LUN! (%d)", context_id);
		list_add(&lun_access->list, &ctx_info->luns);
		goto out;
	}

	ctx = cxl_dev_context_init(cxlflash->dev);
	if (!ctx) {
		cxlflash_err("Could not initialize context");
		rc = -ENODEV;
		goto err0;
	}

	context_id = cxl_process_element(ctx);
	if ((context_id > MAX_CONTEXT) || (context_id < 0)) {
		cxlflash_err("context_id (%d) invalid!", context_id);
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
	perms = ((attach->hdr.flags + 1) & 0x3);

	ctx_info = create_context(cxlflash, ctx, context_id, fd, perms);
	if (unlikely(!ctx_info)) {
		cxlflash_err("Failed to create context! (%d)", context_id);
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
	cxlflash->ctx_info[context_id] = ctx_info;
	fd_install(fd, file);

	attach->hdr.return_flags = 0;
	attach->context_id = context_id;
	attach->block_size = lun_info->blk_len;
	attach->mmio_size = sizeof(afu->afu_map->hosts[0].harea);
	attach->last_lba = lun_info->max_lba;
	attach->max_xfer = sdev->host->max_sectors;

out:
	attach->adap_fd = fd;

	cxlflash_info("returning ctxid=%d fd=%d bs=%lld rc=%d llba=%lld",
		      context_id, fd, attach->block_size, rc, attach->last_lba);
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

	lun_info = lookup_lun (sdev, manage->wwid);
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
	struct ctx_info *ctx_info;
	long reg;
	int rc = 0;

	/* Ensure that this process is attached to the context */
	ctx_info = get_context(cxlflash, recover->context_id, lun_info, false);
	if (unlikely(!ctx_info)) {
		cxlflash_err("Invalid context! (%llu)", recover->context_id);
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
	return rc;
}

/*
 * NAME:	clone_lxt()
 *
 * FUNCTION:	clone a LXT table
 *
 * INPUTS:
 *		afu		- Pointer to afu struct
 *		ctx_hndl_u	- context that owns the destination LXT
 *		res_hndl_u	- res_hndl of the destination LXT
 *		rht_entry	- destination RHT to clone into
 *		rht_entry_src	- source RHT to clone from
 *
 * OUTPUTS:
 *
 * RETURNS:
 *		0	- Success
 *		errno	- Failure
 *
 * NOTES:
 */
static int clone_lxt(struct afu *afu,
		     struct blka *blka,
		     ctx_hndl_t ctx_hndl_u,
		     res_hndl_t res_hndl_u,
		     struct sisl_rht_entry *rht_entry,
		     struct sisl_rht_entry *rht_entry_src)
{
	struct sisl_lxt_entry *lxt;
	unsigned int ngrps;
	u64 aun;		/* chunk# allocated by block allocator */
	int i, j;

	ngrps = LXT_NUM_GROUPS(rht_entry_src->lxt_cnt);

	if (ngrps) {
		/* allocate new LXTs for clone */
		lxt = kzalloc((sizeof(*lxt) * LXT_GROUP_SIZE * ngrps),
				GFP_KERNEL);
		if (unlikely(!lxt))
			return -ENOMEM;

		/* copy over */
		memcpy(lxt, rht_entry_src->lxt_start,
		       (sizeof(*lxt) * rht_entry_src->lxt_cnt));

		/* clone the LBAs in block allocator via ref_cnt */
		mutex_lock(&blka->mutex);
		for (i = 0; i < rht_entry_src->lxt_cnt; i++) {
			aun = (lxt[i].rlba_base >> MC_CHUNK_SHIFT);
			if (ba_clone(&blka->ba_lun, aun) == -1ULL) {
				/* free the clones already made */
				for (j = 0; j < i; j++) {
					aun = (lxt[j].rlba_base >>
					       MC_CHUNK_SHIFT);
					ba_free(&blka->ba_lun, aun);
				}

				mutex_unlock(&blka->mutex);
				kfree(lxt);
				return -EIO;
			}
		}
		mutex_unlock(&blka->mutex);
	} else {
		lxt = NULL;
	}

	smp_wmb();		/* make lxt updates visible */

	/* Now sync up AFU - this can take a while */
	rht_entry->lxt_start = lxt;	/* even if lxt is NULL */
	smp_wmb();

	rht_entry->lxt_cnt = rht_entry_src->lxt_cnt;
	smp_wmb();

	cxlflash_afu_sync(afu, ctx_hndl_u, res_hndl_u, AFU_LW_SYNC);

	cxlflash_dbg("returning");
	return 0;
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

	struct ctx_info *ctx_info_src, *ctx_info_dst;
	struct lun_access *lun_access_src, *lun_access_dst;
	u32 perms;
	int adap_fd_src = clone->adap_fd_src;
	int i, j;
	int rc = 0;
	bool found;
	LIST_HEAD(sidecar);

	cxlflash_info("ctx_id_src=%llu ctx_id_dst=%llu adap_fd_src=%llu",
		      clone->context_id_src, clone->context_id_dst,
		      clone->adap_fd_src);

	/* Do not clone yourself */
	if (unlikely(clone->context_id_src == clone->context_id_dst)) {
		rc = -EINVAL;
		goto out;
	}

	ctx_info_src = get_context(cxlflash, clone->context_id_src, lun_info,
				   true);
	ctx_info_dst = get_context(cxlflash, clone->context_id_dst, lun_info,
				   false);
	if (unlikely(!ctx_info_src || !ctx_info_dst)) {
		cxlflash_err("Invalid context! (%llu,%llu)",
			     clone->context_id_src, clone->context_id_dst);
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

		rc = clone_lxt(afu, blka, clone->context_id_dst, i,
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
				cxlflash_dbg("Capacity changed old=%lld"
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
	struct ctx_info *ctx_info;
	struct cxlflash *cxlflash = (struct cxlflash *)sdev->host->hostdata;
	struct lun_info *lun_info = sdev->hostdata;

	cxlflash_info("context=0x%llx res_hndl=0x%llx, hint=0x%llx",
		      verify->context_id, verify->rsrc_handle,
		      verify->hint);

	ctx_info = get_context(cxlflash, verify->context_id, lun_info, false);
	if (unlikely(!ctx_info)) {
		cxlflash_err("Invalid context! (%llu)", verify->context_id);
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

	return ("UNKNOWN");
}

static int cxlflash_disk_virtual_open(struct scsi_device *sdev, void *arg)
{
	return cxlflash_disk_open(sdev, arg, MODE_VIRTUAL);
}

static int cxlflash_disk_direct_open(struct scsi_device *sdev, void *arg)
{
	return cxlflash_disk_open(sdev, arg, MODE_PHYSICAL);
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
	if (internal_lun || afu->internal_lun)
		switch (cmd) {
		case DK_CXLFLASH_USER_VIRTUAL:
		case DK_CXLFLASH_VLUN_RESIZE:
		case DK_CXLFLASH_RELEASE:
		case DK_CXLFLASH_CLONE:
			cxlflash_err("%s not supported for lun_mode=%d",
				     decode_ioctl(cmd), internal_lun);
			rc = -EINVAL;
			goto cxlflash_ioctl_exit;
		}

	switch (cmd) {
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
	cxlflash_info("ioctl %s (%08X) on dev(%d/%d/%d/%llu) returned rc %d",
		      decode_ioctl(cmd), cmd, shost->host_no, sdev->channel,
		      sdev->id, sdev->lun, rc);
	return rc;
}
