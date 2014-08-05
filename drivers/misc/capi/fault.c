#if 1
#define DEBUG
#else
#undef DEBUG
#endif

#include <linux/workqueue.h>
#include <linux/sched.h>
#include <linux/pid.h>
/* #include <linux/log2.h> */
#include <linux/mm.h>
#include <linux/moduleparam.h>

#undef MODULE_PARAM_PREFIX
#define MODULE_PARAM_PREFIX "capi" "."
#include <asm/current.h>
#include <asm/copro.h>
#include <asm/mmu.h>

#include "capi.h"

#include "../../../arch/powerpc/mm/mmu_decl.h" /* FIXME (for hash_preload) */

bool capi_fault_debug = false;

static void capi_page_fault_error(struct capi_context_t *ctx)
{
	unsigned long flags;

	/* Any situation where we should write C to retry later? */
	capi_ops->ack_irq(ctx, CAPI_PSL_TFC_An_AE, 0);

	spin_lock_irqsave(&ctx->lock, flags);
	ctx->pending_fault = true;
	ctx->fault_addr = ctx->dar;
	spin_unlock_irqrestore(&ctx->lock, flags);

	wake_up_all(&ctx->wq);
}

void capi_handle_page_fault(struct work_struct *work)
{
	struct capi_context_t *ctx = container_of(work, struct capi_context_t, work);
	u64 dsisr = ctx->dsisr;
	u64 dar = ctx->dar;
	unsigned flt = 0;
	int result;
	struct task_struct *task;
	struct mm_struct *mm;

	pr_devel("CAPI BOTTOM HALF handling page fault for afu pe: %i. "
		"DSISR: %#llx DAR: %#llx\n", ctx->ph, dsisr, dar);

	task = get_pid_task(ctx->pid, PIDTYPE_PID);
	if (!task) {
		pr_devel("capi_handle_page_fault unable to get task %i\n", pid_nr(ctx->pid));
		return;
	}
	mm = get_task_mm(task);
	if (!mm) {
		pr_devel("capi_handle_page_fault unable to get mm %i\n", pid_nr(ctx->pid));
		capi_page_fault_error(ctx);
		goto out1;
	}

	/* FIXME: This may sleep, make sure it's handled OK if the application
	 * is terminated (do I need to inc mm->mm_count?) */
	result = copro_handle_mm_fault(mm, dar, dsisr, &flt);
	if (result) {
		pr_devel("copro_handle_mm_fault failed: %#x\n", result);
		capi_page_fault_error(ctx);
		goto out;
	}

	/*
	 * update_mmu_cache() will not have loaded the hash since current->trap
	 * is not a 0x400 or 0x300, so just call hash_preload() here. Don't use
	 * hash_page() as it assumes we are talking about current.
	 *
	 * FIXME: I'm not clear on the locking requirements of hash_preload
	 */
	down_read(&mm->mmap_sem);
	spin_lock(&mm->page_table_lock);
	hash_preload(mm, dar, 0, 0x300);
	spin_unlock(&mm->page_table_lock);
	up_read(&mm->mmap_sem);

	if (ctx->last_dar == dar) {
		if (ctx->last_dar_count++ > 5) {
			pr_err("Continuous page faults on same page.  Something horribly wrong!\n");
			BUG();
		}
	} else {
		ctx->last_dar_count = 0;
		ctx->last_dar = dar;
	}

	pr_devel("Page fault successfully handled for pe: %i!\n", ctx->ph);
	capi_ops->ack_irq(ctx, CAPI_PSL_TFC_An_R, 0);

	/* TODO: Accounting */
out:
	mmput(mm);
out1:
	put_task_struct(task);
}

/* FIXME: This shares a lot of code in common with Cell's __spu_trap_data_seg,
 * split it out into a shared copro file. Also, remove the various symbol
 * exports for variables this mentions */
static int slbfee_mm(struct mm_struct *mm, u64 ea, u64 *esid, u64 *vsid)
{
	int psize, ssize;

	*esid = (ea & ESID_MASK) | SLB_ESID_V;

	switch(REGION_ID(ea)) {
	case USER_REGION_ID:
		pr_devel("slbfee_mm: 0x%llx -- USER_REGION_ID\n", ea);
#ifdef CONFIG_PPC_MM_SLICES
		psize = get_slice_psize(mm, ea);
#else
		psize = mm->context.user_psize;
#endif
		ssize = user_segment_size(ea);
		*vsid = (get_vsid(mm->context.id, ea, ssize)
			<< slb_vsid_shift(ssize)) | SLB_VSID_USER
			| (ssize == MMU_SEGSIZE_1T ? SLB_VSID_B_1T : 0);
		break;
	case VMALLOC_REGION_ID:
		pr_devel("slbfee_mm: 0x%llx -- VMALLOC_REGION_ID\n", ea);
		if (ea < VMALLOC_END)
			psize = mmu_vmalloc_psize;
		else
			psize = mmu_io_psize;
		*vsid = (get_kernel_vsid(ea, mmu_kernel_ssize)
			<< SLB_VSID_SHIFT) | SLB_VSID_KERNEL
			| (mmu_kernel_ssize == MMU_SEGSIZE_1T ? SLB_VSID_B_1T : 0);
		break;
	case KERNEL_REGION_ID:
		pr_devel("slbfee_mm: 0x%llx -- KERNEL_REGION_ID\n", ea);
		psize = mmu_linear_psize;
		*vsid = (get_kernel_vsid(ea, mmu_kernel_ssize)
			<< SLB_VSID_SHIFT) | SLB_VSID_KERNEL
			| (mmu_kernel_ssize == MMU_SEGSIZE_1T ? SLB_VSID_B_1T : 0);
		break;
	default:
		/* Future: support kernel segments so that drivers can use the
		 * CoProcessors */
		pr_debug("invalid region access at %016llx\n", ea);
		return 1;
	}
	*vsid |= mmu_psize_defs[psize].sllp;

	return 0;
}

static struct capi_sste*
find_free_sste(struct capi_sste *primary_group, bool sec_hash,
	       struct capi_sste *secondary_group, unsigned int *lru)
{
	unsigned int i, entry;
	struct capi_sste *sste, *group = primary_group;

	for (i = 0; i < 2; i++) {
		for (entry = 0; entry < 8; entry++) {
			sste = group + entry;
			if (!(sste->esid_data & SLB_ESID_V))
				return sste;
		}
		if (!sec_hash)
			break;
		group = secondary_group;
	}
	/* Nothing free, select an entry to cast out */
	if (sec_hash && (*lru & 0x8))
		sste = secondary_group + (*lru & 0x7);
	else
		sste = primary_group + (*lru & 0x7);
	*lru = (*lru + 1) & 0xf;

	return sste;
}

/*
 * XXX: stab.c contains similar code, however after some investigation it is
 * apparent that there are quite a few differences between CAPI's Segment
 * Storage Table and power3's stab, so it is non-trivial to refactor that code
 * to be useful here - I leave that as an excercise for another day.
 *
 * mask here is the group index, we search primary and secondary here.
 *
 * XXX: check for existing segment? in a wrapper? for prefault?
 */
static int capi_load_segment(struct capi_context_t *ctx, u64 esid_data, u64 vsid_data)
{
	unsigned int mask = (ctx->sst_size >> 7)-1; /* SSTP0[SegTableSize] */
	bool sec_hash = 1;
	struct capi_sste *sste;
	unsigned int hash;

	if (cpu_has_feature(CPU_FTR_HVMODE))
		sec_hash = !!(capi_p1n_read(ctx->afu, CAPI_PSL_SR_An) & CAPI_PSL_SR_An_SC);
	/* else {
	 *	It's the inverse of the high bit of the second non-length byte
	 *	in the sixth optional vector passed in ibm_architecture_vec to
	 *	ibm,client-architecture-support, which is a 0, so sec_hash = 1;
	 *
	 *	What? You got a problem with my coding style?
	 * } */

	if (vsid_data & SLB_VSID_B_1T)
		hash = (esid_data >> SID_SHIFT_1T) & mask;
	else /* 256M */
		hash = (esid_data >> SID_SHIFT) & mask;

	sste = find_free_sste(ctx->sstp + (  hash         << 3), sec_hash,
			      ctx->sstp + ((~hash & mask) << 3), &ctx->sst_lru);

	pr_devel("CAPI Populating SST[%li]: %#llx %#llx\n",
			sste - ctx->sstp, vsid_data, esid_data);

	sste->vsid_data = cpu_to_be64(vsid_data);
	sste->esid_data = cpu_to_be64(esid_data);

	return 0;
}

static void capi_prefault_one(struct capi_context_t *ctx, u64 ea)
{
	u64 vsid_data, esid_data;
	int rc;
	struct task_struct *task;
	struct mm_struct *mm;

	task = get_pid_task(ctx->pid, PIDTYPE_PID);
	if (!task) {
		pr_devel("capi_prefault_one unable to get task %i\n", pid_nr(ctx->pid));
		return;
	}
	mm = get_task_mm(task);
	if (!mm) {
		pr_devel("capi_prefault_one unable to get mm %i\n", pid_nr(ctx->pid));
		put_task_struct(task);
		return;
	}

	rc = slbfee_mm(mm, ea, &esid_data, &vsid_data);
	mmput(mm);
	put_task_struct(task);
	if (rc)
		return;

	capi_load_segment(ctx, esid_data, vsid_data);
}

static u64 next_segment(u64 ea, u64 vsid_data)
{
	if (vsid_data & SLB_VSID_B_1T)
		ea |= (1ULL << 40) - 1;
	else
		ea |= (1ULL << 28) - 1;

	return ea++;
}

static void capi_prefault_vma(struct capi_context_t *ctx)
{
	u64 ea, vsid_data, esid_data, last_esid_data = 0;
	struct vm_area_struct *vma;
	int rc;
	struct task_struct *task;
	struct mm_struct *mm;
	task = get_pid_task(ctx->pid, PIDTYPE_PID);
	if (!task) {
		pr_devel("capi_prefault_vma unable to get task %i\n", pid_nr(ctx->pid));
		return;
	}
	mm = get_task_mm(task);
	if (!mm) {
		pr_devel("capi_prefault_vm unable to get mm %i\n", pid_nr(ctx->pid));
		goto out1;
	}

	down_read(&mm->mmap_sem);	/* TODO: interruptable? */

	for (vma = mm->mmap; vma; vma = vma->vm_next) {
		for (ea = vma->vm_start; ea < vma->vm_end;
				ea = next_segment(ea, vsid_data)) {
			rc = slbfee_mm(mm, ea, &esid_data, &vsid_data);
			if (rc)
				continue;

			if (last_esid_data == esid_data)
				continue;

			capi_load_segment(ctx, esid_data, vsid_data);
			last_esid_data = esid_data;
		}
	}

	up_read(&mm->mmap_sem);

	mmput(mm);
out1:
	put_task_struct(task);
}

enum pref{
	CAPI_PREFAULT_NONE,
	CAPI_PREFAULT_WED,
	CAPI_PREFAULT_MAPPED,
};
static int prefault_how = CAPI_PREFAULT_NONE;
module_param(prefault_how, int, 0644);
MODULE_PARM_DESC(prefault_how, "How much to prefault on afu start: "
    "0 = none 1 = wed 2 = all currently mapped"
    /* "all wed segments cached (grub afu), all possible ea current slice" */);

void capi_prefault(struct capi_context_t *ctx, u64 wed)
{
	switch(prefault_how) {
	case CAPI_PREFAULT_WED:
		capi_prefault_one(ctx, wed);
		break;
	case CAPI_PREFAULT_MAPPED:
		capi_prefault_vma(ctx);
		break;
	}
}

int capi_handle_segment_miss(struct capi_context_t *ctx, u64 ea)
{
	int rc;
	unsigned long flags;
	u64 vsid_data = 0, esid_data = 0;
	struct task_struct *task;
	struct mm_struct *mm;
	task = get_pid_task(ctx->pid, PIDTYPE_PID);
	if (!task) {
		pr_devel("capi_handle_segment_miss unable to get task %i\n", pid_nr(ctx->pid));
		return IRQ_HANDLED;
	}
	mm = get_task_mm(task);
	if (!mm) {
		pr_devel("capi_handle_segment_miss unable to get mm %i\n", pid_nr(ctx->pid));
		goto out1;
	}

	rc = slbfee_mm(mm, ea, &esid_data, &vsid_data);

	pr_devel("CAPI interrupt: Segment fault pe: %i ea: %#llx\n", ctx->ph, ea);

	if (rc) {
		capi_ops->ack_irq(ctx, CAPI_PSL_TFC_An_AE, 0);

		spin_lock_irqsave(&ctx->lock, flags);
		ctx->pending_fault = true;
		ctx->fault_addr = ea;
		spin_unlock_irqrestore(&ctx->lock, flags);

		wake_up_all(&ctx->wq);
	} else {
		capi_load_segment(ctx, esid_data, vsid_data);

		mb(); /* Not sure if I need this */
		capi_ops->ack_irq(ctx, CAPI_PSL_TFC_An_R, 0);

		/* TODO: possibly hash_preload ea */
	}

	mmput(mm);
out1:
	put_task_struct(task);

	return IRQ_HANDLED;
}
