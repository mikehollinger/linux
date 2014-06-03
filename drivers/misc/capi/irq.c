#if 1
#define DEBUG
#else
#undef DEBUG
#endif

#include <linux/interrupt.h>
#include <linux/workqueue.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/pid.h>
#include <linux/of.h>
#include <asm/cputable.h>

#include "capi.h"

/* XXX: Send SIGSTOP to the task that opened the AFU to prevent it doing
 * anything further so we can obtain a trace */
static void freeze_afu_owner(struct capi_afu_t *afu)
{
	struct task_struct *task = get_pid_task(afu->pid, PIDTYPE_PID);
	pr_crit("SENDING SIGSTOP TO %s (%i)\n", task->comm, task->pid);
	put_task_struct(task);

	kill_pid(afu->pid, SIGSTOP, 0);
}

/* XXX: This is implementation specific */
static irqreturn_t handle_psl_slice_error(struct capi_afu_t *afu, u64 dsisr, u64 fir_recov_slice)
{
	u64 fir1, fir2, fir_slice;

	pr_devel("CAPI interrupt: PSL Error (implementation specific, recoverable: %#.16llx)\n", fir_recov_slice);

	if (fir_recov_slice)
		return capi_ops->ack_irq(afu, 0, fir_recov_slice);

	if (cpu_has_feature(CPU_FTR_HVMODE)) { /* TODO: Refactor */
		pr_crit("STOPPING CAPI TRACE\n");
		capi_stop_trace(afu->adapter);
		freeze_afu_owner(afu);

		fir1 = capi_p1_read(afu->adapter, CAPI_PSL_FIR1);
		fir2 = capi_p1_read(afu->adapter, CAPI_PSL_FIR2);
		fir_slice = capi_p1n_read(afu, CAPI_PSL_FIR_SLICE_An);

		pr_warn("PSL_FIR1: 0x%.16llx\nPSL_FIR2: 0x%.16llx\nPSL_FIR_SLICE_An: 0x%.16llx\nPSL_FIR_RECOV_SLICE_An: 0x%.16llx\n",
				fir1, fir2, fir_slice, fir_recov_slice);
		return IRQ_NONE;
	}

	pr_warn("PSL_FIR_RECOV_SLICE_An: 0x%.16llx\n", fir_recov_slice);
	return IRQ_NONE;
}

irqreturn_t capi_irq_err(int irq, void *data)
{
	struct capi_t *adapter = (struct capi_t *)data;
	u64 fir1, fir2, fir_slice, fir_recov_slice, err_ivte;
	int slice;

	WARN(1, "CAPI ERROR interrupt %i\n", irq);

	err_ivte = capi_p1_read(adapter, CAPI_PSL_ErrIVTE);
	pr_warn("PSL_ErrIVTE: 0x%.16llx\n", err_ivte);
	err_ivte = capi_p1n_read(adapter, CAPI_PSL_SERR_An);
	pr_warn("PSL_SERR: 0x%.16llx\n", err_ivte);

	pr_crit("STOPPING CAPI TRACE\n");
	capi_stop_trace(adapter);

	fir1 = capi_p1_read(adapter, CAPI_PSL_FIR1);
	fir2 = capi_p1_read(adapter, CAPI_PSL_FIR2);

	pr_warn("PSL_FIR1: 0x%.16llx\nPSL_FIR2: 0x%.16llx\n", fir1, fir2);

	for (slice = 0; slice < adapter->slices; slice++) {
		if (adapter->slice[slice].pid)
			freeze_afu_owner(&adapter->slice[slice]);
		fir_slice = capi_p1n_read(&adapter->slice[slice], CAPI_PSL_FIR_SLICE_An);
		fir_recov_slice = capi_p1n_read(&adapter->slice[slice], CAPI_PSL_R_FIR_SLICE_An);
		pr_warn("PSL_FIR_SLICE_%in: 0x%.16llx\n", slice, fir_slice);
		pr_warn("PSL_FIR_RECOV_SLICE_%in: 0x%.16llx\n", slice, fir_recov_slice);
	}

	return IRQ_NONE;
}

static irqreturn_t capi_irq(int irq, void *data)
{
	struct capi_afu_t *afu = (struct capi_afu_t *)data;
	struct capi_irq_info irq_info;
	u64 dsisr, dar;
	int result;

	if ((result = capi_ops->get_irq(afu, &irq_info))) {
		WARN(1, "Unable to get CAPI IRQ Info: %i\n", result);
		return IRQ_NONE;
	}

	dsisr = irq_info.dsisr;
	dar = irq_info.dar;

	pr_devel("CAPI interrupt %i for afu %p. DSISR: %#llx DAR: %#llx\n", irq, afu, dsisr, dar);

	if (dsisr & CAPI_PSL_DSISR_An_DS)
		return capi_handle_segment_miss(afu, dar);
	if (dsisr & CAPI_PSL_DSISR_An_DM) {
		/* XXX: If we aren't in_atomic() we might be able to handle the
		 * fault immediately, can we at least try to hash_preload? */
		pr_devel("Scheduling page fault handling for later (in_atomic() = %i)...\n",
				in_atomic());

		INIT_WORK(&afu->work, capi_handle_page_fault);
		afu->dsisr = dsisr;
		afu->dar = dar;
		schedule_work(&afu->work);
		return IRQ_HANDLED;
	}

	if (dsisr & CAPI_PSL_DSISR_An_ST) {
		WARN(1, "CAPI interrupt: Segment Table PTE not found\n");
	}
	if (dsisr & CAPI_PSL_DSISR_An_UR)
		pr_devel("CAPI interrupt: AURP PTE not found\n");
	if (dsisr & CAPI_PSL_DSISR_An_PE)
		return handle_psl_slice_error(afu, dsisr, irq_info.fir_r_slice);
	if (dsisr & CAPI_PSL_DSISR_An_AE) {
		pr_devel("CAPI interrupt: AFU Error\n");

		spin_lock(&afu->lock);
		WARN(afu->pending_afu_err,
		     "FIXME: Potentially clobbering undelivered AFU interrupt\n");
		afu->afu_err = irq_info.afu_err;
		afu->pending_afu_err = 1;
		spin_unlock(&afu->lock);

		wake_up_all(&afu->wq);
		capi_ops->ack_irq(afu, CAPI_PSL_TFC_An_A, 0);
	}
	if (dsisr & CAPI_PSL_DSISR_An_OC)
		pr_devel("CAPI interrupt: OS Context Warning\n");

	if ((dsisr & CAPI_PSL_DSISR_An_DS) == 0) {
		if (dsisr & CAPI_PSL_DSISR_An_M )
			pr_devel("CAPI interrupt: PTE not found\n");
		if (dsisr & CAPI_PSL_DSISR_An_P )
			pr_devel("CAPI interrupt: Storage protection violation\n");
		if (dsisr & CAPI_PSL_DSISR_An_A )
			pr_devel("CAPI interrupt: AFU lock access to write through or cache inhibited storage\n");
		if (dsisr & CAPI_PSL_DSISR_An_S )
			pr_devel("CAPI interrupt: Access was afu_wr or afu_zero\n");
		if (dsisr & CAPI_PSL_DSISR_An_K )
			pr_devel("CAPI interrupt: Access not permitted by virtual page class key protection\n");
	}

	WARN(1, "Unhandled CAPI IRQ\n");

	return IRQ_NONE;
}

static irqreturn_t capi_irq_afu(int irq, void *data, int ivte)
{
	struct capi_afu_t *afu = (struct capi_afu_t *)data;

	pr_devel("Received IVTE %i for afu %p (interrupt %i)\n",
	       ivte, afu, irq);

	spin_lock(&afu->lock);
	afu->pending_irq_mask |= 1 << (ivte-1);
	spin_unlock(&afu->lock);

	wake_up_all(&afu->wq);

	return IRQ_HANDLED;
}

/* FIXME: This isn't very elegant and won't work for > 4 interrupts: */
static irqreturn_t capi_irq_afu_1(int irq, void *data)
{
	return capi_irq_afu(irq, data, 1);
}
static irqreturn_t capi_irq_afu_2(int irq, void *data)
{
	return capi_irq_afu(irq, data, 2);
}
static irqreturn_t capi_irq_afu_3(int irq, void *data)
{
	return capi_irq_afu(irq, data, 3);
}

static irq_handler_t capi_irq_handlers[] = {
	capi_irq, capi_irq_afu_1, capi_irq_afu_2, capi_irq_afu_3,
};

unsigned int
capi_map_irq(struct capi_t *adapter, irq_hw_number_t hwirq,
		irq_handler_t handler, void *cookie)
{
	unsigned int virq;
	int result;

	/* IRQ Domain? */
	virq = irq_create_mapping(NULL, hwirq);
	if (!virq) {
		pr_warning("capi_map_irq: irq_create_mapping failed\n");
		return 0;
	}

	if (adapter->driver->setup_irq)
		adapter->driver->setup_irq(adapter, hwirq, virq);

	pr_devel("hwirq %#lx mapped to virq %u\n", hwirq, virq);

	result = request_irq(virq, handler, 0, "capi", cookie);
	if (result) {
		pr_warning("capi_map_irq: request_irq failed: %i\n", result);
		return 0;
	}

	return virq;
}

void capi_unmap_irq(unsigned int virq, void *cookie)
{
	free_irq(virq, cookie);
	irq_dispose_mapping(virq);
}

void afu_register_irqs(struct capi_afu_t *afu, u32 start, u32 count)
{
	int idx, ivt_off;

	afu->irq_count = count;
	pr_devel("afu_get_dt_irq_ranges: %#x %#x", start, afu->irq_count);
	BUG_ON(afu->irq_count > CAPI_SLICE_IRQS);
	for (ivt_off = start, idx = 0; idx < afu->irq_count; ivt_off++, idx++) {
		afu->hwirq[idx] = ivt_off;
		pr_devel("capi_afu_hwirq[%i]: %#x\n", idx, ivt_off);
		afu->virq[idx] = capi_map_irq(afu->adapter, afu->hwirq[idx],
					      capi_irq_handlers[idx],
					      (void*)afu);
	}
}

void afu_enable_irqs(struct capi_afu_t *afu)
{
	int idx;

	pr_info("Enabling CAPI Interrupts\n");

	for (idx = 0; idx < afu->irq_count; idx++)
		enable_irq(afu->virq[idx]);
}

void afu_disable_irqs(struct capi_afu_t *afu)
{
	int idx;

	pr_info("Disabling CAPI Interrupts\n");

	for (idx = 0; idx < afu->irq_count; idx++)
		disable_irq(afu->virq[idx]);
}

void afu_release_irqs(struct capi_afu_t *afu)
{
	int idx;

	for (idx = 0; idx < CAPI_SLICE_IRQS; idx++) {
		if (afu->virq[idx])
			capi_unmap_irq(afu->virq[idx], (void*)afu);
	}
}
