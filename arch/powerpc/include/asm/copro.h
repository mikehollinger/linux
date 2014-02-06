#ifndef _COPRO_H
#define _COPRO_H

int copro_handle_mm_fault(struct mm_struct *mm, unsigned long ea,
			  unsigned long dsisr, unsigned *flt);

#endif
