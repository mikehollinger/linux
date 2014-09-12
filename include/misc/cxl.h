/*
 * Copyright 2014 IBM Corp.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#ifndef _MISC_ASM_CXL_H
#define _MISC_ASM_CXL_H

#define CXL_IRQ_RANGES 4

struct cxl_irq_ranges {
	irq_hw_number_t offset[CXL_IRQ_RANGES];
	irq_hw_number_t range[CXL_IRQ_RANGES];
};

#ifdef CONFIG_CXL_BASE

void cxl_slbia(struct mm_struct *mm);
void cxl_get(void);
void cxl_put(void);
bool cxl_in_use(void);

#else /* CONFIG_CXL_BASE */

#define cxl_slbia(...) do { } while (0)
#define cxl_in_use(...) false

#endif /* CONFIG_CXL_BASE */

#endif
