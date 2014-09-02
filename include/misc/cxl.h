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

#ifdef CONFIG_CXL_BASE

void cxl_slbia(struct mm_struct *mm);

#else /* CONFIG_CXL_BASE */

#define cxl_slbia(...) do { } while (0)

#endif /* CONFIG_CXL_BASE */

#endif
