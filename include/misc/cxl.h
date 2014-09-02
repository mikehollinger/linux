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

struct cxl_calls {
	void (*cxl_slbia)(struct mm_struct *mm);
	struct module *owner;
};

extern void cxl_slbia(struct mm_struct *mm);
extern int register_cxl_calls(struct cxl_calls *calls);
extern void unregister_cxl_calls(struct cxl_calls *calls);

#else /* CONFIG_CXL_BASE */

#define cxl_slbia(...) do { } while (0)

#endif /* CONFIG_CXL_BASE */

#endif
