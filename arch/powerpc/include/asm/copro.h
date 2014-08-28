/*
 * Copyright 2014 IBM Corp.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#ifndef _COPRO_H
#define _COPRO_H

int copro_handle_mm_fault(struct mm_struct *mm, unsigned long ea,
			  unsigned long dsisr, unsigned *flt);

#endif
