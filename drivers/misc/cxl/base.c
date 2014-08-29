/*
 * Copyright 2014 IBM Corp.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#include <linux/module.h>
#include <linux/rcupdate.h>
#include <asm/errno.h>
#include "cxl.h"

static struct cxl_calls *cxl_calls;

/* protected by rcu */
static struct cxl_calls *cxl_calls;

#ifdef CONFIG_CXL_MODULE

static inline struct cxl_calls *cxl_calls_get(void)
{
	struct cxl_calls *calls = NULL;

	rcu_read_lock();
	calls = rcu_dereference(cxl_calls);
	if (calls && !try_module_get(calls->owner))
		calls = NULL;
	rcu_read_unlock();

	return calls;
}

static inline void cxl_calls_put(struct cxl_calls *calls)
{
	BUG_ON(calls != cxl_calls);

	/* we don't need to rcu this, as we hold a reference to the module */
	module_put(cxl_calls->owner);
}

#else /* !defined CONFIG_CXL_MODULE */

static inline struct cxl_calls *cxl_calls_get(void)
{
	return cxl_calls;
}

static inline void cxl_calls_put(struct cxl_calls *calls) { }

#endif /* CONFIG_CXL_MODULE */

void cxl_slbia(struct mm_struct *mm)
{
	struct cxl_calls *calls;

	calls = cxl_calls_get();
	if (!calls)
		return;

	calls->cxl_slbia(mm);
}
EXPORT_SYMBOL(cxl_slbia);
