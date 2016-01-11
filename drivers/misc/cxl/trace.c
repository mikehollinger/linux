/*
 * Copyright 2015 IBM Corp.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#ifndef __CHECKER__
#define CREATE_TRACE_POINTS
#include "trace.h"

EXPORT_SYMBOL_GPL(__tracepoint_cxl_llcmd);
EXPORT_SYMBOL_GPL(__tracepoint_cxl_detach);
EXPORT_SYMBOL_GPL(__tracepoint_cxl_afu_ctrl);
EXPORT_SYMBOL_GPL(__tracepoint_cxl_psl_ctrl_done);
EXPORT_SYMBOL_GPL(__tracepoint_cxl_psl_ctrl);
EXPORT_SYMBOL_GPL(__tracepoint_cxl_afu_ctrl_done);
EXPORT_SYMBOL_GPL(__tracepoint_cxl_llcmd_done);
EXPORT_SYMBOL_GPL(__tracepoint_cxl_psl_irq_ack);
#endif
