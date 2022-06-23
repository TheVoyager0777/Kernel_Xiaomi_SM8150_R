/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2019-2021, The Linux Foundation. All rights reserved.
 */

#define CREATE_TRACE_POINTS
#include <trace/hooks/sched.h>

#include "walt_refer.h"

void do_trace_sched_yield(void)
{
     struct rq *rq;

     trace_android_rvh_do_sched_yield(rq);
}
EXPORT_SYMBOL(do_trace_sched_yield);

void do_trace_scheduler_tick(void)
{
     struct rq *rq;

     trace_android_vh_scheduler_tick(rq);
}
EXPORT_SYMBOL(do_trace_scheduler_tick);

