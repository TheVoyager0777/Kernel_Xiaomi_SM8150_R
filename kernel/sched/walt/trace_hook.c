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

void do_trace_enqueue_task(void)
{
     struct task_struct *p;
     struct rq *rq;

     trace_android_rvh_after_enqueue_task(rq, p);
}
EXPORT_SYMBOL(do_trace_enqueue_task);

void do_trace_dequeue_task(void)
{
     struct task_struct *p;
     struct rq *rq;

     trace_android_rvh_after_dequeue_task(rq, p);
}
EXPORT_SYMBOL(do_trace_dequeue_task);

void do_trace_rvh_schedule(void)
{
    struct task_struct *prev, *next;
    struct rq *rq;

    trace_android_rvh_schedule(prev, next, rq);
}
