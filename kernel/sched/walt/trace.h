/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2019-2021, The Linux Foundation. All rights reserved.
 */

#undef TRACE_SYSTEM
#define TRACE_SYSTEM schedwalt

#include <linux/tracepoint.h>

struct compute_energy_output;

DECLARE_TRACE(energey_compute_assist,

	TP_PROTO(struct task_struct *p, int dst_cpu,
		  unsigned int energy),

	TP_ARGS(, dst_cpu, energy)
);

#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH ../../kernel/sched/walt
#define TRACE_INCLUDE_FILE trace

#include <trace/define_trace.h>
