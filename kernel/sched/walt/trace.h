/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2019-2021, The Linux Foundation. All rights reserved.
 */

#undef TRACE_SYSTEM
#define TRACE_SYSTEM schedwalt

#if !defined(_TRACE_WALT_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_WALT_H

#include <linux/tracepoint.h>

struct rq;
struct compute_energy_output;

TRACE_EVENT(sched_compute_energy,

	TP_PROTO(struct task_struct *p, int eval_cpu,
		unsigned long eval_energy,
		unsigned long prev_energy,
		unsigned long best_energy,
		unsigned long best_energy_cpu,
		struct compute_energy_output *o),

	TP_ARGS(p, eval_cpu, eval_energy, prev_energy, best_energy,
		best_energy_cpu, o),

	TP_STRUCT__entry(
		__field(int,		pid)
		__array(char,		comm, TASK_COMM_LEN)
		__field(unsigned long,	util)
		__field(int,		prev_cpu)
		__field(unsigned long,	prev_energy)
		__field(int,		eval_cpu)
		__field(unsigned long,	eval_energy)
		__field(int,		best_energy_cpu)
		__field(unsigned long,	best_energy)
		__field(unsigned int,	cluster_first_cpu0)
		__field(unsigned int,	cluster_first_cpu1)
		__field(unsigned int,	cluster_first_cpu2)
		__field(unsigned long,	s0)
		__field(unsigned long,	s1)
		__field(unsigned long,	s2)
		__field(unsigned long,	m0)
		__field(unsigned long,	m1)
		__field(unsigned long,	m2)
		__field(u16,	c0)
		__field(u16,	c1)
		__field(u16,	c2)
	),

	TP_fast_assign(
		__entry->pid			= p->pid;
		memcpy(__entry->comm, p->comm, TASK_COMM_LEN);
		__entry->util			= task_util(p);
		__entry->prev_cpu		= task_cpu(p);
		__entry->prev_energy		= prev_energy;
		__entry->eval_cpu		= eval_cpu;
		__entry->eval_energy		= eval_energy;
		__entry->best_energy_cpu	= best_energy_cpu;
		__entry->best_energy		= best_energy;
		__entry->cluster_first_cpu0	= o->cluster_first_cpu[0];
		__entry->cluster_first_cpu1	= o->cluster_first_cpu[1];
		__entry->cluster_first_cpu2	= o->cluster_first_cpu[2];
		__entry->s0	= o->sum_util[0];
		__entry->s1	= o->sum_util[1];
		__entry->s2	= o->sum_util[2];
		__entry->m0	= o->max_util[0];
		__entry->m1	= o->max_util[1];
		__entry->m2	= o->max_util[2];
		__entry->c0	= o->cost[0];
		__entry->c1	= o->cost[1];
		__entry->c2	= o->cost[2];
	),

	TP_printk("pid=%d comm=%s util=%lu prev_cpu=%d prev_energy=%lu eval_cpu=%d eval_energy=%lu best_energy_cpu=%d best_energy=%lu, fcpu s m c = %u %u %u %u, %u %u %u %u, %u %u %u %u",
		__entry->pid, __entry->comm, __entry->util, __entry->prev_cpu,
		__entry->prev_energy, __entry->eval_cpu, __entry->eval_energy,
		__entry->best_energy_cpu, __entry->best_energy,
		__entry->cluster_first_cpu0, __entry->s0, __entry->m0, __entry->c0,
		__entry->cluster_first_cpu1, __entry->s1, __entry->m1, __entry->c1,
		__entry->cluster_first_cpu2, __entry->s2, __entry->m2, __entry->c2)
);

TRACE_EVENT(walt_nohz_balance_kick,

	TP_PROTO(struct rq *rq),

	TP_ARGS(rq),

	TP_STRUCT__entry(
		__field(int, cpu)
		__field(unsigned int, nr_running)
		__field(unsigned int, nr_cfs_running)
	),

	TP_fast_assign(
		__entry->cpu		= rq->cpu;
		__entry->nr_running	= rq->nr_running;
		__entry->nr_cfs_running	= rq->cfs.h_nr_running;
	),

	TP_printk("cpu=%d nr_running=%u nr_cfs_running=%u",
			__entry->cpu, __entry->nr_running,
			__entry->nr_cfs_running)
);

TRACE_EVENT(walt_newidle_balance,

	TP_PROTO(int this_cpu, int busy_cpu, int pulled, bool help_min_cap, bool enough_idle),

	TP_ARGS(this_cpu, busy_cpu, pulled, help_min_cap, enough_idle),

	TP_STRUCT__entry(
		__field(int, cpu)
		__field(int, busy_cpu)
		__field(int, pulled)
		__field(unsigned int, nr_running)
		__field(unsigned int, rt_nr_running)
		__field(int, nr_iowait)
		__field(bool, help_min_cap)
		__field(u64, avg_idle)
		__field(bool, enough_idle)
		__field(int, overload)
	),

	TP_fast_assign(
		__entry->cpu		= this_cpu;
		__entry->busy_cpu	= busy_cpu;
		__entry->pulled		= pulled;
		__entry->nr_running	= cpu_rq(this_cpu)->nr_running;
		__entry->rt_nr_running	= cpu_rq(this_cpu)->rt.rt_nr_running;
		__entry->nr_iowait	= atomic_read(&(cpu_rq(this_cpu)->nr_iowait));
		__entry->help_min_cap	= help_min_cap;
		__entry->avg_idle	= cpu_rq(this_cpu)->avg_idle;
		__entry->enough_idle	= enough_idle;
		__entry->overload	= cpu_rq(this_cpu)->rd->overload;
	),

	TP_printk("cpu=%d busy_cpu=%d pulled=%d nr_running=%u rt_nr_running=%u nr_iowait=%d help_min_cap=%d avg_idle=%llu enough_idle=%d overload=%d",
			__entry->cpu, __entry->busy_cpu, __entry->pulled,
			__entry->nr_running, __entry->rt_nr_running,
			__entry->nr_iowait, __entry->help_min_cap,
			__entry->avg_idle, __entry->enough_idle,
			__entry->overload)
);

TRACE_EVENT(walt_lb_cpu_util,

	TP_PROTO(int cpu, struct rq *rq),

	TP_ARGS(cpu, rq),

	TP_STRUCT__entry(
		__field(int, cpu)
		__field(unsigned int, nr_running)
		__field(unsigned int, cfs_nr_running)
		__field(unsigned int, nr_big)
		__field(unsigned int, nr_rtg_high_prio_tasks)
		__field(unsigned int, cpu_util)
		__field(unsigned int, capacity_orig)
	),

	TP_fast_assign(
		__entry->cpu			= cpu;
		__entry->nr_running		= cpu_rq(cpu)->nr_running;
		__entry->cfs_nr_running		= cpu_rq(cpu)->cfs.h_nr_running;
		__entry->nr_big			= rq->walt_stats.nr_big_tasks;
		__entry->nr_rtg_high_prio_tasks	= walt_nr_rtg_high_prio(cpu);
		__entry->cpu_util		= cpu_util(cpu);
		__entry->capacity_orig		= capacity_orig_of(cpu);
	),

	TP_printk("cpu=%d nr_running=%u cfs_nr_running=%u nr_big=%u nr_rtg_hp=%u cpu_util=%u capacity_orig=%u",
		__entry->cpu, __entry->nr_running, __entry->cfs_nr_running,
		__entry->nr_big, __entry->nr_rtg_high_prio_tasks,
		__entry->cpu_util, __entry->capacity_orig)
);

TRACE_EVENT(walt_active_load_balance,

	TP_PROTO(struct task_struct *p, int prev_cpu, int new_cpu),

	TP_ARGS(p, prev_cpu, new_cpu),

	TP_STRUCT__entry(
		__field(pid_t, pid)
		__field(bool, misfit)
		__field(int, prev_cpu)
		__field(int, new_cpu)
	),

	TP_fast_assign(
		__entry->pid		= p->pid;
		__entry->misfit		= p->misfit;
		__entry->prev_cpu	= prev_cpu;
		__entry->new_cpu	= new_cpu;
	),

	TP_printk("pid=%d misfit=%d prev_cpu=%d new_cpu=%d\n",
			__entry->pid, __entry->misfit, __entry->prev_cpu,
			__entry->new_cpu)
);

TRACE_EVENT(walt_find_busiest_queue,

	TP_PROTO(int dst_cpu, int busiest_cpu, unsigned long src_mask),

	TP_ARGS(dst_cpu, busiest_cpu, src_mask),

	TP_STRUCT__entry(
		__field(int, dst_cpu)
		__field(int, busiest_cpu)
		__field(unsigned long, src_mask)
	),

	TP_fast_assign(
		__entry->dst_cpu	= dst_cpu;
		__entry->busiest_cpu	= busiest_cpu;
		__entry->src_mask	= src_mask;
	),

	TP_printk("dst_cpu=%d busiest_cpu=%d src_mask=%lx\n",
			__entry->dst_cpu, __entry->busiest_cpu,
			__entry->src_mask)
);

TRACE_EVENT(sched_task_util,

	TP_PROTO(struct task_struct *p, unsigned long candidates,
		int best_energy_cpu, bool sync, int need_idle, int fastpath,
		bool placement_boost, u64 start_t,
		bool stune_boosted, bool is_rtg, bool rtg_skip_min,
		int start_cpu),

	TP_ARGS(p, candidates, best_energy_cpu, sync, need_idle, fastpath,
		placement_boost, start_t, stune_boosted, is_rtg, rtg_skip_min,
		start_cpu),

	TP_STRUCT__entry(
		__field(int,		pid)
		__array(char,		comm, TASK_COMM_LEN)
		__field(unsigned long,	util)
		__field(unsigned long,	candidates)
		__field(int,		prev_cpu)
		__field(int,		best_energy_cpu)
		__field(bool,		sync)
		__field(int,		need_idle)
		__field(int,		fastpath)
		__field(int,		placement_boost)
		__field(int,		rtg_cpu)
		__field(u64,		latency)
		__field(bool,		stune_boosted)
		__field(bool,		is_rtg)
		__field(bool,		rtg_skip_min)
		__field(int,		start_cpu)
		__field(u32,		unfilter)
		__field(unsigned long,  cpus_allowed)
		__field(bool,		low_latency)
	),

	TP_fast_assign(
		__entry->pid                    = p->pid;
		memcpy(__entry->comm, p->comm, TASK_COMM_LEN);
		__entry->util                   = task_util(p);
		__entry->prev_cpu               = task_cpu(p);
		__entry->candidates		= candidates;
		__entry->best_energy_cpu        = best_energy_cpu;
		__entry->sync                   = sync;
		__entry->need_idle              = need_idle;
		__entry->fastpath               = fastpath;
		__entry->placement_boost        = placement_boost;
		__entry->latency                = (sched_clock() - start_t);
		__entry->stune_boosted          = stune_boosted;
		__entry->is_rtg                 = is_rtg;
		__entry->rtg_skip_min		= rtg_skip_min;
		__entry->start_cpu		= start_cpu;
#ifdef CONFIG_SCHED_WALT
		__entry->unfilter		= p->unfilter;
		__entry->low_latency		= walt_low_latency_task(p);
#else
		__entry->unfilter		= 0;
		__entry->low_latency		= 0;
#endif
		__entry->cpus_allowed           = cpumask_bits(&p->cpus_allowed)[0];
	),

	TP_printk("pid=%d comm=%s util=%lu prev_cpu=%d candidates=%#lx best_energy_cpu=%d sync=%d need_idle=%d fastpath=%d placement_boost=%d latency=%llu stune_boosted=%d is_rtg=%d rtg_skip_min=%d start_cpu=%d unfilter=%u affine=%#lx low_latency=%d",
		__entry->pid, __entry->comm, __entry->util, __entry->prev_cpu,
		__entry->candidates, __entry->best_energy_cpu, __entry->sync,
		__entry->need_idle, __entry->fastpath, __entry->placement_boost,
		__entry->latency, __entry->stune_boosted,
		__entry->is_rtg, __entry->rtg_skip_min, __entry->start_cpu,
		__entry->unfilter, __entry->cpus_allowed, __entry->low_latency)
);

/*
 * Tracepoint for find_best_target
 */
TRACE_EVENT(sched_find_best_target,

	TP_PROTO(struct task_struct *tsk, bool prefer_idle,
		 unsigned long min_util, int start_cpu,
		 int best_idle, int best_active, int most_spare_cap,
		 int target, int backup),

	TP_ARGS(tsk, prefer_idle, min_util, start_cpu,
		best_idle, best_active, most_spare_cap,
		target, backup),

	TP_STRUCT__entry(
		__array(char,		comm, TASK_COMM_LEN)
		__field(pid_t,		pid)
		__field(unsigned long,	min_util)
		__field(bool,		prefer_idle)
		__field(int,		start_cpu)
		__field(int,		best_idle)
		__field(int,		best_active)
		__field(int,		most_spare_cap)
		__field(int,		target)
		__field(int,		backup)
		),

	TP_fast_assign(
		memcpy(__entry->comm, tsk->comm, TASK_COMM_LEN);
		__entry->pid            = tsk->pid;
		__entry->min_util       = min_util;
		__entry->prefer_idle    = prefer_idle;
		__entry->start_cpu      = start_cpu;
		__entry->best_idle      = best_idle;
		__entry->best_active    = best_active;
		__entry->most_spare_cap = most_spare_cap;
		__entry->target         = target;
		__entry->backup         = backup;
		),

	TP_printk("pid=%d comm=%s prefer_idle=%d start_cpu=%d best_idle=%d best_active=%d most_spare_cap=%d target=%d backup=%d",
		  __entry->pid, __entry->comm, __entry->prefer_idle,
		  __entry->start_cpu,
		  __entry->best_idle, __entry->best_active,
		  __entry->most_spare_cap,
		  __entry->target, __entry->backup)
);

#endif /* _TRACE_WALT_H */

#include "sched_hook.h"

#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH ../../kernel/sched/walt
#define TRACE_INCLUDE_FILE trace

#include <trace/define_trace.h>
