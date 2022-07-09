/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM sched
#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH trace/hooks
#if !defined(_TRACE_HOOK_SCHED_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_HOOK_SCHED_H
#include <linux/tracepoint.h>
/*
 * Following tracepoints are not exported in tracefs and provide a
 * mechanism for vendor modules to hook and extend functionality
 */
struct task_struct;
DECLARE_TRACE(android_rvh_select_task_rq_fair,
	TP_PROTO(struct task_struct *p, int prev_cpu, int sd_flag, int wake_flags, int *new_cpu),
	TP_ARGS(p, prev_cpu, sd_flag, wake_flags, new_cpu));


DECLARE_TRACE(android_rvh_select_task_rq_rt,
	TP_PROTO(struct task_struct *p, int prev_cpu, int sd_flag, int wake_flags, int *new_cpu),
	TP_ARGS(p, prev_cpu, sd_flag, wake_flags, new_cpu));

DECLARE_TRACE(android_rvh_select_fallback_rq,
	TP_PROTO(int cpu, struct task_struct *p, int *new_cpu),
	TP_ARGS(cpu, p, new_cpu));

struct rq;
DECLARE_TRACE(android_vh_scheduler_tick,
	TP_PROTO(struct rq *rq),
	TP_ARGS(rq));

DECLARE_TRACE(android_rvh_enqueue_task,
	TP_PROTO(struct rq *rq, struct task_struct *p),
	TP_ARGS(rq, p));

DECLARE_TRACE(android_rvh_dequeue_task,
	TP_PROTO(struct rq *rq, struct task_struct *p),
	TP_ARGS(rq, p));

DECLARE_TRACE(android_rvh_can_migrate_task,
	TP_PROTO(struct task_struct *p, int dst_cpu, int *can_migrate),
	TP_ARGS(p, dst_cpu, can_migrate));

DECLARE_TRACE(android_rvh_find_lowest_rq,
	TP_PROTO(struct task_struct *p, struct cpumask *local_cpu_mask,
			int ret, int *lowest_cpu),
	TP_ARGS(p, local_cpu_mask, ret, lowest_cpu));

DECLARE_TRACE(android_rvh_prepare_prio_fork,
	TP_PROTO(struct task_struct *p),
	TP_ARGS(p));

DECLARE_TRACE(android_rvh_finish_prio_fork,
	TP_PROTO(struct task_struct *p),
	TP_ARGS(p));

DECLARE_TRACE(android_rvh_rtmutex_prepare_setprio,
	TP_PROTO(struct task_struct *p, struct task_struct *pi_task),
	TP_ARGS(p, pi_task));

DECLARE_TRACE(android_rvh_set_user_nice,
	TP_PROTO(struct task_struct *p, long *nice),
	TP_ARGS(p, nice));

DECLARE_TRACE(android_rvh_setscheduler,
	TP_PROTO(struct task_struct *p),
	TP_ARGS(p));

struct sched_group;
DECLARE_TRACE(android_rvh_find_busiest_group,
	TP_PROTO(struct sched_group *busiest, struct rq *dst_rq, int *out_balance),
		TP_ARGS(busiest, dst_rq, out_balance));

struct rq_flags;
DECLARE_TRACE(android_rvh_sched_newidle_balance,
	TP_PROTO(struct rq *this_rq, struct rq_flags *rf,
		 int *pulled_task, int *done),
	TP_ARGS(this_rq, rf, pulled_task, done));

DECLARE_TRACE(android_rvh_sched_nohz_balancer_kick,
	TP_PROTO(struct rq *rq, unsigned int *flags, int *done),
	TP_ARGS(rq, flags, done));

DECLARE_TRACE(android_rvh_find_busiest_queue,
	TP_PROTO(int dst_cpu, struct sched_group *group,
		 struct cpumask *env_cpus, struct rq **busiest,
		 int *done),
	TP_ARGS(dst_cpu, group, env_cpus, busiest, done));

DECLARE_TRACE(android_rvh_migrate_queued_task,
	TP_PROTO(struct rq *rq, struct rq_flags *rf,
		 struct task_struct *p, int new_cpu,
		 int *detached),
	TP_ARGS(rq, rf, p, new_cpu, detached));

DECLARE_TRACE(android_rvh_resume_cpus,
	TP_PROTO(struct cpumask *cpus, int *err),
	TP_ARGS(cpus, err));

DECLARE_TRACE(android_rvh_find_energy_efficient_cpu,
	TP_PROTO(struct task_struct *p, int prev_cpu, int sync, int *new_cpu),
	TP_ARGS(p, prev_cpu, sync, new_cpu));

struct compute_energy_output;
DECLARE_TRACE(energey_compute_assist,
        TP_PROTO(struct task_struct *p, int dst_cpu,
		  unsigned int energy),
	TP_ARGS(p, dst_cpu, energy));

struct sched_attr;
DECLARE_TRACE(android_vh_set_sugov_sched_attr,
	TP_PROTO(struct sched_attr *attr),
	TP_ARGS(attr));
DECLARE_TRACE(android_rvh_set_iowait,
	TP_PROTO(struct task_struct *p, int *should_iowait_boost),
	TP_ARGS(p, should_iowait_boost));

struct sugov_policy;
DECLARE_TRACE(android_rvh_set_sugov_update,
	TP_PROTO(struct sugov_policy *sg_policy, unsigned int next_freq, bool *should_update),
	TP_ARGS(sg_policy, next_freq, should_update));
DECLARE_TRACE(android_rvh_schedule,
	TP_PROTO(struct task_struct *prev, struct task_struct *next, struct rq *rq),
	TP_ARGS(prev, next, rq));

struct cgroup_subsys_state;
DECLARE_TRACE(android_rvh_cpu_cgroup_online,
	TP_PROTO(struct cgroup_subsys_state *css),
	TP_ARGS(css));

DECLARE_TRACE(android_rvh_update_cpu_capacity,
	TP_PROTO(int cpu, unsigned long *capacity),
	TP_ARGS(cpu, capacity));

DECLARE_TRACE(android_rvh_update_misfit_status,
	TP_PROTO(struct task_struct *p, struct rq *rq, bool *need_update),
	TP_ARGS(p, rq, need_update));


DECLARE_TRACE(android_vh_update_topology_flags_workfn,
	TP_PROTO(void *unused),
	TP_ARGS(unused));

struct sched_entity;
struct cfs_rq;
DECLARE_TRACE(android_rvh_check_preempt_wakeup,
	TP_PROTO(struct rq *rq, struct task_struct *p, bool *preempt, bool *nopreempt,
			int wake_flags, struct sched_entity *se, struct sched_entity *pse,
			int next_buddy_marked, unsigned int granularity),
	TP_ARGS(rq, p, preempt, nopreempt, wake_flags, se, pse, next_buddy_marked,
			granularity));

DECLARE_TRACE(android_rvh_check_preempt_tick,
	TP_PROTO(struct task_struct *p, unsigned long *ideal_runtime, bool *skip_preempt,
			unsigned long delta_exec, struct cfs_rq *cfs_rq, struct sched_entity *curr,
			unsigned int granularity),
	TP_ARGS(p, ideal_runtime, skip_preempt, delta_exec, cfs_rq, curr, granularity));
DECLARE_TRACE(android_rvh_replace_next_task_fair,
	TP_PROTO(struct rq *rq, struct task_struct **p, struct sched_entity **se, bool *repick,
			bool simple, struct task_struct *prev),
	TP_ARGS(rq, p, se, repick, simple, prev));
	
DECLARE_TRACE(android_rvh_after_enqueue_task,
	TP_PROTO(struct rq *rq, struct task_struct *p),
	TP_ARGS(rq, p));

DECLARE_TRACE(android_rvh_after_dequeue_task,
	TP_PROTO(struct rq *rq, struct task_struct *p),
	TP_ARGS(rq, p));

DECLARE_TRACE(android_rvh_do_sched_yield,
	TP_PROTO(struct rq *rq),
	TP_ARGS(rq));

DECLARE_TRACE(android_rvh_find_best_target,
	TP_PROTO(struct task_struct *p, int cpu, int *ignore),
	TP_ARGS(p, cpu, ignore));
struct cpumask;
DECLARE_TRACE(android_rvh_cpupri_find_fitness,
	TP_PROTO(struct task_struct *p, struct cpumask *lowest_mask),
	TP_ARGS(p, lowest_mask));

#endif /* _TRACE_HOOK_SCHED_H */
/* This part must be outside protection */
#include <trace/define_trace.h>
