/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Android scheduler hooks and modifications
 *
 * Put all of the android-specific scheduler hooks and changes
 * in this .h file to make merges and modifications easier.  It's also
 * simpler to notice what is, and is not, an upstream change this way over time.
 */

#include "sched.h"

#ifdef CONFIG_UCLAMP_TASK
static unsigned int sysctl_sched_min_task_util_for_uclamp = 51;

static inline bool uclamp_boosted(struct task_struct *p)
{
	return ((uclamp_eff_value(p, UCLAMP_MIN) > 0) &&
			(task_util(p) > sysctl_sched_min_task_util_for_uclamp));
}

static inline bool uclamp_latency_sensitive(struct task_struct *p)
{
	struct cgroup_subsys_state *css = task_css(p, cpu_cgrp_id);
	struct task_group *tg;

	if (!css)
		return false;
	tg = container_of(css, struct task_group, css);

	return tg->latency_sensitive;
}

/*
 * Return whether the task on the given cpu is currently non-preemptible
 * while handling a potentially long softint, or if the task is likely
 * to block preemptions soon because it is a ksoftirq thread that is
 * handling slow softints.
 */
static inline bool
task_may_not_preempt(struct task_struct *task, int cpu)
{
	__u32 softirqs = per_cpu(active_softirqs, cpu) |
			 __IRQ_STAT(cpu, __softirq_pending);
	struct task_struct *cpu_ksoftirqd = per_cpu(ksoftirqd, cpu);

	return ((softirqs & LONG_SOFTIRQ_MASK) &&
		(task == cpu_ksoftirqd ||
		 task_thread_info(task)->preempt_count & SOFTIRQ_MASK));
}

#else
static inline bool uclamp_boosted(struct task_struct *p)
{
	return false;
}

static inline bool uclamp_latency_sensitive(struct task_struct *p)
{
	return false;
}

static inline bool task_may_not_preempt(struct task_struct *task, int cpu)
{
	return false;
}
#endif
