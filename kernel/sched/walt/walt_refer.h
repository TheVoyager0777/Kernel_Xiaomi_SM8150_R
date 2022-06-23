/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2019-2021, The Linux Foundation. All rights reserved.
 */

#include "../../../kernel/sched/sched.h"
#include <linux/cpuidle.h>
#include <linux/energy_model.h>
#include <linux/android_vendor.h>
#include "../../../kernel/sched/walt.h"

extern int num_sched_clusters;
extern cpumask_t __read_mostly **cpu_array;
extern int cpu_l2_sibling[NR_CPUS];

extern __read_mostly unsigned int walt_scale_demand_divisor;

extern bool walt_disabled;

#define WALT_MVP_SLICE		3000000U
#define WALT_MVP_LIMIT		(4 * WALT_MVP_SLICE)

#define WALT_RTG_MVP		0
#define WALT_BINDER_MVP		1
#define WALT_TASK_BOOST_MVP	2

#define WALT_NOT_MVP		-1

#define is_mvp(p) (p->mvp_prio != WALT_NOT_MVP)

#define walt_scale_demand(d) ((d)/walt_scale_demand_divisor)

#define WALT_LOW_LATENCY_PROCFS		BIT(0)
#define WALT_LOW_LATENCY_BINDER		BIT(1)
#define WALT_LOW_LATENCY_PIPELINE	BIT(2)

#define wts_to_ts(ts) ({ \
		void *__mptr = (void *)(ts); \
		((struct task_struct *)(__mptr - \
			offsetof(struct task_struct, android_vendor_data1))); })

extern bool walt_disabled;

/* structures for modules */
enum task_boost_type {
	TASK_BOOST_NONE = 0,
	TASK_BOOST_ON_MID,
	TASK_BOOST_ON_MAX,
	TASK_BOOST_STRICT_MAX,
	TASK_BOOST_END,
};

struct compute_energy_output {
	unsigned long	sum_util[MAX_CLUSTERS];
	unsigned long	max_util[MAX_CLUSTERS];
	u16		cost[MAX_CLUSTERS];
	unsigned int	cluster_first_cpu[MAX_CLUSTERS];
};

struct walt_rotate_work {
	struct work_struct w;
	struct task_struct *src_task;
	struct task_struct *dst_task;
	int src_cpu;
	int dst_cpu;
};

struct find_best_target_env {
	int placement_boost;
	int need_idle;
	int fastpath;
	int start_cpu;
	int skip_cpu;
	int	order_index;
	int	end_index;
	bool is_rtg;
	bool boosted;
	bool strict_max;
	u64	prs[8];
};

enum fastpaths {
	NONE = 0,
	SYNC_WAKEUP,
	PREV_CPU_FASTPATH,
	MANY_WAKEUP,
};

/* headers of sysctl table */
extern unsigned int sysctl_panic_on_walt_bug;
extern unsigned int sysctl_sched_suppress_region2;
extern unsigned int sysctl_sched_skip_sp_newly_idle_lb;
extern unsigned int sysctl_sched_asymcap_boost;
extern unsigned int sysctl_walt_low_latency_task_threshold; /* disabled by default */
extern __read_mostly unsigned int sysctl_sched_force_lb_enable;
extern unsigned int sysctl_walt_rtg_cfs_boost_prio;
extern struct ctl_table walt_table[];

static DEFINE_PER_CPU(struct walt_rotate_work, walt_rotate_works);

#define WALT_PANIC(condition)				\
({							\
	if (unlikely(!!(condition)) && !in_sched_bug) {	\
		in_sched_bug = 1;			\
		walt_dump();				\
		BUG_ON(condition);			\
	}						\
})

#define WALT_PANIC_SENTINEL 0x4544DEAD

/*
 * crash if walt bugs are fatal, otherwise return immediately.
 * output format and arguments to console
 */
#define WALT_BUG(p, format, args...)					\
({									\
	if (unlikely(sysctl_panic_on_walt_bug == WALT_PANIC_SENTINEL)) {\
		printk_deferred("WALT-BUG " format, args);		\
		if (p)							\
			walt_task_dump(p);				\
		WALT_PANIC(1);						\
	}								\
})

/* headers of modules */
void do_trace_sched_yield(void);
void do_trace_scheduler_tick(void);
void walt_lb_tick(struct rq *rq);
void walt_cfs_init(void);
void walt_cfs_tick(struct rq *rq);
void walt_create_util_to_cost(void);
void walt_lb_check_for_rotation(struct rq *src_rq);
void walt_cfs_enqueue_task(struct rq *rq, struct task_struct *p);
void walt_cfs_dequeue_task(struct rq *rq, struct task_struct *p);
void walt_get_indicies(struct task_struct *p, int *order_index,
		int *end_index, int per_task_boost, bool is_boosted,
		bool *energy_eval_needed);
void walt_find_best_target(struct sched_domain *sd,
					cpumask_t *candidates,
					struct task_struct *p,
					struct find_best_target_env *fbt_env);
int walt_find_energy_efficient_cpu(struct task_struct *p, int prev_cpu,
				     int sync, int sibling_count_hint);

/* functions references fore modules */
extern inline int walt_same_cluster(int src_cpu, int dst_cpu)
{
	return cpu_rq(src_cpu)->cluster == cpu_rq(dst_cpu)->cluster;
}

static inline bool walt_binder_low_latency_task(struct task_struct *p)
{
	return (p->low_latency & WALT_LOW_LATENCY_BINDER) &&
		(task_util(p) < sysctl_walt_low_latency_task_threshold);
}

static inline bool walt_procfs_low_latency_task(struct task_struct *p)
{
	return (p->low_latency & WALT_LOW_LATENCY_PROCFS) &&
		(task_util(p) < sysctl_walt_low_latency_task_threshold);
}

static inline bool walt_pipeline_low_latency_task(struct task_struct *p)
{
	return p->low_latency & WALT_LOW_LATENCY_PIPELINE;
}

static inline unsigned int walt_get_idle_exit_latency(struct rq *rq)
{
	struct cpuidle_state *idle = idle_get_state(rq);

	if (idle)
		return idle->exit_latency;

	return 0; /* CPU is not idle */
}

static inline unsigned long _task_util_est(struct task_struct *p)
{
	struct util_est ue = READ_ONCE(p->se.avg.util_est);

	return max(ue.ewma, ue.enqueued);
}

static inline unsigned long task_util_est(struct task_struct *p)
{
#ifdef CONFIG_SCHED_WALT
	return p->ravg.demand_scaled;
#endif
	return max(task_util(p), _task_util_est(p));
}

#ifdef CONFIG_UCLAMP_TASK
static inline unsigned long uclamp_task_util(struct task_struct *p)
{
	return clamp(task_util_est(p),
		     uclamp_eff_value(p, UCLAMP_MIN),
		     uclamp_eff_value(p, UCLAMP_MAX));
}
#else
static inline unsigned long uclamp_task_util(struct task_struct *p)
{
	return task_util_est(p);
}
#endif

static inline int per_task_boost(struct task_struct *p)
{
	if (p->boost_period) {
		if (sched_clock() > p->boost_expires) {
			p->boost_period = 0;
			p->boost_expires = 0;
			p->boost = 0;
		}
	}
	return p->boost;
}

static inline unsigned int walt_nr_rtg_high_prio(int cpu)
{
	return cpu_rq(cpu)->walt_stats.nr_rtg_high_prio_tasks;
}

static inline bool task_rtg_high_prio(struct task_struct *p)
{
	return task_in_related_thread_group(p) &&
		(p->prio <= sysctl_walt_rtg_cfs_boost_prio);
}

/* return true if cpu should be chosen over best_energy_cpu */
static inline bool select_cpu_same_energy(int cpu, int best_cpu, int prev_cpu)
{
	if (best_cpu == prev_cpu)
		return false;

	if (idle_cpu(best_cpu) && idle_get_state_idx(cpu_rq(best_cpu)) <= 0)
		return false; /* best_cpu is idle wfi or shallower */

	if (idle_cpu(cpu) && idle_get_state_idx(cpu_rq(cpu)) <= 0)
		return true; /* new cpu is idle wfi or shallower */

	/*
	 * If we are this far this must be a tie between a busy and deep idle,
	 * pick the busy.
	 */
	return idle_cpu(best_cpu);
}

/*
 * The policy of a RT boosted task (via PI mutex) still indicates it is
 * a fair task, so use prio check as well. The prio check alone is not
 * sufficient since idle task also has 120 priority.
 */
static inline bool walt_fair_task(struct task_struct *p)
{
	return p->prio >= MAX_RT_PRIO && !is_idle_task(p);
}

inline bool task_fits_capacity(struct task_struct *p,
					long capacity,
					int cpu);
inline bool task_fits_max(struct task_struct *p, int cpu);
inline bool task_demand_fits(struct task_struct *p, int cpu);
inline bool prefer_spread_on_idle(int cpu);

static inline int wake_to_idle(struct task_struct *p)
{
	return (current->flags & PF_WAKE_UP_IDLE) ||
			(p->flags & PF_WAKE_UP_IDLE);
}

static inline unsigned int capacity_spare_of(int cpu)
{
	return capacity_orig_of(cpu) - cpu_util(cpu);
}

static inline bool
bias_to_this_cpu(struct task_struct *p, int cpu, int start_cpu)
{
	bool base_test = cpumask_test_cpu(cpu, &p->cpus_allowed) &&
			cpu_active(cpu);
	bool start_cap_test = (capacity_orig_of(cpu) >=
					capacity_orig_of(start_cpu));

	return base_test && start_cap_test;
}

#define SCHED_HIGH_IRQ_TIMEOUT 3
static inline u64 sched_irqload(int cpu)
{
	struct rq *rq = cpu_rq(cpu);
	s64 delta;

	delta = get_jiffies_64() - rq->irqload_ts;
	/*
	 * Current context can be preempted by irq and rq->irqload_ts can be
	 * updated by irq context so that delta can be negative.
	 * But this is okay and we can safely return as this means there
	 * was recent irq occurrence.
	 */

	if (delta < SCHED_HIGH_IRQ_TIMEOUT)
		return rq->avg_irqload;
	else
		return 0;
}

#ifdef CONFIG_SCHED_WALT
static inline bool get_rtg_status(struct task_struct *p)
{
	struct related_thread_group *grp;
	bool ret = false;

	rcu_read_lock();

	grp = task_related_thread_group(p);
	if (grp)
		ret = grp->skip_min;

	rcu_read_unlock();

	return ret;
}

static inline bool is_many_wakeup(int sibling_count_hint)
{
	return sibling_count_hint >= sysctl_sched_many_wakeup_threshold;
}

static inline int sched_cpu_high_irqload(int cpu)
{
	return sched_irqload(cpu) >= sysctl_sched_cpu_high_irqload;
}
#else
static inline bool get_rtg_status(struct task_struct *p)
{
	return false;
}

static inline bool is_many_wakeup(int sibling_count_hint)
{
	return false;
}

static inline int sched_cpu_high_irqload(int cpu) { return 0; }
#endif

static inline bool is_mvp_task(struct rq *rq, struct task_struct *p)
{
	lockdep_assert_held(&rq->lock);
	return !list_empty(&p->mvp_list) && p->mvp_list.next;
}

