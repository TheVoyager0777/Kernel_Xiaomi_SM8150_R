/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2019-2021, The Linux Foundation. All rights reserved.
 */

#include "../../../kernel/sched/sched.h"
#include <linux/energy_model.h>
#include <linux/android_vendor.h>

extern int num_sched_clusters;
extern cpumask_t __read_mostly **cpu_array;
extern int cpu_l2_sibling[NR_CPUS];

extern __read_mostly unsigned int walt_scale_demand_divisor;
extern u64 walt_ktime_get_ns(void);

#define walt_scale_demand(d) ((d)/walt_scale_demand_divisor)

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

/* headers of sysctl table */
extern unsigned int sysctl_panic_on_walt_bug;
extern unsigned int sysctl_sched_suppress_region2;
extern unsigned int sysctl_sched_skip_sp_newly_idle_lb;
extern unsigned int sysctl_sched_asymcap_boost;
extern unsigned int sysctl_walt_low_latency_task_threshold; /* disabled by default */
extern __read_mostly unsigned int sysctl_sched_force_lb_enable;
extern unsigned int sysctl_walt_rtg_cfs_boost_prio;
extern struct ctl_table walt_table[];

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

extern int walt_cfs_init(void);
extern void walt_create_util_to_cost(void);

/* functions references fore modules */
extern inline int walt_same_cluster(int src_cpu, int dst_cpu)
{
	return cpu_rq(src_cpu)->cluster == cpu_rq(dst_cpu)->cluster;
}

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

inline bool task_fits_capacity(struct task_struct *p,
					long capacity,
					int cpu);
inline bool task_fits_max(struct task_struct *p, int cpu);
inline bool task_demand_fits(struct task_struct *p, int cpu);
inline bool prefer_spread_on_idle(int cpu);
