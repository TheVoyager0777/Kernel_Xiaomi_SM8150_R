// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2016-2021, The Linux Foundation. All rights reserved.
 */
#include <linux/syscore_ops.h>
#include <linux/ktime.h>
#include "walt_refer.h"
#include "trace.h"
#include "../../../kernel/sched/walt.h"


static ktime_t ktime_last;
static bool walt_ktime_suspended;
static bool walt_clusters_parsed;
cpumask_t __read_mostly **cpu_array;
__read_mostly int num_sched_clusters;

u64 walt_ktime_get_ns(void)
{
	if (unlikely(walt_ktime_suspended))
		return ktime_to_ns(ktime_last);
	return ktime_get_ns();
}

static void walt_resume(void)
{
	walt_ktime_suspended = false;
}

static int walt_suspend(void)
{
	ktime_last = ktime_get();
	walt_ktime_suspended = true;
	return 0;
}

static struct syscore_ops walt_syscore_ops = {
	.resume		= walt_resume,
	.suspend	= walt_suspend
};

static void init_cpu_array(void)
{
	int i;

	cpu_array = kcalloc(num_sched_clusters, sizeof(cpumask_t *),
			GFP_ATOMIC | __GFP_NOFAIL);
	if (!cpu_array)
		SCHED_BUG_ON(1);

	for (i = 0; i < num_sched_clusters; i++) {
		cpu_array[i] = kcalloc(num_sched_clusters, sizeof(cpumask_t),
			GFP_ATOMIC | __GFP_NOFAIL);
		if (!cpu_array[i])
			WALT_PANIC(1);
	}
}

static void build_cpu_array(void)
{
	int i;

	if (!cpu_array)
		SCHED_BUG_ON(1);
	/* Construct cpu_array row by row */
	for (i = 0; i < num_sched_clusters; i++) {
		int j, k = 1;

		/* Fill out first column with appropriate cpu arrays */
		cpumask_copy(&cpu_array[i][0], &sched_cluster[i]->cpus);
		/*
		 * k starts from column 1 because 0 is filled
		 * Fill clusters for the rest of the row,
		 * above i in ascending order
		 */
		for (j = i + 1; j < num_sched_clusters; j++) {
			cpumask_copy(&cpu_array[i][k],
					&sched_cluster[j]->cpus);
			k++;
		}

		/*
		 * k starts from where we left off above.
		 * Fill clusters below i in descending order.
		 */
		for (j = i - 1; j >= 0; j--) {
			cpumask_copy(&cpu_array[i][k],
					&sched_cluster[j]->cpus);
			k++;
		}
	}
}

int cpu_l2_sibling[NR_CPUS] = {[0 ... NR_CPUS-1] = -1};
static void find_cache_siblings(void)
{
	int cpu, cpu2;
	struct device_node *cpu_dev, *cpu_dev2, *cpu_l2_cache_node, *cpu_l2_cache_node2;

	for_each_possible_cpu(cpu) {
		cpu_dev = of_get_cpu_node(cpu, NULL);
		if (!cpu_dev)
			continue;

		cpu_l2_cache_node = of_parse_phandle(cpu_dev, "next-level-cache", 0);
		if (!cpu_l2_cache_node)
			continue;

		for_each_possible_cpu(cpu2) {
			if (cpu == cpu2)
				continue;

			cpu_dev2 = of_get_cpu_node(cpu2, NULL);
			if (!cpu_dev2)
				continue;

			cpu_l2_cache_node2 = of_parse_phandle(cpu_dev2, "next-level-cache", 0);
			if (!cpu_l2_cache_node2)
				continue;

			if (cpu_l2_cache_node == cpu_l2_cache_node2) {
				cpu_l2_sibling[cpu] = cpu2;
				break;
			}
		}
	}
}

static void walt_update_cluster_topology(void)
{
	walt_cfs_init();
	init_cpu_array();
	build_cpu_array();
	find_cache_siblings();

	walt_create_util_to_cost();
	walt_clusters_parsed = true;
}

bool walt_disabled = true;

#if 0
static void walt_update_tg_pointer(struct cgroup_subsys_state *css)
{
	if (!strcmp(css->cgroup->kn->name, "top-app"))
		walt_init_topapp_tg(css_tg(css));
	else if (!strcmp(css->cgroup->kn->name, "foreground"))
		walt_init_foreground_tg(css_tg(css));
	else
		walt_init_tg(css_tg(css));
}

static void android_rvh_cpu_cgroup_online(void *unused, struct cgroup_subsys_state *css)
{
	if (unlikely(walt_disabled))
		return;

	walt_update_tg_pointer(css);
}
#endif

static void android_rvh_update_misfit_status(void *unused, struct task_struct *p,
		struct rq *rq, bool *need_update)
{
	bool old_misfit, misfit;
	int change;

	if (unlikely(walt_disabled))
		return;
	*need_update = false;

	if (!p) {
		rq->misfit_task_load = 0;
		return;
	}

	old_misfit = p->misfit;

	if (task_fits_max(p, rq->cpu))
		rq->misfit_task_load = 0;
	else
		rq->misfit_task_load = task_util(p);

	misfit = rq->misfit_task_load;

	change = misfit - old_misfit;
	if (change) {
		sched_update_nr_prod(rq->cpu, 0, true);
		p->misfit = misfit;
		rq->walt_stats.nr_big_tasks += change;
		BUG_ON(rq->walt_stats.nr_big_tasks < 0);
	}
}

static void android_vh_scheduler_tick(void *unused, struct rq *rq)
{
	struct related_thread_group *grp;
	u32 old_load;

	if (unlikely(walt_disabled))
		return;

	old_load = task_load(rq->curr);
	rcu_read_lock();
	grp = task_related_thread_group(rq->curr);
	if (update_preferred_cluster(grp, rq->curr, old_load, true))
		set_preferred_cluster(grp);
	rcu_read_unlock();
}

static void android_rvh_schedule(void *unused, struct task_struct *prev,
		struct task_struct *next, struct rq *rq)
{
	u64 wallclock = ktime_get_ns();

	if (unlikely(walt_disabled))
		return;
	if (likely(prev != next)) {
		if (!prev->on_rq)
			prev->last_sleep_ts = wallclock;
		update_task_ravg(prev, rq, PUT_PREV_TASK, wallclock, 0);
		update_task_ravg(next, rq, PICK_NEXT_TASK, wallclock, 0);
		if (is_idle_task(next) && rq->walt_stats.cumulative_runnable_avg_scaled != 0)
			WALT_BUG(next, "next=idle cra non zero=%d\n",
				 rq->walt_stats.cumulative_runnable_avg_scaled);
	} else {
		update_task_ravg(prev, rq, TASK_UPDATE, wallclock, 0);
	}
}

static void register_walt_hooks(void)
{
/*
	register_trace_android_rvh_cpu_cgroup_online(android_rvh_cpu_cgroup_online, NULL);
*/
        register_trace_android_rvh_update_misfit_status(android_rvh_update_misfit_status, NULL);
        register_trace_android_vh_scheduler_tick(android_vh_scheduler_tick, NULL);
	register_trace_android_rvh_schedule(android_rvh_schedule, NULL);
}

static int walt_init_stop_handler(void *data)
{

	walt_update_cluster_topology();
	walt_disabled = false;

	return 0;
}

static void walt_init(struct work_struct *work)
{

        register_walt_hooks();

	register_syscore_ops(&walt_syscore_ops);

	walt_cfs_init();

	stop_machine(walt_init_stop_handler, NULL, NULL);

}

static DECLARE_WORK(walt_init_work, walt_init);
static void android_vh_update_topology_flags_workfn(void *unused, void *unused2)
{
	schedule_work(&walt_init_work);
}

static int walt_module_init(void)
{

	register_trace_android_vh_update_topology_flags_workfn(
			android_vh_update_topology_flags_workfn, NULL);

	if (topology_update_done)
		schedule_work(&walt_init_work);

	return 0;
}

core_initcall(walt_module_init);

