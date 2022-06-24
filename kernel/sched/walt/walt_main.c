// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2016-2021, The Linux Foundation. All rights reserved.
 */
#include <linux/syscore_ops.h>
#include <trace/hooks/sched.h>
#include <linux/ktime.h>
#include "walt_refer.h"
#include "trace.h"

#define EARLY_DETECTION_DURATION 9500000

static bool walt_clusters_parsed;
cpumask_t __read_mostly **cpu_array;
__read_mostly int num_sched_clusters;

static inline bool is_ed_enabled(void)
{
	return (walt_rotation_enabled || (boost_policy != SCHED_BOOST_NONE));
}

static inline bool is_ed_task(struct task_struct *p, u64 wallclock)
{
	return (wallclock - p->last_wake_ts >= EARLY_DETECTION_DURATION);
}

static bool is_ed_task_present(struct rq *rq, u64 wallclock, struct task_struct *deq_task)
{
	struct task_struct *p;
	int loop_max = 10;

	rq->ed_task = NULL;

	if (!is_ed_enabled() || !rq->cfs.h_nr_running)
		return false;

	list_for_each_entry(p, &rq->cfs_tasks, se.group_node) {
		if (!loop_max)
			break;

		if (p == deq_task)
			continue;

		if (is_ed_task(p, wallclock)) {
			rq->ed_task = p;
			return true;
		}

		loop_max--;
	}

	return false;
}

static inline void __sched_fork_init(struct task_struct *p)
{
	p->wake_up_idle	= false;
	p->low_latency	= false;
	p->iowaited		= false;
}

static void walt_init_new_task_load(struct task_struct *p)
{
	p->prev_on_rq = 0;
	p->prev_on_rq_cpu = -1;

	INIT_LIST_HEAD(&p->mvp_list);
	p->sum_exec_snapshot = 0;
	p->total_exec = 0;
	p->mvp_prio = WALT_NOT_MVP;
	__sched_fork_init(p);
}

static void walt_init_existing_task_load(struct task_struct *p)
{
	walt_init_new_task_load(p);
	cpumask_copy(&p->cpus_requested, &p->cpus_mask);
}

static void sched_init_rq(struct rq *rq)
{
	rq->num_mvp_tasks = 0;
	INIT_LIST_HEAD(&rq->mvp_tasks);
}

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
	init_cpu_array();
	build_cpu_array();
	find_cache_siblings();

	walt_create_util_to_cost();
	walt_clusters_parsed = true;
}

bool walt_disabled = true;

static void android_rvh_enqueue_task(void *unused, struct rq *rq, struct task_struct *p)
{
	u64 wallclock = sched_ktime_clock();
	bool double_enqueue = false;

	if (unlikely(walt_disabled))
		return;

	lockdep_assert_held(&rq->lock);

	if (p->cpu != cpu_of(rq))
		WALT_BUG(p, "enqueuing on rq %d when task->cpu is %d\n",
				cpu_of(rq), p->cpu);

	/* catch double enqueue */
	if (p->prev_on_rq == 1) {
		WALT_BUG(p, "double enqueue detected: task_cpu=%d new_cpu=%d\n",
			 task_cpu(p), cpu_of(rq));
		double_enqueue = true;
	}

	p->prev_on_rq = 1;
	p->prev_on_rq_cpu = cpu_of(rq);

	p->last_enqueued_ts = wallclock;
	sched_update_nr_prod(rq->cpu, 1);

	if (walt_fair_task(p)) {
		p->misfit = !task_fits_max(p, rq->cpu);
		if (!double_enqueue)
			inc_rq_walt_stats(rq, p);
		walt_cfs_enqueue_task(rq, p);
	}

	if (!double_enqueue)
		walt_inc_cumulative_runnable_avg(rq, p);
	trace_sched_enq_deq_task(p, 1, cpumask_bits(&p->cpus_mask)[0], is_mvp(p));
}

static void android_rvh_dequeue_task(void *unused, struct rq *rq, struct task_struct *p)
{
	bool double_dequeue = false;

	if (unlikely(walt_disabled))
		return;

	lockdep_assert_held(&rq->lock);

	/*
	 * a task can be enqueued before walt is started, and dequeued after.
	 * therefore the check to ensure that prev_on_rq_cpu is needed to prevent
	 * an invalid failure.
	 */
	if (p->prev_on_rq_cpu >= 0 && p->prev_on_rq_cpu != cpu_of(rq))
		WALT_BUG(p, "dequeue cpu %d not same as enqueue %d\n",
			 cpu_of(rq), p->prev_on_rq_cpu);

	/* no longer on a cpu */
	p->prev_on_rq_cpu = -1;

	/* catch double deq */
	if (p->prev_on_rq == 2) {
		WALT_BUG(p, "double dequeue detected: task_cpu=%d new_cpu=%d\n",
			 task_cpu(p), cpu_of(rq));
		double_dequeue = true;
	}

	p->prev_on_rq = 2;
	if (p == rq->ed_task)
		is_ed_task_present(rq, sched_ktime_clock(), p);

	sched_update_nr_prod(rq->cpu, -1);

	if (walt_fair_task(p)) {
		if (!double_dequeue)
			dec_rq_walt_stats(rq, p);
		walt_cfs_dequeue_task(rq, p);
	}

	if (!double_dequeue)
		walt_dec_cumulative_runnable_avg(rq, p);

	trace_sched_enq_deq_task(p, 0, cpumask_bits(&p->cpus_mask)[0], is_mvp(p));
}

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
		sched_update_nr_prod(rq->cpu, 0);
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

	walt_lb_tick(rq);
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
        register_trace_android_rvh_update_misfit_status(android_rvh_update_misfit_status, NULL);
	register_trace_android_rvh_after_enqueue_task(android_rvh_enqueue_task, NULL);
	register_trace_android_rvh_after_dequeue_task(android_rvh_dequeue_task, NULL);
        register_trace_android_vh_scheduler_tick(android_vh_scheduler_tick, NULL);
	register_trace_android_rvh_schedule(android_rvh_schedule, NULL);
}

static int walt_init_stop_handler(void *data)
{
	int cpu;
	struct task_struct *g, *p;

	do_each_thread(g, p) {
		walt_init_existing_task_load(p);
	} while_each_thread(g, p);

	for_each_possible_cpu(cpu) {
		struct rq *rq = cpu_rq(cpu);

		/* Create task members for idle thread */
		init_new_task_load(rq->idle);

		sched_init_rq(rq);
	}

	walt_update_cluster_topology();
	walt_disabled = false;

	return 0;
}

static void walt_init(struct work_struct *work)
{

        register_walt_hooks();

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

