// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2016-2021, The Linux Foundation. All rights reserved.
 * Copyright (C) 2021 XiaoMi, Inc.
 */
#include <trace/events/sched.h>
#include "sched_hook.h"
#include "walt_refer.h"
#include "trace.h"

#define ASYMCAP_BOOST(cpu)	(sysctl_sched_asymcap_boost && !is_min_capacity_cpu(cpu))

extern int num_sched_clusters;

static inline unsigned long walt_lb_cpu_util(int cpu)
{
	struct rq *rq;

	return rq->walt_stats.cumulative_runnable_avg_scaled;
}

static void walt_detach_task(struct task_struct *p, struct rq *src_rq,
			     struct rq *dst_rq)
{
	deactivate_task(src_rq, p, 0);
	double_lock_balance(src_rq, dst_rq);
	if (!(src_rq->clock_update_flags & RQCF_UPDATED))
		update_rq_clock(src_rq);
	set_task_cpu(p, dst_rq->cpu);
	double_unlock_balance(src_rq, dst_rq);
}

static void walt_attach_task(struct task_struct *p, struct rq *rq)
{
	activate_task(rq, p, 0);
	check_preempt_curr(rq, p, 0);
}

#define WALT_ROTATION_THRESHOLD_NS	16000000
void walt_lb_check_for_rotation(struct rq *src_rq)
{
	u64 wc, wait, max_wait = 0, run, max_run = 0;
	int deserved_cpu = nr_cpu_ids, dst_cpu = nr_cpu_ids;
	int i, src_cpu = cpu_of(src_rq);
	struct rq *dst_rq;
	struct walt_rotate_work *wr = NULL;
	struct task_struct *p;

	if (!is_min_capacity_cpu(src_cpu))
		return;

	wc = ktime_get_ns();

	for_each_possible_cpu(i) {
		struct rq *rq = cpu_rq(i);

		if (!is_min_capacity_cpu(i))
			break;

		if (is_reserved(i))
			continue;

		if (!rq->misfit_task_load || !walt_fair_task(rq->curr))
			continue;

		p = rq->curr;
		wait = wc - p->last_enqueued_ts;
		if (wait > max_wait) {
			max_wait = wait;
			deserved_cpu = i;
		}
	}

	if (deserved_cpu != src_cpu)
		return;

	for_each_possible_cpu(i) {
		struct rq *rq = cpu_rq(i);

		if (is_min_capacity_cpu(i))
			continue;

		if (is_reserved(i))
			continue;

		if (!walt_fair_task(rq->curr))
			continue;

		if (rq->nr_running > 1)
			continue;

		p = rq->curr;
		run = wc - p->last_enqueued_ts;

		if (run < WALT_ROTATION_THRESHOLD_NS)
			continue;

		if (run > max_run) {
			max_run = run;
			dst_cpu = i;
		}
	}

	if (dst_cpu == nr_cpu_ids)
		return;

	dst_rq = cpu_rq(dst_cpu);

	double_rq_lock(src_rq, dst_rq);
        if (walt_fair_task(dst_rq->curr) &&
               !src_rq->active_balance && !dst_rq->active_balance &&
		cpumask_test_cpu(dst_cpu, src_rq->curr->cpus_ptr) &&
		cpumask_test_cpu(src_cpu, dst_rq->curr->cpus_ptr)) {
		get_task_struct(src_rq->curr);
		get_task_struct(dst_rq->curr);

		mark_reserved(src_cpu);
		mark_reserved(dst_cpu);
		wr = &per_cpu(walt_rotate_works, src_cpu);

		wr->src_task = src_rq->curr;
		wr->dst_task = dst_rq->curr;

		wr->src_cpu = src_cpu;
		wr->dst_cpu = dst_cpu;

		
                dst_rq->active_balance = 1;
                src_rq->active_balance = 1;
	}
	double_rq_unlock(src_rq, dst_rq);

	if (wr)
		queue_work_on(src_cpu, system_highpri_wq, &wr->w);
}

static int stop_walt_lb_active_migration(void *data)
{
	struct rq *busiest_rq = data;
	int busiest_cpu = cpu_of(busiest_rq);
	int target_cpu = busiest_rq->push_cpu;
	struct rq *target_rq = cpu_rq(target_cpu);
	struct task_struct *push_task;
	int push_task_detached = 0;

	raw_spin_lock_irq(&busiest_rq->lock);
	push_task = busiest_rq->push_task;

	/* sanity checks before initiating the pull */
	if (!cpu_active(busiest_cpu) || !cpu_active(target_cpu) || !push_task)
		goto out_unlock;

	if (unlikely(busiest_cpu != raw_smp_processor_id() ||
		     !busiest_rq->active_balance))
		goto out_unlock;

	if (busiest_rq->nr_running <= 1)
		goto out_unlock;

	BUG_ON(busiest_rq == target_rq);

	if (task_on_rq_queued(push_task) &&
			push_task->state == TASK_RUNNING &&
			task_cpu(push_task) == busiest_cpu &&
			cpu_active(target_cpu) &&
			cpumask_test_cpu(target_cpu, push_task->cpus_ptr)) {
		walt_detach_task(push_task, busiest_rq, target_rq);
		push_task_detached = 1;
	}

out_unlock: /* called with busiest_rq lock */
	busiest_rq->active_balance = 0;
	target_cpu = busiest_rq->push_cpu;
	clear_reserved(target_cpu);
	busiest_rq->push_task = NULL;
	raw_spin_unlock(&busiest_rq->lock);

	if (push_task_detached) {
		raw_spin_lock(&target_rq->lock);
		walt_attach_task(push_task, target_rq);
		raw_spin_unlock(&target_rq->lock);
	}

	if (push_task)
		put_task_struct(push_task);

	local_irq_enable();

	return 0;
}

static DEFINE_RAW_SPINLOCK(walt_lb_migration_lock);
void walt_lb_tick(struct rq *rq)
{
	int prev_cpu = rq->cpu, new_cpu, ret;
	struct task_struct *p = rq->curr;
	unsigned long flags;

        raw_spin_lock(&rq->lock);
 	if (idle_cpu(prev_cpu) && is_reserved(prev_cpu) && !rq->active_balance)
                clear_reserved(prev_cpu);
        raw_spin_unlock(&rq->lock);

	if (!walt_fair_task(p))
		return;

	walt_cfs_tick(rq);

	if (!rq->misfit_task_load)
		return;

	if (p->state != TASK_RUNNING || p->nr_cpus_allowed == 1)
		return;

	raw_spin_lock_irqsave(&walt_lb_migration_lock, flags);

	if (walt_rotation_enabled) {
		walt_lb_check_for_rotation(rq);
		goto out_unlock;
	}

	rcu_read_lock();
	new_cpu = walt_find_energy_efficient_cpu(p, prev_cpu, 0, 1);
	rcu_read_unlock();

	/* prevent active task migration to busy or same/lower capacity CPU */
	if (new_cpu < 0 || !idle_cpu(new_cpu) ||
		capacity_orig_of(new_cpu) <= capacity_orig_of(prev_cpu))
		goto out_unlock;

	raw_spin_lock(&rq->lock);
	if (rq->active_balance) {
		raw_spin_unlock(&rq->lock);
		goto out_unlock;
	}
	rq->active_balance = 1;
	rq->push_cpu = new_cpu;
	get_task_struct(p);
	rq->push_task = p;
	raw_spin_unlock(&rq->lock);

	mark_reserved(new_cpu);
	raw_spin_unlock_irqrestore(&walt_lb_migration_lock, flags);

	trace_walt_active_load_balance(p, prev_cpu, new_cpu);
	ret = stop_one_cpu_nowait(prev_cpu,
			stop_walt_lb_active_migration, rq,
			&rq->active_balance_work);
	if (!ret)
		clear_reserved(new_cpu);
	else
		wake_up_if_idle(new_cpu);

	return;

out_unlock:
	raw_spin_unlock_irqrestore(&walt_lb_migration_lock, flags);
}


