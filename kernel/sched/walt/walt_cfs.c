// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2016-2021, The Linux Foundation. All rights reserved.
 */
#include <trace/events/sched.h>
#include "walt_refer.h"
#include "trace.h"
#include "../../../kernel/sched/tune.h"

static void walt_create_util_to_cost_pd(struct em_perf_domain *pd)
{
	int util, cpu = cpumask_first(to_cpumask(pd->cpus));
	unsigned long fmax;
	unsigned long scale_cpu;
	struct rq *rq = cpu_rq(cpu);
	struct sched_cluster *cluster = rq->cluster;

	fmax = (u64)pd->table[pd->nr_perf_states - 1].frequency;
	scale_cpu = arch_scale_cpu_capacity(cpu);

	for (util = 0; util < 1024; util++) {
		int j;

		int f = (fmax * util) / scale_cpu;
		struct em_perf_state *ps = &pd->table[0];

		for (j = 0; j < pd->nr_perf_states; j++) {
			ps = &pd->table[j];
			if (ps->frequency >= f)
				break;
		}
		cluster->util_to_cost[util] = ps->cost;
	}
}

void walt_create_util_to_cost(void)
{
	struct perf_domain *pd;
	struct root_domain *rd = cpu_rq(smp_processor_id())->rd;

	rcu_read_lock();
	pd = rcu_dereference(rd->pd);
	for (; pd; pd = pd->next)
		walt_create_util_to_cost_pd(pd->em_pd);
	rcu_read_unlock();
}

/*
 * cpu_util_without: compute cpu utilization without any contributions from *p
 * @cpu: the CPU which utilization is requested
 * @p: the task which utilization should be discounted
 *
 * The utilization of a CPU is defined by the utilization of tasks currently
 * enqueued on that CPU as well as tasks which are currently sleeping after an
 * execution on that CPU.
 *
 * This method returns the utilization of the specified CPU by discounting the
 * utilization of the specified task, whenever the task is currently
 * contributing to the CPU utilization.
 */
static unsigned long cpu_util_without(int cpu, struct task_struct *p)
{
	unsigned int util;

	/*
	 * WALT does not decay idle tasks in the same manner
	 * as PELT, so it makes little sense to subtract task
	 * utilization from cpu utilization. Instead just use
	 * cpu_util for this case.
	 */
	if (likely(p->state == TASK_WAKING))
		return cpu_util(cpu);

	/* Task has no contribution or is new */
	if (cpu != task_cpu(p) || !READ_ONCE(p->se.avg.last_update_time))
		return cpu_util(cpu);

	util = max_t(long, cpu_util(cpu) - task_util(p), 0);

	/*
	 * Utilization (estimated) can exceed the CPU capacity, thus let's
	 * clamp to the maximum CPU capacity to ensure consistency with
	 * the cpu_util call.
	 */
	return min_t(unsigned long, util, capacity_orig_of(cpu));
}

static inline bool walt_task_skip_min_cpu(struct task_struct *p)
{
	return (sched_boost_type != CONSERVATIVE_BOOST) &&
		get_rtg_status(p) && (p->unfilter ||
		walt_pipeline_low_latency_task(p));
}

static inline bool walt_is_many_wakeup(int sibling_count_hint)
{
	return sibling_count_hint >= sysctl_sched_many_wakeup_threshold;
}

static inline bool walt_target_ok(int target_cpu, int order_index)
{
	return !((order_index != num_sched_clusters - 1) &&
		 (cpumask_weight(&cpu_array[order_index][0]) == 1) &&
		 (target_cpu == cpumask_first(&cpu_array[order_index][0])));
}

static inline bool is_complex_sibling_idle(int cpu)
{
	if (cpu_l2_sibling[cpu] != -1)
		return idle_cpu(cpu_l2_sibling[cpu]);
	return false;
}

void walt_find_best_target(struct sched_domain *sd,
					cpumask_t *candidates,
					struct task_struct *p,
					struct find_best_target_env *fbt_env)
{
	unsigned long min_task_util = uclamp_task_util(p);
	long target_max_spare_cap = 0;
	unsigned long best_idle_cuml_util = ULONG_MAX;
	unsigned int min_exit_latency = UINT_MAX;
	int i, start_cpu;
	long spare_wake_cap, most_spare_wake_cap = 0;
	int most_spare_cap_cpu = -1;
	int prev_cpu = task_cpu(p);
	int active_candidate = -1;
	int order_index = fbt_env->order_index, end_index = fbt_env->end_index;
	int stop_index = INT_MAX;
	int cluster;
	unsigned int target_nr_rtg_high_prio = UINT_MAX;
	bool rtg_high_prio_task = task_rtg_high_prio(p);
	cpumask_t visit_cpus;

	/* Find start CPU based on boost value */
	start_cpu = fbt_env->start_cpu;

	/*
	 * For higher capacity worth I/O tasks, stop the search
	 * at the end of higher capacity cluster(s).
	 */
	if (order_index > 0 && p->iowaited) {
		stop_index = num_sched_clusters - 2;
		most_spare_wake_cap = LONG_MIN;
	}

	if (fbt_env->strict_max) {
		stop_index = 0;
		most_spare_wake_cap = LONG_MIN;
	}

	/* fast path for prev_cpu */
	if (((capacity_orig_of(prev_cpu) == capacity_orig_of(start_cpu)) ||
				asym_cap_siblings(prev_cpu, start_cpu)) &&
				cpu_active(prev_cpu) && cpu_online(prev_cpu) &&
				idle_cpu(prev_cpu) &&
				cpumask_test_cpu(prev_cpu, p->cpus_ptr)) {
		fbt_env->fastpath = PREV_CPU_FASTPATH;
		cpumask_set_cpu(prev_cpu, candidates);
		goto out;
	}

	for (cluster = 0; cluster < num_sched_clusters; cluster++) {
		int best_idle_cpu_cluster = -1;
		int target_cpu_cluster = -1;
		int this_complex_idle = 0;
		int best_complex_idle = 0;

		target_max_spare_cap = 0;
		min_exit_latency = INT_MAX;
		best_idle_cuml_util = ULONG_MAX;

		cpumask_and(&visit_cpus, &p->cpus_mask,
				&cpu_array[order_index][cluster]);
		for_each_cpu(i, &visit_cpus) {
			unsigned long capacity_orig = capacity_orig_of(i);
			unsigned long wake_cpu_util, new_cpu_util, new_util_cuml;
			long spare_cap;
			unsigned int idle_exit_latency = UINT_MAX;
			struct rq *rq = cpu_rq(i);

			trace_sched_cpu_util(i);
			/* record the prss as we visit cpus in a cluster */
			fbt_env->prs[i] = rq->prev_runnable_sum + rq->grp_time.prev_runnable_sum;

			if (!cpu_active(i))
				continue;

			if (active_candidate == -1)
				active_candidate = i;

			/*
			 * This CPU is the target of an active migration that's
			 * yet to complete. Avoid placing another task on it.
			 */
			if (is_reserved(i))
				continue;

			if (sched_cpu_high_irqload(i))
				continue;

			if (fbt_env->skip_cpu == i)
				continue;

			if (per_task_boost(cpu_rq(i)->curr) ==
					TASK_BOOST_STRICT_MAX)
				continue;

			/*
			 * p's blocked utilization is still accounted for on prev_cpu
			 * so prev_cpu will receive a negative bias due to the double
			 * accounting. However, the blocked utilization may be zero.
			 */
			wake_cpu_util = cpu_util_without(i, p);
			spare_wake_cap = capacity_orig - wake_cpu_util;

			if (spare_wake_cap > most_spare_wake_cap) {
				most_spare_wake_cap = spare_wake_cap;
				most_spare_cap_cpu = i;
			}

			/*
			 * Ensure minimum capacity to grant the required boost.
			 * The target CPU can be already at a capacity level higher
			 * than the one required to boost the task.
			 */
			new_cpu_util = wake_cpu_util + min_task_util;
			if (new_cpu_util > capacity_orig)
				continue;

			/*
			 * Find an optimal backup IDLE CPU for non latency
			 * sensitive tasks.
			 *
			 * Looking for:
			 * - favoring shallowest idle states
			 *   i.e. avoid to wakeup deep-idle CPUs
			 *
			 * The following code path is used by non latency
			 * sensitive tasks if IDLE CPUs are available. If at
			 * least one of such CPUs are available it sets the
			 * best_idle_cpu to the most suitable idle CPU to be
			 * selected.
			 *
			 * If idle CPUs are available, favour these CPUs to
			 * improve performances by spreading tasks.
			 * Indeed, the energy_diff() computed by the caller
			 * will take care to ensure the minimization of energy
			 * consumptions without affecting performance.
			 */
			if (idle_cpu(i)) {
				idle_exit_latency = walt_get_idle_exit_latency(cpu_rq(i));

				this_complex_idle = is_complex_sibling_idle(i) ? 1 : 0;

				if (this_complex_idle < best_complex_idle)
					continue;
				/*
				 * Prefer shallowest over deeper idle state cpu,
				 * of same capacity cpus.
				 */
				if (idle_exit_latency > min_exit_latency)
					continue;

				new_util_cuml = cpu_util_cum(i, 0);
				if (min_exit_latency == idle_exit_latency &&
					(best_idle_cpu_cluster == prev_cpu ||
					(i != prev_cpu &&
					new_util_cuml > best_idle_cuml_util)))
					continue;

				min_exit_latency = idle_exit_latency;
				best_idle_cuml_util = new_util_cuml;
				best_idle_cpu_cluster = i;
				best_complex_idle = this_complex_idle;
				continue;
			}

			/* skip visiting any more busy if idle was found */
			if (best_idle_cpu_cluster != -1)
				continue;

			/*
			 * Compute the maximum possible capacity we expect
			 * to have available on this CPU once the task is
			 * enqueued here.
			 */
			spare_cap = capacity_orig - new_cpu_util;

			/*
			 * Try to spread the rtg high prio tasks so that they
			 * don't preempt each other. This is a optimisitc
			 * check assuming rtg high prio can actually preempt
			 * the current running task with the given vruntime
			 * boost.
			 */
			if (rtg_high_prio_task) {
				if (walt_nr_rtg_high_prio(i) > target_nr_rtg_high_prio)
					continue;

				/* Favor CPUs with maximum spare capacity */
				if (walt_nr_rtg_high_prio(i) == target_nr_rtg_high_prio &&
						spare_cap < target_max_spare_cap)
					continue;
			} else {
				/* Favor CPUs with maximum spare capacity */
				if (spare_cap < target_max_spare_cap)
					continue;
			}

			target_max_spare_cap = spare_cap;
			target_nr_rtg_high_prio = walt_nr_rtg_high_prio(i);
			target_cpu_cluster = i;
		}

		if (best_idle_cpu_cluster != -1)
			cpumask_set_cpu(best_idle_cpu_cluster, candidates);
		else if (target_cpu_cluster != -1)
			cpumask_set_cpu(target_cpu_cluster, candidates);

		if ((cluster >= end_index) && (!cpumask_empty(candidates)) &&
			walt_target_ok(target_cpu_cluster, order_index))
			break;

		if (most_spare_cap_cpu != -1 && cluster >= stop_index)
			break;
	}

	/*
	 * We have set idle or target as long as they are valid CPUs.
	 * If we don't find either, then we fallback to most_spare_cap,
	 * If we don't find most spare cap, we fallback to prev_cpu,
	 * provided that the prev_cpu is active.
	 * If the prev_cpu is not active, we fallback to active_candidate.
	 */

	if (unlikely(cpumask_empty(candidates))) {
		if (most_spare_cap_cpu != -1)
			cpumask_set_cpu(most_spare_cap_cpu, candidates);
		else if (!cpu_active(prev_cpu) && active_candidate != -1)
			cpumask_set_cpu(active_candidate, candidates);
	}

out:
	trace_sched_find_best_target(p, min_task_util, start_cpu, cpumask_bits(candidates)[0],
			     most_spare_cap_cpu, order_index, end_index,
			     fbt_env->skip_cpu, task_on_rq_queued(p));
}

#ifdef CONFIG_SCHED_WALT
static inline unsigned long
cpu_util_next_walt(int cpu, struct task_struct *p, int dst_cpu)
{
	unsigned long util =
			cpu_rq(cpu)->walt_stats.cumulative_runnable_avg_scaled;
	bool queued = task_on_rq_queued(p);

	/*
	 * When task is queued,
	 * (a) The evaluating CPU (cpu) is task's current CPU. If the
	 * task is migrating, discount the task contribution from the
	 * evaluation cpu.
	 * (b) The evaluating CPU (cpu) is task's current CPU. If the
	 * task is NOT migrating, nothing to do. The contribution is
	 * already present on the evaluation CPU.
	 * (c) The evaluating CPU (cpu) is not task's current CPU. But
	 * the task is migrating to the evaluating CPU. So add the
	 * task contribution to it.
	 * (d) The evaluating CPU (cpu) is neither the current CPU nor
	 * the destination CPU. don't care.
	 *
	 * When task is NOT queued i.e waking. Task contribution is not
	 * present on any CPU.
	 *
	 * (a) If the evaluating CPU is the destination CPU, add the task
	 * contribution.
	 * (b) The evaluation CPU is not the destination CPU, don't care.
	 */
	if (unlikely(queued)) {
		if (task_cpu(p) == cpu) {
			if (dst_cpu != cpu)
				util = max_t(long, util - task_util(p), 0);
		} else if (dst_cpu == cpu) {
			util += task_util(p);
		}
	} else if (dst_cpu == cpu) {
		util += task_util(p);
	}

	return min_t(unsigned long, util, capacity_orig_of(cpu));
}
#endif

static inline u64
cpu_util_next_walt_prs(int cpu, struct task_struct *p, int dst_cpu, bool prev_dst_same_cluster,
											u64 *prs)
{
	long util = prs[cpu];

	if (p->ravg.prev_window) {
		if (!prev_dst_same_cluster) {
			/* intercluster migration of non rtg task - mimic fixups */
			util -= p->ravg.prev_window_cpu[cpu];
			if (util < 0)
				util = 0;
			if (cpu == dst_cpu)
				util += p->ravg.prev_window;
		}
	} else {
		if (cpu == dst_cpu)
			util += p->ravg.demand;
	}

	return util;
}

/**
 * walt_em_cpu_energy() - Estimates the energy consumed by the CPUs of a
		performance domain
 * @pd		: performance domain for which energy has to be estimated
 * @max_util	: highest utilization among CPUs of the domain
 * @sum_util	: sum of the utilization of all CPUs in the domain
 *
 * This function must be used only for CPU devices. There is no validation,
 * i.e. if the EM is a CPU type and has cpumask allocated. It is called from
 * the scheduler code quite frequently and that is why there is not checks.
 *
 * Return: the sum of the energy consumed by the CPUs of the domain assuming
 * a capacity state satisfying the max utilization of the domain.
 */
static inline unsigned long walt_em_cpu_energy(struct em_perf_domain *pd,
				unsigned long max_util, unsigned long sum_util,
				struct compute_energy_output *output, unsigned int x)
{
	unsigned long scale_cpu;
	int cpu;
	struct rq *rq = cpu_rq(cpu);

	if (!sum_util)
		return 0;

	/*
	 * In order to predict the capacity state, map the utilization of the
	 * most utilized CPU of the performance domain to a requested frequency,
	 * like schedutil.
	 */
	cpu = cpumask_first(to_cpumask(pd->cpus));
	scale_cpu = arch_scale_cpu_capacity(cpu);

	max_util = max_util + (max_util >> 2); /* account  for TARGET_LOAD usually 80 */
	max_util = max(max_util,
			(arch_scale_freq_capacity(NULL, cpu) * scale_cpu) >>
			SCHED_CAPACITY_SHIFT);

	/*
	 * The capacity of a CPU in the domain at the performance state (ps)
	 * can be computed as:
	 *
	 *             ps->freq * scale_cpu
	 *   ps->cap = --------------------                          (1)
	 *                 cpu_max_freq
	 *
	 * So, ignoring the costs of idle states (which are not available in
	 * the EM), the energy consumed by this CPU at that performance state
	 * is estimated as:
	 *
	 *             ps->power * cpu_util
	 *   cpu_nrg = --------------------                          (2)
	 *                   ps->cap
	 *
	 * since 'cpu_util / ps->cap' represents its percentage of busy time.
	 *
	 *   NOTE: Although the result of this computation actually is in
	 *         units of power, it can be manipulated as an energy value
	 *         over a scheduling period, since it is assumed to be
	 *         constant during that interval.
	 *
	 * By injecting (1) in (2), 'cpu_nrg' can be re-expressed as a product
	 * of two terms:
	 *
	 *             ps->power * cpu_max_freq   cpu_util
	 *   cpu_nrg = ------------------------ * ---------          (3)
	 *                    ps->freq            scale_cpu
	 *
	 * The first term is static, and is stored in the em_perf_state struct
	 * as 'ps->cost'.
	 *
	 * Since all CPUs of the domain have the same micro-architecture, they
	 * share the same 'ps->cost', and the same CPU capacity. Hence, the
	 * total energy of the domain (which is the simple sum of the energy of
	 * all of its CPUs) can be factorized as:
	 *
	 *            ps->cost * \Sum cpu_util
	 *   pd_nrg = ------------------------                       (4)
	 *                  scale_cpu
	 */
	if (max_util >= 1024)
		max_util = 1023;

	if (output) {
		output->cost[x] = rq->cluster->util_to_cost[max_util];
		output->max_util[x] = max_util;
		output->sum_util[x] = sum_util;
	}
	return rq->cluster->util_to_cost[max_util] * sum_util / scale_cpu;
}

/*
 * walt_pd_compute_energy(): Estimates the energy that @pd would consume if @p was
 * migrated to @dst_cpu. compute_energy() predicts what will be the utilization
 * landscape of @pd's CPUs after the task migration, and uses the Energy Model
 * to compute what would be the energy if we decided to actually migrate that
 * task.
 */
static long
walt_pd_compute_energy(struct task_struct *p, int dst_cpu, struct perf_domain *pd, u64 *prs,
		struct compute_energy_output *output, unsigned int x)
{
	struct cpumask *pd_mask = perf_domain_span(pd);
	unsigned long max_util = 0, sum_util = 0;
	int cpu;
	unsigned long cpu_util;
	bool prev_dst_same_cluster = false;

	if (walt_same_cluster(task_cpu(p), dst_cpu))
		prev_dst_same_cluster = true;

	/*
	 * The capacity state of CPUs of the current rd can be driven by CPUs
	 * of another rd if they belong to the same pd. So, account for the
	 * utilization of these CPUs too by masking pd with cpu_online_mask
	 * instead of the rd span.
	 *
	 * If an entire pd is outside of the current rd, it will not appear in
	 * its pd list and will not be accounted by compute_energy().
	 */
	for_each_cpu_and(cpu, pd_mask, cpu_online_mask) {
		sum_util += cpu_util_next_walt(cpu, p, dst_cpu);
		cpu_util = cpu_util_next_walt_prs(cpu, p, dst_cpu, prev_dst_same_cluster, prs);
		max_util = max(max_util, cpu_util);
	}

	max_util = walt_scale_demand(max_util);

	if (output)
		output->cluster_first_cpu[x] = cpumask_first(pd_mask);

	return walt_em_cpu_energy(pd->em_pd, max_util, sum_util, output, x);
}

unsigned long
walt_compute_energy(struct task_struct *p, int dst_cpu, struct perf_domain *pd,
			cpumask_t *candidates, u64 *prs, struct compute_energy_output *output)
{
	long energy = 0;
	unsigned int x = 0;

	for (; pd; pd = pd->next) {
		struct cpumask *pd_mask = perf_domain_span(pd);

		if (cpumask_intersects(candidates, pd_mask)
				|| cpumask_test_cpu(task_cpu(p), pd_mask)) {
			energy += walt_pd_compute_energy(p, dst_cpu, pd, prs, output, x);
			x++;
		}
	}

	return energy;
}

#define MIN_UTIL_FOR_ENERGY_EVAL	52
void walt_get_indicies(struct task_struct *p, int *order_index,
		int *end_index, int per_task_boost, bool is_boosted,
		bool *energy_eval_needed)
{
	int i = 0;
	*order_index = 0;
	*end_index = 0;

	if (num_sched_clusters <= 1)
		return;

	if (per_task_boost > TASK_BOOST_ON_MID) {
		*order_index = num_sched_clusters - 1;
		*energy_eval_needed = false;
		return;
	}

	if (is_full_throttle_boost()) {
		*energy_eval_needed = false;
		*order_index = num_sched_clusters - 1;
		if ((*order_index > 1) && task_demand_fits(p,
			cpumask_first(&cpu_array[*order_index][1])))
			*end_index = 1;
		return;
	}

	if (is_boosted || per_task_boost ||
		task_boost_policy(p) == SCHED_BOOST_ON_BIG ||
		walt_task_skip_min_cpu(p)) {
		*energy_eval_needed = false;
		*order_index = 1;
		if (sysctl_sched_asymcap_boost) {
			*end_index = 1;
			return;
		}
	}

	for (i = *order_index ; i < num_sched_clusters - 1; i++) {
		if (task_demand_fits(p, cpumask_first(&cpu_array[i][0])))
			break;
	}

	*order_index = i;

	if (*order_index == 0 &&
			(task_util(p) >= MIN_UTIL_FOR_ENERGY_EVAL) &&
			!(p->in_iowait && task_in_related_thread_group(p)) &&
			!get_rtg_status(p) &&
			!(sched_boost_type == CONSERVATIVE_BOOST && task_sched_boost(p)) &&
			!sysctl_sched_suppress_region2
		)
		*end_index = 1;

	if (p->in_iowait && task_in_related_thread_group(p))
		*energy_eval_needed = false;
}

static DEFINE_PER_CPU(cpumask_t, energy_cpus);
int walt_find_energy_efficient_cpu(struct task_struct *p, int prev_cpu,
				     int sync, int sibling_count_hint)
{
	unsigned long prev_energy = ULONG_MAX, best_energy = ULONG_MAX;
	struct root_domain *rd = cpu_rq(cpumask_first(cpu_active_mask))->rd;
	int weight, cpu = smp_processor_id(), best_energy_cpu = prev_cpu;
	struct perf_domain *pd;
	unsigned long cur_energy;
	cpumask_t *candidates;
	bool is_rtg, curr_is_rtg;
	struct find_best_target_env fbt_env;
	bool need_idle = wake_to_idle(p) || uclamp_latency_sensitive(p);
	u64 start_t = 0;
	int delta = 0;
	int placement_boost = task_boost_policy(p);
	int task_boost = per_task_boost(p);
	int boost = schedtune_task_boost(p);
	int boosted = (schedtune_task_boost(p) > 0) || (task_boost > 0);
	int start_cpu, order_index, end_index;
	int first_cpu;
	bool energy_eval_needed = true;
	struct compute_energy_output output;

	if (walt_is_many_wakeup(sibling_count_hint) && prev_cpu != cpu &&
			cpumask_test_cpu(prev_cpu, &p->cpus_mask))
		return prev_cpu;

	if (unlikely(!cpu_array))
		return -EPERM;

	walt_get_indicies(p, &order_index, &end_index, task_boost, boost,
								&energy_eval_needed);
	start_cpu = cpumask_first(&cpu_array[order_index][0]);

	is_rtg = task_in_related_thread_group(p);
	curr_is_rtg = task_in_related_thread_group(cpu_rq(cpu)->curr);

	fbt_env.fastpath = 0;
	fbt_env.need_idle = need_idle;

	if (trace_sched_task_util_enabled())
		start_t = sched_clock();

	/* Pre-select a set of candidate CPUs. */
	candidates = this_cpu_ptr(&energy_cpus);
	cpumask_clear(candidates);

	if (sync && (need_idle || (is_rtg && curr_is_rtg)))
		sync = 0;

	if (sysctl_sched_sync_hint_enable && sync
			&& bias_to_this_cpu(p, cpu, start_cpu)) {
		best_energy_cpu = cpu;
		fbt_env.fastpath = SYNC_WAKEUP;
		goto done;
	}

	rcu_read_lock();
	pd = rcu_dereference(rd->pd);
	if (!pd)
		goto fail;

	fbt_env.is_rtg = is_rtg;
	fbt_env.placement_boost = placement_boost;
	fbt_env.start_cpu = start_cpu;
	fbt_env.order_index = order_index;
	fbt_env.end_index = end_index;
	fbt_env.strict_max = is_rtg &&
		(task_boost == TASK_BOOST_STRICT_MAX);
	fbt_env.skip_cpu = walt_is_many_wakeup(sibling_count_hint) ?
			   cpu : -1;

	walt_find_best_target(NULL, candidates, p, &fbt_env);

	/* Bail out if no candidate was found. */
	weight = cpumask_weight(candidates);
	if (!weight)
		goto unlock;

	first_cpu = cpumask_first(candidates);
	if (weight == 1) {
		if (idle_cpu(first_cpu) || first_cpu == prev_cpu) {
			best_energy_cpu = first_cpu;
			goto unlock;
		}
	}

	if (task_placement_boost_enabled(p) || fbt_env.need_idle || boosted ||
	    is_rtg || __cpu_overutilized(prev_cpu, delta) ||
	    !task_fits_max(p, prev_cpu) || cpu_isolated(prev_cpu)) {
		best_energy_cpu = cpu;
		goto unlock;
	}

	if (need_idle && idle_cpu(first_cpu)) {
		best_energy_cpu = first_cpu;
		goto unlock;
	}

	if (!energy_eval_needed) {
		int max_spare_cpu = first_cpu;

		for_each_cpu(cpu, candidates) {
			if (capacity_spare_of(max_spare_cpu) < capacity_spare_of(cpu))
				max_spare_cpu = cpu;
		}
		best_energy_cpu = max_spare_cpu;
		goto unlock;
	}

	if (p->state == TASK_WAKING)
		delta = task_util(p);

	if (cpumask_test_cpu(prev_cpu, &p->cpus_mask) && !__cpu_overutilized(prev_cpu, delta)) {
		if (trace_sched_compute_energy_enabled()) {
			memset(&output, 0, sizeof(output));
			prev_energy = walt_compute_energy(p, prev_cpu, pd, candidates, fbt_env.prs,
					&output);
		} else {
			prev_energy = walt_compute_energy(p, prev_cpu, pd, candidates, fbt_env.prs,
					NULL);
		}

		best_energy = prev_energy;
		trace_sched_compute_energy(p, prev_cpu, prev_energy, 0, 0, 0, &output);
	} else {
		prev_energy = best_energy = ULONG_MAX;
	}

	/* Select the best candidate energy-wise. */
	for_each_cpu(cpu, candidates) {
		if (cpu == prev_cpu)
			continue;

		if (trace_sched_compute_energy_enabled()) {
			memset(&output, 0, sizeof(output));
			cur_energy = walt_compute_energy(p, cpu, pd, candidates, fbt_env.prs,
					&output);
		} else {
			cur_energy = walt_compute_energy(p, cpu, pd, candidates, fbt_env.prs,
					NULL);
		}

		trace_sched_compute_energy(p, cpu, cur_energy,
			prev_energy, best_energy, best_energy_cpu, &output);

		if (cur_energy < best_energy) {
			best_energy = cur_energy;
			best_energy_cpu = cpu;
		} else if (cur_energy == best_energy) {
			if (select_cpu_same_energy(cpu, best_energy_cpu,
							prev_cpu)) {
				best_energy = cur_energy;
				best_energy_cpu = cpu;
			}
		}
	}

	/*
	 * Pick the prev CPU, if best energy CPU can't saves at least 6% of
	 * the energy used by prev_cpu.
	 */
	if (!(idle_cpu(best_energy_cpu) &&
	    walt_get_idle_exit_latency(cpu_rq(best_energy_cpu)) <= 1) &&
	    (prev_energy != ULONG_MAX) && (best_energy_cpu != prev_cpu) &&
	    ((prev_energy - best_energy) <= prev_energy >> 5) &&
	    (capacity_orig_of(prev_cpu) <= capacity_orig_of(start_cpu)))
		best_energy_cpu = prev_cpu;

unlock:
	rcu_read_unlock();

done:
        trace_sched_task_util(p, cpumask_bits(candidates)[0], best_energy_cpu,
			sync, fbt_env.need_idle, fbt_env.fastpath,
			placement_boost, start_t, boosted, is_rtg,
			get_rtg_status(p), start_cpu);

	return best_energy_cpu;

fail:
	rcu_read_unlock();
	return -EPERM;
}

#if 0
void walt_cfs_tick(struct rq *rq)
{
	struct task_struct *p = rq->curr;

	if (unlikely(walt_disabled))
		return;

	raw_spin_lock(&rq->lock);

	if (list_empty(&p->mvp_list) || (p->mvp_list.next == NULL))
		goto out;

	walt_cfs_account_mvp_runtime(rq, rq->curr);
	/*
	 * If the current is not MVP means, we have to re-schedule to
	 * see if we can run any other task including MVP tasks.
	 */
	if ((p->mvp_tasks.next != &p->mvp_list) && rq->cfs.h_nr_running > 1)
		resched_curr(rq);

out:
	raw_spin_unlock(&rq->lock);
}
#endif

static void
walt_select_task_rq_fair(void *unused, struct task_struct *p, int prev_cpu,
				int sd_flag, int wake_flags, int *target_cpu)
{
	int sync;
	int sibling_count_hint;

	sync = (wake_flags & WF_SYNC) && !(current->flags & PF_EXITING);
	sibling_count_hint = p->wake_q_count;
	p->wake_q_count = 0;

	*target_cpu = walt_find_energy_efficient_cpu(p, prev_cpu, sync, sibling_count_hint);
	if (unlikely(*target_cpu < 0))
		*target_cpu = prev_cpu;
}

static void energey_compute_assist(void *unused, struct task_struct *p, int dst_cpu,
		  unsigned int energy)
{
	struct find_best_target_env fbt_env;
	int prev_cpu;
	cpumask_t *candidates;
	struct perf_domain *pd;
	struct compute_energy_output *output;

        energy = walt_compute_energy(p, prev_cpu, pd, candidates, fbt_env.prs,
					output);
}

void walt_cfs_init(void)
{
	register_trace_android_rvh_select_task_rq_fair(walt_select_task_rq_fair, NULL);
	register_trace_energey_compute_assist(energey_compute_assist, NULL);
}

