// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2016-2021, The Linux Foundation. All rights reserved.
 * Copyright (C) 2021 XiaoMi, Inc.
 */
#include "walt_refer.h"

#define CREATE_TRACEPOITS
#include "trace.h"

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

static void register_hooks(void)
{
	register_trace_energey_compute_assist(energey_compute_assist, NULL);
}

int walt_cfs_init(void)
{
        register_hooks();
        return 0;
}
