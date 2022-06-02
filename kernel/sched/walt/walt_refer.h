/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2019-2021, The Linux Foundation. All rights reserved.
 */

#include "../../../kernel/sched/sched.h"
#include <linux/energy_model.h>
#include <linux/android_vendor.h>

extern __read_mostly unsigned int walt_scale_demand_divisor;
#define walt_scale_demand(d) ((d)/walt_scale_demand_divisor)

/* structures for modules */
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

/* functions references fore modules */
extern inline int walt_same_cluster(int src_cpu, int dst_cpu)
{
	return cpu_rq(src_cpu)->cluster == cpu_rq(dst_cpu)->cluster;
}
