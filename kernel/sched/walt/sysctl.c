// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2020-2021, The Linux Foundation. All rights reserved.
 */

#include "walt_refer.h"

static int one_thousand = 1000;

/* Keep the same order as in fs/proc/proc_sysctl.c */
#define SYSCTL_ZERO	((void *)&sysctl_vals[0])
#define SYSCTL_ONE	((void *)&sysctl_vals[1])
#define SYSCTL_INT_MAX	((void *)&sysctl_vals[2])

/* shared constants to be used in various sysctls */
const int sysctl_vals[] = { 0, 1, INT_MAX };
EXPORT_SYMBOL(sysctl_vals);

/*
 * CFS task prio range is [100 ... 139]
 * 120 is the default prio.
 * RTG boost range is [100 ... 119] because giving
 * boost for [120 .. 139] does not make sense.
 * 99 means disabled and it is the default value.
 */
static unsigned int min_cfs_boost_prio = 99;
static unsigned int max_cfs_boost_prio = 119;

unsigned int sysctl_panic_on_walt_bug;
unsigned int sysctl_sched_suppress_region2;
unsigned int sysctl_sched_skip_sp_newly_idle_lb = 1;
unsigned int sysctl_sched_asymcap_boost;
unsigned int sysctl_walt_low_latency_task_threshold; /* disabled by default */
unsigned int sysctl_walt_rtg_cfs_boost_prio = 99; /* disabled by default */
__read_mostly unsigned int sysctl_sched_force_lb_enable = 1;

struct ctl_table walt_table[] = {
	{
		.procname       = "panic_on_walt_bug",
		.data           = &sysctl_panic_on_walt_bug,
		.maxlen         = sizeof(unsigned int),
		.mode           = 0644,
		.proc_handler   = proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_INT_MAX,
	},
	{
		.procname       = "sched_suppress_region2",
		.data           = &sysctl_sched_suppress_region2,
		.maxlen         = sizeof(unsigned int),
		.mode           = 0644,
		.proc_handler   = proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE,
	},
	{
		.procname       = "sched_skip_sp_newly_idle_lb",
		.data           = &sysctl_sched_skip_sp_newly_idle_lb,
		.maxlen         = sizeof(unsigned int),
		.mode           = 0644,
		.proc_handler   = proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE,
	},
	{
		.procname	= "sched_asymcap_boost",
		.data		= &sysctl_sched_asymcap_boost,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= proc_douintvec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE,
	},
      	{
		.procname	= "walt_low_latency_task_threshold",
		.data		= &sysctl_walt_low_latency_task_threshold,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= &one_thousand,
	},
	{
		.procname	= "sched_force_lb_enable",
		.data		= &sysctl_sched_force_lb_enable,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE,
	},
	{
		.procname	= "walt_rtg_cfs_boost_prio",
		.data		= &sysctl_walt_rtg_cfs_boost_prio,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &min_cfs_boost_prio,
		.extra2		= &max_cfs_boost_prio,
	},
	{ }
};

struct ctl_table walt_base_table[] = {
	{ },
};
