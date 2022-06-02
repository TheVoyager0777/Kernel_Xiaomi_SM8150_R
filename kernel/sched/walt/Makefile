# SPDX-License-Identifier: GPL-2.0-only

KCOV_INSTRUMENT := n
KCSAN_SANITIZE := n

obj-$(CONFIG_SCHED_WALT_ENHANCED) += sched-walt.o
sched-walt-$(CONFIG_SCHED_WALT_ENHANCED) := trace.o walt_cfs.o

