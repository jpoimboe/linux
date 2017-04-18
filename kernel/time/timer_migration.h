/*
 * Infrastructure for migrateable timers
 *
 * Copyright(C) 2016 linutronix GmbH
 *
 * This code is licenced under the GPL version 2. For details see
 * kernel-base/COPYING.
 */
#ifndef _KERNEL_TIME_MIGRATION_H
#define _KERNEL_TIME_MIGRATION_H

#if defined(CONFIG_SMP) && defined(CONFIG_NO_HZ_COMMON)
extern void tmigr_handle_remote(void);
extern u64 tmigr_cpu_idle(u64 nextevt);
extern void tmigr_cpu_activate(void);
extern void timer_expire_remote(unsigned int cpu);
extern bool tmigr_enabled;
#else
static inline void tmigr_handle_remote(void) { }
static inline u64 tmigr_cpu_idle(u64 nextevt) { return nextevt; }
static inline void tmigr_cpu_activate(void) { }
#endif

#define TMIGR_NONE		(~0U)

/**
 * struct tmigr_event - A timer event associated to a CPU or a group
 * @nextevt:	The node to enqueue an event in the group queue
 * @group:	The group to which this event belongs (NULL if a cpu event)
 * @cpu:	The cpu to which this event belongs (TMIGR_NONE if a group
 *		event)
 */
struct tmigr_event {
	struct timerqueue_node	nextevt;
	struct tmigr_group	*group;
	unsigned int		cpu;
};

/**
 * struct tmigr_group - the hierachical group for timer migration structure
 * @lock:	Group serialization. Must be taken with interrupts disabled.
 * @active:	Specifies the number of active (not offline and not idle)
 *		childs of the group
 * @migrator:	CPU id of the migrator for this group or TMIGR_NONE
 * @events:	timerqueue head of all events of the group
 * @groupevt:	Next event of the group
 * @parent:	Pointer to the parent group. Null if top level group
 * @cpus:	CPU mask to track the active CPUs
 * @list:	List head to queue in the global group level lists
 * @level:	Specifies the hierarchy level of the group
 * @numa_node:	Specifies the numa node of the group. NUMA_NO_NODE if the
 *		group spawns multiple numa nodes
 * @num_childs:	Number of childs of a group that are connected with the group
 */
struct tmigr_group {
	raw_spinlock_t		lock;
	unsigned int		active;
	unsigned int		migrator;
	struct timerqueue_head	events;
	struct tmigr_event	groupevt;
	struct tmigr_group	*parent;
	cpumask_var_t		cpus;
	struct list_head	list;
	unsigned int		level;
	unsigned int		numa_node;
	unsigned int		num_childs;
};

/**
 * struct tmigr_cpu - Per CPU entry connected to a leaf group in the hierarchy
 * @lock:	Protection for the per cpu data
 * @online:	Online marker vs. the timer migration functionality.
 * @cpuevt:	Specifies the next timer event of the CPU
 * @tmgroup:	Pointer to the leaf group to which this CPU belongs
 */
struct tmigr_cpu {
	raw_spinlock_t		lock;
	bool			online;
	struct tmigr_event	cpuevt;
	struct tmigr_group	*tmgroup;
};

#endif
