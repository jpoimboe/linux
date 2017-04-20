/*
 * Infrastructure for migrateable timers
 *
 * Copyright(C) 2016 linutronix GmbH
 *
 * This code is licenced under the GPL version 2. For details see
 * kernel-base/COPYING.
 */
#include <linux/cpuhotplug.h>
#include <linux/slab.h>
#include <linux/smp.h>
#include <linux/spinlock.h>
#include <linux/timerqueue.h>
#include <linux/timer.h>

#include "timer_migration.h"
#include "tick-internal.h"

#define CREATE_TRACE_POINTS
#include <trace/events/timer_migration.h>

#ifdef DEBUG
# define DBG_BUG_ON(x)	BUG_ON(x)
#else
# define DBG_BUG_ON(x)
#endif

/* Per group capacity. Must be a power of 2! */
static const unsigned int tmigr_childs_per_group = 8;

bool tmigr_enabled __read_mostly;
static unsigned int tmigr_hierarchy_levels __read_mostly;
static unsigned int tmigr_crossnode_level __read_mostly;
static struct list_head *tmigr_level_list __read_mostly;

static DEFINE_MUTEX(tmigr_mutex);

static DEFINE_PER_CPU(struct tmigr_cpu, tmigr_cpu);

static void tmigr_add_evt(struct tmigr_group *group, struct tmigr_event *evt)
{
	/*
	 * Can be called with @evt == NULL, an already queued @evt or
	 * an event that do not need to be queued (expires ==
	 * KTIME_MAX)
	 */
	if (!evt || !RB_EMPTY_NODE(&evt->nextevt.node) ||
	    evt->nextevt.expires == KTIME_MAX)
		return;

	/* @group->group event must not be queued in the parent group */
	DBG_BUG_ON(!RB_EMPTY_NODE(&group->groupevt.nextevt.node));

	/*  If this is the new first to expire event, update group event */
	if (timerqueue_add(&group->events, &evt->nextevt)) {
		group->groupevt.nextevt.expires = evt->nextevt.expires;
		group->groupevt.cpu = evt->cpu;
	}

	trace_tmigr_group_addevt(group);
}

static void tmigr_remove_evt(struct tmigr_group *group, struct tmigr_event *evt)
{
	struct timerqueue_node *next;
	struct tmigr_event *nextevt;
	bool first;

	/*
	 * It's safe to modify the group event of this group, because it is
	 * not queued in the parent group.
	 */
	DBG_BUG_ON(!RB_EMPTY_NODE(&group->groupevt.nextevt.node));

	/* Remove the child event, if pending */
	if (!evt || RB_EMPTY_NODE(&evt->nextevt.node))
		return;
	/*
	 * If this was the last queued event in the group, clear
	 * the group event. If this was the first event to expire,
	 * update the group.
	 */
	first = (timerqueue_getnext(&group->events) == &evt->nextevt);

	if (!timerqueue_del(&group->events, &evt->nextevt)) {
		group->groupevt.nextevt.expires = KTIME_MAX;
		group->groupevt.cpu = TMIGR_NONE;
	} else if (first) {
		next = timerqueue_getnext(&group->events);
		nextevt = container_of(next, struct tmigr_event, nextevt);
		group->groupevt.nextevt.expires = nextevt->nextevt.expires;
		group->groupevt.cpu = nextevt->cpu;
	}

	trace_tmigr_group_removeevt(group);
}

static void tmigr_update_remote(unsigned int cpu, u64 now, unsigned long jif)
{
	struct tmigr_cpu *tmc = per_cpu_ptr(&tmigr_cpu, cpu);
	struct tmigr_group *group = tmc->tmgroup;
	u64 next_local, next_global;

	/*
	 * Here the migrator CPU races with the target CPU.  The migrator
	 * removed @tmc->nextevt from the group's queue, but it then dropped
	 * the group lock.  Concurrently the target CPU might have serviced
	 * an interrupt and therefore have called tmigr_cpu_activate() and
	 * possibly tmigr_cpu_idle() which requeued CPUs @tmc into @group.
	 *
	 * Must hold @tmc->lock for changing @tmc->nextevt and @group->lock
	 * to protect the timer queue of @group.
	 */
	raw_spin_lock_irq(&tmc->lock);
	raw_spin_lock(&group->lock);

	/*
	 * If the cpu went offline or marked itself active again, nothing
	 * more to do.
	 */
	if (!tmc->online || cpumask_test_cpu(cpu, group->cpus))
		goto done;

	/*
	 * Although __timgr_handle_remote() just dequeued the event, still
	 * the target CPU might have added it again after the lock got
	 * dropped. If it's queued the group queue is up to date.
	 */
	if (!RB_EMPTY_NODE(&tmc->cpuevt.nextevt.node))
		goto done;

	/*
	 * Recalculate next event. Needs to be calculated while holding the
	 * lock because the first expiring global timer could have been
	 * removed since the last evaluation.
	 */
	next_local = get_next_timer_interrupt(jif, now, &next_global);

	/*
	 * If next_global is after next_local, event does not have to
	 * be queued.
	 */
	if (next_global >= next_local)
		next_global = KTIME_MAX;

	tmc->cpuevt.nextevt.expires = next_global;

	/* Queue @cpu event (is not ne queued if expires == KTIME_MAX) */
	tmigr_add_evt(group, &tmc->cpuevt);

done:
	trace_tmigr_cpu_update_remote(tmc, cpu);
	raw_spin_unlock(&group->lock);
	raw_spin_unlock_irq(&tmc->lock);
}

static void __tmigr_handle_remote(struct tmigr_group *group, unsigned int cpu,
				  u64 now, unsigned long jif, bool walkup)
{
	struct timerqueue_node *tmr;
	struct tmigr_group *parent;
	struct tmigr_event *evt;

	trace_tmigr_handle_remote(group, cpu);

again:
	raw_spin_lock_irq(&group->lock);
	/*
	 * Handle the group only if @cpu is the migrator or if the group
	 * has no migrator. Otherwise the group is active and is handled by
	 * its own migrator.
	 */
	if (group->migrator != cpu && group->migrator != TMIGR_NONE) {
		raw_spin_unlock_irq(&group->lock);
		return;
	}

	tmr = timerqueue_getnext(&group->events);
	if (tmr && now >= tmr->expires) {
		/*
		 * Remove the expired entry from the queue and handle
		 * it. If this is a leaf group, call the timer poll
		 * function for the given cpu. Otherwise handle the group
		 * itself.  Drop the group lock here in both cases to avoid
		 * lock ordering inversions.
		 */
		evt = container_of(tmr, struct tmigr_event, nextevt);
		tmigr_remove_evt(group, evt);

		raw_spin_unlock_irq(&group->lock);

		/*
		 * If the event is a group event walk down the hierarchy of
		 * that group to the CPU leafs. If not, handle the expired
		 * timer from the remote CPU.
		 */
		if (evt->group) {
			__tmigr_handle_remote(evt->group, cpu, now, jif, false);
		} else {
			timer_expire_remote(evt->cpu);
			tmigr_update_remote(evt->cpu, now, jif);
		}
		goto again;
	}

	/*
	 * If @group is not active, queue the next event in the parent
	 * group. This is required, because the next event of @group
	 * could have been changed by tmigr_update_remote() above.
	 */
	parent = group->parent;
	if (parent && !group->active) {
		raw_spin_lock_nested(&parent->lock, parent->level);
		tmigr_add_evt(parent, &group->groupevt);
		raw_spin_unlock(&parent->lock);
	}
	raw_spin_unlock_irq(&group->lock);

	/* Walk the hierarchy up? */
	if (!walkup || !parent)
		return;

	/* Racy lockless check: See comment in tmigr_handle_remote() */
	if (parent->migrator == cpu)
		__tmigr_handle_remote(parent, cpu, now, jif, true);
}

/**
 * tmigr_handle_remote - Handle migratable timers on remote idle CPUs
 *
 * Called from the timer soft interrupt with interrupts enabled.
 */
void tmigr_handle_remote(void)
{
	struct tmigr_cpu *tmc = this_cpu_ptr(&tmigr_cpu);
	int cpu = smp_processor_id();
	unsigned long basej;
	ktime_t now;

	if (!tmigr_enabled)
		return;

	/*
	 * Check whether this CPU is responsible for handling the global
	 * timers of other CPUs. Do a racy lockless check to avoid lock
	 * contention for the busy case where timer soft interrupts happen
	 * in parallel. It's not an issue, if the CPU misses a concurrent
	 * update of the migrator role for its base group. It's not more
	 * racy than doing this check under the lock, if the update happens
	 * right after the lock is dropped. There is no damage in such a
	 * case other than potentially expiring a global timer one tick
	 * late.
	 */
	if (tmc->tmgroup->migrator != cpu)
		return;

	now = get_jiffies_update(&basej);
	__tmigr_handle_remote(tmc->tmgroup, cpu, now, basej, true);
}

/**
 * tmigr_set_cpu_inactive - Set a CPU inactive in the group
 * @group:	The group from which @cpu is removed
 * @child:	The child group which was updated before
 * @evt:	The event to queue in @group
 * @cpu:	The CPU which becomes inactive
 *
 * Remove @cpu from @group and propagate it through the hierarchy if
 * @cpu was the migrator of @group.
 *
 * Returns KTIME_MAX if @cpu is not the last outgoing CPU in the
 * hierarchy. Otherwise it returns the first expiring global event.
 */
static u64 tmigr_set_cpu_inactive(struct tmigr_group *group,
				  struct tmigr_group *child,
				  struct tmigr_event *evt,
				  unsigned int cpu)
{
	struct tmigr_group *parent;
	u64 nextevt = KTIME_MAX;

	raw_spin_lock_nested(&group->lock, group->level);

	DBG_BUG_ON(!group->active);

	cpumask_clear_cpu(cpu, group->cpus);
	group->active--;

	/*
	 * If @child is not NULL, then this is a recursive invocation to
	 * propagate the deactivation of @cpu. If @child has a new migrator
	 * set it active in @group.
	 */
	if (child && child->migrator != TMIGR_NONE) {
		cpumask_set_cpu(child->migrator, group->cpus);
		group->active++;
	}

	/* Add @evt to @group */
	tmigr_add_evt(group, evt);

	/* If @cpu is not the active migrator, everything is up to date */
	if (group->migrator != cpu)
		goto done;

	/* Update the migrator. */
	if (!group->active)
		group->migrator = TMIGR_NONE;
	else
		group->migrator = cpumask_first(group->cpus);

	parent = group->parent;
	if (parent) {
		/*
		 * @cpu was the migrator in @group, so it is marked as
		 * active in its parent group(s) as well. Propagate the
		 * migrator change.
		 */
		evt = group->active ? NULL : &group->groupevt;
		nextevt = tmigr_set_cpu_inactive(parent, group, evt, cpu);
	} else {
		/*
		 * This is the top level of the hierarchy. If @cpu is about
		 * to go offline wake up some random other cpu so it will
		 * take over the migrator duty and program its timer
		 * proper. Ideally wake the cpu with the closest expiry
		 * time, but that's overkill to figure out.
		 */
		if (!per_cpu(tmigr_cpu, cpu).online) {
			cpu = cpumask_any_but(cpu_online_mask, cpu);
			smp_send_reschedule(cpu);
		}
		/*
		 * Return the earliest event of the top level group to make
		 * sure that its handled.
		 *
		 * This could be optimized by keeping track of the last
		 * global scheduled event and only arming it on @cpu if the
		 * new event is earlier. Not sure if its worth the
		 * complexity.
		 */
		nextevt = group->groupevt.nextevt.expires;
	}
done:
	trace_tmigr_group_set_cpu_inactive(group);
	raw_spin_unlock(&group->lock);
	return nextevt;
}

/**
 * tmigr_cpu_idle - Put current CPU into idle state
 * @nextevt:	The next timer event set in the current CPU
 *
 * Returns either the next event of the current CPU or the next event from
 * the hierarchy if this CPU is the top level migrator.
 *
 * Must be called with interrupts disabled.
 */
u64 tmigr_cpu_idle(u64 nextevt)
{
	struct tmigr_cpu *tmc = this_cpu_ptr(&tmigr_cpu);
	struct tmigr_group *group = tmc->tmgroup;
	int cpu = smp_processor_id();

	if (!tmc->online)
		return nextevt;

	raw_spin_lock(&tmc->lock);
	tmc->cpuevt.nextevt.expires = nextevt;
	nextevt = tmigr_set_cpu_inactive(group, NULL, &tmc->cpuevt, cpu);
	raw_spin_unlock(&tmc->lock);
	return nextevt;
}

/*
 * tmigr_set_cpu_active - Propagate the activation of a CPU
 * @group:	The group in which the CPU is activated
 * @evt:	The event which is removed from @group
 * @cpu:	The CPU which is activated
 */
static void tmigr_set_cpu_active(struct tmigr_group *group,
				 struct tmigr_event *evt,
				 unsigned int cpu)
{
	raw_spin_lock_nested(&group->lock, group->level);

	if (WARN_ON(group->active == group->num_childs)) {
		raw_spin_unlock(&group->lock);
		return;
	}

	cpumask_set_cpu(cpu, group->cpus);
	group->active++;

	/* The first active cpu in a group takes the migrator role */
	if (group->active == 1) {
		struct tmigr_group *parent = group->parent;

		group->migrator = cpu;
		/* Propagate through the hierarchy */
		if (parent)
			tmigr_set_cpu_active(parent, &group->groupevt, cpu);
	}

	trace_tmigr_group_set_cpu_active(group);

	/*
	 * Update groupevt and dequeue @evt. Must be called after parent
	 * groups have been updated above so @group->groupevt is inactive.
	 */
	tmigr_remove_evt(group, evt);
	raw_spin_unlock(&group->lock);
}

/**
 * tmigr_cpu_activate - Activate current CPU
 *
 * Called from the NOHZ and cpu online code.
 */
void tmigr_cpu_activate(void)
{
	struct tmigr_cpu *tmc = this_cpu_ptr(&tmigr_cpu);
	struct tmigr_group *group = tmc->tmgroup;
	int cpu = smp_processor_id();
	unsigned long flags;

	if (!tmc->online || !group)
		return;

	local_irq_save(flags);
	tmigr_set_cpu_active(group, &tmc->cpuevt, cpu);
	local_irq_restore(flags);
}

static void tmigr_free_group(struct tmigr_group *group)
{
	if (group->parent) {
		group->parent->num_childs--;
		if (!group->parent->num_childs)
			tmigr_free_group(group->parent);
	}
	trace_tmigr_group_free(group);
	list_del(&group->list);
	free_cpumask_var(group->cpus);
	kfree(group);
}

static void tmigr_init_group(struct tmigr_group *group, unsigned int lvl,
			     unsigned int node)
{
	raw_spin_lock_init(&group->lock);
	group->level = lvl;
	group->numa_node = lvl < tmigr_crossnode_level ? node : NUMA_NO_NODE;
	group->migrator = TMIGR_NONE;
	timerqueue_init_head(&group->events);
	timerqueue_init(&group->groupevt.nextevt);
	group->groupevt.group = group;
	group->groupevt.nextevt.expires = KTIME_MAX;
	group->groupevt.cpu = TMIGR_NONE;
	group->num_childs = 1;
}

static struct tmigr_group *tmigr_get_group(unsigned int node, unsigned int lvl)
{
	struct tmigr_group *group;

	/* Try to attach to an exisiting group first */
	list_for_each_entry(group, &tmigr_level_list[lvl], list) {
		/*
		 * If @lvl is below the cross numa node level, check
		 * whether this group belongs to the same numa node.
		 */
		if (lvl < tmigr_crossnode_level && group->numa_node != node)
			continue;
		/* If the group has capacity, use it */
		if (group->num_childs < tmigr_childs_per_group) {
			group->num_childs++;
			return group;
		}
	}
	/* Allocate and set up a new group */
	group = kzalloc_node(sizeof(*group), GFP_KERNEL, node);
	if (!group)
		return ERR_PTR(-ENOMEM);

	if (!zalloc_cpumask_var_node(&group->cpus, GFP_KERNEL, node)) {
		kfree(group);
		return ERR_PTR(-ENOMEM);
	}
	tmigr_init_group(group, lvl, node);
	/* Setup successful. Add it to the hierarchy */
	list_add(&group->list, &tmigr_level_list[lvl]);
	trace_tmigr_group_set(group);
	return group;
}

static int tmigr_setup_parents(unsigned int lvl)
{
	struct list_head *lvllist = &tmigr_level_list[lvl];
	struct tmigr_group *group, *parent;
	int ret = 0;

	/* End of hierarchy reached? */
	if (list_is_singular(lvllist))
		return 0;

	DBG_BUG_ON(lvl == tmigr_hierarchy_levels);

	list_for_each_entry(group, lvllist, list) {
		if (group->parent)
			continue;
		parent = tmigr_get_group(group->numa_node, lvl + 1);
		if (IS_ERR(parent))
			return PTR_ERR(parent);

		raw_spin_lock_irq(&group->lock);
		group->parent = parent;
		if (group->active)
			tmigr_set_cpu_active(parent, NULL, group->migrator);
		raw_spin_unlock_irq(&group->lock);
		trace_tmigr_group_setup_parents(group);
		ret = 1;
	}
	return ret;
}

static int tmigr_check_hierarchy(void)
{
	int lvl, ret = 0;

	for (lvl = 0; lvl < tmigr_hierarchy_levels; lvl++) {
		ret = tmigr_setup_parents(lvl);
		if (ret != 1)
			break;
	}
	return ret;
}

static struct tmigr_group *tmigr_add_cpu(unsigned int cpu)
{
	unsigned int node = cpu_to_node(cpu);
	struct tmigr_group *group;

	mutex_lock(&tmigr_mutex);
	group = tmigr_get_group(node, 0);
	if (IS_ERR(group))
		goto out;
	/*
	 * If the group was newly allocated, connect it
	 * to parent group(s) if necessary.
	 */
	if (group->num_childs == 1) {
		int ret = tmigr_check_hierarchy();

		if (ret < 0) {
			tmigr_free_group(group);
			group = ERR_PTR(ret);
		}
	}
out:
	mutex_unlock(&tmigr_mutex);
	return group;
}

static int tmigr_cpu_online(unsigned int cpu)
{
	struct tmigr_cpu *tmc = this_cpu_ptr(&tmigr_cpu);
	struct tmigr_group *group;

	/* First online attempt? Initialize cpu data */
	if (!tmc->tmgroup) {
		raw_spin_lock_init(&tmc->lock);
		timerqueue_init(&tmc->cpuevt.nextevt);
		tmc->cpuevt.group = NULL;
		tmc->cpuevt.cpu = cpu;
		group = tmigr_add_cpu(cpu);
		if (IS_ERR(group))
			return PTR_ERR(group);
		tmc->tmgroup = group;
	}
	tmc->online = true;
	tmigr_cpu_activate();
	return 0;
}

static int tmigr_cpu_offline(unsigned int cpu)
{
	struct tmigr_cpu *tmc = this_cpu_ptr(&tmigr_cpu);
	struct tmigr_group *group = tmc->tmgroup;

	local_irq_disable();
	tmc->online = false;
	tmigr_set_cpu_inactive(group, NULL, NULL, cpu);
	local_irq_enable();

	return 0;
}

static int __init tmigr_init(void)
{
	unsigned int cpulvl, nodelvl, cpus_per_node, i;
	unsigned int nnodes = num_possible_nodes();
	unsigned int ncpus = num_possible_cpus();
	struct tmigr_group *group;
	int ret = -ENOMEM;
	size_t sz;

	/* Nothing to do if running on UP */
	if (ncpus == 1)
		return 0;
	/*
	 * Calculate the required hierarchy levels. Unfortunately there is
	 * no reliable information available, unless all possible CPUs have
	 * been brought up and all numa nodes are populated.
	 *
	 * Estimate the number of levels with the number of possible nodes and
	 * the number of possible cpus. Assume CPUs are spread evenly accross
	 * nodes.
	 */
	cpus_per_node = DIV_ROUND_UP(ncpus, nnodes);
	/* Calc the hierarchy levels required to hold the CPUs of a node */
	cpulvl = DIV_ROUND_UP(order_base_2(cpus_per_node),
			      ilog2(tmigr_childs_per_group));
	/* Calculate the extra levels to connect all nodes */
	nodelvl = DIV_ROUND_UP(order_base_2(nnodes),
			       ilog2(tmigr_childs_per_group));

	tmigr_hierarchy_levels = cpulvl + nodelvl;
	/*
	 * If a numa node spawns more than one CPU level group then the
	 * next level(s) of the hierarchy contains groups which handle all
	 * CPU groups of the same numa node. The level above goes accross
	 * numa nodes. Store this information for the setup code to decide
	 * when node matching is not longer required.
	 */
	tmigr_crossnode_level = cpulvl;

	sz = sizeof(struct list_head) * tmigr_hierarchy_levels;
	tmigr_level_list = kzalloc(sz, GFP_KERNEL);
	if (!tmigr_level_list)
		goto err;

	for (i = 0; i < tmigr_hierarchy_levels; i++)
		INIT_LIST_HEAD(&tmigr_level_list[i]);

	ret = cpuhp_setup_state(CPUHP_AP_TMIGR_ONLINE, "tmigr:online",
				tmigr_cpu_online, tmigr_cpu_offline);
	if (ret)
		goto hp_err;

	tmigr_enabled = true;
	pr_info("Timer migration: %d hierarchy levels\n", tmigr_hierarchy_levels);
	return 0;

hp_err:
	/* Walk levels and free already allocated groups */
	for (i = 0; i < tmigr_hierarchy_levels; i++) {
		list_for_each_entry(group, &tmigr_level_list[i], list)
			tmigr_free_group(group);
	}
	kfree(tmigr_level_list);
err:
	pr_err("Timer migration setup failed\n");
	return ret;
}
late_initcall(tmigr_init);
