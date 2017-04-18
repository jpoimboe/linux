#undef TRACE_SYSTEM
#define TRACE_SYSTEM timer_migration

#if !defined(_TRACE_TIMER_MIGRATION_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_TIMER_MIGRATION_H

#include <linux/tracepoint.h>

/* Group events */
DECLARE_EVENT_CLASS(tmigr_group,

	TP_PROTO(struct tmigr_group *group),

	TP_ARGS(group),

	TP_STRUCT__entry(
		__field( void *,	group	)
		__field( void *,	parent	)
		__field( u64,		nextevt	)
		__field( unsigned int,	lvl	)
		__field( unsigned int,	numa_node )
		__field( unsigned int,	active )
		__field( unsigned int,	migrator )
		__field( unsigned int,	num_childs )
		__field( unsigned int,	evtcpu	)
	),

	TP_fast_assign(
		__entry->group		= group;
		__entry->lvl		= group->level;
		__entry->numa_node	= group->numa_node;
		__entry->active		= group->active;
		__entry->migrator	= group->migrator;
		__entry->num_childs	= group->num_childs;
		__entry->parent		= group->parent;
		__entry->nextevt	= group->groupevt.nextevt.expires;
		__entry->evtcpu		= group->groupevt.cpu;
	),

	TP_printk("group=%p lvl=%d numa=%d active=%d migrator=%d num_childs=%d "
		  "parent=%p nextevt=%llu evtcpu=%d",
		  __entry->group, __entry->lvl, __entry->numa_node,
		  __entry->active, __entry->migrator, __entry->num_childs,
		  __entry->parent, __entry->nextevt, __entry->evtcpu)
);

DEFINE_EVENT(tmigr_group, tmigr_group_addevt,

	TP_PROTO(struct tmigr_group *group),

	TP_ARGS(group)
);

DEFINE_EVENT(tmigr_group, tmigr_group_removeevt,

	TP_PROTO(struct tmigr_group *group),

	TP_ARGS(group)
);

DEFINE_EVENT(tmigr_group, tmigr_group_set_cpu_inactive,

	TP_PROTO(struct tmigr_group *group),

	TP_ARGS(group)
);

DEFINE_EVENT(tmigr_group, tmigr_group_set_cpu_active,

	TP_PROTO(struct tmigr_group *group),

	TP_ARGS(group)
);

DEFINE_EVENT(tmigr_group, tmigr_group_free,

	TP_PROTO(struct tmigr_group *group),

	TP_ARGS(group)
);

DEFINE_EVENT(tmigr_group, tmigr_group_set,

	TP_PROTO(struct tmigr_group *group),

	TP_ARGS(group)
);

DEFINE_EVENT(tmigr_group, tmigr_group_setup_parents,

	TP_PROTO(struct tmigr_group *group),

	TP_ARGS(group)
);

/* CPU events*/
DECLARE_EVENT_CLASS(tmigr_cpugroup,

	TP_PROTO(struct tmigr_cpu *tcpu, unsigned int cpu),

	TP_ARGS(tcpu, cpu),

	TP_STRUCT__entry(
		__field( void *,	parent)
		__field( unsigned int,	cpu)
	),

	TP_fast_assign(
		__entry->cpu		= cpu;
		__entry->parent		= tcpu->tmgroup;
	),

	TP_printk("cpu=%d parent=%p", __entry->cpu, __entry->parent)
);

DEFINE_EVENT(tmigr_cpugroup, tmigr_cpu_update_remote,

	TP_PROTO(struct tmigr_cpu *tcpu, unsigned int cpu),

	TP_ARGS(tcpu, cpu)
);

DEFINE_EVENT(tmigr_cpugroup, tmigr_cpu_add,

	TP_PROTO(struct tmigr_cpu *tcpu, unsigned int cpu),

	TP_ARGS(tcpu, cpu)
);

/* Other events */
TRACE_EVENT(tmigr_handle_remote,

	TP_PROTO(struct tmigr_group *group, unsigned int cpu),

	TP_ARGS(group, cpu),

	TP_STRUCT__entry(
		__field( void *,	group	)
		__field( void *,	parent	)
		__field( u64,		nextevt	)
		__field( unsigned int,	lvl	)
		__field( unsigned int,	numa_node )
		__field( unsigned int,	active )
		__field( unsigned int,	migrator )
		__field( unsigned int,	num_childs )
		__field( unsigned int,	evtcpu	)
		__field( unsigned int,	cpu	)
	),

	TP_fast_assign(
		__entry->group		= group;
		__entry->lvl		= group->level;
		__entry->numa_node	= group->numa_node;
		__entry->active		= group->active;
		__entry->migrator	= group->migrator;
		__entry->num_childs	= group->num_childs;
		__entry->parent		= group->parent;
		__entry->nextevt	= group->groupevt.nextevt.expires;
		__entry->evtcpu		= group->groupevt.cpu;
		__entry->cpu		= cpu;
	),

	TP_printk("group=%p lvl=%d numa=%d active=%d migrator=%d num_childs=%d "
		  "parent=%p nextevt=%llu evtcpu=%d cpu=%d",
		  __entry->group, __entry->lvl, __entry->numa_node,
		  __entry->active, __entry->migrator, __entry->num_childs,
		  __entry->parent, __entry->nextevt, __entry->evtcpu, __entry->cpu)
);

#endif /*  _TRACE_TIMER_MIGRATION_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
