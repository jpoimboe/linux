#ifndef _ASM_X86_UNWIND_H
#define _ASM_X86_UNWIND_H

#include <linux/sched.h>
#include <linux/ftrace.h>
#include <asm/ptrace.h>
#include <asm/stacktrace.h>

struct unwind_state {
	struct stack_info stack_info;
	unsigned long stack_mask;
	struct task_struct *task;
	unsigned long *sp;
	int graph_idx;
#ifdef CONFIG_FRAME_POINTER
	unsigned long *bp;
	struct pt_regs *regs;
#endif
};

void __unwind_start(struct unwind_state *state, struct task_struct *task,
		    struct pt_regs *regs, unsigned long *sp);

bool unwind_next_frame(struct unwind_state *state);


#ifdef CONFIG_FRAME_POINTER

static inline unsigned long *unwind_get_return_address_ptr(struct unwind_state *state)
{
	if (state->stack_info.type == STACK_TYPE_UNKNOWN)
		return NULL;

	return state->bp + 1;
}

unsigned long unwind_get_return_address(struct unwind_state *state);

static inline struct pt_regs *unwind_get_entry_regs(struct unwind_state *state)
{
	return state->regs;
}

#else /* !CONFIG_FRAME_POINTER */

static inline unsigned long *unwind_get_return_address_ptr(struct unwind_state *state)
{
	return NULL;
}

static inline unsigned long unwind_get_return_address(struct unwind_state *state)
{
	if (state->stack_info.type == STACK_TYPE_UNKNOWN)
		return 0;

	return *state->sp;
}

static inline struct pt_regs *unwind_get_entry_regs(struct unwind_state *state)
{
	return NULL;
}

#endif /* CONFIG_FRAME_POINTER */

static inline unsigned long *unwind_get_stack_ptr(struct unwind_state *state)
{
	if (state->stack_info.type == STACK_TYPE_UNKNOWN)
		return NULL;

	return state->sp;
}

static inline bool unwind_done(struct unwind_state *state)
{
	return (state->stack_info.type == STACK_TYPE_UNKNOWN);
}

static inline
void unwind_start(struct unwind_state *state, struct task_struct *task,
		  struct pt_regs *regs, unsigned long *sp)
{
	if (!task)
		task = current;

	sp = sp ? : get_stack_pointer(task, regs);

	__unwind_start(state, task, regs, sp);
}

#endif /* _ASM_X86_UNWIND_H */
