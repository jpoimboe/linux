#include <linux/sched.h>
#include <linux/ftrace.h>
#include <asm/ptrace.h>
#include <asm/bitops.h>
#include <asm/stacktrace.h>
#include <asm/unwind.h>

bool unwind_next_frame(struct unwind_state *state)
{
	struct stack_info *info = &state->stack_info;

	if (info->type == STACK_TYPE_UNKNOWN)
		return false;

	do {
		for (state->sp++; state->sp < info->end; state->sp++)
			if (__kernel_text_address(*state->sp))
				return true;

		state->sp = info->next_sp;

	} while (!get_stack_info(state->sp, state->task, info,
				 &state->stack_mask));

	return false;
}

void __unwind_start(struct unwind_state *state, struct task_struct *task,
		    struct pt_regs *regs, unsigned long *sp)
{
	memset(state, 0, sizeof(*state));

	state->task = task;
	state->sp   = sp;

	get_stack_info(sp, state->task, &state->stack_info, &state->stack_mask);

	if (!__kernel_text_address(*sp))
		unwind_next_frame(state);
}
