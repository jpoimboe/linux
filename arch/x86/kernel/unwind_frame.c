#include <linux/sched.h>
#include <asm/ptrace.h>
#include <asm/bitops.h>
#include <asm/stacktrace.h>
#include <asm/unwind.h>

#define FRAME_HEADER_SIZE (sizeof(long) * 2)

unsigned long unwind_get_return_address(struct unwind_state *state)
{
	unsigned long *addr_p = unwind_get_return_address_ptr(state);
	unsigned long addr;

	if (state->stack_info.type == STACK_TYPE_UNKNOWN)
		return 0;

	addr = ftrace_graph_ret_addr(state->task, &state->graph_idx, *addr_p,
				     addr_p);

	return __kernel_text_address(addr) ? addr : 0;
}
EXPORT_SYMBOL_GPL(unwind_get_return_address);

static bool update_stack_state(struct unwind_state *state, void *addr,
			       size_t len)
{
	struct stack_info *info = &state->stack_info;

	if (on_stack(info, addr, len))
		return true;

	if (get_stack_info(info->next_sp, state->task, info,
			   &state->stack_mask))
		goto unknown;

	if (!on_stack(info, addr, len))
		goto unknown;

	return true;

unknown:
	info->type = STACK_TYPE_UNKNOWN;
	return false;
}

bool unwind_next_frame(struct unwind_state *state)
{
	unsigned long *next_bp;

	if (unwind_done(state))
		return false;

	next_bp = (unsigned long *)*state->bp;

	/*
	 * Make sure the next frame is on a valid stack and can be accessed
	 * safely.
	 */
	if (!update_stack_state(state, next_bp, FRAME_HEADER_SIZE))
		return false;

	/* move to the next frame */
	state->bp = next_bp;
	return true;
}
EXPORT_SYMBOL_GPL(unwind_next_frame);

void __unwind_start(struct unwind_state *state, struct task_struct *task,
		    struct pt_regs *regs, unsigned long *sp)
{
	memset(state, 0, sizeof(*state));

	state->task = task;
	state->bp = get_frame_pointer(task, regs);

	get_stack_info(state->bp, state->task, &state->stack_info,
		       &state->stack_mask);
	update_stack_state(state, state->bp, FRAME_HEADER_SIZE);

	/* unwind to the first frame after the specified stack pointer */
	while (state->bp < sp && !unwind_done(state))
		unwind_next_frame(state);
}
EXPORT_SYMBOL_GPL(__unwind_start);
