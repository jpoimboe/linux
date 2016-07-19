#include <linux/sched.h>
#include <asm/ptrace.h>
#include <asm/bitops.h>
#include <asm/stacktrace.h>
#include <asm/unwind.h>

unsigned long unwind_get_return_address(struct unwind_state *state)
{
	unsigned long addr, graph_addr;

	if (state->stack_info.type == STACK_TYPE_UNKNOWN)
		return 0;

	addr = *unwind_get_return_address_ptr(state);
	graph_addr = ftrace_graph_ret_addr(state->task, &state->graph_idx,
					   addr);
	return graph_addr ? : addr;
}
EXPORT_SYMBOL_GPL(unwind_get_return_address);

/*
 * This determines if the frame pointer actually contains an encoded pointer to
 * pt_regs on the stack.  See ENCODE_FRAME_POINTER.
 */
static struct pt_regs *decode_frame_pointer(struct unwind_state *state,
					    unsigned long *bp)
{
	struct pt_regs *regs = (struct pt_regs *)bp;
	unsigned long *task_begin = task_stack_page(state->task);
	unsigned long *task_end   = task_stack_page(state->task) + THREAD_SIZE;

	if (test_and_set_bit(BITS_PER_LONG - 1, (unsigned long *)&regs))
		return NULL;

	if (on_stack(&state->stack_info, regs, sizeof(*regs)))
		return regs;

	if ((unsigned long *)regs >= task_begin &&
	    (unsigned long *)regs < task_end &&
	    (unsigned long *)(regs + 1) <= task_end)
		return regs;

	return NULL;
}

static unsigned long *update_stack_state(struct unwind_state *state, void *addr,
					 size_t len)
{
	struct stack_info *info = &state->stack_info;
	unsigned long *sp;

	if (on_stack(info, addr, len))
		return addr;

	sp = info->next;
	if (!sp)
		goto unknown;

	if (get_stack_info(sp, state->task, info, &state->stack_mask))
		goto unknown;

	if (!on_stack(info, addr, len))
		goto unknown;

	return sp;

unknown:
	info->type = STACK_TYPE_UNKNOWN;
	return NULL;
}

static bool unwind_next_frame_bp(struct unwind_state *state, unsigned long *bp)
{
	unsigned long *sp;

	sp = update_stack_state(state, bp, sizeof(*bp) * 2);
	if (state->stack_info.type == STACK_TYPE_UNKNOWN)
		return false;

	state->bp = bp;
	state->sp = sp;

	return true;
}

static bool unwind_next_frame_regs(struct unwind_state *state,
				   struct pt_regs *regs)
{
	update_stack_state(state, regs, sizeof(*regs));
	if (state->stack_info.type == STACK_TYPE_UNKNOWN)
		return false;

	state->regs = regs;

	return unwind_next_frame_bp(state, (unsigned long *)regs->bp);
}

bool unwind_next_frame(struct unwind_state *state)
{
	struct pt_regs *regs;
	unsigned long *bp;

	state->regs = NULL;

	if (unwind_done(state))
		return false;

	bp = (unsigned long *)*state->bp;
	regs = decode_frame_pointer(state, bp);
	if (regs)
		return unwind_next_frame_regs(state, regs);

	return unwind_next_frame_bp(state, bp);
}
EXPORT_SYMBOL_GPL(unwind_next_frame);

void __unwind_start(struct unwind_state *state, struct task_struct *task,
		    struct pt_regs *regs, unsigned long *sp)
{
	memset(state, 0, sizeof(*state));

	state->task = task;
	state->sp = sp;
	state->bp = get_frame_pointer(task, regs);
	state->regs = NULL;

	get_stack_info(sp, state->task, &state->stack_info, &state->stack_mask);

	/* unwind to the first frame after the user-specified stack pointer */
	while (state->bp < sp && !unwind_done(state))
		unwind_next_frame(state);
}
EXPORT_SYMBOL_GPL(__unwind_start);
