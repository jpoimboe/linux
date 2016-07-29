#include <linux/sched.h>
#include <asm/ptrace.h>
#include <asm/bitops.h>
#include <asm/stacktrace.h>
#include <asm/unwind.h>

#define FRAME_HEADER_SIZE (sizeof(long) * 2)

unsigned long unwind_get_return_address(struct unwind_state *state)
{
	unsigned long addr;
	unsigned long *addr_p = unwind_get_return_address_ptr(state);

	if (state->stack_info.type == STACK_TYPE_UNKNOWN)
		return 0;

	if (state->regs && user_mode(state->regs))
		return 0;

	/*
	 * This catches an awkward code path where do_execve() is called by a
	 * kernel thread from ret_from_fork.  There's a window where PF_KTHREAD
	 * has been cleared but regs->cs still indicates kernel mode.
	 */
	if (state->regs == task_pt_regs(state->task))
		return 0;

	addr = ftrace_graph_ret_addr(state->task, &state->graph_idx, *addr_p,
				     addr_p);

	if (!__kernel_text_address(addr)) {
		printk_deferred_once(KERN_WARNING
			"WARNING: unrecognized kernel stack return address %p at %p in %s:%d\n",
			(void *)addr, addr_p, state->task->comm,
			state->task->pid);
		return 0;
	}

	return addr;
}
EXPORT_SYMBOL_GPL(unwind_get_return_address);

static bool is_last_task_frame(struct unwind_state *state)
{
	unsigned long bp = (unsigned long)state->bp;
	unsigned long regs = (unsigned long)task_pt_regs(state->task);

	return bp == regs - FRAME_HEADER_SIZE;
}

/*
 * This determines if the frame pointer actually contains an encoded pointer to
 * pt_regs on the stack.  See ENCODE_FRAME_POINTER.
 */
static struct pt_regs *decode_frame_pointer(unsigned long *bp)
{
	unsigned long regs = (unsigned long)bp;

	/* if the MSB is set, it's not an encoded pointer */
	if (regs & (1UL << (BITS_PER_LONG - 1)))
		return NULL;

	/* decode it by setting the MSB */
	regs |= 1UL << (BITS_PER_LONG - 1);

	return (struct pt_regs *)regs;
}

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
	struct pt_regs *regs;
	unsigned long *next_bp, *next_sp;
	size_t next_len;

	if (unwind_done(state))
		return false;

	/* have we reached the end? */
	if (state->regs && user_mode(state->regs))
		goto the_end;

	if (is_last_task_frame(state)) {
		if ((state->task->flags & PF_KTHREAD))
			goto the_end;

		/*
		 * Entry code doesn't encode the pt_regs pointer on syscalls,
		 * so manually set the regs here.
		 */
		state->regs = task_pt_regs(state->task);
		state->bp = NULL;
		return true;
	}

	/* get the next frame pointer */
	if (state->regs)
		next_bp = (unsigned long *)state->regs->bp;
	else
		next_bp = (unsigned long *)*state->bp;

	/* is the next frame pointer an encoded pointer to pt_regs? */
	regs = decode_frame_pointer(next_bp);
	if (regs) {
		next_sp = (unsigned long *)regs;
		next_len = sizeof(*regs);
	} else {
		next_sp = next_bp;
		next_len = FRAME_HEADER_SIZE;
	}

	/* make sure the next frame's data is accessible */
	if (!update_stack_state(state, next_sp, next_len))
		goto bad_address;

	/* move to the next frame */
	if (regs) {
		state->regs = regs;
		state->bp = NULL;
	} else {
		state->bp = next_bp;
		state->regs = NULL;
	}

	return true;

bad_address:
	if (state->regs)
		printk_deferred_once(KERN_WARNING
			"WARNING: kernel stack regs at %p in %s:%d has bad 'bp' value %p\n",
			state->regs, state->task->comm,
			state->task->pid, next_bp);
	else
		printk_deferred_once(KERN_WARNING
			"WARNING: kernel stack frame pointer at %p in %s:%d has bad value %p\n",
			state->bp, state->task->comm,
			state->task->pid, next_bp);
the_end:
	state->stack_info.type = STACK_TYPE_UNKNOWN;
	return false;
}
EXPORT_SYMBOL_GPL(unwind_next_frame);

void __unwind_start(struct unwind_state *state, struct task_struct *task,
		    struct pt_regs *regs, unsigned long *start_sp)
{
	unsigned long *bp, *sp;
	size_t len;

	memset(state, 0, sizeof(*state));
	state->task = task;

	/* don't even attempt to start from user-mode regs */
	if (regs && user_mode(regs))
		return;

	/* set up the first stack frame */
	bp = get_frame_pointer(task, regs);
	regs = decode_frame_pointer(bp);
	if (regs) {
		state->regs = regs;
		sp = (unsigned long *)regs;
		len = sizeof(*regs);
	}
	else {
		state->bp = bp;
		sp = bp;
		len = FRAME_HEADER_SIZE;
	}

	/* initialize stack info and make sure the frame data is accessible */
	get_stack_info(sp, state->task, &state->stack_info, &state->stack_mask);
	update_stack_state(state, sp, len);

	/* skip any irrelevant stack frames */
	while (state->bp < start_sp && !unwind_done(state))
		unwind_next_frame(state);
}
EXPORT_SYMBOL_GPL(__unwind_start);
