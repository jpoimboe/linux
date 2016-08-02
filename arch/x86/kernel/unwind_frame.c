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

	if (!__kernel_text_address(addr)) {
		printk_deferred_once(KERN_WARNING "WARNING: unrecognized kernel stack return address %p in %s:%d\n",
			(void *)addr, state->task->comm, state->task->pid);
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

#ifdef CONFIG_X86_64
/*
 * This determines if the frame pointer actually contains an encoded pointer to
 * pt_regs on the stack.  See ENCODE_FRAME_POINTER.
 */
static struct pt_regs *decode_frame_pointer(struct unwind_state *state,
					    unsigned long bp)
{
	struct pt_regs *regs;
	unsigned long *task_begin = task_stack_page(state->task);
	unsigned long *task_end   = task_stack_page(state->task) + THREAD_SIZE;

	/* if the MSB is set, it's not an encoded pointer */
	if (bp & (1UL << (BITS_PER_LONG - 1)))
		return NULL;

	/* decode it by setting the MSB */
	bp |= 1UL << (BITS_PER_LONG - 1);
	regs = (struct pt_regs *)bp;

	/* make sure the regs are on the current unwind_state stack */
	if (on_stack(&state->stack_info, regs, sizeof(*regs)))
		return regs;

	/*
	 * The regs might have been placed on the task stack before entry code
	 * switched to the irq stack.
	 */
	if (state->stack_info.type == STACK_TYPE_IRQ &&
	    state->stack_info.next_sp >= task_begin &&
	    state->stack_info.next_sp < task_end &&
	    (unsigned long *)regs >= task_begin &&
	    (unsigned long *)regs < task_end &&
	    (unsigned long *)(regs + 1) <= task_end)
		return regs;

	return NULL;
}
#else
static struct pt_regs *decode_frame_pointer(struct unwind_state *state,
					    unsigned long bp)
{
	return NULL;
}
#endif

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
	unsigned long *next_bp;
	enum stack_type prev_type = state->stack_info.type;

	state->regs = NULL;

	if (unwind_done(state))
		return false;

	/*
	 * The entry code doesn't encode pt_regs on syscalls, so check for them
	 * here.  The last frame pointer and associated syscall pt_regs (for
	 * user tasks) are always at a standard location at the end of the task
	 * stack.  If we've reached the end, go ahead and exit early to avoid
	 * trying to decode an invalid frame pointer.
	 */
	if (is_last_task_frame(state)) {
		if (!(state->task->flags & PF_KTHREAD))
			state->regs = task_pt_regs(state->task);
		state->stack_info.type = STACK_TYPE_UNKNOWN;
		return false;
	}

	next_bp = (unsigned long *)*state->bp;

	/*
	 * Check if the next frame pointer is really an encoded pt_regs
	 * pointer.
	 */
	regs = decode_frame_pointer(state, (unsigned long)next_bp);
	if (regs) {
		/*
		 * We may need to switch to the next stack to access the regs.
		 * This can happen when switching from the IRQ stack: the
		 * encoded regs pointer is on the IRQ stack but the regs
		 * themselves are on the task stack.
		 */
		if (!update_stack_state(state, regs, sizeof(*regs))) {
			printk_deferred_once(KERN_WARNING "WARNING: kernel stack frame pointer at %p in %s:%d decodes to bad regs pointer %p\n",
				state->bp, state->task->comm, state->task->pid,
				regs);

			return false;
		}

		/*
		 * The regs are now safe to access and are made available to
		 * the user even if we've reached the end.
		 */
		state->regs = regs;

		if (user_mode(regs)) {
			/* reached the end */
			state->stack_info.type = STACK_TYPE_UNKNOWN;
			return false;
		}

		next_bp = (unsigned long *)regs->bp;
	}

	/*
	 * Make sure the next frame is on a valid stack and can be accessed
	 * safely.
	 */
	if (!update_stack_state(state, next_bp, FRAME_HEADER_SIZE)) {
		/*
		 * The next frame isn't on a valid stack, and we haven't
		 * reached the end, which means something went wrong: either a
		 * bad next stack pointer or a bad frame pointer.
		 */
		if (state->regs)
			printk_deferred_once(KERN_WARNING "WARNING: kernel stack regs->bp at %p in %s:%d points to bad address %p\n",
				state->bp, state->task->comm,
				state->task->pid, regs);
		else
			printk_deferred_once(KERN_WARNING "WARNING: kernel stack frame pointer at %p in %s:%d points to bad address %p\n",
				state->bp, state->task->comm,
				state->task->pid, next_bp);

		return false;
	}

	/* make sure the stack only unwinds up */
	if (state->stack_info.type == prev_type && next_bp <= state->bp) {
		printk_deferred_once(KERN_WARNING "WARNING: kernel stack frame pointer at %p in %s:%d points the wrong way (%p)\n",
				     state->bp, state->task->comm,
				     state->task->pid, next_bp);
		state->stack_info.type = STACK_TYPE_UNKNOWN;
		return false;
	}

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
	state->regs = NULL;

	get_stack_info(state->bp, state->task, &state->stack_info,
		       &state->stack_mask);
	update_stack_state(state, state->bp, FRAME_HEADER_SIZE);

	/* unwind to the first frame after the specified stack pointer */
	while (state->bp < sp && !unwind_done(state))
		unwind_next_frame(state);
}
EXPORT_SYMBOL_GPL(__unwind_start);
