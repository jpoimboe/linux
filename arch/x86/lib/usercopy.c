/*
 * User address space access functions.
 *
 *  For licencing details see kernel-base/COPYING
 */

#include <linux/highmem.h>
#include <linux/export.h>

#include <asm/word-at-a-time.h>
#include <linux/sched.h>
#include <asm/unwind.h>

/*
 * We rely on the nested NMI work to allow atomic faults from the NMI path; the
 * nested NMI paths are careful to preserve CR2.
 */
unsigned long
copy_from_user_nmi(void *to, const void __user *from, unsigned long n)
{
	unsigned long ret;

	if (__range_not_ok(from, n, TASK_SIZE))
		return n;

	/*
	 * Even though this function is typically called from NMI/IRQ context
	 * disable pagefaults so that its behaviour is consistent even when
	 * called form other contexts.
	 */
	pagefault_disable();
	ret = __copy_from_user_inatomic(to, from, n);
	pagefault_enable();

	return ret;
}
EXPORT_SYMBOL_GPL(copy_from_user_nmi);

#if defined(CONFIG_HARDENED_USERCOPY) && defined(CONFIG_FRAME_POINTER)
/*
 * Walks up the stack frames to make sure that the specified object is
 * entirely contained by a single stack frame.
 *
 * Returns:
 *		 1 if within a frame
 *		-1 if placed across a frame boundary (or outside stack)
 *		 0 unable to determine (no frame pointers, etc)
 */
int arch_within_stack_frames(const void * const stack,
			     const void * const stackend,
			     const void *obj, unsigned long len)
{
	const void *frame = NULL;
	const void *oldframe;

	oldframe = __builtin_frame_address(2);
	if (oldframe)
		frame = __builtin_frame_address(3);
	/*
	 * low ----------------------------------------------> high
	 * [saved bp][saved ip][args][local vars][saved bp][saved ip]
	 *                     ^----------------^
	 *               allow copies only within here
	 */
	while (stack <= frame && frame < stackend) {
		/*
		 * If obj + len extends past the last frame, this
		 * check won't pass and the next frame will be 0,
		 * causing us to bail out and correctly report
		 * the copy as invalid.
		 */
		if (obj + len <= frame)
			return obj >= oldframe + 2 * sizeof(void *) ? 1 : -1;
		oldframe = frame;
		frame = *(const void * const *)frame;
	}
	return -1;
}
#endif /* CONFIG_HARDENED_USERCOPY && CONFIG_FRAME_POINTER */
