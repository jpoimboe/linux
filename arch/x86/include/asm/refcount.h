#ifndef __ASM_X86_REFCOUNT_H
#define __ASM_X86_REFCOUNT_H
/*
 * x86-specific implementation of refcount_t. Ported from PAX_REFCOUNT
 * from PaX/grsecurity.
 */
#include <linux/refcount.h>

#define _REFCOUNT_EXCEPTION				\
	".pushsection .text.unlikely\n"			\
	"111:\tmovl $0x7fffffff, %[counter]\n"		\
	"112:\t" ASM_UD0 "\n"				\
	".popsection\n"					\
	"113:\n"					\
	_ASM_EXTABLE_REFCOUNT(112b, 113b)

#define REFCOUNT_CHECK					\
	"js 111f\n\t"					\
	_REFCOUNT_EXCEPTION

#define REFCOUNT_ERROR					\
	"jmp 111f\n\t"					\
	_REFCOUNT_EXCEPTION

static __always_inline void refcount_add(unsigned int i, refcount_t *r)
{
	asm volatile(LOCK_PREFIX "addl %1,%0\n\t"
		REFCOUNT_CHECK
		: [counter] "+m" (r->refs.counter)
		: "ir" (i)
		: "cc", "cx");
}

static __always_inline void refcount_inc(refcount_t *r)
{
	asm volatile(LOCK_PREFIX "incl %0\n\t"
		REFCOUNT_CHECK
		: [counter] "+m" (r->refs.counter)
		: : "cc", "cx");
}

static __always_inline void refcount_dec(refcount_t *r)
{
	asm volatile(LOCK_PREFIX "decl %0\n\t"
		REFCOUNT_CHECK
		: [counter] "+m" (r->refs.counter)
		: : "cc", "cx");
}

static __always_inline __must_check
bool refcount_sub_and_test(unsigned int i, refcount_t *r)
{
	GEN_BINARY_SUFFIXED_RMWcc(LOCK_PREFIX "subl", REFCOUNT_CHECK,
				  r->refs.counter, "er", i, "%0", e);
}

static __always_inline __must_check bool refcount_dec_and_test(refcount_t *r)
{
	GEN_UNARY_SUFFIXED_RMWcc(LOCK_PREFIX "decl", REFCOUNT_CHECK,
				 r->refs.counter, "%0", e);
}

static __always_inline __must_check bool refcount_inc_not_zero(refcount_t *r)
{
	int c;

	c = atomic_read(&(r->refs));
	do {
		if (unlikely(c <= 0))
			break;
	} while (!atomic_try_cmpxchg(&(r->refs), &c, c + 1));

	/* Did we start or finish in an undesirable state? */
	if (unlikely(c <= 0 || c + 1 < 0)) {
		asm volatile(REFCOUNT_ERROR
			: : [counter] "m" (r->refs.counter)
			: "cc", "cx");
	}

	return c != 0;
}

#endif
