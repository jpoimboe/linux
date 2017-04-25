#ifndef __ASM_X86_REFCOUNT_H
#define __ASM_X86_REFCOUNT_H
/*
 * x86-specific implementation of refcount_t. Ported from PAX_REFCOUNT in
 * PaX/grsecurity and changed to use "js" instead of "jo" to trap on all
 * signed results, not just when overflowing.
 */
#include <linux/refcount.h>
#include <asm/irq_vectors.h>

#define __REFCOUNT_EXCEPTION(size)			\
	".if "__stringify(size)" == 4\n\t"		\
	".pushsection .text.refcount_overflow\n"	\
	".elseif "__stringify(size)" == -4\n\t"		\
	".pushsection .text.refcount_underflow\n"	\
	".else\n"					\
	".error \"invalid size\"\n"			\
	".endif\n"					\
	"111:\tlea %[counter],%%"_ASM_CX"\n\t"		\
	"int $"__stringify(X86_REFCOUNT_VECTOR)"\n"	\
	"222:\n\t"					\
	".popsection\n"					\
	"333:\n"					\
	_ASM_EXTABLE(222b, 333b)

#define __REFCOUNT_CHECK(size)				\
	"js 111f\n"					\
	__REFCOUNT_EXCEPTION(size)

#define __REFCOUNT_ERROR(size)				\
	"jmp 111f\n"					\
	__REFCOUNT_EXCEPTION(size)

#define REFCOUNT_CHECK_OVERFLOW(size)	__REFCOUNT_CHECK(size)
#define REFCOUNT_CHECK_UNDERFLOW(size)	__REFCOUNT_CHECK(-(size))

static __always_inline void refcount_add(unsigned int i, refcount_t *r)
{
	asm volatile(LOCK_PREFIX "addl %1,%0\n\t"
		REFCOUNT_CHECK_OVERFLOW(4)
		: [counter] "+m" (r->refs.counter)
		: "ir" (i)
		: "cc", "cx");
}

static __always_inline void refcount_inc(refcount_t *r)
{
	asm volatile(LOCK_PREFIX "incl %0\n\t"
		REFCOUNT_CHECK_OVERFLOW(4)
		: [counter] "+m" (r->refs.counter)
		: : "cc", "cx");
}

static __always_inline void refcount_dec(refcount_t *r)
{
	asm volatile(LOCK_PREFIX "decl %0\n\t"
		REFCOUNT_CHECK_UNDERFLOW(4)
		: [counter] "+m" (r->refs.counter)
		: : "cc", "cx");
}

static __always_inline __must_check
bool refcount_sub_and_test(unsigned int i, refcount_t *r)
{
	GEN_BINARY_SUFFIXED_RMWcc(LOCK_PREFIX "subl",
				REFCOUNT_CHECK_UNDERFLOW(4), r->refs.counter,
				"er", i, "%0", e);
}

static __always_inline __must_check bool refcount_dec_and_test(refcount_t *r)
{
	GEN_UNARY_SUFFIXED_RMWcc(LOCK_PREFIX "decl",
				REFCOUNT_CHECK_UNDERFLOW(4), r->refs.counter,
				"%0", e);
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
		asm volatile(__REFCOUNT_ERROR(4)
			: : [counter] "m" (r->refs.counter)
			: "cc", "cx");
	}

	return c != 0;
}

#endif
