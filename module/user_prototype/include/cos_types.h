#ifndef TYPES_H
#define TYPES_H

#define MNULL ((void*)0)

/* 
 * These types are for addresses that are never meant to be
 * dereferenced.  They will generally be used to set up page table
 * entries.
 */
typedef unsigned long phys_addr_t;
typedef unsigned long vaddr_t;
typedef unsigned int page_index_t;

#define MAX_ISOLATION_LVL_VAL 3
#define IL_INV_UNMAP 0x1 // when invoking, should we be unmapped?
#define IL_RET_UNMAP 0x2 // when returning, should we unmap?
/*
 * Note on Symmetric Trust, Symmetric Distruct, and Asym trust: 
 * ST iff (flags & (CAP_INV_UNMAP|CAP_RET_UNMAP) == 0)
 * SDT iff (flags & CAP_INV_UNMAP && flags & CAP_RET_UNMAP)
 * AST iff (!(flags & CAP_INV_UNMAP) && flags & CAP_RET_UNMAP)
 */
#define IL_ST  (0)
#define IL_SDT (CAP_INV_UNMAP|CAP_RET_UNMAP)
#define IL_AST (CAP_RET_UNMAP)
typedef unsigned int isolation_level_t;

typedef struct { volatile unsigned int counter; } atomic_t;

#ifdef CONFIG_SMP
#define LOCK "lock ; "
#else
#define LOCK ""
#endif

#define ATOMIC_INIT(i)	{ (i) }

static __inline__ void set_atomic(atomic_t *a, unsigned int val)
{
	a->counter = val;

	return;
}

/**
 * atomic_dec - decrement atomic variable
 * @v: pointer of type atomic_t
 * 
 * Atomically decrements @v by 1.
 */ 
static __inline__ void atomic_inc(atomic_t *v)
{
	__asm__ __volatile__(
		LOCK "incl %0"
		:"=m" (v->counter)
		:"m" (v->counter));
}

/**
 * atomic_dec - decrement atomic variable
 * @v: pointer of type atomic_t
 * 
 * Atomically decrements @v by 1.
 */ 
static __inline__ void atomic_dec(atomic_t *v)
{
	__asm__ __volatile__(
		LOCK "decl %0"
		:"=m" (v->counter)
		:"m" (v->counter));
}

/**
 * atomic_dec_and_test - decrement and test
 * @v: pointer of type atomic_t
 * 
 * Atomically decrements @v by 1 and
 * returns true if the result is 0, or false for all other
 * cases.
 */ 
static __inline__ int atomic_dec_and_test(atomic_t *v)
{
	unsigned char c;

	__asm__ __volatile__(
		LOCK "decl %0; sete %1"
		:"=m" (v->counter), "=qm" (c)
		:"m" (v->counter) : "memory");
	return c != 0;
}

#endif /* TYPES_H */