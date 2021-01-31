/* NetHack 3.7	rnd.c	$NHDT-Date: 1596498205 2020/08/03 23:43:25 $  $NHDT-Branch: NetHack-3.7 $:$NHDT-Revision: 1.30 $ */
/*      Copyright (c) 2004 by Robert Patrick Rankin               */
/* NetHack may be freely redistributed.  See license for details. */

#include "hack.h"

#ifdef USE_ISAAC64
#include "isaac64.h"

static struct isaac64_ctx rnglist[RNG_INDEX_MAX] = { };

static void
init_isaac64(enum whichrng rng, unsigned long seed)
{
    unsigned char new_rng_state[sizeof seed];
    unsigned i;

    if (rng < 0 || rng >= RNG_INDEX_MAX)
        panic("Bad rng %d passed to init_isaac64().", rng);

    for (i = 0; i < sizeof seed; i++) {
        new_rng_state[i] = (unsigned char) (seed & 0xFF);
        seed >>= 8;
    }
    isaac64_init(&rnglist[rng], new_rng_state,
                 (int) sizeof new_rng_state);
}

static int
rng_RND(enum whichrng rng, int x)
{
    return (isaac64_next_uint64(&rnglist[rng]) % x);
}

#else   /* USE_ISAAC64 */

/* "Rand()"s definition is determined by [OS]conf.h */
#if defined(LINT) && defined(UNIX) /* rand() is long... */
extern int rand(void);
#define system_RND(x) (rand() % x)
#else /* LINT */
#if defined(UNIX) || defined(RANDOM)
#define system_RND(x) ((int) (Rand() % (long) (x)))
#else
/* Good luck: the bottom order bits are cyclic. */
#define system_RND(x) ((int) ((Rand() >> 3) % (x)))
#endif
#endif /* LINT */

static int
rng_RND(enum whichrng rng, int x)
{
    if (which_rng == RNG_DISP) {
        static unsigned seed = 1;
        seed *= 2739110765;
        return (int)((seed >> 16) % (unsigned)x);
    } else {
        return system_RND(x);
    }
}
#endif  /* USE_ISAAC64 */

/* Sets the seed for the random number generator */
#ifdef USE_ISAAC64

static void
set_random(enum whichrng rng, unsigned long seed)
{
    init_isaac64(rng, seed);
}

#else /* USE_ISAAC64 */

/*ARGSUSED*/
static void
set_random(enum whichrng rng, unsigned long seed)
{
    if (rng == RNG_DISP) return;

    /* the types are different enough here that sweeping the different
     * routine names into one via #defines is even more confusing
     */
# ifdef RANDOM /* srandom() from sys/share/random.c */
    srandom((unsigned int) seed);
# else
#  if defined(__APPLE__) || defined(BSD) || defined(LINUX) || defined(ULTRIX) \
    || defined(CYGWIN32) /* system srandom() */
#   if defined(BSD) && !defined(POSIX_TYPES) && defined(SUNOS4)
    (void)
#   endif
        srandom((int) seed);
#  else
#   ifdef UNIX /* system srand48() */
    srand48((long) seed);
#   else       /* poor quality system routine */
    srand((int) seed);
#   endif
#  endif
# endif
}

#endif /* USE_ISAAC64 */

/* An appropriate version of this must always be provided in
   port-specific code somewhere. It returns a number suitable
   as seed for the random number generator */
extern unsigned long sys_random_seed(void);

/*
 * Initializes the random number generator.
 * Only call once.
 */
void
init_random(enum whichrng rng)
{
    set_random(rng, sys_random_seed());
}

/* Reshuffles the random number generator. */
void
reseed_random(enum whichrng rng)
{
    /* only reseed if we are certain that the seed generation is unguessable
     * by the players. */
    if (has_strong_rngseed)
        init_random(rng);
}


/* 0 <= rn2(x) < x */
int
rng_rn2(enum whichrng rng, register int x)
{
#if (NH_DEVEL_STATUS != NH_STATUS_RELEASED)
    if (x <= 0) {
        impossible("rn2(%d) attempted", x);
        return 0;
    }
#endif
    return rng_RND(rng, x);
}

/* 0 <= rnl(x) < x; sometimes subtracting Luck;
   good luck approaches 0, bad luck approaches (x-1) */
int
rng_rnl(enum whichrng rng, register int x)
{
    register int i, adjustment;

#if (NH_DEVEL_STATUS != NH_STATUS_RELEASED)
    if (x <= 0) {
        impossible("rnl(%d) attempted", x);
        return 0;
    }
#endif

    adjustment = Luck;
    if (x <= 15) {
        /* for small ranges, use Luck/3 (rounded away from 0);
           also guard against architecture-specific differences
           of integer division involving negative values */
        adjustment = (abs(adjustment) + 1) / 3 * sgn(adjustment);
        /*
         *       11..13 ->  4
         *        8..10 ->  3
         *        5.. 7 ->  2
         *        2.. 4 ->  1
         *       -1,0,1 ->  0 (no adjustment)
         *       -4..-2 -> -1
         *       -7..-5 -> -2
         *      -10..-8 -> -3
         *      -13..-11-> -4
         */
    }

    i = rng_RND(rng, x);
    if (adjustment && rng_rn2(rng, 37 + abs(adjustment))) {
        i -= adjustment;
        if (i < 0)
            i = 0;
        else if (i >= x)
            i = x - 1;
    }
    return i;
}

/* 1 <= rnd(x) <= x */
int
rng_rnd(enum whichrng rng, register int x)
{
#if (NH_DEVEL_STATUS != NH_STATUS_RELEASED)
    if (x <= 0) {
        impossible("rnd(%d) attempted", x);
        return 1;
    }
#endif
    x = rng_RND(rng, x) + 1;
    return x;
}

/* d(N,X) == NdX == dX+dX+...+dX N times; n <= d(n,x) <= (n*x) */
int
rng_d(enum whichrng rng, register int n, register int x)
{
    register int tmp = n;

#if (NH_DEVEL_STATUS != NH_STATUS_RELEASED)
    if (x < 0 || n < 0 || (x == 0 && n != 0)) {
        impossible("d(%d,%d) attempted", n, x);
        return 1;
    }
#endif
    while (n--)
        tmp += rng_RND(rng, x);
    return tmp; /* Alea iacta est. -- J.C. */
}

/* 1 <= rne(x) <= max(u.ulevel/3,5) */
int
rng_rne(enum whichrng rng, register int x)
{
    register int tmp, utmp;

    utmp = (u.ulevel < 15) ? 5 : u.ulevel / 3;
    tmp = 1;
    while (tmp < utmp && !rng_rn2(rng, x))
        tmp++;
    return tmp;

    /* was:
     *  tmp = 1;
     *  while (!rn2(x))
     *    tmp++;
     *  return min(tmp, (u.ulevel < 15) ? 5 : u.ulevel / 3);
     * which is clearer but less efficient and stands a vanishingly
     * small chance of overflowing tmp
     */
}

/* rnz: everyone's favorite! */
int
rng_rnz(enum whichrng rng, int i)
{
#ifdef LINT
    int x = i;
    int tmp = 1000;
#else
    register long x = (long) i;
    register long tmp = 1000L;
#endif

    tmp += rng_rn2(rng, 1000);
    tmp *= rng_rne(rng, 4);
    if (rng_rn2(rng, 2)) {
        x *= tmp;
        x /= 1000;
    } else {
        x *= 1000;
        x /= tmp;
    }
    return (int) x;
}

/*rnd.c*/
