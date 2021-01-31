/* NetHack 3.7	rnd.c	$NHDT-Date: 1596498205 2020/08/03 23:43:25 $  $NHDT-Branch: NetHack-3.7 $:$NHDT-Revision: 1.30 $ */
/*      Copyright (c) 2004 by Robert Patrick Rankin               */
/* NetHack may be freely redistributed.  See license for details. */

#include "hack.h"

#ifdef USE_CHACHA
#include "chacha.h"

static uint32_t
get_chacha_rng(enum whichrng whichrng)
{
    if (g.program_state.saving) {
        panic("tried to advance rng whilst saving; would lead to incorrect seed being saved");
    }

    struct chacha_rng_t *rng = &g.rngs[whichrng];
    uint32_t res;
    if (!rng->buf_valid) {
        chacha_8rounds_prng(rng->buf, (unsigned char *) g.seed, whichrng, rng->position / 16);
        rng->buf_valid = TRUE;
    }
    res = rng->buf[rng->position % 16];

    rng->position++;
    rng->budgeted_position++;
    if (rng->rng_budget) {
        rng->rng_budget->actual_count_direct++;
    }
    if (rng->position % 16 == 0) {
        rng->buf_valid = FALSE;
    }
    return res;
}

static int
rng_RND(enum whichrng rng, int x)
{
    return (get_chacha_rng(rng) % x);
}

#else   /* USE_CHACHA */

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
rng_RND(enum whichrng rng, register int x)
{
    if (rng == RNG_DISP) {
        static unsigned seed = 1;
        seed *= 2739110765;
        return (int)((seed >> 16) % (unsigned)x);
    } else {
        return system_RND(x);
    }
}
#endif  /* USE_CHACHA */

/* An appropriate version of this must always be provided in
   port-specific code somewhere. It returns a number suitable
   as seed for the random number generator */
extern unsigned long sys_random_seed(void);

/*
 * Initializes the random number generator.
 * Only call once.
 */
void
init_random(void)
{
#ifdef USE_CHACHA
    /* if the seed is strong, it's worth invoking this function multiple times
       to get more entropy. if the seed isn't strong, this is effectively the
       same as just duplicating the key a few times. (this is djb's recommended
       key initialisation for 128-bit keys; though in this case we probably only
       have 32 or 64 bits of entropy.) */
    unsigned i, j;
    unsigned long this_word;

    for (i = 0; i < sizeof(g.seed); i += sizeof(this_word)) {
        this_word = sys_random_seed();
        for (j = 0; j < sizeof(this_word); j++) {
            g.seed[i + j] = this_word & 0xFF;
            this_word >>= 8;
        }
    }

    /* Reset all RNG counters. */
    memset(g.rngs, 0x00, sizeof(g.rngs));

    /* make the core stream random */
    g.rngs[RNG_CORE].position = sys_random_seed();

#else
    unsigned long seed = sys_random_seed();
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
#endif
}

void
hint_reseed_random(void)
{
#if !defined(USE_CHACHA)
    /* only reseed if we are certain that the seed generation is unguessable
     * by the players. */
    if (has_strong_rngseed) {
        init_random();
    }
#endif
}

void
save_rng_state(NHFILE *nhfp)
{
    int i;

    if (nhfp->structlevel) {
        /* TODO: only serialise this if necessary. See comment in decl.h */
        bwrite(nhfp->fd, (genericptr_t) g.seed, sizeof(g.seed));
        for (i = 0; i < RNG_INDEX_MAX; ++i) {
            if (g.rngs[i].rng_budget) {
                panic("Attempted a save whilst an RNG budget is active, this is not going to preserve the right state");
            }

            bwrite(nhfp->fd, (genericptr_t) &g.rngs[i].position, sizeof(uint64_t));
            bwrite(nhfp->fd, (genericptr_t) &g.rngs[i].budgeted_position, sizeof(uint64_t));
        }
    }
}

void
restore_rng_state(NHFILE *nhfp)
{
    int i;

    if (nhfp->structlevel) {
        mread(nhfp->fd, (genericptr_t) g.seed, sizeof(g.seed));
        for (i = 0; i < RNG_INDEX_MAX; ++i) {
            struct chacha_rng_t *rng = &g.rngs[i];
            mread(nhfp->fd, (genericptr_t) &rng->position, sizeof(uint64_t));
            mread(nhfp->fd, (genericptr_t) &rng->budgeted_position, sizeof(uint64_t));
            rng->buf_valid = FALSE;
        }
    }
}

rng_budget_t *
create_rng_budget0(const char *file, int line, enum whichrng whichrng, long budget)
{
#ifdef USE_CHACHA
    rng_budget_t *rngb = (rng_budget_t *) alloc(sizeof(rng_budget_t));

    rngb->file = file;
    rngb->line = line;
    rngb->whichrng = whichrng;
    rngb->budget = budget;
    rngb->actual_count_direct = 0;
    rngb->actual_count_indirect = 0;

    rngb->parent = g.rngs[whichrng].rng_budget;
    rngb->depth =
        (g.rngs[whichrng].rng_budget ?
         g.rngs[whichrng].rng_budget->depth + 1 : 0);
    g.rngs[whichrng].rng_budget = rngb;

    return rngb;
#else
    return NULL;
#endif
}

void
destroy_rng_budget(rng_budget_t *rngb)
{
#ifdef USE_CHACHA
    int leftover_budget = rngb->budget - rngb->actual_count_direct - rngb->actual_count_indirect;
    struct chacha_rng_t *rng = &g.rngs[rngb->whichrng];

    if (rng->rng_budget != rngb) {
        panic("destroy_rng_budget called on budget '%s:%d', but top of stack is currently '%s:%d'",
              rngb->file, rngb->line,
              rng->rng_budget ? rng->rng_budget->file : "NULL",
              rng->rng_budget ? rng->rng_budget->line : -1);
    }

    if (showdebug(__FILE__)) {
        if (leftover_budget < 0) {
            pline("RNG budget '%s:%d' overflowed: budget = %d, actual = %d+%d (direct+indirect)",
                  rngb->file, rngb->line,
                  rngb->budget,
                  rngb->actual_count_direct,
                  rngb->actual_count_indirect);
        }
    }

    rng->budgeted_position += leftover_budget;
    if (rng->budgeted_position > rng->position) {
        /* advance the RNG */
        rng->buf_valid = rng->buf_valid && (rng->position / 16 == rng->budgeted_position / 16);
        rng->position = rng->budgeted_position;
    }

    rng->rng_budget = rngb->parent;
    if (rng->rng_budget) {
        rng->rng_budget->actual_count_indirect += rngb->budget;
    }

    free((genericptr_t) rngb);
#else
    return;
#endif
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
    rng_budget_t *rngb = create_rng_budget(rng, MAXULEV/3);

    utmp = (u.ulevel < 15) ? 5 : u.ulevel / 3;
    tmp = 1;
    while (tmp < utmp && !rng_rn2(rng, x))
        tmp++;

    destroy_rng_budget(rngb);
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
