/* Realise a differential path by descending on how badly a message misses it.
 *
 * Forcing the exact path difference one step at a time works until the state
 * difference gets complicated -- around step 13 here -- and then the step is
 * simply unreachable by any choice of that step's word, and the attempt dies
 * with nothing to show.  The trouble is the objective, not the search: "does
 * this message follow the path exactly" is a cliff, and a cliff has no
 * gradient to walk down.
 *
 * So score a message by *how far* its differences sit from the path:
 *
 *     fitness = sum over steps of popcount(actual difference in a XOR expected)
 *
 * which is zero exactly when the path holds, and which single-bit flips of the
 * message move by small amounts.  That is a landscape steepest descent can
 * work, and restarts handle the local minima it settles into.
 *
 * The pair is still scored the way the pinned evaluator scores it, by
 * re-convergence depth, and the best pair seen is reported whether or not the
 * path ever closed.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>
#include <time.h>

typedef uint32_t u32;
typedef uint64_t u64;

#define MAXS 80
static int STEPS;
static u32 PATHD[MAXS], DW[16];
static double SECONDS;
static int NTHREADS;

static const u32 IV[5] = {0x67452301u, 0xEFCDAB89u, 0x98BADCFEu, 0x10325476u, 0xC3D2E1F0u};
static const u32 KC[4] = {0x5A827999u, 0x6ED9EBA1u, 0x8F1BBCDCu, 0xCA62C1D6u};

static inline u32 rotl(u32 x, int n) { return (x << n) | (x >> (32 - n)); }
static inline u32 ff(int t, u32 b, u32 c, u32 d) {
    if (t < 20) return (b & c) | (~b & d);
    if (t < 40) return b ^ c ^ d;
    if (t < 60) return (b & c) | (b & d) | (c & d);
    return b ^ c ^ d;
}

static void expand2(const u32 *m, u32 *w, int steps) {
    for (int i = 0; i < 16; i++) w[i] = m[i];
    for (int t = 16; t < steps; t++)
        w[t] = rotl(w[t-3] ^ w[t-8] ^ w[t-14] ^ w[t-16], 1);
}

/* distance from the path, and the re-convergence depth, in one walk */
static int fitness(const u32 *m1, int steps, int *depth_out) {
    u32 w1[MAXS], w2[MAXS], m2[16];
    for (int i = 0; i < 16; i++) m2[i] = m1[i] ^ DW[i];
    expand2(m1, w1, steps);
    expand2(m2, w2, steps);
    u32 a1 = IV[0], b1 = IV[1], c1 = IV[2], d1 = IV[3], e1 = IV[4];
    u32 a2 = a1, b2 = b1, c2 = c1, d2 = d1, e2 = e1;
    int fit = 0, depth = 0;
    for (int t = 0; t < steps; t++) {
        u32 n1 = rotl(a1, 5) + ff(t, b1, c1, d1) + e1 + KC[t/20] + w1[t];
        u32 n2 = rotl(a2, 5) + ff(t, b2, c2, d2) + e2 + KC[t/20] + w2[t];
        e1 = d1; d1 = c1; c1 = rotl(b1, 30); b1 = a1; a1 = n1;
        e2 = d2; d2 = c2; c2 = rotl(b2, 30); b2 = a2; a2 = n2;
        fit += __builtin_popcount((a1 ^ a2) ^ PATHD[t]);
        if (a1 == a2 && b1 == b2 && c1 == c2 && d1 == d2 && e1 == e2) depth = t + 1;
    }
    if (depth_out) *depth_out = depth;
    return fit;
}

static pthread_mutex_t LOCK = PTHREAD_MUTEX_INITIALIZER;
static int BEST = 0, BEST_FIT = 1 << 30;
static u32 BEST_M1[16], BEST_M2[16];
static volatile u64 CLIMBS = 0;
static volatile int STOP = 0;

static u64 splitmix(u64 *s) {
    u64 z = (*s += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

static void offer(const u32 *m1, int depth, int fit) {
    pthread_mutex_lock(&LOCK);
    if (depth > BEST) {
        BEST = depth;
        for (int i = 0; i < 16; i++) { BEST_M1[i] = m1[i]; BEST_M2[i] = m1[i] ^ DW[i]; }
        fprintf(stderr, "re-convergence at step %d (path distance %d)\n", depth, fit);
    }
    if (fit < BEST_FIT) BEST_FIT = fit;
    pthread_mutex_unlock(&LOCK);
}

static void *worker(void *vp) {
    u64 rng = *(u64 *)vp;
    u32 m[16], trial[16];
    while (!STOP) {
        for (int i = 0; i < 16; i++) m[i] = (u32)splitmix(&rng);
        int depth, fit = fitness(m, STEPS, &depth);
        offer(m, depth, fit);
        int moved = 1;
        while (moved && !STOP) {
            moved = 0;
            for (int bit = 0; bit < 512; bit++) {
                memcpy(trial, m, sizeof(m));
                trial[bit >> 5] ^= 1u << (bit & 31);
                int d2, f2 = fitness(trial, STEPS, &d2);
                if (f2 < fit) {
                    memcpy(m, trial, sizeof(m));
                    fit = f2; moved = 1;
                    if (d2 > BEST) offer(m, d2, f2);
                }
            }
        }
        fitness(m, STEPS, &depth);
        offer(m, depth, fit);
        pthread_mutex_lock(&LOCK); CLIMBS++; pthread_mutex_unlock(&LOCK);
    }
    return NULL;
}

int main(int argc, char **argv) {
    if (argc < 4 + 80 + 16) {
        fprintf(stderr, "usage: %s <steps> <seconds> <threads> <80 path words> <16 delta words>\n", argv[0]);
        return 2;
    }
    STEPS = atoi(argv[1]); SECONDS = atof(argv[2]); NTHREADS = atoi(argv[3]);
    for (int i = 0; i < 80; i++) PATHD[i] = (u32)strtoul(argv[4 + i], NULL, 16);
    for (int i = 0; i < 16; i++) DW[i] = (u32)strtoul(argv[84 + i], NULL, 16);

    pthread_t th[64]; u64 seeds[64];
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (int i = 0; i < NTHREADS; i++) {
        seeds[i] = 0x9E3779B97F4A7C15ULL * (i + 3) ^ (u64)time(NULL);
        pthread_create(&th[i], NULL, worker, &seeds[i]);
    }
    for (;;) {
        struct timespec ts = {1, 0};
        nanosleep(&ts, NULL);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        double el = (t1.tv_sec - t0.tv_sec) + 1e-9 * (t1.tv_nsec - t0.tv_nsec);
        if (el > SECONDS || BEST >= STEPS) break;
    }
    STOP = 1;
    for (int i = 0; i < NTHREADS; i++) pthread_join(th[i], NULL);
    fprintf(stderr, "%llu climbs, best path distance %d, deepest re-convergence %d\n",
            (unsigned long long)CLIMBS, BEST_FIT, BEST);
    if (!BEST) return 1;
    printf("%d ", BEST);
    for (int i = 0; i < 16; i++) printf("%08x", BEST_M1[i]);
    printf(" ");
    for (int i = 0; i < 16; i++) printf("%08x", BEST_M2[i]);
    printf("\n");
    return 0;
}
