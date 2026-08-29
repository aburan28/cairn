/* Pollard rho with distinguished points for prime-field ECDLP.
 *
 * Solves k*G = Q on y^2 = x^3 + a*x + b over F_p, for p up to ~2^62 so that
 * a product of two field elements fits an unsigned __int128.
 *
 * The walk is the standard additive (van Oorschot-Wiener) one: each step adds
 * one of R precomputed points S[i] = u_i*G + v_i*Q, chosen by the low bits of
 * the current x, carrying (a,b) with current = a*G + b*Q.  Trails are not
 * restarted at a distinguished point: once two trails merge they agree
 * forever, so the first shared DP already reports two different (a,b) for one
 * point, which is the collision.  A self-collision (a rho cycle) reports the
 * same DP twice with the coefficients shifted by the cycle delta, so cycles
 * are productive rather than fruitless -- only a cycle shorter than the DP
 * spacing is sterile, and that is what the stall reset below catches.
 *
 * Inversion dominates affine addition, so W walks step in lockstep and share
 * one inversion by Montgomery's trick: W-1 multiplications each way plus one
 * exponentiation, instead of W exponentiations.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>
#include <time.h>

typedef unsigned __int128 u128;
typedef uint64_t u64;

static u64 P, A_CURVE, N_ORD, GX, GY, QX, QY;
static int DBITS = 10, NTHREADS = 4, WALKS = 512;
static u64 DMASK;

#define R_STEPS 64
static u64 SX[R_STEPS], SY[R_STEPS], SU[R_STEPS], SV[R_STEPS];

static inline u64 mulmod(u64 x, u64 y, u64 m) { return (u64)(((u128)x * y) % m); }
static inline u64 addmod(u64 x, u64 y, u64 m) { u64 s = x + y; return s >= m ? s - m : s; }
static inline u64 submod(u64 x, u64 y, u64 m) { return x >= y ? x - y : x + m - y; }

static u64 powmod(u64 base, u64 e, u64 m) {
    u64 r = 1 % m, b = base % m;
    while (e) { if (e & 1) r = mulmod(r, b, m); b = mulmod(b, b, m); e >>= 1; }
    return r;
}
static inline u64 invmod(u64 x, u64 m) { return powmod(x, m - 2, m); }

/* affine point; INF flagged by z == 0 */
typedef struct { u64 x, y; int inf; } pt;

static pt pt_add(pt p1, pt p2) {
    pt r;
    if (p1.inf) return p2;
    if (p2.inf) return p1;
    if (p1.x == p2.x) {
        if ((p1.y + p2.y) % P == 0) { r.inf = 1; r.x = r.y = 0; return r; }
        u64 num = addmod(mulmod(3, mulmod(p1.x, p1.x, P), P), A_CURVE, P);
        u64 lam = mulmod(num, invmod(addmod(p1.y, p1.y, P), P), P);
        u64 x3 = submod(mulmod(lam, lam, P), addmod(p1.x, p1.x, P), P);
        r.x = x3; r.y = submod(mulmod(lam, submod(p1.x, x3, P), P), p1.y, P); r.inf = 0;
        return r;
    }
    u64 lam = mulmod(submod(p2.y, p1.y, P), invmod(submod(p2.x, p1.x, P), P), P);
    u64 x3 = submod(submod(mulmod(lam, lam, P), p1.x, P), p2.x, P);
    r.x = x3; r.y = submod(mulmod(lam, submod(p1.x, x3, P), P), p1.y, P); r.inf = 0;
    return r;
}

static pt pt_mul(u64 k, pt p) {
    pt r = {0, 0, 1}, acc = p;
    while (k) { if (k & 1) r = pt_add(r, acc); acc = pt_add(acc, acc); k >>= 1; }
    return r;
}

/* ---- distinguished-point table: open addressing, one lock ---- */
typedef struct { u64 x, a, b; int used; } dp_t;
static dp_t *TABLE;
static u64 TSIZE = 1u << 22;
static pthread_mutex_t TLOCK = PTHREAD_MUTEX_INITIALIZER;

static volatile int SOLVED = 0;
static u64 ANSWER = 0;
static volatile u64 TOTAL_STEPS = 0, TOTAL_DPS = 0;

static u64 splitmix(u64 *s) {
    u64 z = (*s += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

/* a candidate k from a collision; verified before it is accepted */
static void try_solve(u64 a1, u64 b1, u64 a2, u64 b2) {
    if (b1 == b2) return;
    u64 num = submod(a2, a1, N_ORD);
    u64 den = submod(b1, b2, N_ORD);
    u64 k = mulmod(num, invmod(den, N_ORD), N_ORD);
    if (k == 0) return;
    pt G = {GX, GY, 0};
    pt t = pt_mul(k, G);
    if (!t.inf && t.x == QX && t.y == QY) {
        pthread_mutex_lock(&TLOCK);
        if (!SOLVED) { ANSWER = k; SOLVED = 1; }
        pthread_mutex_unlock(&TLOCK);
    }
}

static void report_dp(u64 x, u64 a, u64 b) {
    u64 h = (x * 0x9E3779B97F4A7C15ULL) >> 20;
    pthread_mutex_lock(&TLOCK);
    TOTAL_DPS++;
    for (u64 i = 0; i < 64; i++) {
        u64 slot = (h + i) & (TSIZE - 1);
        if (!TABLE[slot].used) {
            TABLE[slot].used = 1; TABLE[slot].x = x; TABLE[slot].a = a; TABLE[slot].b = b;
            pthread_mutex_unlock(&TLOCK);
            return;
        }
        if (TABLE[slot].x == x) {
            u64 oa = TABLE[slot].a, ob = TABLE[slot].b;
            pthread_mutex_unlock(&TLOCK);
            try_solve(oa, ob, a, b);
            return;
        }
    }
    pthread_mutex_unlock(&TLOCK);
}

typedef struct { int tid; u64 seed; } targ;

static void *worker(void *vp) {
    targ *ta = (targ *)vp;
    u64 rng = ta->seed;
    int W = WALKS;
    u64 *wx = malloc(W * 8), *wy = malloc(W * 8), *wa = malloc(W * 8), *wb = malloc(W * 8);
    u64 *den = malloc(W * 8), *pre = malloc(W * 8), *inv = malloc(W * 8);
    u64 *stall = calloc(W, 8);
    pt G = {GX, GY, 0}, Qp = {QX, QY, 0};

    for (int i = 0; i < W; i++) {
        u64 a = splitmix(&rng) % N_ORD, b = splitmix(&rng) % N_ORD;
        if (a == 0) a = 1;
        if (b == 0) b = 1;
        pt s = pt_add(pt_mul(a, G), pt_mul(b, Qp));
        wx[i] = s.x; wy[i] = s.y; wa[i] = a; wb[i] = b;
    }

    u64 stall_limit = ((u64)20) << DBITS;
    u64 local = 0;
    while (!SOLVED) {
        /* denominators for one lockstep round */
        for (int i = 0; i < W; i++) {
            int idx = (int)(wx[i] & (R_STEPS - 1));
            u64 d = submod(SX[idx], wx[i], P);
            den[i] = d ? d : 1;   /* degenerate: reset this walk below */
        }
        pre[0] = den[0];
        for (int i = 1; i < W; i++) pre[i] = mulmod(pre[i - 1], den[i], P);
        u64 acc = invmod(pre[W - 1], P);
        for (int i = W - 1; i > 0; i--) {
            inv[i] = mulmod(acc, pre[i - 1], P);
            acc = mulmod(acc, den[i], P);
        }
        inv[0] = acc;

        for (int i = 0; i < W; i++) {
            int idx = (int)(wx[i] & (R_STEPS - 1));
            if (wx[i] == SX[idx]) {          /* doubling or infinity: re-seed */
                u64 a = splitmix(&rng) % N_ORD, b = splitmix(&rng) % N_ORD;
                if (a == 0) a = 1;
                if (b == 0) b = 1;
                pt s = pt_add(pt_mul(a, G), pt_mul(b, Qp));
                wx[i] = s.x; wy[i] = s.y; wa[i] = a; wb[i] = b; stall[i] = 0;
                continue;
            }
            u64 lam = mulmod(submod(SY[idx], wy[i], P), inv[i], P);
            u64 x3 = submod(submod(mulmod(lam, lam, P), wx[i], P), SX[idx], P);
            u64 y3 = submod(mulmod(lam, submod(wx[i], x3, P), P), wy[i], P);
            wx[i] = x3; wy[i] = y3;
            wa[i] = addmod(wa[i], SU[idx], N_ORD);
            wb[i] = addmod(wb[i], SV[idx], N_ORD);
            stall[i]++;
            if ((x3 & DMASK) == 0) {
                report_dp(x3, wa[i], wb[i]);
                stall[i] = 0;
            } else if (stall[i] > stall_limit) {   /* short sterile cycle */
                u64 a = splitmix(&rng) % N_ORD, b = splitmix(&rng) % N_ORD;
                if (a == 0) a = 1;
                if (b == 0) b = 1;
                pt s = pt_add(pt_mul(a, G), pt_mul(b, Qp));
                wx[i] = s.x; wy[i] = s.y; wa[i] = a; wb[i] = b; stall[i] = 0;
            }
        }
        local += W;
        if (local >= (1u << 20)) {
            pthread_mutex_lock(&TLOCK);
            TOTAL_STEPS += local;
            pthread_mutex_unlock(&TLOCK);
            local = 0;
        }
    }
    pthread_mutex_lock(&TLOCK);
    TOTAL_STEPS += local;
    pthread_mutex_unlock(&TLOCK);
    return NULL;
}

static u64 parse_u64(const char *s) { return strtoull(s, NULL, 0); }

int main(int argc, char **argv) {
    if (argc < 8) {
        fprintf(stderr, "usage: %s p a n Gx Gy Qx Qy [dbits] [threads] [walks] [seed]\n", argv[0]);
        return 2;
    }
    P = parse_u64(argv[1]); A_CURVE = parse_u64(argv[2]); N_ORD = parse_u64(argv[3]);
    GX = parse_u64(argv[4]); GY = parse_u64(argv[5]);
    QX = parse_u64(argv[6]); QY = parse_u64(argv[7]);
    if (argc > 8) DBITS = atoi(argv[8]);
    if (argc > 9) NTHREADS = atoi(argv[9]);
    if (argc > 10) WALKS = atoi(argv[10]);
    u64 seed = argc > 11 ? parse_u64(argv[11]) : 0x1234567890abcdefULL;
    DMASK = (DBITS >= 64) ? ~0ULL : ((1ULL << DBITS) - 1);

    TABLE = calloc(TSIZE, sizeof(dp_t));
    if (!TABLE) { fprintf(stderr, "table alloc failed\n"); return 1; }

    pt G = {GX, GY, 0}, Qp = {QX, QY, 0};
    u64 rng = seed ^ 0xdeadbeefULL;
    for (int i = 0; i < R_STEPS; i++) {
        u64 u = splitmix(&rng) % N_ORD, v = splitmix(&rng) % N_ORD;
        if (u == 0) u = 1;
        if (v == 0) v = 1;
        pt s = pt_add(pt_mul(u, G), pt_mul(v, Qp));
        SX[i] = s.x; SY[i] = s.y; SU[i] = u; SV[i] = v;
    }

    pthread_t th[64];
    targ ta[64];
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (int i = 0; i < NTHREADS; i++) {
        ta[i].tid = i; ta[i].seed = seed + 0x100000001b3ULL * (i + 1);
        pthread_create(&th[i], NULL, worker, &ta[i]);
    }
    /* progress, and a place for a caller to see liveness */
    while (!SOLVED) {
        struct timespec ts = {1, 0};
        nanosleep(&ts, NULL);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        double el = (t1.tv_sec - t0.tv_sec) + 1e-9 * (t1.tv_nsec - t0.tv_nsec);
        fprintf(stderr, "\r%.0fs  steps=%llu (%.2fM/s)  dps=%llu   ",
                el, (unsigned long long)TOTAL_STEPS,
                TOTAL_STEPS / el / 1e6, (unsigned long long)TOTAL_DPS);
        fflush(stderr);
    }
    for (int i = 0; i < NTHREADS; i++) pthread_join(th[i], NULL);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    double el = (t1.tv_sec - t0.tv_sec) + 1e-9 * (t1.tv_nsec - t0.tv_nsec);
    fprintf(stderr, "\nsolved in %.1fs, %llu steps, %llu dps\n", el,
            (unsigned long long)TOTAL_STEPS, (unsigned long long)TOTAL_DPS);
    printf("%llu\n", (unsigned long long)ANSWER);
    return 0;
}
