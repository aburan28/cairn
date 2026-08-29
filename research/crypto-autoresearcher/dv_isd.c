/* Minimum-weight search over the SHA-1 disturbance-vector code, by
 * information-set decoding (Lee-Brickell).
 *
 * The score counts disturbances in steps 20..74 only, so the object being
 * searched is the projection of the constrained code onto those 1,760 bit
 * positions -- and that projection is injective, because sixty consecutive
 * zero words force the whole vector to zero.  Minimum window weight is
 * therefore the minimum weight of a [1760, 352] code, and ISD is the standard
 * tool for exactly that.
 *
 * Each round: randomise the column order, bring the generator to systematic
 * form against the first 352 independent columns, and read off the weight of
 * every sum of one or two rows.  A row in systematic form is a codeword with a
 * single 1 in the information set, so a genuinely low-weight codeword shows up
 * as soon as a permutation puts most of its support outside that set -- which
 * is why the whole thing is randomised and repeated rather than clever.
 *
 * Rows carry their full 80-word codeword rather than just the windowed
 * projection, so the winner can be printed as the sixteen seed words the
 * verifier expands, with no reconstruction step to get wrong.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#define NW 80
static int LO = 20, HI = 75;      /* scored window, set on the command line */
#define WINBITS (55 * 32)

static int DIM;
static uint32_t rows[512][NW];
static uint32_t work[512][NW];
static int colorder[WINBITS];
static int winbits;

static uint64_t rs = 88172645463325252ULL;
static uint64_t rnd(void) { rs ^= rs << 13; rs ^= rs >> 7; rs ^= rs << 17; return rs; }

static inline int wwt(const uint32_t *v) {
    int w = 0;
    for (int t = LO; t < HI; t++) w += __builtin_popcount(v[t]);
    return w;
}
/* Ties on the scored window are broken by total weight.  Every disturbance
 * outside the window still costs the message search a condition to satisfy --
 * cheaply, because the words there are free, but not for nothing -- and among
 * equally good vectors the sparse one is the one that search can use. */
static int TOTW = 0;
static inline int twt(const uint32_t *v) {
    int w = 0;
    for (int t = 0; t < NW; t++) w += __builtin_popcount(v[t]);
    return w;
}
static inline int better(const uint32_t *v, int w, int best_w, int best_t) {
    if (w != best_w) return w < best_w;
    return TOTW && twt(v) < best_t;
}
static inline int bitat(const uint32_t *v, int c) {
    return (v[LO + (c >> 5)] >> (c & 31)) & 1;
}

int main(int argc, char **argv) {
    const char *path = argc > 1 ? argv[1] : "dv_basis.txt";
    double seconds = argc > 2 ? atof(argv[2]) : 30.0;
    if (argc > 3) rs = strtoull(argv[3], NULL, 10) | 1;
    if (argc > 5) { LO = atoi(argv[4]); HI = atoi(argv[5]); }
    winbits = (HI - LO) * 32;

    FILE *fh = fopen(path, "r");
    if (!fh) { fprintf(stderr, "cannot open %s\n", path); return 1; }
    int nw;
    if (fscanf(fh, "%d %d", &DIM, &nw) != 2 || nw != NW) return 1;
    for (int i = 0; i < DIM; i++)
        for (int t = 0; t < NW; t++)
            if (fscanf(fh, "%x", &rows[i][t]) != 1) return 1;
    fclose(fh);

    for (int c = 0; c < winbits; c++) colorder[c] = c;

    uint32_t best[NW];
    int best_w = 1 << 30, best_t = 1 << 30;
    long rounds = 0;
    TOTW = 1;
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    for (;;) {
        clock_gettime(CLOCK_MONOTONIC, &t1);
        double el = (t1.tv_sec - t0.tv_sec) + 1e-9 * (t1.tv_nsec - t0.tv_nsec);
        if (el > seconds) break;
        rounds++;

        for (int c = winbits - 1; c > 0; c--) {
            int j = (int)(rnd() % (uint64_t)(c + 1));
            int tmp = colorder[c]; colorder[c] = colorder[j]; colorder[j] = tmp;
        }
        memcpy(work, rows, sizeof(uint32_t) * DIM * NW);

        int r = 0;
        for (int ci = 0; ci < winbits && r < DIM; ci++) {
            int c = colorder[ci];
            int piv = -1;
            for (int i = r; i < DIM; i++) if (bitat(work[i], c)) { piv = i; break; }
            if (piv < 0) continue;
            if (piv != r) for (int t = 0; t < NW; t++) {
                uint32_t x = work[r][t]; work[r][t] = work[piv][t]; work[piv][t] = x;
            }
            for (int i = 0; i < DIM; i++) {
                if (i == r || !bitat(work[i], c)) continue;
                for (int t = 0; t < NW; t++) work[i][t] ^= work[r][t];
            }
            r++;
        }

        for (int i = 0; i < DIM; i++) {
            int w = wwt(work[i]);
            if (w && better(work[i], w, best_w, best_t)) {
                best_w = w; best_t = twt(work[i]);
                memcpy(best, work[i], sizeof(best));
                fprintf(stderr, "weight %d (total %d, round %ld, single)\n", w, best_t, rounds);
            }
        }
        for (int i = 0; i < DIM; i++) {
            for (int j = i + 1; j < DIM; j++) {
                int w = 0;
                for (int t = LO; t < HI; t++) w += __builtin_popcount(work[i][t] ^ work[j][t]);
                if (!w) continue;
                uint32_t cand[NW];
                for (int t = 0; t < NW; t++) cand[t] = work[i][t] ^ work[j][t];
                if (better(cand, w, best_w, best_t)) {
                    best_w = w; best_t = twt(cand);
                    memcpy(best, cand, sizeof(best));
                    fprintf(stderr, "weight %d (total %d, round %ld, pair)\n", w, best_t, rounds);
                }
            }
        }
    }

    fprintf(stderr, "%ld rounds, best window weight %d\n", rounds, best_w);
    /* the whole vector, not the first sixteen words: in the reduced-step
     * space the basis vectors are disturbance vectors outright rather than
     * codewords their first sixteen words would regenerate. */
    for (int t = 0; t < NW; t++) printf("%08x%s", best[t], t == NW - 1 ? "\n" : " ");
    return 0;
}
