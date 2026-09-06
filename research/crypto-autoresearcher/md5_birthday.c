/* Birthday search for a truncated-digest MD5 collision behind a pinned prefix.
 *
 * The instance in examples/hash-differential/checkers/collide_md5_48.py asks
 * for two messages that share one 64-byte prefix block, have the same length,
 * differ somewhere, and agree on the leading DIGEST_BYTES of the digest. A
 * generic birthday search settles it in about 2^(4*DIGEST_BYTES) compressions
 * with no cryptanalysis anywhere in it, which is exactly what the checker's
 * own docstring says it costs.
 *
 * Both messages are prefix || eight bytes, so padded they are exactly two
 * blocks, and the first block is the same for every candidate. Its chaining
 * value is computed once; each step of the walk is one compression of the
 * second block. Brent's cycle finding is used rather than a table: 2^24
 * entries is a few hundred megabytes for nothing, since the walk needs no
 * memory at all and about three compressions per expected step.
 *
 * STEPS is a parameter because the checker family in that directory pins the
 * number of compression steps, and a reduced-round instance is the same
 * search with a shorter loop.
 *
 *   md5_birthday <prefix-hex> <steps> <digest-bytes> [seed]
 *
 * prints two lowercase hex messages, one per line, that the checker accepts.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef uint32_t u32;
typedef uint64_t u64;

static int STEPS = 64;

static const u32 K[64] = {
    0xD76AA478, 0xE8C7B756, 0x242070DB, 0xC1BDCEEE, 0xF57C0FAF, 0x4787C62A,
    0xA8304613, 0xFD469501, 0x698098D8, 0x8B44F7AF, 0xFFFF5BB1, 0x895CD7BE,
    0x6B901122, 0xFD987193, 0xA679438E, 0x49B40821, 0xF61E2562, 0xC040B340,
    0x265E5A51, 0xE9B6C7AA, 0xD62F105D, 0x02441453, 0xD8A1E681, 0xE7D3FBC8,
    0x21E1CDE6, 0xC33707D6, 0xF4D50D87, 0x455A14ED, 0xA9E3E905, 0xFCEFA3F8,
    0x676F02D9, 0x8D2A4C8A, 0xFFFA3942, 0x8771F681, 0x6D9D6122, 0xFDE5380C,
    0xA4BEEA44, 0x4BDECFA9, 0xF6BB4B60, 0xBEBFBC70, 0x289B7EC6, 0xEAA127FA,
    0xD4EF3085, 0x04881D05, 0xD9D4D039, 0xE6DB99E5, 0x1FA27CF8, 0xC4AC5665,
    0xF4292244, 0x432AFF97, 0xAB9423A7, 0xFC93A039, 0x655B59C3, 0x8F0CCC92,
    0xFFEFF47D, 0x85845DD1, 0x6FA87E4F, 0xFE2CE6E0, 0xA3014314, 0x4E0811A1,
    0xF7537E82, 0xBD3AF235, 0x2AD7D2BB, 0xEB86D391,
};
static const int S[4][4] = {{7, 12, 17, 22}, {5, 9, 14, 20}, {4, 11, 16, 23}, {6, 10, 15, 21}};

static inline u32 rotl(u32 x, int n) { return (x << n) | (x >> (32 - n)); }

/* The checker's `_compress`, step for step, including its reduced-step loop. */
static void compress(u32 st[4], const unsigned char block[64]) {
    u32 w[16];
    for (int i = 0; i < 16; i++)
        w[i] = (u32)block[4 * i] | ((u32)block[4 * i + 1] << 8) |
               ((u32)block[4 * i + 2] << 16) | ((u32)block[4 * i + 3] << 24);
    u32 a = st[0], b = st[1], c = st[2], d = st[3];
    for (int i = 0; i < STEPS; i++) {
        int rnd = i >> 4;
        u32 f;
        int k;
        if (rnd == 0) { f = (b & c) | (~b & d); k = i; }
        else if (rnd == 1) { f = (d & b) | (~d & c); k = (5 * i + 1) & 15; }
        else if (rnd == 2) { f = b ^ c ^ d; k = (3 * i + 5) & 15; }
        else { f = c ^ (b | ~d); k = (7 * i) & 15; }
        u32 t = a + f + K[i] + w[k];
        u32 nb = b + rotl(t, S[rnd][i & 3]);
        a = d; d = c; c = b; b = nb;
    }
    st[0] += a; st[1] += b; st[2] += c; st[3] += d;
}

static u32 CHAIN[4];      /* state after the prefix block */
static int DIGEST_BYTES = 6;
static u64 MASK;

/* The second (final) block: eight message bytes, then the padding for a
 * 72-byte message -- 0x80, zeros, and the 576-bit length little-endian. */
static u64 step(u64 x) {
    unsigned char block[64];
    memset(block, 0, sizeof block);
    for (int i = 0; i < 8; i++) block[i] = (unsigned char)(x >> (8 * i));
    block[8] = 0x80;
    u64 bits = 72 * 8;
    for (int i = 0; i < 8; i++) block[56 + i] = (unsigned char)(bits >> (8 * i));
    u32 st[4] = {CHAIN[0], CHAIN[1], CHAIN[2], CHAIN[3]};
    compress(st, block);
    unsigned char out[16];
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++) out[4 * i + j] = (unsigned char)(st[i] >> (8 * j));
    u64 v = 0;
    for (int i = 0; i < 8; i++) v |= (u64)out[i] << (8 * i);
    return v & MASK;
}

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static u64 splitmix(u64 *s) {
    u64 z = (*s += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "usage: %s <prefix-hex> <steps> <digest-bytes> [seed]\n", argv[0]);
        return 2;
    }
    unsigned char prefix[64];
    if (strlen(argv[1]) != 128) {
        fprintf(stderr, "the prefix must be exactly 64 bytes (128 hex characters)\n");
        return 2;
    }
    for (int i = 0; i < 64; i++) {
        int hi = hexval(argv[1][2 * i]), lo = hexval(argv[1][2 * i + 1]);
        if (hi < 0 || lo < 0) { fprintf(stderr, "prefix is not hex\n"); return 2; }
        prefix[i] = (unsigned char)(hi * 16 + lo);
    }
    STEPS = atoi(argv[2]);
    DIGEST_BYTES = atoi(argv[3]);
    if (STEPS < 1 || STEPS > 64 || DIGEST_BYTES < 1 || DIGEST_BYTES > 8) {
        fprintf(stderr, "steps in 1..64, digest bytes in 1..8\n");
        return 2;
    }
    MASK = DIGEST_BYTES == 8 ? ~0ULL : ((1ULL << (8 * DIGEST_BYTES)) - 1);
    u64 seed = argc > 4 ? strtoull(argv[4], NULL, 10) : 0x243F6A8885A308D3ULL;

    CHAIN[0] = 0x67452301; CHAIN[1] = 0xEFCDAB89; CHAIN[2] = 0x98BADCFE; CHAIN[3] = 0x10325476;
    compress(CHAIN, prefix);

    /* Brent's algorithm on f: {0,1}^(8*DIGEST_BYTES) -> itself. A start point
     * that already lies on the cycle gives a period, not a collision, so the
     * search restarts from a fresh point when mu turns out to be zero. */
    for (int attempt = 0; attempt < 64; attempt++) {
        u64 x0 = splitmix(&seed) & MASK;
        u64 power = 1, lam = 1;
        u64 tortoise = x0, hare = step(x0);
        u64 evals = 1;
        while (tortoise != hare) {
            if (power == lam) { tortoise = hare; power <<= 1; lam = 0; }
            hare = step(hare);
            lam++;
            evals++;
        }
        tortoise = x0; hare = x0;
        for (u64 i = 0; i < lam; i++) { hare = step(hare); evals++; }
        u64 mu = 0, prev_t = tortoise, prev_h = hare;
        while (tortoise != hare) {
            prev_t = tortoise; prev_h = hare;
            tortoise = step(tortoise); hare = step(hare);
            evals += 2;
            mu++;
        }
        if (mu == 0) {
            fprintf(stderr, "attempt %d: start point lay on the cycle (lambda=%llu); restarting\n",
                    attempt, (unsigned long long)lam);
            continue;
        }
        if (prev_t == prev_h || step(prev_t) != step(prev_h)) {
            fprintf(stderr, "internal error: predecessors do not collide\n");
            return 1;
        }
        fprintf(stderr, "collision after %llu compressions (mu=%llu, lambda=%llu)\n",
                (unsigned long long)evals, (unsigned long long)mu, (unsigned long long)lam);
        u64 pair[2] = {prev_t, prev_h};
        for (int p = 0; p < 2; p++) {
            for (int i = 0; i < 64; i++) printf("%02x", prefix[i]);
            for (int i = 0; i < 8; i++) printf("%02x", (unsigned)((pair[p] >> (8 * i)) & 0xff));
            printf("\n");
        }
        return 0;
    }
    fprintf(stderr, "no collision after 64 attempts\n");
    return 1;
}
