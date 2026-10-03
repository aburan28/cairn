/**
 * The search jobs this reader knows the shape of, keyed by the checker that
 * pins each one.
 *
 * # Why the page needs this at all
 *
 * `GET /progress/{id}` reports what the log has paid for: units, and the
 * steps those units cost. Turning that into *how far along the search is*
 * needs two numbers the log does not hold -- the group order, which sets the
 * expected cost of a Pollard rho, and the size of the equivalence class the
 * walk runs on, which divides it. Both live in the job document the checker
 * pins by hash, and the node never parses that document (`src/schema.rs`
 * says so). So the page carries the handful of constants it needs.
 *
 * # Why a copy is safe here, when copies are usually what drifts
 *
 * An objective pins its checker by SHA-256, the checker pins the job by id,
 * and the job's constants are inside that id. Changing any of them posts a
 * *different* objective with a different checker hash, which this table does
 * not know and the page then shows without an expected cost rather than with
 * a wrong one. An entry here can therefore go stale in exactly one way --
 * by being wrong on the day it was written -- and `jobs.test.ts` re-reads
 * every job file and objective in the repository to rule that out.
 *
 * Nothing here is used for payment, and the expected cost is a statement
 * about Pollard rho, not about this network: `expectedSteps` is the textbook
 * `sqrt(pi * n / 2)` divided by the square root of the class size, which for
 * ECC2K-130 is the 2^60.8 that Bailey et al. and the campaign's own status
 * page quote.
 */

export type SearchJob = {
  /** The job's own `name`. */
  name: string;
  /** Repository-relative path of the job document. */
  path: string;
  version: 1 | 2;
  /** The group order `n`, lowercase hex. */
  order: string;
  /**
   * How many points one walk state stands for. Version 2 walks orbits of
   * `<-1> x <sigma>`, so `2m`; version 1 is `2` with the negation map and
   * `1` without.
   */
  classSize: number;
  /** Version 2: the field degree and the distinguishing weight. */
  m?: number;
  dpMaxWeight?: number;
  /** Version 1: a point is distinguished when its low `dpBits` bits are zero. */
  dpBits?: number;
  /** Version 2: `seed = (unit << trailBits) | trail`. */
  trailBits?: number;
};

export const JOBS: Record<string, SearchJob> = {
  // examples/certicom-ecdlp/objective-ecc2k130-orbit-batch.json
  "502f5b58881ed1a83b0f882153f78b724bc4319744853d080e8b2134aec661a3": {
    name: "certicom ecc2k-130",
    path: "examples/certicom-ecdlp/jobs/ecc2k130.json",
    version: 2,
    order: "200000000000000004d4fdd5703a3f269",
    classSize: 262,
    m: 131,
    dpMaxWeight: 34,
    trailBits: 16,
  },
  // examples/certicom-ecdlp/objective-ecc2k-23-orbit-batch.json
  "0ba12ff65fbdf7170cbd1f70732fac3ee6cfb222e0f4bdc8712ed0c162079626": {
    name: "cairn ecc2k-23 orbit rho",
    path: "examples/certicom-ecdlp/jobs/ecc2k-23.json",
    version: 2,
    order: "1ffaed",
    classSize: 46,
    m: 23,
    dpMaxWeight: 8,
    trailBits: 16,
  },
  // examples/certicom-ecdlp/objective-nums-50-rho-batch.json
  "9c69e6f201d15d30f34fa7a2d53409c92a456dcec0e529c4081ec7e1b380c01c": {
    name: "cairn nums-50 rho",
    path: "examples/certicom-ecdlp/jobs/nums-50-rho.json",
    version: 1,
    order: "4000002c8af47",
    classSize: 1,
    dpBits: 16,
  },
  // examples/certicom-ecdlp/objective-eccp131-rho-batch.json
  "24e217f87140ab291d405c18e7b9d4d5f423905fe22f2e4ead8bb7c64f044787": {
    name: "cairn certicom eccp131 rho",
    path: "examples/certicom-ecdlp/jobs/eccp131-rho.json",
    version: 1,
    order: "48e1d43f293469e317f7ed728f6b8e6f1",
    classSize: 2,
    dpBits: 44,
  },
};

/** The job an objective's pinned checker runs, if this reader knows it. */
export function jobFor(verifier: { checker_sha256?: unknown } | undefined | null): SearchJob | null {
  const hash = verifier?.checker_sha256;
  return typeof hash === "string" ? (JOBS[hash.toLowerCase()] ?? null) : null;
}

/**
 * The expected number of group operations to a collision: `sqrt(pi * n / 2)`,
 * divided by the square root of the class size. The group order is at most
 * 2^131 here, so the conversion to a double loses nothing a sixth significant
 * figure would notice.
 */
export function expectedSteps(job: SearchJob): number {
  const n = Number(BigInt(`0x${job.order}`));
  return Math.sqrt((Math.PI * n) / (2 * job.classSize));
}

/**
 * Expected steps to one distinguished unit.
 *
 * Version 1 is the mask: `2^dpBits`. Version 2 is the weight test: points of
 * odd order on a Koblitz curve have trace-zero abscissae, so only even
 * weights occur, and the hit rate is the share of the `2^(m-1)` even-weight
 * strings with weight at most the cutoff. `orbit_dp.py dp_expected_bits`
 * computes the same ratio, floored to a power of two.
 */
export function stepsPerUnit(job: SearchJob): number | null {
  if (job.version === 1) {
    return typeof job.dpBits === "number" ? 2 ** job.dpBits : null;
  }
  if (typeof job.m !== "number" || typeof job.dpMaxWeight !== "number") return null;
  let hits = 0n;
  for (let w = 0; w <= job.dpMaxWeight; w += 2) hits += binomial(BigInt(job.m), BigInt(w));
  if (hits === 0n) return null;
  return Number(1n << BigInt(job.m - 1)) / Number(hits);
}

function binomial(n: bigint, k: bigint): bigint {
  let r = 1n;
  for (let i = 0n; i < k; i += 1n) r = (r * (n - i)) / (i + 1n);
  return r;
}

/** The expected number of units the whole search produces. */
export function expectedUnits(job: SearchJob): number | null {
  const per = stepsPerUnit(job);
  return per ? expectedSteps(job) / per : null;
}
