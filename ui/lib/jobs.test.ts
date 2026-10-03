import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { JOBS, expectedSteps, expectedUnits, jobFor, stepsPerUnit } from "./jobs";

const repo = join(__dirname, "..", "..");
const read = (path: string) => JSON.parse(readFileSync(join(repo, path), "utf8"));

// The table is a copy of constants that live in the repository's own job
// files, keyed by hashes that live in its objective files. A copy is a thing
// that drifts, so every entry is checked against both sources on every run.
describe("the known-jobs table matches the repository", () => {
  const objectives = [
    "examples/certicom-ecdlp/objective-ecc2k130-orbit-batch.json",
    "examples/certicom-ecdlp/objective-ecc2k-23-orbit-batch.json",
    "examples/certicom-ecdlp/objective-nums-50-rho-batch.json",
    "examples/certicom-ecdlp/objective-eccp131-rho-batch.json",
  ];

  it("keys every entry by the checker hash an objective actually pins", () => {
    const pinned = new Set(objectives.map((path) => read(path).verifier.checker_sha256));
    for (const hash of Object.keys(JOBS)) expect(pinned).toContain(hash);
    expect(Object.keys(JOBS)).toHaveLength(objectives.length);
  });

  it("copies each job's constants exactly", () => {
    for (const job of Object.values(JOBS)) {
      const file = read(job.path);
      expect(job.name).toBe(file.name);
      expect(job.version).toBe(file.version);
      expect(job.order).toBe(file.order);
      if (file.version === 2) {
        expect(job.m).toBe(file.m);
        expect(job.dpMaxWeight).toBe(file.dp_max_weight);
        expect(job.trailBits).toBe(file.trail_bits);
        expect(job.classSize).toBe(2 * file.m);
      } else {
        expect(job.dpBits).toBe(file.dp_bits);
        expect(job.classSize).toBe(file.negation_map ? 2 : 1);
      }
    }
  });

  it("finds a job by its verifier and nothing by an unknown one", () => {
    const objective = read(objectives[0]);
    expect(jobFor(objective.verifier)?.name).toBe("certicom ecc2k-130");
    expect(jobFor({ checker_sha256: "00" })).toBeNull();
    expect(jobFor(undefined)).toBeNull();
    expect(jobFor({})).toBeNull();
  });
});

describe("the expected cost", () => {
  const ecc2k130 = JOBS["502f5b58881ed1a83b0f882153f78b724bc4319744853d080e8b2134aec661a3"];
  const ecc2k23 = JOBS["0ba12ff65fbdf7170cbd1f70732fac3ee6cfb222e0f4bdc8712ed0c162079626"];
  const log2 = (x: number) => Math.log2(x);

  it("reproduces the ECC2K-130 figures the design note quotes", () => {
    // docs/design/orbit-piecework.md: about 2^60.81 iterations, 2^25.27
    // steps per orbit, about 2^35.54 orbits.
    expect(log2(expectedSteps(ecc2k130))).toBeCloseTo(60.81, 1);
    expect(log2(stepsPerUnit(ecc2k130)!)).toBeCloseTo(25.27, 1);
    expect(log2(expectedUnits(ecc2k130)!)).toBeCloseTo(35.54, 1);
  });

  it("is a few dozen orbits on the 21-bit twin, which is what the demo sees", () => {
    // sqrt(pi * 0x1ffaed / (2 * 46)) is about 268 steps; at about 7 steps an
    // orbit that is about 38 orbits, and scripts/orbit-demo.sh collides
    // inside its fourth batch of eight.
    expect(expectedSteps(ecc2k23)).toBeCloseTo(267.6, 0);
    expect(stepsPerUnit(ecc2k23)).toBeCloseTo(6.99, 1);
    expect(expectedUnits(ecc2k23)).toBeGreaterThan(30);
    expect(expectedUnits(ecc2k23)).toBeLessThan(45);
  });

  it("uses the mask for a version 1 job", () => {
    const nums50 = JOBS["9c69e6f201d15d30f34fa7a2d53409c92a456dcec0e529c4081ec7e1b380c01c"];
    expect(stepsPerUnit(nums50)).toBe(2 ** 16);
    // sqrt(pi * 2^50 / 2) is about 2^25.3, the figure README quotes for rho there.
    expect(log2(expectedSteps(nums50))).toBeCloseTo(25.33, 1);
  });
});
