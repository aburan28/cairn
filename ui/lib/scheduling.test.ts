import { describe, expect, it } from "vitest";
import { cpuSummary, resourceSummary, type CpuProfile } from "./scheduling";

describe("CPU observations and offers", () => {
  it("keeps base and boost labels distinct and displays only usable ISA flags", () => {
    const cpu: CpuProfile = {
      arch: "x86_64", vendor: "GenuineIntel", model: "Test CPU",
      features: ["avx2"], reported_features: ["avx2", "avx512f"],
      base_khz: 2_400_000, max_khz: 4_100_000,
      observed_min_khz: 1_200_000, observed_max_khz: 2_800_000,
      source: "fixture", observed_at: "2026-10-16T00:00:00Z",
    };
    expect(cpuSummary(cpu)).toBe("Test CPU · 2.40 GHz base · 4.10 GHz boost ceiling · avx2");
    expect(cpuSummary(null)).toBeNull();
  });
  it("shows fractional CPU quotas and explicit instruction requirements", () => {
    const capacity = { cpus: 1, memory_mb: null, gpus: null, storage_mb: null, concurrency: null };
    expect(resourceSummary({ ...capacity, cpu_millis: 500 })).toBe("0.5 CPUs");
    expect(resourceSummary({ ...capacity, cpu: { arch: "x86_64", features: ["avx512f", "avx512bw"] } })).toBe("1 CPU · x86_64 · avx512f, avx512bw");
    expect(resourceSummary({ ...capacity, invalid: true })).toBe("Invalid resource requirements");
  });
});
