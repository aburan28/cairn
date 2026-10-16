# CPU capabilities and compute estimates

The agent refreshes its CPU profile on each host registration and before each
executor job. `GET /hosts`, `GET /network` and the Network reader expose the
model, usable ISA extensions and clocks. `/assignments?host=NAME` matches CPU
requirements alongside resource counts. This is routing and experiment
provenance; verified-result bounty rewards continue to depend on the verifier.

## Detection

`hardware.cpu` and `resources.cpu` contain:

| Field | Meaning |
|---|---|
| `arch`, `vendor`, `model` | Reported architecture, vendor and CPU model; unavailable values are null |
| `features` | Runtime-usable instructions, conservatively filtered against OS reports |
| `reported_features` | Common Linux flags before runtime gating; not execution eligibility |
| `base_khz`, `max_khz` | Reported base clock and hardware boost ceiling, in integer kHz |
| `observed_min_khz`, `observed_max_khz` | Lowest/highest sampled Linux per-core `cpu MHz`, converted to integer kHz |
| `source`, `observed_at` | Probe method and sample time |

On x86, CPUID and OSXSAVE/XCR0 gate AVX, AVX2 and AVX-512. Foundation, BW,
VL, IFMA, VNNI, BF16 and other AVX-512 extensions are separate features. The
ambiguous requirement `avx512` is refused: specify `avx512f` and every extension
the program needs. Linux aliases such as `avx512_vnni` normalize to
`avx512vnni`. Linux flags are intersected across all listed processors,
including ones with missing flags; a union could fault after core migration.
Affinity can make this conservative when only some of those cores are usable.

AArch64 runtime detection covers NEON, AES, SHA, dot product, SVE/SVE2, I8MM
and BF16, also intersecting Linux reports. macOS uses runtime detection, CPU
identity and available `sysctl` clocks. Unknown fields stay null; no frequency
is guessed. AMX permissions and SVE vector length are not profiled. The agent's
GPU/cgroup/service integration still targets Linux.

`resources.cpu_millis` expresses CPU time in thousandths of a core: `500` is
half a CPU. The Linux agent takes the smaller of process-visible CPU capacity
and cgroup v2 quotas, including visible ancestors. A larger quota cannot
replace a smaller affinity limit. Memory offers take the smaller known host
and cgroup capacities. Hidden ancestors, cgroup v1 and changing concurrent
load are not guaranteed by this observation.

Base, boost and sampled clocks are different facts. None guarantees sustained
throughput. The node's own `node.hardware.cpu` is a startup snapshot; the agent
refreshes registrations every interval (60 seconds by default). Each receipt
samples again before launch. Guests, sandboxes and later VM migrations can mask
more features: an experiment must check its **actual execution environment**
before using specialized instructions. Host preflight does not certify guest
CPUID.

## Requirements

An objective can put this inside its existing optional verifier routing metadata:

```json
{"capabilities":{"assignment":"queued","resources":{
  "cpus":2,"memory_mb":4096,
  "cpu":{"arch":"x86_64","features":["avx512f","avx512bw"]}
}}}
```

CPU predicates also accept exact `vendor` and `model` strings and
`min_base_khz` (a reported base clock floor, not sustained performance).
Unknown observations cannot satisfy requirements. Malformed resource hints
are marked `invalid` and match no host; they never become unconstrained
eligibility. Old objectives with no requirements remain compatible. Legacy
flag lists cannot satisfy CPU-specific requirements without a typed profile.

Executor job JSON accepts the same predicate as `cpu_requirements`, and a
`workload` key for pricing:

```json
{"id":"experiment-001","image":"ghcr.io/example/experiment:1",
 "argv":["/experiment"],"cpus":2,"memory_mb":4096,
 "workload":"boomer-experiment-v1",
 "cpu_requirements":{"arch":"x86_64","features":["avx512f","avx512bw"]}}
```

Pin an image digest for reproducible experiments. A failed host preflight
leaves an unavailable/abandoned receipt without launching the command.
Receipts capture full host hardware and `cpu_profile_id` beside the job spec,
sandbox, streams and timing. They do not prove that a result is correct.
`agent exec --cpu-requirements requirements.json --workload KEY` accepts the
same predicate from a file. Matching and quoting do not dispatch code.

## Rate cards and quotes

Run `cairn agent run --node URL --rate-card /absolute/path/rates.json`.
`agent exec` and `agent install` accept the same flag; alternatively set
`CAIRN_AGENT_RATE_CARD`. The installed service user must be able to read the
file. Cards are validated and loaded at startup; restart to change prices.
No rates are assumed by default.

Example **illustrative rates**, not measured market valuations:

```json
{"unit":"USD","rates":[
  {"id":"vector-2.4ghz","workload":"boomer-experiment-v1",
   "cpu":{"arch":"x86_64","features":["avx512f","avx512bw"],"min_base_khz":2400000},
   "cpu_second_microunits":3,"memory_gib_second_microunits":2},
  {"id":"baseline","workload":"boomer-experiment-v1",
   "cpu_second_microunits":1,"memory_gib_second_microunits":2}
]}
```

The first matching workload and CPU predicate wins. Put specific model/ISA/clock
rates before a generic fallback. There is no automatic GHz or ISA multiplier:
set rates from actual workload throughput and cost measurements. AVX-512 can
lower clocks; memory-bound work may not benefit; models differ per GHz.
Use a new workload key for a different experiment or kernel.

```sh
curl --fail-with-body http://localhost:8080/compute/quote \
  -H 'Content-Type: application/json' \
  --data '{"host":"worker-1","workload":"boomer-experiment-v1","cpus":2,"memory_mb":512,"duration_ms":1500,"cpu":{"features":["avx512f","avx512bw"]}}'
```

Provide exactly one of integer `cpus` or integer `cpu_millis`. At the vector
rate, `ceil((2 × 3 + 512/1024 × 2) × 1.5) = 11` microunits, or USD 0.000011.
Checked `u128` arithmetic rounds up once after summing CPU and memory. Overflow
is refused. The response pins the entire rate card, chosen `rate_id`,
`rate_card_id`, CPU profile and id, normalized request, quote and registration
times. Nothing reserves capacity or a price.

Missing hosts return 404; stale hosts, missing cards, unsupported workloads,
insufficient capacity and CPU mismatches return 409; malformed input returns
400. JSON and the normal POST Host protections apply. GPU, storage and network
charges are outside this CPU/memory quote contract.

Experiment receipts include `compute_estimate`, using requested CPU/memory
allocations times elapsed wall time (including sandbox setup), with the full
terms retained. This is an allocation estimate, **not utilization metering or
an invoice**. Unbounded allocations, missing workload/rate, unavailable
execution, GPU work and unknown capacity produce an explicit `unpriced` reason.
`memory_mb` follows the existing MiB convention (1024 MiB = 1 GiB). The
executor's job limits still take whole CPUs; fractional quote requests do not
add fractional CPU enforcement to that runner. Experiment snapshots read kernel
GPU facts without launching `nvidia-smi`; fields needing that tool can be unknown.

## Trust boundary

Hardware and prices are host reports, even for an enrolled member. A forged
model, feature, clock or benchmark can lie. Hardware attestation, independent
benchmark calibration, energy metering, reservations, automatic billing and
market price discovery are not implemented. Quotes and receipts create no
ledger records, move no balances, settle no claims and do not change bounty
rewards. The objective's pinned verifier remains the result authority.
