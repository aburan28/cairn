#!/usr/bin/env python3
"""Walk one unit of a shared Pollard rho job and emit distinguished points.

    python3 examples/certicom-ecdlp/tools/rho_dp.py job-id  --job JOB
    python3 examples/certicom-ecdlp/tools/rho_dp.py walk    --job JOB --walker I  [--out FILE]
    python3 examples/certicom-ecdlp/tools/rho_dp.py walk    --job JOB --unit U    [--out-dir DIR]
    python3 examples/certicom-ecdlp/tools/rho_dp.py verify  --job JOB ARTIFACT...
    python3 examples/certicom-ecdlp/tools/rho_dp.py collide --job JOB ARTIFACT ARTIFACT

This is the contributor's side of a piecework rho objective, in pure Python
so that a peer with no Rust toolchain can still take part. It reproduces,
byte for byte, the walk that `crypto cryptanalysis rho-collab` runs
(`src/cryptanalysis/pollard_collab/{job,walk}.rs` in aburan28/crypto):

- the **job id** is SHA-256 over the canonical `tag=value\\n` lines of the
  job document, values lowercased, so two peers holding byte-different
  files of the same job agree on it;
- every scalar the walk needs is `PRF(job_id, tag, index) mod n`, where
  the PRF is two SHA-256 blocks over `job_id || 0 || tag || 0 || index_be8
  || ctr`; the `r`-adding branch table is `B_j = u_j P + v_j Q` from tags
  `branch-u`/`branch-v`, and walker `i` starts at `a_i P + b_i Q` from
  `walker-a`/`walker-b`;
- a step adds the branch selected by the low 64 bits of `x` modulo the
  branch count; under the negation map each point is folded to the
  representative with `2y <= p`, and a fruitless 2-cycle is broken by
  doubling;
- a point is **distinguished** when the low `dp_bits` bits of `x` are zero.

Two peers who run this on the same job and the same walker index produce
the same trail. Two peers who run it on *different* indices produce trails
that, once they meet anywhere, stay merged until the next distinguished
point -- which is how a collision between any two contributors' walks
solves the instance.

What it emits is the artifact the rho checkers accept: exactly four hex
strings, `{"x", "y", "a", "b"}`, with `y` canonical (`2y <= p`) so that the
same point has one spelling whatever walk reached it. Nothing else travels
in the artifact -- a walker index or step count would let a copier re-mint
a public point by relabelling it; see docs/design/rho-piecework.md.

`collide` is the payoff: given two artifacts for the same point with
different coefficients, it computes `k` with `k*G = Q`, which is the answer
to the *other* objective on the same instance.
"""
import argparse
import hashlib
import json
import os
import sys

# -- arithmetic ----------------------------------------------------------------


def _inv(x, p):
    return pow(x, -1, p)


def _add(P, Q, a, p):
    if P is None:
        return Q
    if Q is None:
        return P
    (x1, y1), (x2, y2) = P, Q
    if x1 == x2:
        if (y1 + y2) % p == 0:
            return None
        lam = (3 * x1 * x1 + a) * _inv(2 * y1 % p, p) % p
    else:
        lam = (y2 - y1) * _inv((x2 - x1) % p, p) % p
    x3 = (lam * lam - x1 - x2) % p
    return (x3, (lam * (x1 - x3) - y1) % p)


def _mul(k, P, a, p):
    R, A = None, P
    while k:
        if k & 1:
            R = _add(R, A, a, p)
        A = _add(A, A, a, p)
        k >>= 1
    return R


def _neg(P, p):
    if P is None:
        return None
    return (P[0], (-P[1]) % p)


def _on_curve(P, a, b, p):
    if P is None:
        return True
    x, y = P
    return 0 <= x < p and 0 <= y < p and (y * y - (x * x * x + a * x + b)) % p == 0


# -- the job -------------------------------------------------------------------


def _hex(v):
    """Lowercase, no prefix, no leading zeros: `BigUint::to_str_radix(16)`."""
    return format(v, "x")


def _parse_hex(s):
    t = s.strip()
    if t.startswith("0x") or t.startswith("0X"):
        t = t[2:]
    if not t:
        raise ValueError("empty hex scalar")
    return int(t, 16)


def load_job(path):
    with open(path) as handle:
        return json.load(handle)


def job_id(job):
    """SHA-256 over the canonical field encoding -- `JobSpec::canonical_bytes`."""
    lines = [
        ("version", str(job["version"])),
        ("name", job["name"]),
        ("p", job["p"]),
        ("a", job["a"]),
        ("b", job["b"]),
        ("gx", job["generator"]["x"]),
        ("gy", job["generator"]["y"]),
        ("qx", job["target"]["x"]),
        ("qy", job["target"]["y"]),
        ("n", job["order"]),
        ("dp_bits", str(job["dp_bits"])),
        ("branches", str(job["num_branches"])),
        ("negation", "true" if job["negation_map"] else "false"),
        ("unit_size", str(job["unit_size"])),
        ("max_steps", str(job["max_steps_per_walker"])),
        ("seed", str(job["seed"])),
    ]
    out = b"".join(f"{tag}={value.lower()}\n".encode() for tag, value in lines)
    return hashlib.sha256(out).hexdigest()


def derive_scalar(jid, tag, idx, n):
    """`PRF(job_id, tag, idx) mod n`: two SHA-256 blocks, 512 bits before reduction."""
    wide = b""
    for ctr in (0, 1):
        buf = jid.encode() + b"\x00" + tag.encode() + b"\x00" + idx.to_bytes(8, "big") + bytes([ctr])
        wide += hashlib.sha256(buf).digest()
    return int.from_bytes(wide, "big") % n


class Context:
    """A validated job with its branch table -- `JobContext`."""

    def __init__(self, job):
        if job["version"] != 1:
            raise ValueError(f"job version {job['version']} is not 1")
        self.job = job
        self.p = _parse_hex(job["p"])
        self.a = _parse_hex(job["a"])
        self.b = _parse_hex(job["b"])
        self.n = _parse_hex(job["order"])
        self.g = (_parse_hex(job["generator"]["x"]), _parse_hex(job["generator"]["y"]))
        self.q = (_parse_hex(job["target"]["x"]), _parse_hex(job["target"]["y"]))
        self.dp_bits = int(job["dp_bits"])
        self.negation = bool(job["negation_map"])
        self.unit_size = int(job["unit_size"])
        if not _on_curve(self.g, self.a, self.b, self.p):
            raise ValueError("generator is not on the curve")
        if not _on_curve(self.q, self.a, self.b, self.p):
            raise ValueError("target is not on the curve")
        if _mul(self.n, self.g, self.a, self.p) is not None:
            raise ValueError("n*P is not the identity: order is wrong")
        self.id = job_id(job)
        self.branches = []
        for j in range(int(job["num_branches"])):
            u = derive_scalar(self.id, "branch-u", j, self.n)
            v = derive_scalar(self.id, "branch-v", j, self.n)
            self.branches.append((u, v, self.combine(u, v)))
        self.dp_mask = (1 << self.dp_bits) - 1
        cap = int(job["max_steps_per_walker"])
        self.step_cap = cap if cap else 20 << self.dp_bits

    def combine(self, a, b):
        return _add(_mul(a, self.g, self.a, self.p), _mul(b, self.q, self.a, self.p), self.a, self.p)

    def is_dp(self, P):
        return P is not None and (P[0] & self.dp_mask) == 0

    def needs_flip(self, P):
        return P is not None and 2 * P[1] > self.p

    def walker_start(self, i):
        a = derive_scalar(self.id, "walker-a", i, self.n)
        b = derive_scalar(self.id, "walker-b", i, self.n)
        return a, b, self.combine(a, b)

    def step(self, R, a, b, last):
        """One step of the walk -- `walk::step`."""
        idx = (R[0] & 0xFFFFFFFFFFFFFFFF) % len(self.branches)
        u, v, B = self.branches[idx]
        np_ = _add(R, B, self.a, self.p)
        na = (a + u) % self.n
        nb = (b + v) % self.n
        if self.negation:
            if last is not None and np_ == last:
                np_ = _add(R, R, self.a, self.p)
                na = (2 * a) % self.n
                nb = (2 * b) % self.n
            if self.needs_flip(np_):
                np_ = _neg(np_, self.p)
                na = (-na) % self.n
                nb = (-nb) % self.n
        return np_, na, nb

    def run_walker(self, i):
        """Walk from walker `i`'s derived start to a distinguished point.

        Returns `(steps, x, y, a, b)` or `None` for a dead trail (step cap
        hit: a fruitless cycle, or an unlucky sparse region).
        """
        a, b, R = self.walker_start(i)
        if self.negation and self.needs_flip(R):
            R = _neg(R, self.p)
            a, b = (-a) % self.n, (-b) % self.n
        last = None
        steps = 0
        while True:
            if self.is_dp(R):
                return steps, R[0], R[1], a, b
            if steps >= self.step_cap:
                return None
            np_, na, nb = self.step(R, a, b, last)
            last, R, a, b = R, np_, na, nb
            steps += 1

    def artifact(self, x, y, a, b):
        """The canonical artifact for a point: `2y <= p`, coefficients to match."""
        if 2 * y > self.p:
            y, a, b = (-y) % self.p, (-a) % self.n, (-b) % self.n
        return {"x": _hex(x), "y": _hex(y), "a": _hex(a), "b": _hex(b)}

    def verify(self, artifact):
        """What the pinned checker checks, as a (bool, reason) pair."""
        if not isinstance(artifact, dict) or set(artifact) != {"x", "y", "a", "b"}:
            return False, "artifact must be exactly {x, y, a, b}"
        vals = {}
        for key in ("x", "y", "a", "b"):
            s = artifact[key]
            if not isinstance(s, str) or not s or any(c not in "0123456789abcdef" for c in s):
                return False, f"{key} must be lowercase hex"
            if len(s) > 1 and s[0] == "0":
                return False, f"{key} has a leading zero; one point, one spelling"
            vals[key] = int(s, 16)
        x, y, a, b = vals["x"], vals["y"], vals["a"], vals["b"]
        if not _on_curve((x, y), self.a, self.b, self.p):
            return False, "point is not on the curve"
        if x & self.dp_mask:
            return False, f"x is not distinguished: low {self.dp_bits} bits are not zero"
        if 2 * y > self.p:
            return False, "y is not canonical: need 2y <= p"
        if not (0 <= a < self.n and 0 <= b < self.n):
            return False, "coefficients must lie in [0, n)"
        if self.combine(a, b) != (x, y):
            return False, "a*P + b*Q is not the claimed point"
        return True, f"verified: a*P + b*Q is a distinguished point (2^{self.dp_bits} steps of work)"

    def solve_collision(self, first, second):
        """`k` from two artifacts for one point with different coefficients.

        `a1 P + b1 Q = a2 P + b2 Q` gives `(a1 - a2) = (b2 - b1) k`, so
        `k = (a1 - a2) / (b2 - b1) mod n` when `b1 != b2`. Returns `None`
        when the two are the same trail (equal coefficients) or when the
        coefficients are degenerate.
        """
        for art in (first, second):
            ok, why = self.verify(art)
            if not ok:
                raise ValueError(why)
        if first["x"] != second["x"] or first["y"] != second["y"]:
            raise ValueError("not the same point")
        a1, b1 = int(first["a"], 16), int(first["b"], 16)
        a2, b2 = int(second["a"], 16), int(second["b"], 16)
        if b1 == b2:
            return None
        k = (a1 - a2) * pow((b2 - b1) % self.n, -1, self.n) % self.n
        if _mul(k, self.g, self.a, self.p) != self.q:
            raise ValueError("collision did not solve: is n the order of P?")
        return k


# -- CLI -----------------------------------------------------------------------


def _write(artifact, path):
    text = json.dumps(artifact, sort_keys=True, indent=2) + "\n"
    if path:
        with open(path, "w") as handle:
            handle.write(text)
    else:
        sys.stdout.write(text)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_id = sub.add_parser("job-id", help="print the job id every participant must agree on")
    p_id.add_argument("--job", required=True)

    p_walk = sub.add_parser("walk", help="walk one walker or one unit to distinguished points")
    p_walk.add_argument("--job", required=True)
    group = p_walk.add_mutually_exclusive_group(required=True)
    group.add_argument("--walker", type=int, help="a single walker index")
    group.add_argument("--unit", type=int, help="every walker in unit U: [U*unit_size, (U+1)*unit_size)")
    p_walk.add_argument("--out", help="write the single artifact here (with --walker)")
    p_walk.add_argument("--out-dir", help="write one artifact file per point here (with --unit)")
    p_walk.add_argument("--quiet", action="store_true")

    p_verify = sub.add_parser("verify", help="check artifacts the way the pinned checker does")
    p_verify.add_argument("--job", required=True)
    p_verify.add_argument("artifacts", nargs="+")

    p_coll = sub.add_parser("collide", help="compute k from two artifacts for one point")
    p_coll.add_argument("--job", required=True)
    p_coll.add_argument("first")
    p_coll.add_argument("second")

    args = parser.parse_args(argv)
    job = load_job(args.job)

    if args.cmd == "job-id":
        print(job_id(job))
        return 0

    ctx = Context(job)

    if args.cmd == "walk":
        if args.walker is not None:
            indices = [args.walker]
        else:
            first = args.unit * ctx.unit_size
            indices = range(first, first + ctx.unit_size)
        if args.out_dir:
            os.makedirs(args.out_dir, exist_ok=True)
        found = 0
        for i in indices:
            rec = ctx.run_walker(i)
            if rec is None:
                if not args.quiet:
                    print(f"walker {i}: dead trail after {ctx.step_cap} steps", file=sys.stderr)
                continue
            steps, x, y, a, b = rec
            artifact = ctx.artifact(x, y, a, b)
            found += 1
            if not args.quiet:
                print(f"walker {i}: distinguished point after {steps} steps", file=sys.stderr)
            if args.out_dir:
                _write(artifact, os.path.join(args.out_dir, f"dp-{i}.json"))
            else:
                _write(artifact, args.out if args.walker is not None else None)
        return 0 if found else 1

    if args.cmd == "verify":
        bad = 0
        for path in args.artifacts:
            with open(path) as handle:
                ok, why = ctx.verify(json.load(handle))
            print(f"{'ok  ' if ok else 'FAIL'}  {path}: {why}")
            bad += not ok
        return 1 if bad else 0

    if args.cmd == "collide":
        with open(args.first) as handle:
            first = json.load(handle)
        with open(args.second) as handle:
            second = json.load(handle)
        k = ctx.solve_collision(first, second)
        if k is None:
            print("same trail: identical coefficients, nothing to solve", file=sys.stderr)
            return 1
        print(json.dumps({"k": f"{k:064x}"}))
        return 0

    return 2


if __name__ == "__main__":
    sys.exit(main())
