#!/usr/bin/env python3
"""Citation Flow Harness — test slicing invariance of attribution schemes.

Current rule: geometric per-hop decay (DELTA per hop, split among direct cites).
Proposed: reward-weighted transitive ancestors (delta split by ancestor's own settled reward).

Usage:
  python3 citation-flow-harness.py [--delta DELTA] [--max-depth N] [--scenario NAME] [--json] [--export CSV]
"""

from fractions import Fraction
from collections import defaultdict
import argparse
import json
import sys

# ---------------------------------------------------------------------------
# Core attribution schemes
# ---------------------------------------------------------------------------

def build_chain(steps):
    """steps: [(who, reward)] each citing the previous. Returns claims dict."""
    claims = {}
    prev = None
    for i, (who, reward) in enumerate(steps):
        cid = f"c{i}"
        claims[cid] = {"who": who, "reward": reward, "cites": [prev] if prev else []}
        prev = cid
    return claims


def current_flow(claims, max_depth=6, delta=Fraction(1, 4)):
    """Geometric per-hop decay, as implemented today."""
    out = defaultdict(Fraction)
    for cid, c in claims.items():
        stack = [(cid, Fraction(c["reward"]), 0, ())]
        while stack:
            here, share, depth, path = stack.pop()
            node = claims[here]
            cites = [x for x in node["cites"] if x in claims and x not in path]
            if depth >= max_depth or not cites:
                out[node["who"]] += share
                continue
            up = share * delta
            out[node["who"]] += (share - up)
            per = up / len(cites)
            for p in cites:
                stack.append((p, per, depth + 1, path + (here,)))
    return out


def ancestors_with_weight(claims, cid):
    """Every transitive ancestor, and its own settled reward as the weight."""
    seen, stack, out = set(), list(claims[cid]["cites"]), {}
    while stack:
        a = stack.pop()
        if a in seen or a not in claims:
            continue
        seen.add(a)
        out[a] = claims[a]["reward"]
        stack.extend(claims[a]["cites"])
    return out


def proposed_flow(claims, delta=Fraction(1, 4)):
    """Delta split among ALL transitive ancestors, weighted by their reward."""
    out = defaultdict(Fraction)
    for cid, c in claims.items():
        reward = Fraction(c["reward"])
        anc = ancestors_with_weight(claims, cid)
        total = sum(anc.values())
        if not anc or total == 0:
            out[c["who"]] += reward
            continue
        up = reward * delta
        out[c["who"]] += (reward - up)
        for a, w in anc.items():
            who = claims[a]["who"]
            out[who] += up * Fraction(w, total)
    return out


def hybrid_flow(claims, delta=Fraction(1, 4), max_depth=6):
    """Hybrid: reward-weighted ancestors but capped at max_depth hops."""
    out = defaultdict(Fraction)
    for cid, c in claims.items():
        reward = Fraction(c["reward"])
        anc = ancestors_with_weight(claims, cid)
        # Filter by depth
        depth_limited = {}
        for a in anc:
            # Compute depth from cid to a
            depth = 0
            cur = cid
            while cur != a and cur in claims:
                cites = claims[cur]["cites"]
                if not cites or cites[0] not in claims:
                    break
                cur = cites[0]
                depth += 1
                if cur == a:
                    break
            if depth <= max_depth:
                depth_limited[a] = anc[a]
        total = sum(depth_limited.values())
        if not depth_limited or total == 0:
            out[c["who"]] += reward
            continue
        up = reward * delta
        out[c["who"]] += (reward - up)
        for a, w in depth_limited.items():
            who = claims[a]["who"]
            out[who] += up * Fraction(w, total)
    return out


# ---------------------------------------------------------------------------
# Attack scenario builders
# ---------------------------------------------------------------------------

def scenario_honest():
    """Alice 12pts, Bob 12->16 (400k), Carol 16->20 (400k)."""
    return [("alice", 300_000), ("bob", 400_000), ("carol", 400_000)]


def scenario_bob_slices(n):
    """Bob splits his 400k into n claims."""
    return [("alice", 300_000)] + [("bob", 400_000 // n)] * n + [("carol", 400_000)]


def scenario_sybil_attack():
    """Attacker creates many fake identities citing each other, then cites alice."""
    # Attacker creates 10 sybil identities each with small reward
    sybils = [(f"sybil{i}", 10_000) for i in range(10)]
    # All sybils cite alice (300k), then attacker cites all sybils
    steps = [("alice", 300_000)] + sybils + [("attacker", 400_000)]
    return steps


def scenario_collusion_ring():
    """Three parties cite each other in a cycle (if allowed) or dense cluster."""
    # Dense mutual citation: A->B, B->C, C->A, plus original work
    # Note: our chain builder only supports linear chains, so we simulate
    # by having each cite the previous in a circle
    return [("alice", 300_000), ("bob", 200_000), ("carol", 200_000), ("dave", 200_000), ("eve", 400_000)]


def scenario_free_rider():
    """Contributor cites only the funder, skipping intermediate work."""
    # Alice does work (300k), Bob improves (400k), Carol cites only Alice (skips Bob)
    # We simulate by having Carol's claim cite Alice directly
    steps = [("alice", 300_000), ("bob", 400_000)]
    # Carol would be added with a custom cite structure, but chain is linear
    return steps


def scenario_deep_chain():
    """Long chain of incremental improvements."""
    return [("a0", 100_000)] + [(f"a{i}", 100_000) for i in range(1, 20)]


def scenario_wide_fanin():
    """Many small contributions cite one major work."""
    base = [("founder", 500_000)]
    contrib = [(f"contrib{i}", 50_000) for i in range(20)]
    return base + contrib


# ---------------------------------------------------------------------------
# Analysis helpers
# ---------------------------------------------------------------------------

def analyze_flow(name, steps, schemes, delta=Fraction(1, 4), max_depth=6):
    """Run all schemes on a scenario and return comparison."""
    claims = build_chain(steps)
    results = {}
    for scheme_name, scheme_fn in schemes:
        if scheme_name in ("current", "hybrid"):
            results[scheme_name] = scheme_fn(claims, max_depth=max_depth, delta=delta)
        else:
            results[scheme_name] = scheme_fn(claims, delta=delta)
    return claims, results


def conservation_check(results, total_in):
    """Verify all schemes conserve total reward."""
    for name, flow in results.items():
        total_out = sum(flow.values())
        if total_out != total_in:
            return False, f"{name}: {total_out} != {total_in}"
    return True, "OK"


def slicing_invariance(steps_list, scheme_fn, delta=Fraction(1, 4), max_depth=6):
    """Measure how much alice's flow changes as bob slices more."""
    alice_flows = []
    for steps in steps_list:
        claims = build_chain(steps)
        flow = scheme_fn(claims, delta=delta, max_depth=max_depth) if scheme_fn.__name__ in ("current_flow", "hybrid_flow") else scheme_fn(claims, delta=delta)
        alice_flows.append(float(flow.get("alice", 0)))
    return alice_flows


def inflow_by_payer(steps, scheme="proposed", delta=Fraction(1, 4)):
    """Show who pays alice's citation inflow."""
    claims = build_chain(steps)
    if scheme == "proposed":
        flow_fn = proposed_flow
    elif scheme == "current":
        flow_fn = lambda c, d=delta: current_flow(c, max_depth=6, delta=d)
    else:
        flow_fn = lambda c, d=delta: hybrid_flow(c, max_depth=6, delta=d)

    by = defaultdict(Fraction)
    for cid, c in claims.items():
        anc = ancestors_with_weight(claims, cid)
        total = sum(anc.values())
        if not anc or total == 0:
            continue
        up = Fraction(c["reward"]) * delta
        for a, w in anc.items():
            if claims[a]["who"] == "alice":
                by[c["who"]] += up * Fraction(w, total)
    return by


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------

def format_flow(flow, label, width=28):
    items = "  ".join(f"{k}={float(v):>10.0f}" for k, v in sorted(flow.items()))
    return f"  {label:{width}s} {items}"


def print_scenario(name, steps, schemes, delta, max_depth, json_out=False):
    claims, results = analyze_flow(name, steps, schemes, delta, max_depth)
    total_in = sum(r for _, r in steps)
    ok, msg = conservation_check(results, total_in)

    if json_out:
        return {
            "scenario": name,
            "total_in": total_in,
            "conservation": ok,
            "flows": {k: {kk: float(vv) for kk, vv in v.items()} for k, v in results.items()}
        }

    print(f"\n{name} (total_in={total_in:,})")
    for scheme_name, flow in results.items():
        print(format_flow(flow, scheme_name))
    if not ok:
        print(f"  WARNING: {msg}")
    return results


def print_slicing_table(schemes, delta, max_depth):
    """Print alice's flow as bob slices more finely."""
    print("\nConvergence: alice's total as bob slices ever more finely")
    header = f"  {'slices':>7} | " + " | ".join(f"{s:>10}" for s, _ in schemes)
    print(header)
    print("  " + "-" * len(header))

    for n in (1, 4, 16, 64, 256, 1024):
        steps = scenario_bob_slices(n)
        row = f"  {n:>7} | "
        vals = []
        for scheme_name, scheme_fn in schemes:
            claims = build_chain(steps)
            if scheme_name in ("current", "hybrid"):
                flow = scheme_fn(claims, max_depth=max_depth, delta=delta)
            else:
                flow = scheme_fn(claims, delta=delta)
            vals.append(float(flow.get("alice", 0)))
        row += " | ".join(f"{v:>10.0f}" for v in vals)
        print(row)


def print_inflow_by_payer(schemes, delta, max_depth):
    """Show who pays alice in each scenario."""
    print("\nInflow to alice by payer (proposed scheme):")
    for label, steps in (("bob unsliced", scenario_honest()),
                         ("bob x4", scenario_bob_slices(4)),
                         ("bob x16", scenario_bob_slices(16))):
        by = inflow_by_payer(steps, "proposed", delta)
        parts = "  ".join(f"from {k}={float(v):>9.0f}" for k, v in sorted(by.items()))
        print(f"  {label:14s} {parts}")


# ---------------------------------------------------------------------------
# Export functions
# ---------------------------------------------------------------------------

def export_csv(results_dict, filename):
    """Export comparison results to CSV."""
    import csv
    with open(filename, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['scenario', 'scheme', 'recipient', 'flow'])
        for scenario, data in results_dict.items():
            for scheme, flow in data['flows'].items():
                for recipient, amount in flow.items():
                    writer.writerow([scenario, scheme, recipient, amount])


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Citation Flow Harness — test slicing invariance of attribution schemes"
    )
    parser.add_argument("--delta", type=float, default=0.25,
                        help="Delta fraction (default 0.25 = 1/4)")
    parser.add_argument("--max-depth", type=int, default=6,
                        help="Max citation depth for current/hybrid schemes (default 6)")
    parser.add_argument("--scenario", choices=[
        "honest", "bob_slices_4", "bob_slices_16", "bob_slices_64",
        "sybil", "collusion", "deep_chain", "wide_fanin", "all"
    ], default="all", help="Scenario to run")
    parser.add_argument("--schemes", nargs="+",
                        choices=["current", "proposed", "hybrid"],
                        default=["current", "proposed", "hybrid"],
                        help="Schemes to compare")
    parser.add_argument("--json", action="store_true", help="Output JSON")
    parser.add_argument("--csv", help="Export results to CSV file")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    args = parser.parse_args()

    delta = Fraction(args.delta).limit_denominator()
    max_depth = args.max_depth

    scheme_fns = {
        "current": current_flow,
        "proposed": proposed_flow,
        "hybrid": hybrid_flow,
    }
    schemes = [(name, scheme_fns[name]) for name in args.schemes]

    # Build scenarios
    all_scenarios = {
        "honest": ("Honest (no slicing)", scenario_honest()),
        "bob_slices_4": ("Bob slices 4x", scenario_bob_slices(4)),
        "bob_slices_16": ("Bob slices 16x", scenario_bob_slices(16)),
        "bob_slices_64": ("Bob slices 64x", scenario_bob_slices(64)),
        "sybil": ("Sybil attack (10 sybils + attacker)", scenario_sybil_attack()),
        "collusion": ("Collusion ring (5 parties)", scenario_collusion_ring()),
        "deep_chain": ("Deep chain (20 incremental)", scenario_deep_chain()),
        "wide_fanin": ("Wide fan-in (20 contributors)", scenario_wide_fanin()),
    }

    if args.scenario == "all":
        selected = list(all_scenarios.values())
    else:
        selected = [all_scenarios[args.scenario]]

    all_results = {}

    for label, steps in selected:
        res = print_scenario(label, steps, schemes, delta, max_depth, json_out=True)
        all_results[label] = res

    if not args.json:
        print_slicing_table(schemes, delta, max_depth)
        print_inflow_by_payer(schemes, delta, max_depth)

    if args.json:
        print(json.dumps(all_results, indent=2))

    if args.csv:
        export_csv(all_results, args.csv)
        print(f"\nExported to {args.csv}", file=sys.stderr)


if __name__ == "__main__":
    main()