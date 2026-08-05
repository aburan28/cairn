"""Is reward-weighted ancestor attribution slicing-invariant?

Current rule: a claim sends delta upstream, split among its direct citations,
recursively -- so decay is geometric in *hops*. Slicing adds hops.

Proposed: a claim sends delta upstream, split among all its transitive
ancestors weighted by each ancestor's own settled reward. On a ratchet,
settled reward IS progress moved (telescoping guarantees the slices of one
improvement sum to the unsliced reward), so the weights are slicing-invariant
by construction.
"""
from fractions import Fraction

DELTA = Fraction(1, 4)

def chain(steps):
    """steps: [(who, reward)] each citing the previous. Returns claims dict."""
    claims = {}
    prev = None
    for i, (who, reward) in enumerate(steps):
        cid = f"c{i}"
        claims[cid] = {"who": who, "reward": reward, "cites": [prev] if prev else []}
        prev = cid
    return claims

def current_flow(claims, max_depth=6):
    """Geometric per-hop decay, as implemented today."""
    out = {}
    for cid, c in claims.items():
        stack = [(cid, Fraction(c["reward"]), 0, ())]
        while stack:
            here, share, depth, path = stack.pop()
            node = claims[here]
            cites = [x for x in node["cites"] if x in claims and x not in path]
            if depth >= max_depth or not cites:
                out[node["who"]] = out.get(node["who"], 0) + share
                continue
            up = share * DELTA
            out[node["who"]] = out.get(node["who"], 0) + (share - up)
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

def proposed_flow(claims):
    """delta split among ALL transitive ancestors, weighted by their reward."""
    out = {}
    for cid, c in claims.items():
        reward = Fraction(c["reward"])
        anc = ancestors_with_weight(claims, cid)
        total = sum(anc.values())
        if not anc or total == 0:
            out[c["who"]] = out.get(c["who"], 0) + reward
            continue
        up = reward * DELTA
        out[c["who"]] = out.get(c["who"], 0) + (reward - up)
        for a, w in anc.items():
            who = claims[a]["who"]
            out[who] = out.get(who, 0) + up * Fraction(w, total)
    return out

def report(name, steps):
    claims = chain(steps)
    cur, prop = current_flow(claims), proposed_flow(claims)
    tot_in = sum(r for _, r in steps)
    print(f"  {name:28s} current: " + "  ".join(f"{k}={float(v):>10.0f}" for k,v in sorted(cur.items())))
    print(f"  {'':28s} proposed:" + "  ".join(f"{k}={float(v):>10.0f}" for k,v in sorted(prop.items())))
    assert sum(cur.values()) == tot_in, "current does not conserve"
    assert sum(prop.values()) == tot_in, "proposed does not conserve"

print("README showcase: alice 12pts, bob 12->16, carol 16->20")
honest = [("alice", 300_000), ("bob", 400_000), ("carol", 400_000)]
report("honest (bob one claim)", honest)

sliced = [("alice", 300_000)] + [("bob", 100_000)]*4 + [("carol", 400_000)]
report("bob slices into 4", sliced)

sliced16 = [("alice", 300_000)] + [("bob", 25_000)]*16 + [("carol", 400_000)]
report("bob slices into 16", sliced16)

print()
def alice_of(steps, f):
    return f(chain(steps))["alice"]
for label, f in (("current", current_flow), ("proposed", proposed_flow)):
    a1, a4, a16 = (float(alice_of(s, f)) for s in (honest, sliced, sliced16))
    print(f"  alice under {label:9s}: 1 slice {a1:>10.0f} | 4 slices {a4:>10.0f} | 16 slices {a16:>10.0f}"
          f"  -> {'INVARIANT' if a1==a4==a16 else f'LOSES {100*(a1-a16)/a1:.0f}%'}")

print()
print("Where does the residual 8% come from? Split alice's inflow by payer.")
from collections import defaultdict
def inflow_by_payer(steps):
    claims = chain(steps)
    by = defaultdict(Fraction)
    for cid, c in claims.items():
        anc = ancestors_with_weight(claims, cid)
        total = sum(anc.values())
        if not anc or total == 0:
            continue
        up = Fraction(c["reward"]) * DELTA
        for a, w in anc.items():
            if claims[a]["who"] == "alice":
                by[c["who"]] += up * Fraction(w, total)
    return by

for label, steps in (("bob unsliced", honest), ("bob x4", sliced), ("bob x16", sliced16)):
    by = inflow_by_payer(steps)
    parts = "  ".join(f"from {k}={float(v):>9.0f}" for k, v in sorted(by.items()))
    print(f"  {label:14s} {parts}")
