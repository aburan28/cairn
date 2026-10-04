#!/usr/bin/env python3
"""Recompute a few exact facts about the toy curve y^2 = x^3 + 2x + 3 over F_97.

This is what a `replay` objective pins: a command that, run again by anyone,
prints the same integers it printed for the submitter. The verifier does not
read these values off the artifact and believe them; it runs this program in
a jail and compares, field by field, what came out with what was claimed.

Everything printed here is a count or an exact integer, which is what
`reproducible_fields` may name: a timing or a memory figure would differ run
to run and the verifier refuses such a field name at validation.
"""
import json

P = 97
A = 2
B = 3


def on_curve(x, y):
    return (y * y - (x * x * x + A * x + B)) % P == 0


def points():
    pts = [(x, y) for x in range(P) for y in range(P) if on_curve(x, y)]
    return pts


def add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    (x1, y1), (x2, y2) = p1, p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if p1 == p2:
        lam = (3 * x1 * x1 + A) * pow(2 * y1, -1, P) % P
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, P) % P
    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)


def order(point):
    n = 1
    acc = point
    while acc is not None:
        acc = add(acc, point)
        n += 1
    return n


def main():
    pts = points()
    group_order = len(pts) + 1  # plus the point at infinity
    generator = (3, 6)
    assert on_curve(*generator)
    print(
        json.dumps(
            {
                "group_order": group_order,
                "affine_points": len(pts),
                "generator_order": order(generator),
                "two_torsion_points": sum(1 for (_, y) in pts if y == 0),
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
