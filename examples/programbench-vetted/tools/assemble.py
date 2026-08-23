"""Assemble the pilot's reference program. Authoring tool; not pinned.

The evaluator carries only the flat opcode list, the way a real
ProgramBench task carries only a runnable binary. This file is the listing
that produced it, kept so the example is auditable, and `--check` re-derives
the machine code currently pinned in the evaluator.
"""
import re
import sys

OPS = {
    "PUSH_ACC": 0, "PUSH_X": 1, "PUSH_I": 2, "PUSH_CONST": 3,
    "ADD": 4, "MUL": 5, "XOR": 6, "MOD": 7, "SHL": 8,
    "STORE_ACC": 9, "JZ": 10, "JMP": 11, "HALT": 12, "DUP": 13,
    "SUB": 14, "POP": 15,
}

M = 1000003

LISTING = f"""
    PUSH_X
    PUSH_CONST 3
    MOD                 ; t = x % 3
    DUP
    JZ L0               ; t == 0
    PUSH_CONST 1
    SUB
    JZ L1               ; t == 1
    JMP L2              ; t == 2
L0: POP
    PUSH_ACC
    PUSH_CONST 7
    MUL
    PUSH_X
    ADD
    PUSH_CONST {M}
    MOD
    STORE_ACC
    HALT
L1: PUSH_ACC
    PUSH_X
    PUSH_I
    PUSH_CONST 5
    MOD
    SHL
    XOR
    PUSH_CONST {M}
    MOD
    STORE_ACC
    HALT
L2: PUSH_ACC
    PUSH_X
    DUP
    MUL
    ADD
    PUSH_CONST {M}
    MOD
    STORE_ACC
    HALT
"""


def assemble(listing=LISTING):
    lines = []
    for raw in listing.splitlines():
        line = raw.split(";")[0].strip()
        if line:
            lines.append(line)
    labels, body = {}, []
    for line in lines:
        if ":" in line:
            label, rest = line.split(":", 1)
            labels[label.strip()] = len(body)
            line = rest.strip()
            if not line:
                continue
        body.append(line)
    code = []
    for line in body:
        parts = line.split()
        op = OPS[parts[0]]
        if len(parts) == 1:
            arg = 0
        elif parts[1] in labels:
            arg = labels[parts[1]]
        else:
            arg = int(parts[1])
        code += [op, arg]
    return code


if __name__ == "__main__":
    code = assemble()
    if "--check" in sys.argv:
        src = open(f"{sys.path[0]}/../evaluators/programbench_pilot.py").read()
        block = re.search(r"PROGRAM = \[(.*?)\]", src, re.S).group(1)
        pinned = [int(n) for n in re.findall(r"-?\d+", block)]
        print("MATCH" if pinned == code else f"MISMATCH\npinned {pinned}\nbuilt  {code}")
        sys.exit(0 if pinned == code else 1)
    print(f"{len(code) // 2} instructions")
    rows = [", ".join(str(n) for n in code[i:i + 10]) for i in range(0, len(code), 10)]
    print("PROGRAM = [\n    " + ",\n    ".join(rows) + ",\n]")
