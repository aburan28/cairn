"""Baseline: a bubble-sort network. Replace this file to lower the score.

Print a JSON list of [low, high] comparators on 8 wires, applied in order.
"""

import json

N = 8
print(json.dumps([[j, j + 1] for i in range(N - 1) for j in range(N - 1 - i)]))
