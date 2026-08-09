"""Certificate: a 2-colouring of K_17 with no monochromatic K_4.

R(4,4) = 18 means every 2-colouring of K_18 contains a monochromatic K_4, and
that 17 is the largest complete graph where one can be avoided. Such a
colouring exists -- the Paley graph of order 17 is one -- so this is a
pass/fail certificate rather than a ratchet: either the artifact avoids every
monochromatic K_4 or it does not.

Worth having alongside the scored objectives because it is the honest shape for
a question with a *witness* rather than a *frontier*. Not everything worth
funding is a number to push.

The check is C(17,4) = 2380 four-subsets, each a look at six edges. Complete,
not sampled.

Returns a bool. Invalid input is a rejection, never an exception -- a bad
artifact and a broken checker are different facts.
"""

VERTICES = 17
CLIQUE = 4


def _valid_edges(edges) -> bool:
    """A full upper-triangular adjacency: one colour bit per unordered pair."""
    if not isinstance(edges, list) or len(edges) != VERTICES:
        return False
    for row in edges:
        if not isinstance(row, list) or len(row) != VERTICES:
            return False
        for value in row:
            if not isinstance(value, int) or isinstance(value, bool) or value not in (0, 1):
                return False
    return True


def _symmetric_with_empty_diagonal(edges: list[list[int]]) -> bool:
    """An edge has one colour, however it is read.

    Checked rather than assumed: an asymmetric matrix would let a submitter
    give the same pair two colours and dodge the clique test from one side.
    """
    for i in range(VERTICES):
        if edges[i][i] != 0:
            return False
        for j in range(i + 1, VERTICES):
            if edges[i][j] != edges[j][i]:
                return False
    return True


def _has_mono_clique(edges: list[list[int]], colour: int) -> bool:
    for a in range(VERTICES):
        for b in range(a + 1, VERTICES):
            if edges[a][b] != colour:
                continue
            for c in range(b + 1, VERTICES):
                if edges[a][c] != colour or edges[b][c] != colour:
                    continue
                for d in range(c + 1, VERTICES):
                    if (
                        edges[a][d] == colour
                        and edges[b][d] == colour
                        and edges[c][d] == colour
                    ):
                        return True
    return False


def check(artifact: dict) -> bool:
    edges = artifact.get("edges")
    if not _valid_edges(edges):
        return False
    if not _symmetric_with_empty_diagonal(edges):
        return False
    return not _has_mono_clique(edges, 0) and not _has_mono_clique(edges, 1)
