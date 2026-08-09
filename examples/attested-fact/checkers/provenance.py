"""Certificate checker: is this assertion faithfully sourced?

WHAT THIS SETTLES, AND WHAT IT DOES NOT
---------------------------------------
It settles that a quotation is *faithful* and that the documents it came from
are the ones the objective named. It does not settle that the assertion is
true, and nothing in this network can, because truth about the world is not a
function of an artifact.

That distinction is the whole point of the example. A verifier is a pinned,
deterministic program; it can check a proof term, a circuit, or a quotation. It
cannot check what happened in 1881. Any checker that claimed to would really be
checking something else -- that a chosen source says so -- and calling that
"verified" would break the one guarantee this network makes, because nobody
could re-derive it from the log.

So the record this produces says: *this assertion is supported by these exact
documents, quoted without alteration.* A reader still has to decide whether the
sources are any good. What they no longer have to do is take the submitter's
word that the sources say what the submitter claims.

WHY THE SOURCE SET IS PINNED HERE
---------------------------------
SOURCES below is a digest allowlist, and this file is itself pinned by
`checker_sha256` in the objective. So the accepted sources are part of the
objective's identity: changing which documents count means posting a different
objective, exactly as changing any other rule does.

The submitter supplies the source *text* and the checker re-derives its digest.
That is not a weakness -- it is what removes the filesystem from the check. The
text either hashes to a pinned id or it does not, and a submitter who invents a
document cannot make it hash to one of these.

WHAT IS DELIBERATELY STRICT
---------------------------
* Quotes must appear byte-for-byte after whitespace folding. No fuzzy matching:
  "approximately what the source said" is the thing this exists to refuse.
* At least MIN_SOURCES *distinct* documents must support the assertion, so one
  document cited twice is not corroboration.
"""

import hashlib
import re

# Digests of the documents this objective accepts as sources. Pinned here, and
# this file is pinned by the objective, so the set is part of the objective's id.
SOURCES = {
    "sha256:5fcf1032005aba0ab8358eafacf8e5074be9bd397fb5e66196acf59e2ed34a93":
        "sources/garfield-encyclopedia.txt",
    "sha256:7d56de4b282eb8613f9f1867f5974523489537b90ae11c38ce8b016711f91a96":
        "sources/garfield-medical-summary.txt",
}

MIN_SOURCES = 2
MAX_TEXT_BYTES = 1 << 20


def _digest(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def _fold(text: str) -> str:
    """Collapse runs of whitespace, so a line wrap is not a mismatch.

    This is the only normalisation. Case is preserved and punctuation is
    preserved, because "the source said something like this" is exactly the
    claim this checker exists to refuse.
    """
    return re.sub(r"\s+", " ", text).strip()


def check(artifact: dict) -> tuple[bool, str]:
    assertion = artifact.get("assertion")
    if not isinstance(assertion, str) or not assertion.strip():
        return False, "artifact.assertion must be a non-empty string"

    citations = artifact.get("sources")
    if not isinstance(citations, list) or not citations:
        return False, "artifact.sources must be a non-empty list"

    seen = set()
    for i, citation in enumerate(citations):
        if not isinstance(citation, dict):
            return False, f"sources[{i}] must be an object"

        document = citation.get("document")
        if document not in SOURCES:
            return False, (
                f"sources[{i}].document {document!r} is not a source this "
                f"objective accepts; the pinned set is {sorted(SOURCES)}"
            )

        text = citation.get("text")
        if not isinstance(text, str):
            return False, f"sources[{i}].text must be the source document, as a string"
        if len(text.encode("utf-8")) > MAX_TEXT_BYTES:
            return False, f"sources[{i}].text exceeds {MAX_TEXT_BYTES} bytes"

        # The binding that makes the rest meaningful: this text really is the
        # document that was cited, rather than something the submitter wrote.
        found = _digest(text)
        if found != document:
            return False, (
                f"sources[{i}].text hashes to {found}, not the {document} it "
                f"claims to be"
            )

        quote = citation.get("quote")
        if not isinstance(quote, str) or not quote.strip():
            return False, f"sources[{i}].quote must be a non-empty string"
        if _fold(quote) not in _fold(text):
            return False, (
                f"sources[{i}].quote does not appear in {SOURCES[document]}. "
                f"Quotes are compared byte-for-byte after folding whitespace"
            )

        seen.add(document)

    if len(seen) < MIN_SOURCES:
        return False, (
            f"{len(seen)} distinct source(s) cited, need >= {MIN_SOURCES}; "
            f"citing one document twice is not corroboration"
        )

    return True, (
        f"{len(citations)} quotation(s) from {len(seen)} pinned source(s) verified "
        f"verbatim. This attests provenance, NOT that the assertion is true"
    )
