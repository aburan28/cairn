"""Content-addressed storage for pinned verifier code.

An objective pins its checker by SHA-256 and *references* it by a path relative
to the bundle root. The hash makes substitution impossible; the path makes
availability somebody else's problem. A node holding the log but not the
operator's working directory cannot run the checker, so it answers UNAVAILABLE
forever -- which means the guarantee the whole project rests on, *anyone can
independently re-derive every settled result from the log alone*, held only for
whoever also had the filesystem.

THE PIN IS ALREADY THE CONTENT ADDRESS

So there is no second identity scheme and, deliberately, no new record field. A
blob's name *is* the hex SHA-256 the objective already declares in
``checker_sha256`` / ``evaluator_sha256`` / ``statistic.sha256``. Adding a
locator to the objective was rejected twice over: inside the digest, a dead URL
would fork the objective and orphan every claim against it; outside it, it would
be unpinned attacker-controlled text that every verifying node fetches.

PARITY

This mirrors ``src/blobs.rs`` and must keep mirroring it. The two things that
have to agree exactly, or a Python node and a Rust node sharing a root will fail
to find each other's blobs:

* the address: bare lowercase hex, no ``sha256:`` prefix (that spelling belongs
  to record ids), of the file's exact bytes with no normalization;
* the layout: ``<root>/.proofwork/blobs/<address>``, flat.

``conformance/vectors.json`` pins both.

RULES

*Verify before write.* :meth:`BlobStore.put` hashes in memory and refuses a
mismatch before anything reaches the filesystem, so the store never holds a file
that could be executed under a name it does not hash to. The write is to a
temporary name and then renamed, so a crash mid-write cannot leave a short file
visible under a real address.

*A ceiling, checked before allocating.* :data:`MAX_BLOB_BYTES` bounds a blob
wherever it arrives, against a declared length where one exists.

*An address is 64 lowercase hex characters or it is not an address.*
:func:`is_address` is load-bearing rather than cosmetic: the address becomes a
filename and it arrives from an objective a stranger wrote. Without the check,
``"sha256": "../../../../etc/passwd"`` reaches ``os.path.join``.
"""
from __future__ import annotations

import hashlib
import os
from typing import Iterable

#: Where a store lives under a bundle root. Beside the pinned code rather than
#: beside the log, because the root is what a pinned path resolves against.
STORE_DIR = os.path.join(".proofwork", "blobs")

#: Largest blob this implementation will store, serve, or accept.
#:
#: A pinned checker is a source file; the shipped examples are a few kilobytes.
#: Deliberately not configurable: a node that raised it would accept blobs its
#: peers refuse, and that asymmetry is invisible until an objective becomes
#: unverifiable on half the network.
MAX_BLOB_BYTES = 1 << 20

_HEX = set("0123456789abcdef")


def address(data: bytes) -> str:
    """The content address of ``data``: bare lowercase hex, no prefix.

    Matches the spelling an objective's verifier block already uses. Two
    spellings for one hash would be two names for one blob, and each half of the
    network would fail to find the other half's copy.
    """
    return hashlib.sha256(data).hexdigest()


def is_address(text: object) -> bool:
    """Exactly 64 characters, each ``0-9a-f``.

    Uppercase is refused rather than folded: two spellings would be two files,
    and the objective declaring the uppercase form would be unverifiable on a
    node that stored the lowercase one.
    """
    return isinstance(text, str) and len(text) == 64 and set(text) <= _HEX


class BlobError(Exception):
    """Base for every refusal in this module."""


class NotAnAddress(BlobError):
    """Refused before it is allowed anywhere near a path join."""


class TooLarge(BlobError):
    """Over ``MAX_BLOB_BYTES``."""


class Mismatch(BlobError):
    """Bytes offered under an address they do not hash to. Never written."""


class Absent(BlobError):
    """No local copy.

    Distinct from every other class here because it is the one that must become
    UNAVAILABLE rather than a refusal: a blob this node does not have says
    nothing about anybody's artifact, and a peer can fix it by sending it.
    """


class BlobStore:
    """A directory of blobs, each filed under its own content address.

    Flat rather than sharded by hash prefix. Sharding keeps directory sizes down
    when there are millions of objects; a node holds one blob per distinct pinned
    checker it has heard of, and a two-level tree would buy nothing but a second
    place for the path arithmetic to go wrong.
    """

    def __init__(self, directory: str):
        self.directory = directory

    @classmethod
    def under(cls, root: str) -> "BlobStore":
        """The store belonging to a bundle root."""
        return cls(os.path.join(root, STORE_DIR))

    def path_of(self, addr: str) -> str:
        """Where a blob would live.

        Raises for anything that is not an address, so no caller can turn a
        hostile pin into a path outside the store.
        """
        if not is_address(addr):
            raise NotAnAddress(
                f"{addr!r} is not a content address (64 lowercase hex characters)"
            )
        return os.path.join(self.directory, addr)

    def holds(self, addr: str) -> bool:
        """Whether a copy is on disk. Existence only -- cheap enough to call once
        per pin per round.

        A file whose contents have rotted is reported as held here and caught by
        :meth:`read`, which is the only place the bytes are used.
        """
        try:
            return os.path.isfile(self.path_of(addr))
        except NotAnAddress:
            return False

    def read(self, wanted: str) -> bytes:
        """Read a blob, verifying it against its own filename.

        Not paranoia about our own writes: the store is an ordinary directory an
        operator can edit, a backup can restore badly, and a disk can corrupt. A
        file whose name is the hash of its contents and whose contents disagree
        is not a blob, so it is deleted rather than returned -- otherwise it
        shadows the real blob forever, since :meth:`holds` would go on reporting
        the address as held and the fetch that would replace it would never be
        attempted.
        """
        path = self.path_of(wanted)
        try:
            size = os.path.getsize(path)
        except FileNotFoundError:
            raise Absent(f"no local copy of verifier code {wanted}") from None
        # The declared length, before the allocation. A store entry is untrusted
        # input for the same reason a wire frame is.
        if size > MAX_BLOB_BYTES:
            raise TooLarge(f"verifier code is {size} bytes, limit is {MAX_BLOB_BYTES}")
        with open(path, "rb") as handle:
            data = handle.read()
        actual = address(data)
        if actual != wanted:
            try:
                os.remove(path)
            except OSError:
                pass
            raise Mismatch(f"verifier code hashes to {actual}, offered under {wanted}")
        return data

    def put(self, declared: str, data: bytes) -> str:
        """Store ``data`` under ``declared``, **verifying first**.

        Every path into the store goes through here, which is what makes "a
        received blob is checked against the pin before it is written anywhere it
        could be run" a property of the class rather than of each call site. The
        order is: shape of the address, then the ceiling, then the hash, then the
        filesystem. Nothing hostile reaches disk.
        """
        path = self.path_of(declared)
        if len(data) > MAX_BLOB_BYTES:
            raise TooLarge(f"verifier code is {len(data)} bytes, limit is {MAX_BLOB_BYTES}")
        actual = address(data)
        if actual != declared:
            raise Mismatch(f"verifier code hashes to {actual}, offered under {declared}")
        if os.path.isfile(path):
            return path
        os.makedirs(self.directory, mode=0o700, exist_ok=True)
        # Written under a temporary name and renamed, so a crash cannot leave a
        # truncated file visible under an address it does not hash to. The
        # temporary name carries the pid so two processes sharing a root do not
        # rename each other's partial writes into place.
        staging = os.path.join(self.directory, f".{declared}.{os.getpid()}.partial")
        try:
            # No execute bit: this file holds code a stranger sent, and the only
            # thing that should open it is the interpreter running the verifier.
            handle = os.open(staging, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            try:
                os.write(handle, data)
            finally:
                os.close(handle)
            os.replace(staging, path)
        except OSError as exc:
            try:
                os.remove(staging)
            except OSError:
                pass
            raise BlobError(f"blob store: {exc}") from exc
        return path

    def publish_file(self, path: str, declared: str) -> bool:
        """Publish a bundle file whose hash the objective declares.

        How code enters the network: the funder has the file on disk, and this
        makes their node able to serve it. ``False`` means the file is absent or
        does not match the pin -- not an error, because a node replaying somebody
        else's objectives has neither the bundle nor any obligation to.
        """
        if not is_address(declared):
            raise NotAnAddress(f"{declared!r} is not a content address")
        try:
            if not os.path.isfile(path) or os.path.getsize(path) > MAX_BLOB_BYTES:
                return False
            with open(path, "rb") as handle:
                data = handle.read()
        except OSError:
            return False
        if address(data) != declared:
            return False
        self.put(declared, data)
        return True

    def addresses(self) -> list[str]:
        """Every address held, sorted.

        An empty or absent directory is empty, not an error: a node that has
        never fetched anything is a normal node. Anything whose name is not an
        address is not a blob, whatever it contains.
        """
        try:
            names = os.listdir(self.directory)
        except OSError:
            return []
        return sorted(name for name in names if is_address(name))

    def retain(self, keep: Iterable[str]) -> int:
        """Drop every blob outside ``keep``, returning how many went.

        Collection is explicit -- a command an operator runs, never something a
        sync round does on its way past. A node cannot tell a blob nobody wants
        from a blob pinned by an objective it has not synced yet, and dropping
        the second kind on a timer would make a node stop being able to serve
        precisely the code its peers are about to ask it for.
        """
        keeping = set(keep)
        dropped = 0
        for held in self.addresses():
            if held in keeping:
                continue
            try:
                os.remove(self.path_of(held))
                dropped += 1
            except OSError:
                pass
        return dropped
