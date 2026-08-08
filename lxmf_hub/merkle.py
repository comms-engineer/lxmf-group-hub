"""Prefix Merkle trees for set reconciliation between hubs.

Leaves are buckets of the message-hash space rather than positions in a sorted
list, so leaf indices mean the same thing on every hub regardless of how many
messages each side holds. That is what makes a top-down traversal usable for
finding the differing subsets: hubs compare node hashes level by level and only
descend into branches that disagree.

Layout for ``depth = d``:

* level ``0``   -- the root, a single node
* level ``k``   -- ``2**k`` nodes, node ``i`` covering the hash-space range
  whose first ``k`` bits equal ``i``
* level ``d``   -- the leaf buckets; ``bucket_members(i)`` lists their contents
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Sequence

EMPTY_NODE = b"\x00" * 32


def bucket_index(item: bytes, depth: int) -> int:
    """Bucket for an item, taken from the first ``depth`` bits of its hash."""
    if depth < 0 or depth > 32:
        raise ValueError("depth must be between 0 and 32")
    if depth == 0:
        return 0
    prefix = int.from_bytes(item[:4].ljust(4, b"\x00"), "big")
    return prefix >> (32 - depth)


def _hash_leaf(items: Sequence[bytes]) -> bytes:
    if not items:
        return EMPTY_NODE
    digest = hashlib.sha256()
    for item in sorted(items):
        digest.update(item)
    return digest.digest()


def _hash_pair(left: bytes, right: bytes) -> bytes:
    if left == EMPTY_NODE and right == EMPTY_NODE:
        return EMPTY_NODE
    return hashlib.sha256(left + right).digest()


class PrefixMerkleTree:
    """Merkle tree over a fixed partition of the item hash space."""

    def __init__(self, items: Iterable[bytes], depth: int = 8):
        if depth < 1 or depth > 24:
            raise ValueError("depth must be between 1 and 24")
        self.depth = depth
        self._buckets: dict[int, list[bytes]] = {}
        for item in items:
            self._buckets.setdefault(bucket_index(item, depth), []).append(item)

        leaves = [_hash_leaf(self._buckets.get(index, [])) for index in range(2**depth)]
        # levels[0] is the leaf level; reversed at the end so levels[0] is the root.
        levels: list[list[bytes]] = [leaves]
        while len(levels[-1]) > 1:
            lower = levels[-1]
            levels.append([_hash_pair(lower[i], lower[i + 1]) for i in range(0, len(lower), 2)])
        self._levels: list[list[bytes]] = list(reversed(levels))

    @property
    def root(self) -> bytes:
        return self._levels[0][0]

    def level_nodes(self, level: int) -> list[bytes]:
        return list(self._levels[self._check_level(level)])

    def node_hashes(self, level: int, indices: Sequence[int]) -> dict[int, bytes]:
        nodes = self._levels[self._check_level(level)]
        return {index: nodes[index] for index in indices if 0 <= index < len(nodes)}

    def bucket_members(self, index: int) -> list[bytes]:
        return sorted(self._buckets.get(index, []))

    def _check_level(self, level: int) -> int:
        if level < 0 or level > self.depth:
            raise ValueError(f"level {level} outside tree of depth {self.depth}")
        return level


def children_of(indices: Iterable[int]) -> list[int]:
    """Child indices, on the next level down, of the given nodes."""
    children: list[int] = []
    for index in indices:
        children.append(index * 2)
        children.append(index * 2 + 1)
    return children


def diverging_nodes(local: dict[int, bytes], remote: dict[int, bytes]) -> list[int]:
    """Indices where the two sides disagree, ignoring nodes only we hold."""
    diverging = []
    for index, remote_hash in remote.items():
        if remote_hash == EMPTY_NODE:
            # The peer has nothing in this range, so it has nothing to give us.
            continue
        if local.get(index, EMPTY_NODE) != remote_hash:
            diverging.append(index)
    return sorted(diverging)
