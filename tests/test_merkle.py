import hashlib

from lxmf_hub.merkle import (
    EMPTY_NODE,
    PrefixMerkleTree,
    bucket_index,
    children_of,
    diverging_nodes,
)


def hashes(count, salt=b""):
    return [hashlib.sha256(salt + str(index).encode()).digest() for index in range(count)]


def test_empty_tree_has_empty_root():
    assert PrefixMerkleTree([], depth=4).root == EMPTY_NODE


def test_root_is_order_independent():
    items = hashes(40)
    first = PrefixMerkleTree(items, depth=6).root
    second = PrefixMerkleTree(list(reversed(items)), depth=6).root
    assert first == second


def test_root_changes_with_membership():
    items = hashes(20)
    base = PrefixMerkleTree(items, depth=6).root
    assert PrefixMerkleTree(items[:-1], depth=6).root != base


def test_bucket_indices_are_aligned_across_trees():
    items = hashes(50)
    left = PrefixMerkleTree(items, depth=8)
    right = PrefixMerkleTree(items[:25], depth=8)
    for item in items[:25]:
        index = bucket_index(item, 8)
        assert item in left.bucket_members(index)
        assert item in right.bucket_members(index)


def test_level_sizes():
    tree = PrefixMerkleTree(hashes(10), depth=5)
    for level in range(6):
        assert len(tree.level_nodes(level)) == 2**level


def test_traversal_finds_exactly_the_missing_items():
    depth = 6
    shared = hashes(60)
    only_remote = hashes(15, salt=b"remote")
    local = PrefixMerkleTree(shared, depth=depth)
    remote = PrefixMerkleTree(shared + only_remote, depth=depth)

    assert local.root != remote.root

    diverging = [0]
    for level in range(1, depth + 1):
        candidates = children_of(diverging)
        diverging = diverging_nodes(
            local.node_hashes(level, candidates), remote.node_hashes(level, candidates)
        )
        assert diverging

    missing = []
    for index in diverging:
        local_members = set(local.bucket_members(index))
        missing.extend(item for item in remote.bucket_members(index) if item not in local_members)

    assert sorted(missing) == sorted(only_remote)


def test_traversal_ignores_items_only_we_hold():
    depth = 5
    shared = hashes(30)
    only_local = hashes(10, salt=b"local")
    local = PrefixMerkleTree(shared + only_local, depth=depth)
    remote = PrefixMerkleTree(shared, depth=depth)

    diverging = [0]
    for level in range(1, depth + 1):
        candidates = children_of(diverging)
        diverging = diverging_nodes(
            local.node_hashes(level, candidates), remote.node_hashes(level, candidates)
        )

    missing = []
    for index in diverging:
        local_members = set(local.bucket_members(index))
        missing.extend(item for item in remote.bucket_members(index) if item not in local_members)

    assert missing == []
