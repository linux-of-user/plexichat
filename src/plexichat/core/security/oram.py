import random
import math
from typing import List, Optional, Dict, Any


class Block:
    """Represents a data block in ORAM."""
    def __init__(self, block_id: int, data: Any, is_dummy: bool = False):
        self.id = block_id
        self.data = data
        self.is_dummy = is_dummy


class Bucket:
    """A bucket containing up to Z blocks."""
    def __init__(self, capacity: int):
        self.capacity = capacity
        self.blocks: List[Block] = []

    def add_block(self, block: Block):
        if len(self.blocks) < self.capacity:
            self.blocks.append(block)

    def get_blocks(self) -> List[Block]:
        return self.blocks

    def clear(self):
        self.blocks = []


class PathORAM:
    """Basic Path ORAM implementation for metadata access pattern protection."""

    def __init__(self, num_blocks: int, bucket_size: int = 4):
        self.num_blocks = num_blocks
        self.bucket_size = bucket_size
        self.height = math.ceil(math.log2(num_blocks)) if num_blocks > 1 else 1
        self.num_leaves = 2 ** self.height
        self.num_nodes = 2 ** (self.height + 1) - 1

        # Tree: list of buckets, indexed by node id (0 = root)
        self.tree: List[Bucket] = [Bucket(bucket_size) for _ in range(self.num_nodes)]

        # Position map: logical id -> leaf position
        self.position_map: Dict[int, int] = {}

        # Stash for temporary blocks
        self.stash: List[Block] = []

        # Initialize with dummy blocks
        self._initialize_dummies()

    def _initialize_dummies(self):
        """Fill the tree with dummy blocks."""
        for node in range(self.num_nodes):
            for _ in range(self.bucket_size):
                dummy = Block(-1, None, is_dummy=True)
                self.tree[node].add_block(dummy)

    def _get_path(self, leaf: int) -> List[int]:
        """Get the path from root to leaf."""
        path = []
        current = leaf
        while current >= 0:
            path.append(current)
            current = (current - 1) // 2
        return path[::-1]  # root to leaf

    def _read_path(self, leaf: int) -> List[Block]:
        """Read all blocks on the path to leaf."""
        path = self._get_path(leaf)
        blocks = []
        for node in path:
            blocks.extend(self.tree[node].get_blocks())
        return blocks

    def _write_path(self, leaf: int, blocks: List[Block]):
        """Write blocks back to the path, distributing evenly."""
        path = self._get_path(leaf)
        # Clear existing blocks on path
        for node in path:
            self.tree[node].clear()

        # Distribute blocks to buckets
        block_idx = 0
        for node in path:
            bucket = self.tree[node]
            while len(bucket.blocks) < bucket.capacity and block_idx < len(blocks):
                bucket.add_block(blocks[block_idx])
                block_idx += 1

        # Remaining blocks go to stash
        self.stash.extend(blocks[block_idx:])

    def access(self, op: str, block_id: int, data: Any = None) -> Optional[Any]:
        """
        Access a block: 'read' or 'write'.
        For write, provide data.
        Returns data for read.
        """
        if block_id not in self.position_map:
            # New block, assign random leaf
            self.position_map[block_id] = random.randint(0, self.num_leaves - 1)

        leaf = self.position_map[block_id]

        # Read path
        path_blocks = self._read_path(leaf)
        all_blocks = path_blocks + self.stash

        # Find the block
        target_block = None
        for block in all_blocks:
            if block.id == block_id and not block.is_dummy:
                target_block = block
                break

        if op == 'read':
            if target_block:
                return target_block.data
            else:
                raise ValueError(f"Block {block_id} not found")
        elif op == 'write':
            if target_block:
                target_block.data = data
            else:
                # New block
                target_block = Block(block_id, data)
                all_blocks.append(target_block)
        else:
            raise ValueError("Operation must be 'read' or 'write'")

        # Evict: select up to bucket_size blocks from stash + target
        evict_blocks = [b for b in all_blocks if not b.is_dummy][:self.bucket_size]
        if target_block not in evict_blocks:
            evict_blocks.append(target_block)

        # Update position map for evicted blocks
        for block in evict_blocks:
            self.position_map[block.id] = random.randint(0, self.num_leaves - 1)

        # Remove evicted from stash
        self.stash = [b for b in self.stash if b not in evict_blocks]

        # Write back
        self._write_path(leaf, evict_blocks)

        return None if op == 'write' else target_block.data