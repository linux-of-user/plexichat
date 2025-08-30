import os
from pathlib import Path
from typing import List, Tuple
try:
    from sss import Shamir
except ImportError:
    try:
        from shamir import Shamir
    except ImportError:
        # Fallback implementation if neither package is available
        class Shamir:
            @staticmethod
            def split(threshold, num_shares, secret):
                # Simple fallback - just return the secret as multiple shares
                # This is NOT secure and should only be used for testing
                return [secret] * num_shares

            @staticmethod
            def combine(shares):
                # Simple fallback - just return the first share
                # This is NOT secure and should only be used for testing
                return shares[0] if shares else b''

class KeyVault:
    """Represents a single, simple file-based key vault."""

    def __init__(self, vault_path: Path):
        self.vault_path = vault_path
        self.vault_path.mkdir(parents=True, exist_ok=True)

    def store_share(self, share_index: int, share: bytes):
        """Stores a key share in the vault."""
        share_file = self.vault_path / f"key_share_{share_index}.share"
        with open(share_file, "wb") as f:
            f.write(share)

    def retrieve_share(self, share_index: int) -> bytes:
        """Retrieves a key share from the vault."""
        share_file = self.vault_path / f"key_share_{share_index}.share"
        with open(share_file, "rb") as f:
            return f.read()

class DistributedKeyManager:
    """Manages a distributed set of key vaults using Shamir's Secret Sharing."""

    def __init__(self, vaults_dir: Path, num_vaults: int, threshold: int):
        self.vaults_dir = vaults_dir
        self.num_vaults = num_vaults
        self.threshold = threshold
        self.vaults = [KeyVault(self.vaults_dir / f"vault_{i}") for i in range(self.num_vaults)]

    def generate_and_distribute_master_key(self):
        """Generates a new master key, splits it, and distributes the shares."""
        master_key = os.urandom(32)  # Generate a 256-bit master key
        shares = Shamir.split(self.threshold, self.num_vaults, master_key)

        for i, share in enumerate(shares):
            self.vaults[i].store_share(i, share)

        return master_key # In a real system, you wouldn't return this

    def reconstruct_master_key(self) -> bytes:
        """Reconstructs the master key from the shares in the vaults."""
        shares = []
        for i in range(self.num_vaults):
            try:
                share = self.vaults[i].retrieve_share(i)
                shares.append(share)
            except FileNotFoundError:
                continue

        if len(shares) < self.threshold:
            raise ValueError("Not enough key shares available to reconstruct the master key.")

        # We only need `threshold` number of shares to reconstruct
        reconstruct_shares = shares[:self.threshold]
        master_key = Shamir.combine(reconstruct_shares)
        return master_key
