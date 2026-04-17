# BreachChecker: Checks if a password is in a known breach dataset (e.g. RockYou).

import os
import hashlib
from typing import Optional, Tuple


class BreachChecker:

    def __init__(self, dataset_path: str = None):
        # Default: look for rockyou.txt next to this file (backend/rockyou.txt)
        if dataset_path is None:
            dataset_path = os.path.join(os.path.dirname(__file__), 'rockyou.txt')
        self.dataset_path = dataset_path
        self._hashed_passwords = set()
        self._total_loaded = 0
        self._is_loaded = False

    def _hash_password(self, password: str) -> str:
        # Hash a password with SHA-256 for storage/comparison.
        return hashlib.sha256(password.encode('utf-8', errors='ignore')).hexdigest()

    def load_dataset(self) -> bool:
# Load the breach dataset into memory (hashed for privacy). Returns True if successful.
        if self._is_loaded:
            return True

        if not os.path.exists(self.dataset_path):
            print(f"[BreachChecker] Dataset not found: {self.dataset_path}")
            return False

        print(f"[BreachChecker] Loading breach dataset from {self.dataset_path}...")
        count = 0
        try:
            with open(self.dataset_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    password = line.strip()
                    if password:
                        self._hashed_passwords.add(self._hash_password(password))
                        count += 1
                        if count % 1_000_000 == 0:
                            print(f"[BreachChecker]   ...loaded {count:,} passwords")

            self._total_loaded = count
            self._is_loaded = True
            print(f"[BreachChecker] Loaded {count:,} passwords from breach dataset")
            return True

        except Exception as e:
            print(f"[BreachChecker] Error loading dataset: {e}")
            return False

    def is_breached(self, password: str) -> Tuple[bool, Optional[str]]:
        # Check if the given password is in the breach dataset. Returns (found, message).
        if not self._is_loaded:
            return False, None  

        pw_hash = self._hash_password(password)
        found = pw_hash in self._hashed_passwords

        if found:
            return True, (
                f"This password was found in a database of {self._total_loaded:,} "
                f"leaked passwords (RockYou breach). Choose a different password."
            )
        return False, None

    @property
    def is_loaded(self) -> bool:
        return self._is_loaded

    @property
    def total_passwords(self) -> int:
        return self._total_loaded