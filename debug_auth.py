"""
PassMetric Debug — Run this from your backend/ directory to diagnose login issues.
Usage:  python debug_auth.py
"""

import os
import sys
import json
import base64
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError

# Adjust path if needed
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cryptManager import CryptManager

ph = PasswordHasher()

# ─── Find the database ────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
possible_paths = [
    os.path.join(BASE_DIR, 'passmetric.db'),
    os.path.join(BASE_DIR, 'instance', 'passmetric.db'),
    os.path.join(os.getcwd(), 'passmetric.db'),
    os.path.join(os.getcwd(), 'instance', 'passmetric.db'),
]

print("=" * 60)
print("  PassMetric Auth Debugger")
print("=" * 60)

print("\n[1] Searching for database files...\n")
found_dbs = []
for p in possible_paths:
    exists = os.path.exists(p)
    size = os.path.getsize(p) if exists else 0
    marker = "FOUND" if exists else "  -  "
    print(f"  {marker}  {p}  ({size} bytes)" if exists else f"  {marker}  {p}")
    if exists:
        found_dbs.append(p)

if not found_dbs:
    print("\n  ERROR: No database file found!")
    print("  Make sure you run this script from the backend/ directory.")
    sys.exit(1)

# Use the first found DB
import sqlite3

for db_path in found_dbs:
    print(f"\n{'=' * 60}")
    print(f"  Inspecting: {db_path}")
    print(f"{'=' * 60}")

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Check if users table exists
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
    if not cursor.fetchone():
        print("  No 'users' table found in this database.")
        conn.close()
        continue

    # List all users
    cursor.execute("SELECT id, email, master_password_hash, vault_salt FROM users")
    users = cursor.fetchall()

    print(f"\n[2] Users in database: {len(users)}\n")

    for user_id, email, pw_hash, vault_salt in users:
        print(f"  User #{user_id}: {email}")
        print(f"    Hash length: {len(pw_hash)} chars")
        print(f"    Hash prefix: {pw_hash[:50]}...")
        print(f"    Salt length: {len(vault_salt)} chars")

        # Validate hash format
        if pw_hash.startswith('$argon2'):
            print(f"    Hash format: VALID (argon2)")
        else:
            print(f"    Hash format: INVALID — not an argon2 hash!")
            print(f"    Full hash: {pw_hash}")
        print()

    conn.close()

# ─── Interactive test ─────────────────────────────────────────────────
print(f"\n{'=' * 60}")
print("  Interactive Password Verification Test")
print(f"{'=' * 60}")

test_email = input("\n  Enter the email to test: ").strip().lower()
test_password = input("  Enter the password to test: ").strip()

if not test_email or not test_password:
    print("  Skipping test.")
    sys.exit(0)

# Search across all found databases
for db_path in found_dbs:
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute("SELECT id, email, master_password_hash, vault_salt FROM users WHERE email = ?", (test_email,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        print(f"\n  User '{test_email}' NOT FOUND in {os.path.basename(db_path)}")
        continue

    user_id, email, stored_hash, vault_salt = row
    print(f"\n  Found user in: {db_path}")
    print(f"  Stored hash: {stored_hash[:60]}...")

    # Test verification
    print(f"\n  Testing ph.verify(stored_hash, '{test_password}')...")
    try:
        ph.verify(stored_hash, test_password)
        print("  RESULT: PASSWORD MATCHES!")

        # Also test vault key derivation
        salt_bytes = base64.b64decode(vault_salt)
        vault_key = CryptManager.derive_key(test_password, salt_bytes)
        print(f"  Vault key derived successfully ({len(vault_key)} bytes)")

    except VerifyMismatchError:
        print("  RESULT: PASSWORD DOES NOT MATCH")
        print()
        print("  This means the password you entered is different from")
        print("  the one used during registration. Possible causes:")
        print("    - You registered with a different password")
        print("    - The account was created during an earlier test run")
        print("    - Copy/paste added invisible characters")
        print()
        print("  QUICK FIX: Delete the database and re-register:")
        print(f"    rm {db_path}")
        print("    Then restart your Flask server and register again.")

    except VerificationError as e:
        print(f"  RESULT: HASH IS CORRUPTED — {e}")
        print("  The stored hash cannot be parsed by argon2.")
        print(f"  QUICK FIX: Delete the database and re-register:")
        print(f"    rm {db_path}")

    except Exception as e:
        print(f"  RESULT: UNEXPECTED ERROR — {type(e).__name__}: {e}")

# ─── Also test hashing round-trip ─────────────────────────────────────
print(f"\n{'=' * 60}")
print("  Sanity Check: Hash → Verify round-trip")
print(f"{'=' * 60}")

test_hash = ph.hash(test_password)
print(f"\n  Fresh hash: {test_hash[:60]}...")
try:
    ph.verify(test_hash, test_password)
    print("  Round-trip: PASS — argon2 is working correctly")
except Exception as e:
    print(f"  Round-trip: FAIL — argon2 is broken! {e}")

print()
