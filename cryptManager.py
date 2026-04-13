import os
import base64
from hashlib import scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from argon2 import PasswordHasher
from argon2.low_level import hash_secret_raw, Type
ARGON2_AVAILABLE = True

class CryptManager:
    # Argon2id parameters (OWASP recommended values)
    ARGON2_TIME_COST = 2        # Number of iterations
    ARGON2_MEMORY_COST = 65536  # Memory usage in KiB (64 MB)
    ARGON2_PARALLELISM = 1      # Number of parallel threads

    SALT_LENGTH = 32  # 256 bits
    KEY_LENGTH = 32   # 256 bits for AES-256

    def __init__(self):
        pass

        # Generate a cryptographically secure random salt.
        # Returns: bytes: Random salt of SALT_LENGTH bytes
    @staticmethod
    def generate_salt() -> bytes:
        return os.urandom(CryptManager.SALT_LENGTH)
    
    # Derive encryption key from master password using Argon2id
    @staticmethod
    def derive_key(master_password: str, salt: bytes) -> bytes:
        return hash_secret_raw(
                secret=master_password.encode('utf-8'),
                salt=salt,
                time_cost=CryptManager.ARGON2_TIME_COST,
                memory_cost=CryptManager.ARGON2_MEMORY_COST,
                parallelism=CryptManager.ARGON2_PARALLELISM,
                hash_len=CryptManager.KEY_LENGTH,
                type=Type.ID)
    
    # Encrypt data using AES-GCM.
    @staticmethod
    def encrypt_data(data: str, key: bytes) -> dict:
        nonce = os.urandom(12)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, data.encode('utf-8'), None)
        return {
            'nonce': base64.b64encode(nonce).decode('utf-8'),
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8')
        }
    
    # Decrypt data using AES-GCM
    @staticmethod
    def decrypt_data(encrypted_data: dict, key: bytes) -> str:
        nonce = base64.b64decode(encrypted_data['nonce'])
        ciphertext = base64.b64decode(encrypted_data['ciphertext'])
        aesgcm = AESGCM(key)

        # Decrypt and verify authentication tag
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext.decode('utf-8')
    
    # Verfies the master pass by attempting to decrypt
    @staticmethod
    def verify_master_password(master_password: str, salt: bytes, verification_data: dict) -> bool:
        try:
            key = CryptManager.derive_key(master_password, salt)
            CryptManager.decrypt_data(verification_data, key)
            return True
        except Exception:
            return False

if __name__ == "__main__":
    print("Testing CryptManager...")

    # Test key derivation
    password = "MySecurePassword123!"
    salt = CryptManager.generate_salt()
    key = CryptManager.derive_key(password, salt)
    print(f" Key derived (length: {len(key)} bytes)")
    
    # Test encryption
    plaintext = "This is my secret password: P@ssw0rd!"
    encrypted = CryptManager.encrypt_data(plaintext, key)
    print(f" Data encrypted (ciphertext length: {len(encrypted['ciphertext'])} chars)")
    
    # Test decryption
    decrypted = CryptManager.decrypt_data(encrypted, key)
    assert decrypted == plaintext
    print(f" Data decrypted successfully")
    
    # Test password verification
    assert CryptManager.verify_master_password(password, salt, encrypted)
    print(f" Password verification works")
    
    # Test wrong password
    assert not CryptManager.verify_master_password("WrongPassword", salt, encrypted)
    print(f" Wrong password rejected")
    
    print("\n All crypto tests passed!")