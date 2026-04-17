import json
import os
import base64
from datetime import datetime
from typing import List, Dict, Optional
from backend.cryptManager import CryptManager


class VaultEntry:
    def __init__(self, website: str, username: str, password: str, notes: str = "", entry_id: Optional[str] = None):
        self.entry_id = entry_id or self.generate_entry_id()
        self.website = website
        self.username = username
        self.password = password
        self.notes = notes
        self.created_at = datetime.utcnow().isoformat()
        self.updated_at = datetime.utcnow().isoformat()

    @staticmethod
    def generate_entry_id() -> str:
        return base64.urlsafe_b64encode(os.urandom(16)).decode('utf-8').rstrip('=')
    
    def to_dict(self) -> Dict:
        return {
            'entry_id': self.entry_id,
            'website': self.website,
            'username': self.username,
            'password': self.password,
            'notes': self.notes,
            'created_at': self.created_at,
            'updated_at': self.updated_at
        }
    
    @staticmethod
    def from_dict(data: Dict) -> 'VaultEntry':
        entry = VaultEntry(
            website=data['website'],
            username=data['username'],
            password=data['password'],
            notes=data.get('notes', ''),
            entry_id=data.get('entry_id')
        )
        entry.created_at = data.get('created_at', entry.created_at)
        entry.updated_at = data.get('updated_at', entry.updated_at)
        return entry
    
    def update(self, website: Optional[str] = None, username: Optional[str] = None, password: Optional[str] = None, notes: Optional[str] = None):
        if website is not None:
            self.website = website
        if username is not None:
            self.username = username
        if password is not None:
            self.password = password
        if notes is not None:
            self.notes = notes
        self.updated_at = datetime.utcnow().isoformat()

class PasswordVault:
        def __init__(self, vault_file: str = "vault.json"):
            self.vault_file = vault_file
            self.entries: List[VaultEntry] = []
            self.salt: Optional[bytes] = None
            self.key: Optional[bytes] = None
            self.is_unlocked = False
    
        def create_vault(self, master_password: str) -> bool:
            if os.path.exists(self.vault_file):
                print(f"Vault already exists at {self.vault_file}. Please unlock it.")
                return False
            
            self.salt = CryptManager.generate_salt() # Generate a new random salt for this vault
            self.key = CryptManager.derive_key(master_password, self.salt) # Derive the encryption key from the master password and salt
            verification_data = CryptManager.encrypt_data("verification", self.key) # Create a verification token to confirm correct master password on unlock

            self.entries = [] 
            self.is_unlocked = True
            self.save_vault(verification_data)

            return True
        
        def unlock_vault(self, master_password: str) -> bool:
            if not os.path.exists(self.vault_file):
                print(f"No vault found at {self.vault_file}. Please create one first.")
                return False
            
            with open(self.vault_file, 'r') as f:
                vault_data = json.load(f)
            
            self.salt = base64.b64decode(vault_data['salt']) # Load the salt from the vault file
            self.key = CryptManager.derive_key(master_password, self.salt) # Derive the encryption key from the provided master password and loaded salt

            if not CryptManager.verify_master_password(master_password, self.salt, vault_data['verification']):
                print("Incorrect master password.")
                return False
            
            self.entries = [VaultEntry.from_dict(entry) for entry in vault_data.get('entries', [])]
            self.is_unlocked = True
            return True
        
        def lock_vault(self):
            self.entries = []
            self.salt = None
            self.key = None
            self.is_unlocked = False

        def add_entry(self, website: str, username: str, password: str, notes: str = "") -> VaultEntry:
            if not self.is_unlocked:
                print("Vault is locked. Please unlock it first.")
                return None
            
            entry = VaultEntry(website, username, password, notes)
            self.entries.append(entry)
            self.save_vault()
            return entry
        
        def get_entry(self, entry_id: str) -> Optional[VaultEntry]:
            if not self.is_unlocked:
                print("Vault is locked. Please unlock it first.")
                return None
            
            for entry in self.entries:
                if entry.entry_id == entry_id:
                    return entry
            return None
        
        def get_all_entries(self) -> List[VaultEntry]:
            if not self.is_unlocked:
                print("Vault is locked. Please unlock it first.")
                return []
            return self.entries
        
        def update_entry(self, entry_id: str, website: Optional[str] = None, username: Optional[str] = None, password: Optional[str] = None, notes: Optional[str] = None) -> bool:
            if not self.is_unlocked:
                print("Vault is locked. Please unlock it first.")
                return None
            
            entry = self.get_entry(entry_id)
            if entry is None:
                print(f"No entry found with ID {entry_id}.")
                return False
            
            entry.update(website, username, password, notes)
            self.save_vault()
            return True
        
        def delete_entry(self, entry_id: str) -> bool:
            if not self.is_unlocked:
                print("Vault is locked. Please unlock it first.")
                return None
            
            for i, entry in enumerate(self.entries):
                if entry.entry_id == entry_id:
                    del self.entries[i]
                    self.save_vault()
                    return True
            print(f"No entry found with ID {entry_id}.")
            return False
        
        def search_entries(self, query: str) -> List[VaultEntry]:
            if not self.is_unlocked:
                print("Vault is locked. Please unlock it first.")
                return False
            
            query = query.lower()
            results = []

            for entry in self.entries:
                if (query in entry.website.lower() or 
                    query in entry.username.lower() or 
                    query in entry.notes.lower()):
                    results.append(entry)
            return results
        
        def save_vault(self, verification_data: Optional[dict] = None):
            if not self.is_unlocked:
                print("Vault is locked. Please unlock it first.")
                return False
            
            
            vault_data = {
                'salt': base64.b64encode(self.salt).decode('utf-8'),
                'verification': verification_data or CryptManager.encrypt_data("verification", self.key),
                'entries': [entry.to_dict() for entry in self.entries]
            }
            with open(self.vault_file, 'w') as f:
                json.dump(vault_data, f, indent=4)

        def vault_exists(self) -> bool:
            return os.path.exists(self.vault_file)
        