import os
import base64
from datetime import datetime, timezone
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

db = SQLAlchemy()

class User(UserMixin, db.Model):
    __tablename__ = 'users'

    
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    # Argon2id hash of the master password (for login verification)
    master_password_hash = db.Column(db.String(512), nullable=False)
    # Salt for vault encryption key derivation
    vault_salt = db.Column(db.String(64), nullable=False)
    # Encrypted verification token (proves derived key is correct)
    vault_verification = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    
    failed_login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)        # Null = not locked
    last_failed_login = db.Column(db.DateTime, nullable=True)

    email_verified = db.Column(db.Boolean, default=False)
    email_verification_token = db.Column(db.String(128), nullable=True)
    email_verification_sent_at = db.Column(db.DateTime, nullable=True)

    totp_secret = db.Column(db.String(64), nullable=True)       # Null = 2FA not enabled
    totp_enabled = db.Column(db.Boolean, default=False)

    # This tells SQLAlchemy there's a relationship to vault entries
    vault_entries = db.relationship('VaultEntry', backref='owner', lazy=True)


class VaultEntry(db.Model):
    __tablename__ = 'vault_entries'

    id = db.Column(db.Integer, primary_key=True)
    entry_id = db.Column(db.String(32), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)

    website = db.Column(db.String(255), nullable=False)
    username = db.Column(db.String(255), nullable=False)

    # The password is stored ENCRYPTED (JSON blob with nonce + ciphertext)
    encrypted_password = db.Column(db.Text, nullable=False)

    notes = db.Column(db.Text, default='')
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    @staticmethod
    def generate_entry_id():
        return base64.urlsafe_b64encode(os.urandom(16)).decode('utf-8').rstrip('=')