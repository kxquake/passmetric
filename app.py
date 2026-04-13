import secrets
import os
import json
import base64

from flask import Flask, session, request, jsonify, send_from_directory
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from combinedAnalyzer import CombinedPasswordAnalyzer
from passGen import PasswordGenerator, PasswordRequirements
from models import db, User, VaultEntry
from cryptManager import CryptManager


app = Flask(
    __name__,
    static_folder=os.path.join(os.path.dirname(__file__), '..', 'frontend'),
    static_url_path=''
)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

ph = PasswordHasher()

analyzer = CombinedPasswordAnalyzer()
generator = PasswordGenerator()


app.config['SECRET_KEY'] = secrets.token_hex(32)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///passmetric.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

with app.app_context():
    db.create_all()

@app.route('/')
def index():
    return send_from_directory(app.static_folder, 'indexx.html')


@app.route('/api/hello', methods=['GET'])
def hello():
    return jsonify({'message': 'PassMetric API is running!'})

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

@login_manager.unauthorized_handler
def unauthorized():
    return jsonify({'error': 'Unauthorized'}), 401

@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    email = data.get('email', '').strip().lower()
    master_password = data.get('master_password', '')

    if not email or not master_password:
        return jsonify({'error': 'Email and password are required'}), 400

    # Check if email already exists
    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'Account already exists'}), 409
    
    # Evaluate master password strength
    analysis = analyzer.analyze_password(master_password, include_ml=False)
    if analysis['rule_based']['score'] < 30:
        return jsonify({
            'error': 'Master password is too weak',
            'analysis': {
            'score': analysis['rule_based']['score'],
            'issues': analysis['rule_based']['issues'],
            'recommendations': analysis['rule_based']['recommendations']
                }
            }), 400

    # Hash password for login verification
    password_hash = ph.hash(master_password)

    # Generate vault encryption salt and derive key
    vault_salt = CryptManager.generate_salt()
    vault_key = CryptManager.derive_key(master_password, vault_salt)

    # Create verification token (proves the key is correct on future logins)
    verification = CryptManager.encrypt_data("passmetric_ok", vault_key)

    # Save user to database
    user = User(
        email=email,
        master_password_hash=password_hash,
        vault_salt=base64.b64encode(vault_salt).decode('utf-8'),
        vault_verification=json.dumps(verification)
    )
    db.session.add(user)
    db.session.commit()

    # Auto-login after registration
    login_user(user)
    session['vault_key'] = base64.b64encode(vault_key).decode('utf-8')

    return jsonify({'message': 'Account created', 'email': email}), 201

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email', '').strip().lower()
    master_password = data.get('master_password', '')

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'error': 'Invalid email or password'}), 401

    # Verify password against stored hash
    try:
        ph.verify(user.master_password_hash, master_password)
    except VerifyMismatchError:
        return jsonify({'error': 'Invalid email or password'}), 401

    # Derive vault encryption key and store in session
    vault_salt = base64.b64decode(user.vault_salt)
    vault_key = CryptManager.derive_key(master_password, vault_salt)

    login_user(user)
    session['vault_key'] = base64.b64encode(vault_key).decode('utf-8')

    return jsonify({'message': 'Logged in', 'email': email}), 200

@app.route('/api/auth/logout', methods=['POST'])
@login_required
def logout():
    session.pop('vault_key', None)   # Destroy the encryption key
    logout_user()
    return jsonify({'message': 'Logged out'}), 200

@app.route('/api/auth/me', methods=['GET'])
@login_required
def me():
    return jsonify({'email': current_user.email}), 200



@app.route('/api/analyze', methods=['POST'])
def analyze_password():
    data = request.get_json()             # Parse the JSON body
    password = data.get('password', '')

    if not password:
        return jsonify({'error': 'Password is required'}), 400

    analysis = analyzer.analyze_password(password, include_ml=False)
    return jsonify(analysis), 200

@app.route('/api/generate', methods=['POST'])
def generate_password():
    data = request.get_json()             # Parse the JSON body
    requirements_data = data.get('requirements', {})

    requirements = PasswordRequirements(
        length=requirements_data.get('length', 12),
        include_uppercase=requirements_data.get('include_uppercase', True),
        include_lowercase=requirements_data.get('include_lowercase', True),
        include_digits=requirements_data.get('include_digits', True),
        include_symbols=requirements_data.get('include_special', True)
    )

    password = generator.generate_password(requirements)
    return jsonify({'password': password}), 200

# Helper function to get the vault key from session
def get_vault_key():
    key_b64 = session.get('vault_key')
    if not key_b64:
        return None
    return base64.b64decode(key_b64)


#add vault entry
@app.route('/api/vault/entries', methods=['POST'])
@login_required
def add_entry():
    vault_key = get_vault_key()
    if not vault_key:
        return jsonify({'error': 'Vault locked'}), 403

    data = request.get_json()
    website = data.get('website', '').strip()
    username = data.get('username', '').strip()
    password = data.get('password', '')

    if not website or not username or not password:
        return jsonify({'error': 'All fields required'}), 400

    # Encrypt the password before storing
    encrypted = CryptManager.encrypt_data(password, vault_key)

    entry = VaultEntry(
        entry_id=VaultEntry.generate_entry_id(),
        user_id=current_user.id,
        website=website,
        username=username,
        encrypted_password=json.dumps(encrypted),
        notes=data.get('notes', '')
    )
    db.session.add(entry)
    db.session.commit()

    return jsonify({'message': 'Entry added', 'entry_id': entry.entry_id}), 201

#list vault entries
@app.route('/api/vault/entries', methods=['GET'])
@login_required
def list_entries():
    vault_key = get_vault_key()
    if not vault_key:
        return jsonify({'error': 'Vault locked'}), 403

    entries = VaultEntry.query.filter_by(user_id=current_user.id).all()
    result = []

    for entry in entries:
        encrypted = json.loads(entry.encrypted_password)
        password = CryptManager.decrypt_data(encrypted, vault_key)

        result.append({
            'entry_id': entry.entry_id,
            'website': entry.website,
            'username': entry.username,
            'password': password,
            'notes': entry.notes
        })

    return jsonify({'entries': result}), 200

#Update vault entry
@app.route('/api/vault/entries/<entry_id>', methods=['PUT'])
@login_required
def update_entry(entry_id):
    vault_key = get_vault_key()
    if not vault_key:
        return jsonify({'error': 'Vault locked'}), 403

    entry = VaultEntry.query.filter_by(
        entry_id=entry_id, user_id=current_user.id
    ).first()
    if not entry:
        return jsonify({'error': 'Not found'}), 404

    data = request.get_json()
    if 'website' in data:
        entry.website = data['website']
    if 'username' in data:
        entry.username = data['username']
    if 'password' in data:
        encrypted = CryptManager.encrypt_data(data['password'], vault_key)
        entry.encrypted_password = json.dumps(encrypted)
    if 'notes' in data:
        entry.notes = data['notes']

    db.session.commit()
    return jsonify({'message': 'Updated'}), 200

#Delete vault entry
@app.route('/api/vault/entries/<entry_id>', methods=['DELETE'])
@login_required
def delete_entry(entry_id):
    entry = VaultEntry.query.filter_by(
        entry_id=entry_id, user_id=current_user.id
    ).first()
    if not entry:
        return jsonify({'error': 'Not found'}), 404

    db.session.delete(entry)
    db.session.commit()
    return jsonify({'message': 'Deleted'}), 200


#Search vault entries
@app.route('/api/vault/search', methods=['GET'])
@login_required
def search_entries():
    vault_key = get_vault_key()
    if not vault_key:
        return jsonify({'error': 'Vault locked'}), 403

    query = request.args.get('q', '').lower()
    entries = VaultEntry.query.filter_by(user_id=current_user.id).all()

    results = []
    for entry in entries:
        if query in entry.website.lower() or query in entry.username.lower():
            encrypted = json.loads(entry.encrypted_password)
            password = CryptManager.decrypt_data(encrypted, vault_key)
            results.append({
                'entry_id': entry.entry_id,
                'website': entry.website,
                'username': entry.username,
                'password': password,
                'notes': entry.notes
            })

    return jsonify({'entries': results}), 200


#Route for generating passphrase
@app.route('/api/tools/generate-passphrase', methods=['POST'])
@login_required
def generate_passphrase():
    data = request.get_json() or {}
    passphrase = generator.generate_passphrase(
        word_count=data.get('word_count', 4),
        separator=data.get('separator', '-'),
        capitalize=data.get('capitalize', True),
        add_number=data.get('add_number', True)
    )
    analysis = analyzer.analyze_password(passphrase, include_ml=False)
    return jsonify({'passphrase': passphrase, 'analysis': analysis})

#Route for health audit
@app.route('/api/tools/health-audit', methods=['GET'])
@login_required
def health_audit():
    vault_key = get_vault_key()
    if not vault_key:
        return jsonify({'error': 'Vault locked'}), 403

    entries = VaultEntry.query.filter_by(user_id=current_user.id).all()
    results = []

    for entry in entries:
        encrypted = json.loads(entry.encrypted_password)
        password = CryptManager.decrypt_data(encrypted, vault_key)
        analysis = analyzer.analyze_password(password, include_ml=False)

        results.append({
            'website': entry.website,
            'username': entry.username,
            'score': analysis['rule_based']['score'],
            'strength': analysis['combined_strength']
        })

    avg = sum(r['score'] for r in results) / len(results) if results else 0
    weak = sum(1 for r in results if r['score'] < 40)

    return jsonify({
        'average_score': round(avg, 1),
        'total': len(results),
        'weak_count': weak,
        'entries': results
    })




if __name__ == '__main__':
    app.run(debug=True, port=5000)