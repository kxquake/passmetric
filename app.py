import secrets
import os
import json
import base64
import smtplib

from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from flask import Flask, redirect, session, request, jsonify, send_from_directory
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect, generate_csrf
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError
from combinedAnalyzer import CombinedPasswordAnalyzer
from passGen import PasswordGenerator, PasswordRequirements
from models import db, User, VaultEntry
from cryptManager import CryptManager
from breachChecker import BreachChecker
from pybloom_live import ScalableBloomFilter
from datetime import datetime, timedelta, timezone
from itsdangerous import URLSafeTimedSerializer


app = Flask(
    __name__,
    static_folder=os.path.join(os.path.dirname(__file__), '..', 'frontend'),
    static_url_path=''
)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
    strategy="fixed-window",
)

# If the rate-limit storage is ever unreachable, don't block real requests.
# Log the failure and let the request through 
limiter.storage 
app.config['RATELIMIT_IN_MEMORY_FALLBACK_ENABLED'] = True
app.config['RATELIMIT_SWALLOW_ERRORS'] = True

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

csrf = CSRFProtect(app)

ph = PasswordHasher()

analyzer = CombinedPasswordAnalyzer()
generator = PasswordGenerator()
breach_checker = BreachChecker()
breach_checker.load_dataset()  # Loads breach dataset on startup

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION = timedelta(minutes=15) # Account lockout duration after max failed attempts
ATTEMPT_RESET_WINDOW = timedelta(minutes=30) # Time window to reset failed attempts count if no failures occur

app.config['SESSION_COOKIE_HTTPONLY'] = True    # JS can't read session cookie
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Prevent cross-site sending
app.config['SESSION_COOKIE_SECURE'] = False     # Set True when using HTTPS
app.config['WTF_CSRF_TIME_LIMIT'] = 3600       # CSRF token valid for 1 hour

SMTP_HOST = os.environ.get('SMTP_HOST', 'smtp.gmail.com')
SMTP_PORT = int(os.environ.get('SMTP_PORT', 587))
SMTP_USER = os.environ.get('SMTP_USER', '')
SMTP_PASS = os.environ.get('SMTP_PASS', '')
APP_URL = os.environ.get('APP_URL', 'http://localhost:5000')

email_serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

def generate_email_token(email):
    return email_serializer.dumps(email, salt='email-confirm')

def verify_email_token(token, max_age=3600):
    try:
        email = email_serializer.loads(token, salt='email-verify', max_age=max_age)
        return email
    except Exception:
        return None
def send_verification_email(to_email, token):
    verify_url = f"{APP_URL}/verify-email?token={token}"

    msg = MIMEMultipart('alternative')
    msg['Subject'] = 'PassMetric — Verify your email'
    msg['From'] = SMTP_USER
    msg['To'] = to_email

    html = f"""
    <html><body style="font-family: sans-serif; background: #0f172a; color: #e2e8f0; padding: 40px;">
        <div style="max-width: 480px; margin: auto;">
            <h2 style="color: #6366f1;">PassMetric</h2>
            <p>Welcome! Please verify your email to activate your vault.</p>
            <a href="{verify_url}"
               style="display: inline-block; padding: 12px 28px; background: #6366f1;
                      color: white; text-decoration: none; border-radius: 8px;
                      font-weight: 600; margin: 20px 0;">
                Verify Email
            </a>
            <p style="font-size: 13px; color: #94a3b8;">
                This link expires in 1 hour. If you didn't create this account, ignore this email.
            </p>
        </div>
    </body></html>
    """

    msg.attach(MIMEText(html, 'html'))

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.send_message(msg)
        print(f"[EMAIL] Verification sent to {to_email}")
    except Exception as e:
        print(f"[EMAIL] Failed to send: {e}")
        # For local dev without SMTP, print the link to console
        print(f"[EMAIL] Verify URL: {verify_url}")

# Decorator to block access to certain routes if email is not verified
def require_verified_email(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.email_verified:
            return jsonify({
                'error': 'Please verify your email first',
                'email_verified': False
            }), 403
        return f(*args, **kwargs)
    return decorated

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SECRET_KEY_FILE = os.path.join(BASE_DIR, '.secret_key')
 
def get_or_create_secret_key():
    if os.path.exists(SECRET_KEY_FILE):
        with open(SECRET_KEY_FILE, 'r') as f:
            key = f.read().strip()
            if key:  # Make sure it's not empty
                return key
    # Generate a new key and save it
    key = secrets.token_hex(32)
    with open(SECRET_KEY_FILE, 'w') as f:
        f.write(key)
    return key
 
app.config['SECRET_KEY'] = get_or_create_secret_key()

DB_PATH = os.path.join(BASE_DIR, 'passmetric.db')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + DB_PATH
 
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
 
db.init_app(app)
 
with app.app_context():
    db.create_all()


@app.route('/')
def index():
    return send_from_directory(app.static_folder, 'indexx.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return send_from_directory(app.static_folder, 'dashboard.html')


@app.route('/api/hello', methods=['GET'])
def hello():
    return jsonify({'message': 'PassMetric API is running!'})

@app.route('/api/csrf-token', methods=['GET'])
def get_csrf_token():
    token = generate_csrf()
    return jsonify({'csrf_token': token})

# For JSON requests, CSRF tokens wont be enforced (since they should be protected by CORS and auth tokens), but for form submissions we will.
@app.before_request
def csrf_protect_forms():
    if request.content_type == 'application/json':
        pass 

@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Cross-Origin-Opener-Policy'] = 'same-origin'
    response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'

    if not app.debug:
        response.headers['Strict-Transport-Security'] = (
            'max-age=31536000; includeSubDomains'
        )

    if request.path.startswith('/api/') or request.path == '/dashboard':
        response.headers['Cache-Control'] = 'no-store, private'

    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' https://js.hcaptcha.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "frame-src https://newassets.hcaptcha.com; "
        "connect-src 'self' https://hcaptcha.com https://*.hcaptcha.com; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "form-action 'self';"
    )
    return response


# Generic error handler: ensure /api/* always returns JSON, never HTML
@app.errorhandler(Exception)
def handle_any_exception(e):
    import traceback
    # Let Flask handle HTTP exceptions (e.g. 404, 401) with their own status
    from werkzeug.exceptions import HTTPException
    if isinstance(e, HTTPException):
        if request.path.startswith('/api/'):
            return jsonify({'error': e.description, 'code': e.code}), e.code
        return e  # non-API: let Flask render the default page
    # For unexpected exceptions, log the traceback and return JSON
    traceback.print_exc()
    if request.path.startswith('/api/'):
        return jsonify({
            'error': f'{type(e).__name__}: {str(e)}',
            'code': 500
        }), 500
    return e

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

@login_manager.unauthorized_handler
def unauthorized():
    # If it's an API request, return JSON
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Unauthorized'}), 401
    # Otherwise redirect to login page
    return redirect('/')

@app.route('/api/auth/register', methods=['POST'])
@limiter.limit("3 per minute")  # Limit registration attempts to prevent abuse
@limiter.limit("20 per hour")
def register():
    import traceback

    data = request.get_json() or {}
    email = data.get('email', '').strip().lower()
    master_password = data.get('master_password', '')
    check_breaches = data.get('check_breaches', True)
    confirm_weak = data.get('confirm_weak', False)

    if not email or not master_password:
        return jsonify({'error': 'Email and password are required'}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'Account already exists'}), 409

    #  Step-by-step error reporting — tells us exactly which step crashed
    step = 'analyze_password'
    try:
        analysis = analyzer.analyze_password(master_password, include_ml=False)
        if analysis is None or 'rule_based' not in analysis:
            print(f"[REGISTER] analyze_password returned unexpected shape: {analysis!r}")
            return jsonify({'error': 'Password analysis failed'}), 500

        step = 'extract_score'
        score = analysis['rule_based'].get('score', 0)

        step = 'breach_check'
        is_breached = False
        breach_msg = None
        if check_breaches and breach_checker.is_loaded:
            result = breach_checker.is_breached(master_password)
            if result is not None:
                is_breached, breach_msg = result

        step = 'weak_password_confirmation'
        if not confirm_weak and (is_breached or score < 30):
            return jsonify({
                'error': 'Weak or exposed password',
                'requires_confirmation': True,
                'is_breached': is_breached,
                'breach_message': breach_msg,
                'score': score,
                'strength': analysis.get('combined_strength', 'WEAK'),
                'issues': analysis['rule_based'].get('issues', []),
                'recommendations': analysis['rule_based'].get('recommendations', []),
            }), 400

        step = 'hash_password'
        password_hash = ph.hash(master_password)

        step = 'generate_vault_salt'
        vault_salt = CryptManager.generate_salt()

        step = 'derive_vault_key'
        vault_key = CryptManager.derive_key(master_password, vault_salt)

        step = 'create_verification_token'
        verification = CryptManager.encrypt_data("passmetric_ok", vault_key)

        email_token = generate_email_token(email)

        step = 'create_user_row'
        user = User(
            email=email,
            master_password_hash=password_hash,
            vault_salt=base64.b64encode(vault_salt).decode('utf-8'),
            vault_verification=json.dumps(verification),
            email_verified=False,
            email_verification_token=email_token,
            email_verification_sent_at=datetime.now(timezone.utc)

        )
        db.session.add(user)
        db.session.commit()

        send_verification_email(email, email_token) 

        step = 'login_user'
        login_user(user)
        session['vault_key'] = base64.b64encode(vault_key).decode('utf-8')

        return jsonify({'message': 'Account created', 'email': email}), 201

    except Exception as e:
        print(f"\n[REGISTER] FAILED at step: {step!r}")
        print(f"[REGISTER] Exception: {type(e).__name__}: {e}")
        traceback.print_exc()
        return jsonify({
            'error': f'Registration failed at step "{step}": {type(e).__name__}: {e}',
            'step': step,
        }), 500
                
@app.route('/verify-email')
def verify_email():
    token = request.args.get('token', '')
    email = verify_email_token(token)

    if not email:
        return '<h2>Invalid or expired verification link.</h2>', 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return '<h2>User not found.</h2>', 404

    user.email_verified = True
    user.email_verification_token = None
    db.session.commit()

    # Redirect to login page with success message
    return '''
    <html><body style="font-family:sans-serif;background:#0f172a;color:#e2e8f0;
          display:flex;justify-content:center;align-items:center;height:100vh;">
        <div style="text-align:center;">
            <h2 style="color:#22c55e;">Email Verified!</h2>
            <p>Your account is now active.</p>
            <a href="/" style="color:#6366f1;">Go to login</a>
        </div>
    </body></html>
    '''


@app.route('/api/auth/resend-verification', methods=['POST'])
@login_required
@limiter.limit("2 per minute")
def resend_verification():
    if current_user.email_verified:
        return jsonify({'message': 'Already verified'}), 200

    token = generate_email_token(current_user.email)
    current_user.email_verification_token = token
    current_user.email_verification_sent_at = datetime.now(timezone.utc)
    db.session.commit()

    send_verification_email(current_user.email, token)
    return jsonify({'message': 'Verification email resent'}), 200


# Password pre-check endpoint: analyze strength and check breaches before registration
@app.route('/api/auth/precheck-password', methods=['POST'])
def precheck_password():
    data = request.get_json() or {}
    password = data.get('password', '')

    if not password:
        return jsonify({'error': 'Password is required'}), 400

    try:
        analysis = analyzer.analyze_password(password)
    except Exception:
        analysis = analyzer.analyze_password(password, include_ml=False)

    is_breached = False
    breach_msg = None
    if breach_checker.is_loaded:
        is_breached, breach_msg = breach_checker.is_breached(password)

    return jsonify({
        'score': analysis['rule_based']['score'],
        'strength': analysis['combined_strength'],
        'is_breached': is_breached,
        'breach_message': breach_msg,
        'is_weak': analysis['rule_based']['score'] < 30,
        'needs_warning': bool(is_breached or analysis['rule_based']['score'] < 30),
    }), 200

@app.route('/api/auth/login', methods=['POST'])
@limiter.limit("3 per minute")  # Limit registration attempts to prevent abuse
@limiter.limit("20 per hour")
def login():
    data = request.get_json()
    email = data.get('email', '').strip().lower()
    master_password = data.get('master_password', '')

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'error': 'Invalid email or password'}), 401
    
    now = datetime.now(timezone.utc)

    # Check if account is locked
    if user.locked_until and user.locked_until > now:
        remaining = int((user.locked_until - now).total_seconds())
        minutes_left = max(1, remaining // 60)
        return jsonify({
            'error': f'Account temporarily locked. Try again in {minutes_left} minute(s).',
            'locked': True,
            'retry_after_seconds': remaining
        }), 423  # 423 Locked
    
    # Reset failed attempts if last failure was long ago
    if (user.last_failed_login and
        user.failed_login_attempts > 0 and
        (now - user.last_failed_login) > ATTEMPT_RESET_WINDOW):
        user.failed_login_attempts = 0


    # Verify password against stored hash
    try:
        ph.verify(user.master_password_hash, master_password)
    except (VerifyMismatchError, VerificationError, Exception):
        # ── Record failed attempt ──
        user.failed_login_attempts += 1
        user.last_failed_login = now

        if user.failed_login_attempts >= MAX_FAILED_ATTEMPTS:
            user.locked_until = now + LOCKOUT_DURATION
            db.session.commit()
            return jsonify({
                'error': f'Too many failed attempts. Account locked for {LOCKOUT_DURATION.seconds // 60} minutes.',
                'locked': True
            }), 423

        remaining_attempts = MAX_FAILED_ATTEMPTS - user.failed_login_attempts
        db.session.commit()
        return jsonify({
            'error': 'Invalid email or password',
            'attempts_remaining': remaining_attempts
        }), 401

    # Login successful — reset lockout state
    user.failed_login_attempts = 0
    user.locked_until = None
    user.last_failed_login = None

    # Rehash if needed
    if ph.check_needs_rehash(user.master_password_hash):
        user.master_password_hash = ph.hash(master_password)

    # Derive vault key
    vault_salt = base64.b64decode(user.vault_salt)
    vault_key = CryptManager.derive_key(master_password, vault_salt)
    login_user(user)
    session['vault_key'] = base64.b64encode(vault_key).decode('utf-8')

    db.session.commit()
    return jsonify({'message': 'Logged in', 'email': email}), 200

@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({
        'error': 'Too many attempts. Please try again later.',
        'retry_after': e.description
    }), 429


@app.route('/api/auth/logout', methods=['POST'])
@login_required
def logout():
    session.pop('vault_key', None)   # Destroy the encryption key
    session.clear()                 # Clear all session data
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

    analysis = analyzer.analyze_password(password)

    if breach_checker.is_loaded:
        is_breached, breach_msg = breach_checker.is_breached(password)
        analysis['breach'] = {
            'is_breached': is_breached,
            'message': breach_msg,
            'dataset_size': breach_checker.total_passwords
        }
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
@require_verified_email
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

    # Check if the vault password is breached 
    breach_warning = None
    if breach_checker.is_loaded:
        is_breached, breach_msg = breach_checker.is_breached(password)
        if is_breached:
            breach_warning = breach_msg

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

    response = {'message': 'Entry added', 'entry_id': entry.entry_id}
    if breach_warning:
        response['breach_warning'] = breach_warning
    
    return jsonify(response), 201

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

#CLEAR all VAULT ENTRIES
@app.route('/api/vault/clear', methods=['POST'])
@login_required
def clear_vault():
    VaultEntry.query.filter_by(user_id=current_user.id).delete()
    db.session.commit()
    return jsonify({'message': 'Vault cleared'}), 200

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
        analysis = analyzer.analyze_password(password)  # ML included auto

        # Breach check
        is_breached = False
        if breach_checker.is_loaded:
            is_breached, _ = breach_checker.is_breached(password)

        results.append({
            'website': entry.website,
            'username': entry.username,
            'score': analysis['rule_based']['score'],
            'strength': analysis['combined_strength'],
            'is_breached': is_breached,            
            'ml_prediction': analysis.get('ml_based', {}).get('prediction') if analysis.get('ml_based') else None
        })

    avg = sum(r['score'] for r in results) / len(results) if results else 0
    weak = sum(1 for r in results if r['score'] < 40)
    breached = sum(1 for r in results if r['is_breached'])

    return jsonify({
        'average_score': round(avg, 1),
        'total': len(results),
        'weak_count': weak,
        'breached_count': breached,                
        'entries': results
    })

@app.route('/api/tools/breach-check', methods=['POST'])
@login_required
def check_breach():
    """Check a password against the breach database."""
    data = request.get_json()
    password = data.get('password', '')

    if not password:
        return jsonify({'error': 'Password is required'}), 400

    if not breach_checker.is_loaded:
        return jsonify({
            'error': 'Breach database not available',
            'is_breached': False
        }), 503

    is_breached, breach_msg = breach_checker.is_breached(password)
    return jsonify({
        'is_breached': is_breached,
        'message': breach_msg,
        'dataset_size': breach_checker.total_passwords
    }), 200


@app.route('/api/tools/breach-check-vault', methods=['GET'])
@login_required
def check_vault_breaches():
    """Check ALL vault passwords against the breach database."""
    vault_key = get_vault_key()
    if not vault_key:
        return jsonify({'error': 'Vault locked'}), 403

    if not breach_checker.is_loaded:
        return jsonify({'error': 'Breach database not available'}), 503

    entries = VaultEntry.query.filter_by(user_id=current_user.id).all()
    results = []
    breached_count = 0

    for entry in entries:
        encrypted = json.loads(entry.encrypted_password)
        password = CryptManager.decrypt_data(encrypted, vault_key)
        is_breached, breach_msg = breach_checker.is_breached(password)

        if is_breached:
            breached_count += 1

        results.append({
            'entry_id': entry.entry_id,
            'website': entry.website,
            'username': entry.username,
            'is_breached': is_breached,
        })
    

    return jsonify({
        'total': len(results),
        'breached_count': breached_count,
        'entries': results,
        'dataset_size': breach_checker.total_passwords
    }), 200






if __name__ == '__main__':
    app.run(debug=True, port=5000)