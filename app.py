import os
basedir = os.path.abspath(os.path.dirname(__file__))
db_path = os.path.join(basedir, "database.db")
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
import bcrypt
import base64
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(32)
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{db_path}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# ---------------- Models ----------------

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.LargeBinary(60), nullable=False)   # bcrypt hash
    salt = db.Column(db.LargeBinary(16), nullable=False)            # for AES key derivation


class Credential(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    site_name = db.Column(db.String(255), nullable=False)
    site_url = db.Column(db.String(255), nullable=True)
    username = db.Column(db.String(255), nullable=False)
    password_encrypted = db.Column(db.LargeBinary, nullable=False)
    iv = db.Column(db.LargeBinary(16), nullable=False)

    user = db.relationship('User', backref=db.backref('credentials', lazy=True))


# ---------------- Crypto Helpers ----------------

backend = default_backend()
ITERATIONS = 100_000

def derive_key(master_password: str, salt: bytes) -> bytes:
    """Derive a 256-bit AES key from master password using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS,
        backend=backend
    )
    return kdf.derive(master_password.encode('utf-8'))


def encrypt_password(plain_text: str, key: bytes) -> (bytes, bytes):
    """Encrypt a password using AES-GCM or AES-CBC with HMAC. For simplicity here, AES-GCM-like via AES in GCM-mode is not in cryptography’s high-level; we use AES-CBC and rely on HTTPS + DB compromise resistance for demo."""
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()

    # PKCS7 padding
    pad_len = 16 - (len(plain_text.encode('utf-8')) % 16)
    padded = plain_text.encode('utf-8') + bytes([pad_len]) * pad_len

    ct = encryptor.update(padded) + encryptor.finalize()
    return ct, iv


def decrypt_password(cipher_text: bytes, iv: bytes, key: bytes) -> str:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    padded = decryptor.update(cipher_text) + decryptor.finalize()

    pad_len = padded[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError("Invalid padding")
    data = padded[:-pad_len]
    return data.decode('utf-8')


# ---------------- Auth Helpers ----------------

def get_current_user():
    user_id = session.get('user_id')
    if not user_id:
        return None
    return User.query.get(user_id)


# ---------------- Routes ----------------

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


# ---- Registration ----

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email').strip().lower()
        password = request.form.get('password')
        confirm = request.form.get('confirm_password')

        if password != confirm:
            flash("Passwords do not match", "danger")
            return redirect(url_for('register'))

        if User.query.filter_by(email=email).first():
            flash("Email already registered", "danger")
            return redirect(url_for('register'))

        # bcrypt hash for login
        pw_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        # per-user salt for AES key derivation
        salt = os.urandom(16)

        user = User(email=email, password_hash=pw_hash, salt=salt)
        db.session.add(user)
        db.session.commit()

        flash("Registration successful. Please log in.", "success")
        return redirect(url_for('login'))

    return render_template('register.html')


# ---- Login ----

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email').strip().lower()
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if not user or not bcrypt.checkpw(password.encode('utf-8'), user.password_hash):
            flash("Invalid credentials", "danger")
            return redirect(url_for('login'))

        # on success: store user_id and AES key in session
        session['user_id'] = user.id
        # derive AES key from the master password
        key = derive_key(password, user.salt)
        session['aes_key'] = base64.b64encode(key).decode('utf-8')

        flash("Logged in successfully", "success")
        return redirect(url_for('dashboard'))

    return render_template('login.html')


# ---- Logout ----

@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out", "success")
    return redirect(url_for('login'))


# ---- Dashboard ----

@app.route('/dashboard')
def dashboard():
    user = get_current_user()
    if not user:
        return redirect(url_for('login'))
    return render_template('dashboard.html', user=user)


# ---- API for credentials ----

@app.route('/api/credentials', methods=['GET'])
def api_list_credentials():
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401

    key_b64 = session.get('aes_key')
    if not key_b64:
        return jsonify({'error': 'No encryption key in session'}), 401
    key = base64.b64decode(key_b64)

    data = []
    for cred in user.credentials:
        try:
            password = decrypt_password(cred.password_encrypted, cred.iv, key)
        except Exception:
            password = "Decryption error"
        data.append({
            'id': cred.id,
            'site_name': cred.site_name,
            'site_url': cred.site_url,
            'username': cred.username,
            'password': password
        })
    return jsonify(data)


@app.route('/api/credentials', methods=['POST'])
def api_add_credential():
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401

    key_b64 = session.get('aes_key')
    if not key_b64:
        return jsonify({'error': 'No encryption key in session'}), 401
    key = base64.b64decode(key_b64)

    data = request.get_json()
    site_name = data.get('site_name')
    site_url = data.get('site_url')
    username = data.get('username')
    password = data.get('password')

    if not site_name or not username or not password:
        return jsonify({'error': 'Missing fields'}), 400

    ct, iv = encrypt_password(password, key)
    cred = Credential(
        user_id=user.id,
        site_name=site_name,
        site_url=site_url,
        username=username,
        password_encrypted=ct,
        iv=iv
    )
    db.session.add(cred)
    db.session.commit()

    return jsonify({'status': 'ok', 'id': cred.id})


@app.route('/api/credentials/<int:cred_id>', methods=['DELETE'])
def api_delete_credential(cred_id):
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Unauthorized'}), 401

    cred = Credential.query.filter_by(id=cred_id, user_id=user.id).first()
    if not cred:
        return jsonify({'error': 'Not found'}), 404

    db.session.delete(cred)
    db.session.commit()
    return jsonify({'status': 'deleted'})


# ---- Page for adding credentials ----

@app.route('/add')
def add_credential_page():
    user = get_current_user()
    if not user:
        return redirect(url_for('login'))
    return render_template('add_credential.html')


# ---- DB Init ----

with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)