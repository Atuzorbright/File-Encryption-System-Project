import os
import sqlite3
import secrets
import io
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# Configuration settings
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'vault_storage')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
DATABASE_PATH = "secure_share.db"

def get_db_connection():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# ==========================================
# CRYPTOGRAPHIC UTILITY FUNCTIONS (AES-256-GCM)
# ==========================================
def encrypt_file_payload(file_bytes, key):
    """Encrypts raw bytes using AES-GCM with a specific 256-bit key."""
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)  # Standard 12-byte initialization vector (IV)
    ciphertext = aesgcm.encrypt(nonce, file_bytes, None)
    return nonce + ciphertext  # Prepend nonce for extraction during decryption

def decrypt_file_payload(encrypted_bytes, key):
    """Extracts nonce and decrypts ciphertext using AES-GCM."""
    aesgcm = AESGCM(key)
    nonce = encrypted_bytes[:12]
    ciphertext = encrypted_bytes[12:]
    return aesgcm.decrypt(nonce, ciphertext, None)

# ==========================================
# AUTHENTICATION ROUTING CONTROLLER
# ==========================================
@app.route('/', methods=['GET', 'POST'])
def gateway_auth():
    if 'user_email' in session:
        return redirect(url_for('user_workspace'))
        
    if request.method == 'POST':
        action_type = request.form.get('action')
        db = get_db_connection()
        
        # Handler A: Registration Endpoint
        if action_type == 'register':
            name = request.form.get('name').strip()
            phone = request.form.get('phone').strip()
            email = request.form.get('email').strip().lower()
            password = request.form.get('password')
            
            # Form Validation Rules
            if not (name and phone and email and password):
                flash("All fields are mandatory for identity creation.", "danger")
                return redirect(url_for('gateway_auth'))
                
            hashed_pwd = generate_password_hash(password, method='scrypt')
            try:
                db.execute(
                    "INSERT INTO users (name, phone, email, password) VALUES (?, ?, ?, ?)",
                    (name, phone, email, hashed_pwd)
                )
                db.commit()
                flash("Registration successful! You can now log in.", "success")
            except sqlite3.IntegrityError:
                flash("This Gmail account/username is already registered.", "danger")
            finally:
                db.close()
            return redirect(url_for('gateway_auth'))
            
        # Handler B: Login Authenticator
        elif action_type == 'login':
            email = request.form.get('email').strip().lower()
            password = request.form.get('password')
            
            user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
            db.close()
            
            if user and check_password_hash(user['password'], password):
                session['user_email'] = user['email']
                session['user_name'] = user['name']
                return redirect(url_for('user_workspace'))
            else:
                flash("Invalid login credentials. Please try again.", "danger")
                return redirect(url_for('gateway_auth'))
                
    return render_template('login.html')

# ==========================================
# CORE WORKSPACE / DASHBOARD ENDPOINTS
# ==========================================
@app.route('/workspace', methods=['GET', 'POST'])
def user_workspace():
    if 'user_email' not in session:
        return redirect(url_for('gateway_auth'))
        
    current_user = session['user_email']
    db = get_db_connection()
    
    if request.method == 'POST':
        recipient = request.form.get('recipient_email').strip().lower()
        uploaded_file = request.files.get('secure_file')
        
        if not recipient or not uploaded_file or uploaded_file.filename == '':
            flash("Please provide a valid recipient email and attach a document.", "warning")
            return redirect(url_for('user_workspace'))
            
        # Check if recipient user profile exists
        check_user = db.execute("SELECT id FROM users WHERE email = ?", (recipient,)).fetchone()
        if not check_user:
            flash("Recipient email is not registered in the system.", "danger")
            db.close()
            return redirect(url_for('user_workspace'))
            
        # Extract filename metrics and read raw file bytes
        orig_filename = secure_filename(uploaded_file.filename)
        file_payload = uploaded_file.read()
        
        # 1. Generate unique 256-bit symmetric key for this file session
        raw_crypto_key = AESGCM.generate_key(bit_length=256)
        
        # 2. Execute Cryptographic Encryption Engine
        try:
            encrypted_data = encrypt_file_payload(file_payload, raw_crypto_key)
            
            # Save file using an isolated token name to obfuscate original details
            random_token = secrets.token_hex(16)
            encrypted_filename = f"ENC_{random_token}.dat"
            target_storage_path = os.path.join(UPLOAD_FOLDER, encrypted_filename)
            
            with open(target_storage_path, 'wb') as storage_stream:
                storage_stream.write(encrypted_data)
                
            # Hex-encode key for safe relational string storage
            hex_stored_key = raw_crypto_key.hex()
            
            # 3. Log cryptographic records into DB Ledger
            db.execute(
                """INSERT INTO shared_files 
                   (sender_email, recipient_email, original_filename, encrypted_filename, encryption_key) 
                   VALUES (?, ?, ?, ?, ?)""",
                (current_user, recipient, orig_filename, encrypted_filename, hex_stored_key)
            )
            db.commit()
            flash("File encrypted and dispatched securely.", "success")
            
        except Exception as crypto_error:
            flash(f"System experienced a cryptographic error: {str(crypto_error)}", "danger")
            
    # Fetch rows where user is EITHER sender OR recipient to fill the transaction grid
    records = db.execute(
        """SELECT * FROM shared_files 
           WHERE sender_email = ? OR recipient_email = ? 
           ORDER BY upload_timestamp DESC""", 
        (current_user, current_user)
    ).fetchall()
    
    db.close()
    return render_template('dashboard.html', transactions=records, current_user=current_user)

# ==========================================
# FILE DECRYPTION & DOWNLOAD DISPATCHER
# ==========================================
@app.route('/workspace/view/<int:file_id>')
def view_secure_file(file_id):
    if 'user_email' not in session:
        return redirect(url_for('gateway_auth'))
        
    current_user = session['user_email']
    db = get_db_connection()
    
    # Retrieve encryption parameters mapping entry
    record = db.execute("SELECT * FROM shared_files WHERE id = ?", (file_id,)).fetchone()
    db.close()
    
    if not record:
        flash("Requested transaction logs do not exist.", "danger")
        return redirect(url_for('user_workspace'))
        
    # Security Rule Matrix check: Only explicit sender or recipient can decipher package
    if current_user != record['sender_email'] and current_user != record['recipient_email']:
        flash("Access Denied. You do not possess clearance keys for this package.", "danger")
        return redirect(url_for('user_workspace'))
        
    encrypted_file_path = os.path.join(UPLOAD_FOLDER, record['encrypted_filename'])
    
    if not os.path.exists(encrypted_file_path):
        flash("Physical data blocks missing or purged from server storage arrays.", "danger")
        return redirect(url_for('user_workspace'))
        
    try:
        # Read the encrypted payload from storage
        with open(encrypted_file_path, 'rb') as source_stream:
            raw_cipher_data = source_stream.read()
            
        # Parse Hex-key index back to binary formatting
        binary_crypto_key = bytes.fromhex(record['encryption_key'])
        
        # Execute Real-Time Decryption Module
        decrypted_payload = decrypt_file_payload(raw_cipher_data, binary_crypto_key)
        
        # Stream raw unencrypted array safely into browser runtime memory
        return send_file(
            io.BytesIO(decrypted_payload),
            download_name=record['original_filename'],
            as_attachment=True
        )
    except Exception as decrypt_fault:
        flash(f"Decryption block error: Data may be corrupted. Details: {str(decrypt_fault)}", "danger")
        return redirect(url_for('user_workspace'))

@app.route('/logout')
def system_logout():
    session.clear()
    flash("Session terminated cleanly.", "info")
    return redirect(url_for('gateway_auth'))

if __name__ == '__main__':
    app.run(debug=True)