from flask import Flask, render_template, request, redirect, session, send_file, jsonify
import os
import re
import mysql.connector
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
from crypto_utils import (
    generate_secure_rsa_keys,
    encrypt_file_hybrid,
    decrypt_file_hybrid,
    encrypt_chacha_strong,
    decrypt_chacha_strong,
    decrypt_aes,
    encrypt_aes,
    detect_algo_from_file,
)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "yogesh_securef_secret_key_change_in_prod")

INACTIVITY_TIMEOUT = 900
app.permanent_session_lifetime = timedelta(seconds=INACTIVITY_TIMEOUT)

UPLOAD_FOLDER  = os.path.abspath("uploads")
ENCRYPT_FOLDER = os.path.abspath("encrypted")
DECRYPT_FOLDER = os.path.abspath("decrypted")
KEY_FOLDER     = os.path.abspath("keys")

for folder in [UPLOAD_FOLDER, ENCRYPT_FOLDER, DECRYPT_FOLDER, KEY_FOLDER]:
    os.makedirs(folder, exist_ok=True)

DB_CONFIG = {
    "host":     os.environ.get("DB_HOST",     "localhost"),
    "user":     os.environ.get("DB_USER",     "root"),
    "password": os.environ.get("DB_PASSWORD", "yogesh_123"),
    "database": os.environ.get("DB_NAME",     "securef_db")
}

MAX_ATTEMPTS    = 5
LOCKOUT_MINUTES = 15

# ================= FILE SECURITY CONFIG =================

MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MB

ALLOWED_EXTENSIONS = {
    'txt', 'md', 'pdf', 'docx', 'doc', 'pptx', 'ppt', 'xlsx', 'xls',
    'csv', 'json', 'xml', 'rtf', 'odt', 'ods', 'odp',
    'jpg', 'jpeg', 'png', 'gif', 'svg', 'webp', 'bmp', 'tiff', 'ico',
    'mp3', 'mp4', 'wav', 'avi', 'mkv', 'mov', 'flac', 'aac', 'ogg', 'webm',
    'zip', 'rar', '7z', 'tar', 'gz', 'bz2',
    'py', 'js', 'ts', 'html', 'css', 'php', 'sql', 'sh', 'java', 'c', 'cpp',
    'h', 'cs', 'rb', 'go', 'rs', 'kt', 'swift',
    'yaml', 'yml', 'toml', 'ini', 'env', 'log',
    'ttf', 'otf', 'woff', 'woff2',
}

BLOCKED_EXTENSIONS = {
    'exe', 'msi', 'com', 'scr', 'pif', 'cpl', 'msc',
    'bat', 'cmd', 'vbs', 'vbe', 'js_script', 'wsf', 'wsh', 'ps1', 'ps2',
    'psc1', 'psc2', 'reg', 'inf', 'hta',
    'dll', 'sys', 'drv', 'ocx', 'cpl',
    'apk', 'ipa', 'xapk',
    'jar', 'class', 'jnlp',
    'gadget', 'lnk', 'url',
    'xlsm', 'xlsb', 'docm', 'dotm', 'pptm', 'potm',
}

def is_allowed_file(filename, filesize):
    if filesize and filesize > MAX_FILE_SIZE:
        size_mb = filesize / (1024 * 1024)
        return False, f"File too large ({size_mb:.1f} MB). Maximum allowed size is 50 MB."
    if '.' not in filename:
        return False, "File has no extension. Please upload a valid file."
    ext = filename.rsplit('.', 1)[-1].lower().strip()
    if ext in BLOCKED_EXTENSIONS:
        return False, f".{ext} files are blocked for security reasons."
    if ext not in ALLOWED_EXTENSIONS:
        return False, f".{ext} files are not supported."
    return True, "ok"

# ================= PASSWORD STRENGTH VALIDATOR =================

def is_strong_password(password):
    if len(password) < 8:
        return False, "Password kam se kam 8 characters ka hona chahiye."
    if not re.search(r'[A-Z]', password):
        return False, "Password mein kam se kam ek uppercase letter (A-Z) hona chahiye."
    if not re.search(r'[a-z]', password):
        return False, "Password mein kam se kam ek lowercase letter (a-z) hona chahiye."
    if not re.search(r'\d', password):
        return False, "Password mein kam se kam ek digit (0-9) hona chahiye."
    if not re.search(r'[!@#$%^&*()\-_=+\[\]{};:\'",.<>?\/\\|`~]', password):
        return False, "Password mein kam se kam ek special character hona chahiye (!@#$%^&* etc)."
    return True, "ok"

# ================= DB HELPERS =================

def get_db():
    return mysql.connector.connect(**DB_CONFIG)

def get_client_ip():
    if request.headers.get("X-Forwarded-For"):
        ip = request.headers.get("X-Forwarded-For").split(",")[0].strip()
    elif request.headers.get("X-Real-IP"):
        ip = request.headers.get("X-Real-IP")
    else:
        ip = request.remote_addr
    return ip if ip else "Unknown"

def get_user_agent_info():
    ua = request.headers.get("User-Agent", "")
    browser = "Unknown"
    os_name = "Unknown"

    if "Edg/" in ua or "Edge/" in ua:
        browser = "Microsoft Edge"
    elif "OPR/" in ua or "Opera/" in ua:
        browser = "Opera"
    elif "Chrome/" in ua and "Safari/" in ua:
        browser = "Chrome"
    elif "Firefox/" in ua:
        browser = "Firefox"
    elif "Safari/" in ua:
        browser = "Safari"

    if "Windows NT 11" in ua or "Windows NT 10" in ua:
        os_name = "Windows 10/11"
    elif "Windows NT 6.3" in ua:
        os_name = "Windows 8.1"
    elif "Windows NT 6.1" in ua:
        os_name = "Windows 7"
    elif "Windows" in ua:
        os_name = "Windows"
    elif "Android" in ua:
        os_name = "Android"
    elif "iPhone" in ua or "iPad" in ua:
        os_name = "iOS"
    elif "Macintosh" in ua or "Mac OS X" in ua:
        os_name = "macOS"
    elif "Linux" in ua:
        os_name = "Linux"

    device = "Mobile" if any(x in ua for x in ["Mobile", "Android", "iPhone", "iPad"]) else "Desktop"

    return browser, os_name, device

def init_db():
    conn = mysql.connector.connect(
        host=DB_CONFIG["host"],
        user=DB_CONFIG["user"],
        password=DB_CONFIG["password"]
    )
    c = conn.cursor()
    c.execute("CREATE DATABASE IF NOT EXISTS securef_db")
    conn.commit()
    conn.close()

    conn = mysql.connector.connect(**DB_CONFIG)
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id            INT AUTO_INCREMENT PRIMARY KEY,
            username      VARCHAR(100)  NOT NULL UNIQUE,
            password      VARCHAR(500)  NOT NULL,
            register_ip   VARCHAR(45),
            created_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_login    DATETIME,
            last_login_ip VARCHAR(45)
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS login_attempts (
            id           INT AUTO_INCREMENT PRIMARY KEY,
            username     VARCHAR(100) NOT NULL,
            ip_address   VARCHAR(45),
            attempted_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS encrypted_files (
            id               INT AUTO_INCREMENT PRIMARY KEY,
            username         VARCHAR(100)  NOT NULL,
            original_name    VARCHAR(500)  NOT NULL,
            encrypted_name   VARCHAR(500)  NOT NULL,
            encrypted_path   VARCHAR(1000) NOT NULL,
            algorithm        VARCHAR(50)   NOT NULL,
            original_size    BIGINT        NOT NULL DEFAULT 0,
            encrypted_size   BIGINT        NOT NULL DEFAULT 0,
            created_at       DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS decrypted_files (
            id               INT AUTO_INCREMENT PRIMARY KEY,
            username         VARCHAR(100)  NOT NULL,
            original_name    VARCHAR(500)  NOT NULL,
            decrypted_name   VARCHAR(500)  NOT NULL,
            decrypted_path   VARCHAR(1000) NOT NULL,
            algorithm        VARCHAR(50)   NOT NULL,
            file_size        BIGINT        NOT NULL DEFAULT 0,
            created_at       DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS security_logs (
            id           INT AUTO_INCREMENT PRIMARY KEY,
            username     VARCHAR(100),
            event_type   VARCHAR(80)   NOT NULL,
            severity     ENUM('Success','Info','Warning','Critical') DEFAULT 'Info',
            category     ENUM('Auth','FileAction','Security','Session','System') DEFAULT 'Auth',
            description  TEXT,
            ip_address   VARCHAR(45)   DEFAULT 'Unknown',
            browser      VARCHAR(150),
            os           VARCHAR(100),
            device       VARCHAR(50),
            user_agent   TEXT,
            created_at   DATETIME      DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_username  (username),
            INDEX idx_severity  (severity),
            INDEX idx_category  (category),
            INDEX idx_created   (created_at)
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS contact_messages (
            id          INT AUTO_INCREMENT PRIMARY KEY,
            first_name  VARCHAR(100)  NOT NULL,
            last_name   VARCHAR(100),
            email       VARCHAR(200)  NOT NULL,
            subject     VARCHAR(100),
            message     TEXT          NOT NULL,
            ip_address  VARCHAR(45),
            created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()
    conn.close()
    print("Database init complete!")

init_db()

# ================= SECURITY LOG HELPER =================

def log_security_event(username, event_type, severity, category, description):
    try:
        ip              = get_client_ip()
        browser, os_name, device = get_user_agent_info()
        ua              = request.headers.get("User-Agent", "")[:500]

        conn = get_db()
        c    = conn.cursor()
        c.execute("""
            INSERT INTO security_logs
                (username, event_type, severity, category, description,
                 ip_address, browser, os, device, user_agent)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (username, event_type, severity, category, description,
              ip, browser, os_name, device, ua))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[SECURITY LOG ERROR] {e}")

# ================= LOGIN ATTEMPT HELPERS =================

def check_login_attempts(username):
    conn = get_db()
    c = conn.cursor()
    window_start = datetime.now() - timedelta(minutes=LOCKOUT_MINUTES)
    c.execute("""
        SELECT attempted_at FROM login_attempts
        WHERE username = %s AND attempted_at >= %s
        ORDER BY attempted_at ASC
    """, (username, window_start))
    rows = c.fetchall()
    conn.close()
    attempts = len(rows)
    if attempts >= MAX_ATTEMPTS:
        fifth_attempt_time = rows[MAX_ATTEMPTS - 1][0]
        lockout_until = fifth_attempt_time + timedelta(minutes=LOCKOUT_MINUTES)
        remaining = (lockout_until - datetime.now()).total_seconds()
        if remaining > 0:
            return {"locked": True, "attempts": attempts, "remaining_seconds": int(remaining)}
        else:
            clear_attempts(username)
            return {"locked": False, "attempts": 0, "remaining_seconds": 0}
    return {"locked": False, "attempts": attempts, "remaining_seconds": 0}

def record_failed_attempt(username, ip):
    conn = get_db()
    c = conn.cursor()
    c.execute("INSERT INTO login_attempts (username, ip_address) VALUES (%s, %s)", (username, ip))
    conn.commit()
    conn.close()

def clear_attempts(username):
    conn = get_db()
    c = conn.cursor()
    c.execute("DELETE FROM login_attempts WHERE username = %s", (username,))
    conn.commit()
    conn.close()

def get_error_message(attempts_after_fail):
    remaining_attempts = MAX_ATTEMPTS - attempts_after_fail
    if attempts_after_fail >= MAX_ATTEMPTS:
        return None
    elif attempts_after_fail >= 3:
        return f"Warning: Invalid credentials! Only {remaining_attempts} attempt(s) left before lockout for {LOCKOUT_MINUTES} minutes."
    else:
        return "Invalid username or password!"

def save_file_record(username, original_name, encrypted_name, encrypted_path, algorithm, original_size, encrypted_size):
    conn = get_db()
    c = conn.cursor()
    c.execute("""
        INSERT INTO encrypted_files
            (username, original_name, encrypted_name, encrypted_path, algorithm, original_size, encrypted_size)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
    """, (username, original_name, encrypted_name, encrypted_path, algorithm, original_size, encrypted_size))
    conn.commit()
    file_id = c.lastrowid
    conn.close()
    return file_id

def get_user_files(username):
    conn = get_db()
    c = conn.cursor(dictionary=True)
    c.execute("""
        SELECT id, original_name, encrypted_name, algorithm,
               original_size, encrypted_size, created_at
        FROM encrypted_files
        WHERE username = %s
        ORDER BY created_at DESC
    """, (username,))
    rows = c.fetchall()
    conn.close()
    return rows

def get_file_by_id(file_id, username):
    conn = get_db()
    c = conn.cursor(dictionary=True)
    c.execute("""
        SELECT * FROM encrypted_files
        WHERE id = %s AND username = %s
    """, (file_id, username))
    row = c.fetchone()
    conn.close()
    return row

def delete_file_record(file_id, username):
    conn = get_db()
    c = conn.cursor()
    c.execute("DELETE FROM encrypted_files WHERE id = %s AND username = %s", (file_id, username))
    conn.commit()
    conn.close()

# ================= ROUTES =================

@app.route("/")
def home():
    return render_template("indexmain.html")

@app.route("/about")
def about():
    return render_template("about.html")

# ================= GUEST PAGE =================

@app.route("/guest")
def guest():
    return render_template("guest.html")

# ================= GUEST ROUTES (No Login Required) =================

@app.route("/guest/generate-rsa-keys", methods=["POST"])
def guest_generate_rsa_keys():
    data     = request.get_json(silent=True) or {}
    password = (data.get("password") or "").strip()

    if not password:
        return jsonify({"error": "Password required to generate keys"}), 400

    try:
        private_key_bytes, public_key_bytes = generate_secure_rsa_keys(password)
        return jsonify({
            "public_key":  public_key_bytes.decode("utf-8"),
            "private_key": private_key_bytes.decode("utf-8")
        })
    except Exception as e:
        return jsonify({"error": f"Key generation failed: {str(e)}"}), 500


@app.route("/guest/encrypt-file", methods=["POST"])
def guest_encrypt_file():
    file      = request.files.get("file")
    password  = request.form.get("password", "")
    algorithm = request.form.get("algorithm", "").upper()

    if not file or file.filename == "":
        return jsonify({"error": "No file selected"}), 400

    filename = secure_filename(file.filename)

    file.seek(0, 2)
    filesize = file.tell()
    file.seek(0)

    allowed, reason = is_allowed_file(filename, filesize)
    if not allowed:
        return jsonify({"error": reason}), 400

    filepath = os.path.join(UPLOAD_FOLDER, "guest_" + filename)
    file.save(filepath)

    encrypted_filename = filename + ".enc"
    encrypted_path     = os.path.join(ENCRYPT_FOLDER, "guest_" + encrypted_filename)

    try:
        if algorithm == "HYBRID":
            pub_key_text = request.form.get("public_key", "").strip()
            if not pub_key_text:
                return jsonify({"error": "Public key required for Hybrid encryption"}), 400
            encrypt_file_hybrid(filepath, encrypted_path, pub_key_text.encode("utf-8"))

        elif algorithm == "CHACHA":
            if not password:
                return jsonify({"error": "Password required"}), 400
            encrypt_chacha_strong(filepath, encrypted_path, password)

        elif algorithm == "AES":
            if not password:
                return jsonify({"error": "Password required"}), 400
            encrypt_aes(filepath, encrypted_path, password, 32)

        else:
            return jsonify({"error": f"Invalid algorithm: {algorithm}"}), 400

    except Exception as e:
        try: os.remove(filepath)
        except: pass
        return jsonify({"error": f"Encryption failed: {str(e)}"}), 500

    try: os.remove(filepath)
    except: pass

    return send_file(
        encrypted_path,
        as_attachment=True,
        download_name=encrypted_filename,
        mimetype="application/octet-stream"
    )


@app.route("/guest/decrypt", methods=["POST"])
def guest_decrypt():
    file      = request.files.get("file")
    algorithm = request.form.get("algorithm", "").upper()

    if not file or file.filename == "":
        return jsonify({"error": "No file selected"}), 400

    filename = secure_filename(file.filename)
    filepath = os.path.join(UPLOAD_FOLDER, "guest_" + filename)
    file.save(filepath)

    detected = detect_algo_from_file(filepath)
    if detected and detected != algorithm:
        algorithm = detected

    decrypted_filename = "decrypted_" + filename.replace(".enc", "")
    decrypted_path     = os.path.join(DECRYPT_FOLDER, "guest_" + decrypted_filename)

    try:
        if algorithm == "HYBRID":
            priv_key_file = request.files.get("private_key")
            password      = request.form.get("password", "").strip()
            if not priv_key_file:
                return jsonify({"error": "Private key file required"}), 400
            if not password:
                return jsonify({"error": "Password required to unlock the private key"}), 400
            decrypt_file_hybrid(filepath, decrypted_path, priv_key_file.read(), password=password)

        elif algorithm == "CHACHA":
            password = request.form.get("password", "")
            if not password:
                return jsonify({"error": "Password required"}), 400
            decrypt_chacha_strong(filepath, decrypted_path, password)

        elif algorithm == "AES":
            password = request.form.get("password", "")
            if not password:
                return jsonify({"error": "Password required"}), 400
            decrypt_aes(filepath, decrypted_path, password, 32)

        else:
            return jsonify({"error": "Invalid or unrecognized algorithm"}), 400

    except ValueError:
        try: os.remove(filepath)
        except: pass
        return jsonify({"error": "Decryption failed — wrong password, wrong key, or corrupted file"}), 400

    except Exception as e:
        try: os.remove(filepath)
        except: pass
        return jsonify({"error": f"Decryption failed: {str(e)}"}), 500

    try: os.remove(filepath)
    except: pass

    return send_file(
        decrypted_path,
        as_attachment=True,
        download_name=decrypted_filename,
        mimetype="application/octet-stream"
    )

# ================= CONTACT =================

@app.route("/contact", methods=["GET", "POST"])
def contact():
    if request.method == "POST":
        first_name = request.form.get("first_name", "").strip()
        last_name  = request.form.get("last_name",  "").strip()
        email      = request.form.get("email",      "").strip()
        subject    = request.form.get("subject",    "").strip()
        message    = request.form.get("message",    "").strip()

        if not first_name or not email or not message:
            return render_template(
                "contact.html",
                error="Naam, email aur message zaroori hai!"
            )

        if len(message) > 500:
            return render_template(
                "contact.html",
                error="Message 500 characters se zyada nahi ho sakta."
            )

        ip = get_client_ip()

        try:
            conn = get_db()
            c    = conn.cursor()
            c.execute("""
                INSERT INTO contact_messages
                    (first_name, last_name, email, subject, message, ip_address)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (first_name, last_name, email, subject, message, ip))
            conn.commit()
            conn.close()
        except Exception as db_err:
            print(f"[CONTACT DB ERROR] {db_err}")
            return render_template(
                "contact.html",
                error="Database error, please try again."
            )

        log_security_event(
            username    = None,
            event_type  = "CONTACT_FORM",
            severity    = "Info",
            category    = "System",
            description = (
                f"Contact form submitted by {first_name} {last_name} "
                f"({email}) — Subject: {subject or 'N/A'}"
            )
        )

        return render_template("contact.html", success=True)

    return render_template("contact.html")

# ================= DASHBOARD =================

@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect("/login")

    username = session["user"]
    files    = get_user_files(username)

    from datetime import date, timedelta as td

    total_enc   = len(files)
    week_ago    = datetime.now() - td(days=7)
    week_total  = sum(1 for f in files if f["created_at"] >= week_ago)
    algo_aes    = sum(1 for f in files if "aes"    in f["algorithm"].lower())
    algo_chacha = sum(1 for f in files if "chacha" in f["algorithm"].lower())
    algo_hybrid = sum(1 for f in files if "hybrid" in f["algorithm"].lower() or "rsa" in f["algorithm"].lower())

    today        = date.today()
    daily_labels = []
    daily_data   = []
    for i in range(6, -1, -1):
        d = today - td(days=i)
        daily_labels.append(d.strftime("%a"))
        daily_data.append(sum(1 for f in files if f["created_at"].date() == d))

    if total_enc == 0:
        sec_bits      = "—"
        sec_color     = "#9ab8a8"
        sec_algos_str = "No files yet"
    else:
        algo_scores = {
            "AES-256-GCM":       algo_aes,
            "ChaCha20-Poly1305": algo_chacha,
            "RSA+AES Hybrid":    algo_hybrid,
        }
        top_algo  = max(algo_scores, key=algo_scores.get)
        bits_map  = {
            "AES-256-GCM":       "256-bit",
            "ChaCha20-Poly1305": "256-bit",
            "RSA+AES Hybrid":    "2048-bit RSA + 256-bit AES",
        }
        color_map = {
            "AES-256-GCM":       "#00c853",
            "ChaCha20-Poly1305": "#40c4ff",
            "RSA+AES Hybrid":    "#ffab40",
        }
        sec_bits      = bits_map.get(top_algo, "256-bit")
        sec_color     = color_map.get(top_algo, "#00c853")
        used          = [k for k, v in algo_scores.items() if v > 0]
        sec_algos_str = ", ".join(used) if used else "No files yet"

    return render_template(
        "dashboard.html",
        files         = files,
        username      = username,
        total_enc     = total_enc,
        week_total    = week_total,
        algo_aes      = algo_aes,
        algo_chacha   = algo_chacha,
        algo_hybrid   = algo_hybrid,
        algo_total    = total_enc,
        daily_labels  = daily_labels,
        daily_data    = daily_data,
        sec_bits      = sec_bits,
        sec_color     = sec_color,
        sec_algos_str = sec_algos_str,
    )

@app.route("/ping", methods=["POST"])
def ping():
    if "user" not in session:
        return jsonify({"status": "expired"}), 401
    session.modified = True
    return jsonify({"status": "ok"}), 200

# ================= REGISTER =================

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]

        valid, msg = is_strong_password(password)
        if not valid:
            log_security_event(
                username    = username,
                event_type  = "REGISTER_WEAK_PASSWORD",
                severity    = "Warning",
                category    = "Auth",
                description = f"Registration attempt with weak password for username: {username}"
            )
            return render_template("register1.html", error=msg)

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        ip_address      = get_client_ip()
        try:
            conn = get_db()
            c = conn.cursor()
            c.execute(
                "INSERT INTO users (username, password, register_ip) VALUES (%s, %s, %s)",
                (username, hashed_password, ip_address)
            )
            conn.commit()
            conn.close()

            log_security_event(
                username    = username,
                event_type  = "USER_REGISTER",
                severity    = "Info",
                category    = "Auth",
                description = f"New user registered: {username}"
            )

            return redirect("/login")
        except mysql.connector.IntegrityError:
            return render_template("register1.html", error="Username already taken!")
        except mysql.connector.Error as e:
            return render_template("register1.html", error=f"Database error: {str(e)}")
    return render_template("register1.html")

# ================= LOGIN =================

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        ip       = get_client_ip()
        status   = check_login_attempts(username)

        if status["locked"]:
            mins  = status["remaining_seconds"] // 60
            secs  = status["remaining_seconds"] % 60
            error = f"Too many failed attempts. Try again in {mins}m {secs}s."
            log_security_event(
                username    = username,
                event_type  = "LOGIN_BLOCKED",
                severity    = "Critical",
                category    = "Security",
                description = f"Login attempt on locked account: {username}. Remaining lockout: {mins}m {secs}s"
            )
            return render_template("login1.html", error=error)

        try:
            conn = get_db()
            c    = conn.cursor()
            c.execute("SELECT id, username, password FROM users WHERE username = %s", (username,))
            user = c.fetchone()

            if user:
                if check_password_hash(user[2], password):
                    c.execute(
                        "UPDATE users SET last_login = NOW(), last_login_ip = %s WHERE username = %s",
                        (ip, username)
                    )
                    conn.commit()
                    conn.close()
                    clear_attempts(username)
                    session.clear()
                    session["user"]   = username
                    session.permanent = True

                    log_security_event(
                        username    = username,
                        event_type  = "LOGIN_SUCCESS",
                        severity    = "Success",
                        category    = "Auth",
                        description = f"{username} successfully logged in from {ip}"
                    )
                    return redirect("/dashboard")

                else:
                    conn.close()
                    record_failed_attempt(username, ip)
                    new_status = check_login_attempts(username)

                    if new_status["locked"]:
                        mins  = new_status["remaining_seconds"] // 60
                        secs  = new_status["remaining_seconds"] % 60
                        error = f"Account locked after {MAX_ATTEMPTS} failed attempts. Try again in {mins}m {secs}s."
                        log_security_event(
                            username    = username,
                            event_type  = "ACCOUNT_LOCKED",
                            severity    = "Critical",
                            category    = "Security",
                            description = f"Account locked: {username} — {MAX_ATTEMPTS} failed login attempts from {ip}"
                        )
                    else:
                        error = get_error_message(new_status["attempts"])
                        log_security_event(
                            username    = username,
                            event_type  = "LOGIN_FAILED",
                            severity    = "Warning",
                            category    = "Auth",
                            description = f"Failed login attempt #{new_status['attempts']} for user: {username} from {ip}"
                        )
                    return render_template("login1.html", error=error)

            else:
                conn.close()
                record_failed_attempt(username, ip)
                new_status = check_login_attempts(username)
                error      = get_error_message(new_status["attempts"])
                log_security_event(
                    username    = username,
                    event_type  = "LOGIN_UNKNOWN_USER",
                    severity    = "Warning",
                    category    = "Security",
                    description = f"Login attempt with unknown username: '{username}' from {ip}"
                )
                return render_template("login1.html", error=error)

        except mysql.connector.Error:
            return render_template("login1.html", error="Database error, please try again.")

    return render_template("login1.html")

@app.route("/logout")
def logout():
    username = session.get("user", "Unknown")
    log_security_event(
        username    = username,
        event_type  = "LOGOUT",
        severity    = "Info",
        category    = "Session",
        description = f"{username} logged out"
    )
    session.clear()
    return redirect("/")

@app.route("/encrypt", methods=["GET"])
def encrypt_page():
    if "user" not in session:
        return redirect("/login")
    return render_template("encrypt.html", username=session["user"])

@app.route("/generate-rsa-keys", methods=["POST"])
def generate_rsa_keys():
    if "user" not in session:
        return jsonify({"error": "Not logged in"}), 401

    data     = request.get_json(silent=True) or {}
    password = (data.get("password") or "").strip()

    if not password:
        return jsonify({"error": "Password required to generate keys"}), 400

    try:
        private_key_bytes, public_key_bytes = generate_secure_rsa_keys(password)
        private_pem = private_key_bytes.decode("utf-8")
        public_pem  = public_key_bytes.decode("utf-8")

        log_security_event(
            username    = session["user"],
            event_type  = "RSA_KEY_GENERATED",
            severity    = "Info",
            category    = "Security",
            description = f"RSA key pair generated by {session['user']}"
        )

        return jsonify({"public_key": public_pem, "private_key": private_pem})
    except Exception as e:
        return jsonify({"error": f"Key generation failed: {str(e)}"}), 500


@app.route("/api/detect-algo", methods=["POST"])
def api_detect_algo():
    if "user" not in session:
        return jsonify({"error": "Not logged in"}), 401

    file = request.files.get("file")
    if not file or file.filename == "":
        return jsonify({"error": "No file"}), 400

    filename = secure_filename(file.filename)
    tmp_path = os.path.join(UPLOAD_FOLDER, "tmp_detect_" + filename)
    file.save(tmp_path)

    try:
        algo = detect_algo_from_file(tmp_path)
    finally:
        try:
            os.remove(tmp_path)
        except Exception:
            pass

    if algo is None:
        n = filename.lower()
        if "chacha" in n or "cc20" in n:
            algo = "CHACHA"
        elif "hybrid" in n or "rsa" in n:
            algo = "HYBRID"
        else:
            algo = "AES"

    algo_display_map = {
        "AES":    "AES-256-GCM",
        "CHACHA": "ChaCha20-Poly1305",
        "HYBRID": "RSA+AES Hybrid",
    }
    return jsonify({
        "algorithm":         algo,
        "algorithm_display": algo_display_map.get(algo, algo),
        "source":            "magic_header",
    })


# ================= ENCRYPT FILE (Logged In) =================

@app.route("/encrypt-file", methods=["POST"])
def encrypt_file_route():
    if "user" not in session:
        return jsonify({"error": "Not logged in"}), 401

    file      = request.files.get("file")
    password  = request.form.get("password", "")
    algorithm = request.form.get("algorithm", "").upper()

    if not file or file.filename == "":
        return jsonify({"error": "No file selected"}), 400

    filename = secure_filename(file.filename)

    file.seek(0, 2)
    filesize = file.tell()
    file.seek(0)

    allowed, reason = is_allowed_file(filename, filesize)
    if not allowed:
        log_security_event(
            username    = session["user"],
            event_type  = "FILE_BLOCKED",
            severity    = "Critical",
            category    = "Security",
            description = f"Blocked file upload by {session['user']}: {filename} — {reason}"
        )
        return jsonify({"error": reason}), 400

    filepath   = os.path.join(UPLOAD_FOLDER, filename)
    file.save(filepath)
    original_size = os.path.getsize(filepath)

    encrypted_filename = filename + ".enc"
    encrypted_path     = os.path.join(ENCRYPT_FOLDER, encrypted_filename)

    try:
        if algorithm == "HYBRID":
            pub_key_text = request.form.get("public_key", "").strip()
            if not pub_key_text:
                return jsonify({"error": "Public key required for Hybrid encryption"}), 400
            encrypt_file_hybrid(filepath, encrypted_path, pub_key_text.encode("utf-8"))

        elif algorithm == "CHACHA":
            if not password:
                return jsonify({"error": "Password required"}), 400
            encrypt_chacha_strong(filepath, encrypted_path, password)

        elif algorithm == "AES":
            if not password:
                return jsonify({"error": "Password required"}), 400
            encrypt_aes(filepath, encrypted_path, password, 32)

        else:
            return jsonify({"error": f"Invalid algorithm: {algorithm}"}), 400

    except Exception as e:
        try: os.remove(filepath)
        except: pass
        return jsonify({"error": f"Encryption failed: {str(e)}"}), 500

    encrypted_size = os.path.getsize(encrypted_path) if os.path.exists(encrypted_path) else 0

    algo_map     = {"AES": "AES-256-GCM", "CHACHA": "ChaCha20-Poly1305", "HYBRID": "RSA+AES Hybrid"}
    algo_display = algo_map.get(algorithm, algorithm)

    save_file_record(
        username       = session["user"],
        original_name  = filename,
        encrypted_name = encrypted_filename,
        encrypted_path = encrypted_path,
        algorithm      = algo_display,
        original_size  = original_size,
        encrypted_size = encrypted_size
    )

    log_security_event(
        username    = session["user"],
        event_type  = "FILE_ENCRYPT",
        severity    = "Success",
        category    = "FileAction",
        description = f"{session['user']} encrypted file '{filename}' using {algo_display} ({original_size} bytes)"
    )

    try: os.remove(filepath)
    except: pass

    return send_file(
        encrypted_path,
        as_attachment=True,
        download_name=encrypted_filename,
        mimetype="application/octet-stream"
    )


# ================= DECRYPT (Logged In) =================

@app.route("/decrypt", methods=["GET", "POST"])
def decrypt():
    if "user" not in session:
        return redirect("/login")

    if request.method == "GET":
        return render_template("decrypt.html", username=session["user"])

    file      = request.files.get("file")
    algorithm = request.form.get("algorithm", "").upper()

    if not file or file.filename == "":
        return jsonify({"error": "No file selected"}), 400

    filename = secure_filename(file.filename)
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    file.save(filepath)

    detected = detect_algo_from_file(filepath)
    if detected and detected != algorithm:
        algorithm = detected

    decrypted_filename = "decrypted_" + filename.replace(".enc", "")
    decrypted_path     = os.path.join(DECRYPT_FOLDER, decrypted_filename)

    try:
        if algorithm == "HYBRID":
            priv_key_file = request.files.get("private_key")
            password      = request.form.get("password", "").strip()
            if not priv_key_file:
                return jsonify({"error": "Private key file required"}), 400
            if not password:
                return jsonify({"error": "Password required to unlock the private key"}), 400
            decrypt_file_hybrid(filepath, decrypted_path, priv_key_file.read(), password=password)

        elif algorithm == "CHACHA":
            password = request.form.get("password", "")
            if not password:
                return jsonify({"error": "Password required"}), 400
            decrypt_chacha_strong(filepath, decrypted_path, password)

        elif algorithm == "AES":
            password = request.form.get("password", "")
            if not password:
                return jsonify({"error": "Password required"}), 400
            decrypt_aes(filepath, decrypted_path, password, 32)

        else:
            return jsonify({"error": "Invalid or unrecognized algorithm"}), 400

    except ValueError as e:
        try: os.remove(filepath)
        except: pass
        log_security_event(
            username    = session["user"],
            event_type  = "FILE_DECRYPT_FAILED",
            severity    = "Warning",
            category    = "Security",
            description = f"Decryption failed for '{filename}' by {session['user']} — wrong password/key or corrupted file"
        )
        return jsonify({"error": "Decryption failed — wrong password, wrong key, or corrupted file"}), 400

    except Exception as e:
        try: os.remove(filepath)
        except: pass
        return jsonify({"error": f"Decryption failed: {str(e)}"}), 500

    try: os.remove(filepath)
    except: pass

    file_size    = os.path.getsize(decrypted_path) if os.path.exists(decrypted_path) else 0
    algo_map     = {"AES": "AES-256-GCM", "CHACHA": "ChaCha20-Poly1305", "HYBRID": "RSA+AES Hybrid"}
    algo_display = algo_map.get(algorithm, algorithm)

    try:
        conn = get_db()
        c    = conn.cursor()
        c.execute("""
            INSERT INTO decrypted_files
                (username, original_name, decrypted_name, decrypted_path, algorithm, file_size)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (session["user"], filename, decrypted_filename, decrypted_path, algo_display, file_size))
        conn.commit()
        conn.close()
    except Exception as db_err:
        print(f"[DECRYPT DB] Warning: {db_err}")

    log_security_event(
        username    = session["user"],
        event_type  = "FILE_DECRYPT",
        severity    = "Success",
        category    = "FileAction",
        description = f"{session['user']} decrypted file '{filename}' using {algo_display}"
    )

    return send_file(
        decrypted_path,
        as_attachment=True,
        download_name=decrypted_filename,
        mimetype="application/octet-stream"
    )


# ================= MY FILES =================

@app.route("/download-file/<int:file_id>")
def download_file(file_id):
    if "user" not in session:
        return redirect("/login")
    record = get_file_by_id(file_id, session["user"])
    if not record:
        return "File not found or access denied.", 404
    if not os.path.exists(record["encrypted_path"]):
        return "File no longer exists on server.", 404

    log_security_event(
        username    = session["user"],
        event_type  = "FILE_DOWNLOAD",
        severity    = "Info",
        category    = "FileAction",
        description = f"{session['user']} downloaded encrypted file: {record['encrypted_name']}"
    )

    return send_file(
        record["encrypted_path"],
        as_attachment=True,
        download_name=record["encrypted_name"],
        mimetype="application/octet-stream"
    )

@app.route("/delete-file/<int:file_id>", methods=["POST"])
def delete_file(file_id):
    if "user" not in session:
        return jsonify({"error": "Not logged in"}), 401
    record = get_file_by_id(file_id, session["user"])
    if not record:
        return jsonify({"error": "File not found"}), 404
    try:
        if os.path.exists(record["encrypted_path"]):
            os.remove(record["encrypted_path"])
    except Exception as e:
        print(f"[DELETE] Warning: {e}")

    log_security_event(
        username    = session["user"],
        event_type  = "FILE_DELETE",
        severity    = "Warning",
        category    = "FileAction",
        description = f"{session['user']} deleted file: {record['original_name']} (ID: {file_id})"
    )

    delete_file_record(file_id, session["user"])
    return jsonify({"success": True})

@app.route("/my-files")
def my_files():
    if "user" not in session:
        return redirect("/login")
    return render_template("my_files.html", username=session["user"])

@app.route("/api/dashboard-stats")
def api_dashboard_stats():
    if "user" not in session:
        return jsonify({"error": "Not logged in"}), 401

    username = session["user"]
    conn     = get_db()
    c        = conn.cursor(dictionary=True)

    c.execute("SELECT COUNT(*) as total FROM encrypted_files WHERE username = %s", (username,))
    total = c.fetchone()["total"]

    c.execute("""
        SELECT algorithm, COUNT(*) as count
        FROM encrypted_files WHERE username = %s
        GROUP BY algorithm
    """, (username,))
    algo_rows = c.fetchall()

    c.execute("""
        SELECT COUNT(*) as week_total FROM encrypted_files
        WHERE username = %s
        AND created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
    """, (username,))
    week_total = c.fetchone()["week_total"]

    c.execute("""
        SELECT DATE(created_at) as day, COUNT(*) as count
        FROM encrypted_files
        WHERE username = %s
        AND created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
        GROUP BY DATE(created_at)
        ORDER BY day ASC
    """, (username,))
    daily_rows = c.fetchall()
    conn.close()

    from datetime import date, timedelta
    today    = date.today()
    days_map = {r["day"]: r["count"] for r in daily_rows}
    daily_data, day_labels = [], []
    for i in range(6, -1, -1):
        d = today - timedelta(days=i)
        day_labels.append(d.strftime("%a"))
        daily_data.append(days_map.get(d, 0))

    algo_counts  = {row["algorithm"]: row["count"] for row in algo_rows}
    return jsonify({
        "username":        username,
        "total_encrypted": total,
        "week_total":      week_total,
        "algo_aes":        algo_counts.get("AES-256-GCM",       0),
        "algo_chacha":     algo_counts.get("ChaCha20-Poly1305", 0),
        "algo_hybrid":     algo_counts.get("RSA+AES Hybrid",    0),
        "algo_total":      total,
        "daily_labels":    day_labels,
        "daily_data":      daily_data,
    })


# ================= SECURITY LOG PAGE + API =================

@app.route("/security_log")
def security_log():
    if "user" not in session:
        return redirect("/login")
    return render_template("securitylog.html", username=session["user"])


@app.route("/api/security-logs")
def api_security_logs():
    if "user" not in session:
        return jsonify({"error": "Not logged in"}), 401

    username = session["user"]
    page     = int(request.args.get("page",  1))
    limit    = int(request.args.get("limit", 20))
    severity = request.args.get("severity", "")
    category = request.args.get("category", "")
    search   = request.args.get("search",   "")
    sort_by  = request.args.get("sort_by",  "created_at")
    sort_dir = request.args.get("sort_dir", "DESC")
    offset   = (page - 1) * limit

    allowed_cols = ["created_at", "severity", "category", "event_type", "ip_address"]
    if sort_by not in allowed_cols:
        sort_by = "created_at"
    if sort_dir not in ["ASC", "DESC"]:
        sort_dir = "DESC"

    where  = "WHERE username = %s"
    params = [username]

    if severity:
        where += " AND severity = %s"
        params.append(severity)
    if category:
        where += " AND category = %s"
        params.append(category)
    if search:
        where += " AND (event_type LIKE %s OR description LIKE %s OR ip_address LIKE %s)"
        s = f"%{search}%"
        params.extend([s, s, s])

    try:
        conn = get_db()
        c    = conn.cursor(dictionary=True)

        c.execute(f"SELECT COUNT(*) as total FROM security_logs {where}", params)
        total = c.fetchone()["total"]

        c.execute(f"""
            SELECT
                COUNT(*) as total,
                SUM(severity='Critical') as critical,
                SUM(severity='Warning')  as warning,
                SUM(severity='Info')     as info,
                SUM(severity='Success')  as success
            FROM security_logs {where}
        """, params)
        stats = c.fetchone()

        c.execute(f"""
            SELECT id, username, event_type, severity, category,
                   description, ip_address, browser, os, device, created_at
            FROM security_logs {where}
            ORDER BY {sort_by} {sort_dir}
            LIMIT %s OFFSET %s
        """, params + [limit, offset])
        logs = c.fetchall()
        conn.close()

        for l in logs:
            if l["created_at"]:
                l["created_at"] = l["created_at"].strftime("%Y-%m-%dT%H:%M:%S")

        return jsonify({
            "logs": logs,
            "pagination": {
                "total": total,
                "page":  page,
                "limit": limit,
                "pages": max(1, -(-total // limit)),
            },
            "stats": {
                "total":    stats["total"]    or 0,
                "critical": stats["critical"] or 0,
                "warning":  stats["warning"]  or 0,
                "info":     stats["info"]     or 0,
                "success":  stats["success"]  or 0,
            }
        })

    except Exception as e:
        print(f"[SECURITY LOG API ERROR] {e}")
        return jsonify({"error": "Database error"}), 500


# ================= MY FILES API =================

@app.route("/api/my-files")
def api_my_files():
    if "user" not in session:
        return jsonify({"error": "Not logged in"}), 401
    files = get_user_files(session["user"])
    for f in files:
        dt = f["created_at"]
        f["created_at"] = dt.strftime("%Y-%m-%dT%H:%M:%S")
    return jsonify({"files": files, "total": len(files)})


if __name__ == "__main__":
    debug_mode = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app.run(debug=debug_mode, host="0.0.0.0")