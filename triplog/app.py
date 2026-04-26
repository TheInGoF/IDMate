"""ID·Mate Triplog — Flask Web-UI + CSV-Export."""

import base64
import csv
import hashlib
import io
import json
import math
import os
import shutil
import sqlite3
import threading
import time
import calendar
from datetime import datetime, timedelta, timezone
import logging
from functools import wraps

try:
    from cryptography.fernet import Fernet as _Fernet
    _FERNET_AVAILABLE = True
except ImportError:
    _FERNET_AVAILABLE = False

try:
    import pyotp
    import qrcode
    import qrcode.image.pil
    _TOTP_AVAILABLE = True
except ImportError:
    _TOTP_AVAILABLE = False

from flask import Flask, render_template, request, jsonify, Response, redirect, url_for, session, send_from_directory, abort
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash as _werkzeug_hash, check_password_hash as _werkzeug_check
from argon2 import PasswordHasher as _Argon2Hasher
from argon2.exceptions import VerificationError, VerifyMismatchError
from werkzeug.utils import secure_filename

import config
import detector
import geocoder as geo

# ── Password hashing: argon2 (new) with werkzeug/pbkdf2 fallback (migration) ──
_argon2 = _Argon2Hasher()

def generate_password_hash(password):
    return _argon2.hash(password)

def check_password_hash(stored_hash, password):
    if stored_hash.startswith("$argon2"):
        try:
            return _argon2.verify(stored_hash, password)
        except (VerifyMismatchError, VerificationError):
            return False
    # Fallback: werkzeug/pbkdf2 hash (pre-migration)
    return _werkzeug_check(stored_hash, password)

def _needs_rehash(stored_hash):
    """True if hash is old pbkdf2 format and should be upgraded to argon2."""
    return not stored_hash.startswith("$argon2")


def _generate_recovery_codes(count=10):
    """Generate recovery codes (8-char hex, uppercase)."""
    import secrets
    return [secrets.token_hex(4).upper() for _ in range(count)]


def _store_recovery_codes(db, user_id, codes):
    """Hash and store recovery codes as JSON array."""
    import json
    hashed = [generate_password_hash(c) for c in codes]
    db.execute("UPDATE users SET recovery_codes = ? WHERE id = ?",
               (json.dumps(hashed), user_id))
    db.commit()


def _consume_recovery_code(db, user_id, code):
    """Verify a recovery code. If valid, remove it (one-shot). Returns True/False."""
    import json
    row = db.execute("SELECT recovery_codes FROM users WHERE id = ?", (user_id,)).fetchone()
    if not row or not row["recovery_codes"]:
        return False
    hashes = json.loads(row["recovery_codes"])
    code = code.strip().upper()
    for i, h in enumerate(hashes):
        if check_password_hash(h, code):
            remaining = hashes[:i] + hashes[i + 1:]
            db.execute("UPDATE users SET recovery_codes = ? WHERE id = ?",
                       (json.dumps(remaining), user_id))
            db.commit()
            return True
    return False


app = Flask(__name__)


_LOCAL_TZ = detector.LOCAL_TZ


def _to_rfc3339(ts):
    """Normalize timestamp string to RFC3339 UTC with Z.
    Stored times are local time (Europe/Berlin) without offset."""
    ts = str(ts).strip().replace(" ", "T")
    if ts.endswith("Z") or "+" in ts[10:]:
        return ts.replace("+00:00", "Z") if not ts.endswith("Z") else ts
    dt = datetime.fromisoformat(ts).replace(tzinfo=_LOCAL_TZ).astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _to_rfc3339_padded(ts, pad_minutes=2):
    """Like _to_rfc3339, but with padding for InfluxDB range queries."""
    ts = str(ts).strip().replace(" ", "T")
    if ts.endswith("Z") or "+" in ts[10:]:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    else:
        dt = datetime.fromisoformat(ts).replace(tzinfo=_LOCAL_TZ)
    dt = dt.astimezone(timezone.utc) + timedelta(minutes=pad_minutes)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

def _get_secret_key():
    """Get SECRET_KEY from env, or generate persistently from DB."""
    if config.SECRET_KEY:
        return config.SECRET_KEY
    import secrets as _sec
    db = sqlite3.connect(config.DB_PATH, timeout=10)
    db.execute("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
    row = db.execute("SELECT value FROM settings WHERE key = 'secret_key'").fetchone()
    if row:
        key = row[0]
    else:
        key = _sec.token_hex(32)
        db.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('secret_key', ?)", (key,))
        db.commit()
    db.close()
    return key

app.secret_key = _get_secret_key()
app.jinja_env.globals["version"] = config.VERSION
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = True
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=7)
app.config["REMEMBER_COOKIE_DURATION"] = timedelta(days=7)

csrf = CSRFProtect(app)
app.config["WTF_CSRF_CHECK_DEFAULT"] = False  # Not global, only targeted

@app.after_request
def set_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://unpkg.com; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://unpkg.com; "
        "img-src 'self' data: blob: https://tile.openstreetmap.org "
        "https://*.basemaps.cartocdn.com https://server.arcgisonline.com; "
        "connect-src 'self' https://nominatim.openstreetmap.org https://cdn.jsdelivr.net https://unpkg.com; "
        "font-src 'self' https://cdn.jsdelivr.net https://unpkg.com; "
        "frame-ancestors 'none'"
    )
    return response


@app.before_request
def _csrf_for_forms():
    """Only check CSRF for HTML forms, not for JSON API requests."""
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return
    if request.endpoint == "login" and request.method == "POST":
        csrf.protect()

# ── i18n ─────────────────────────────────────────────────────

_lang_dir = os.path.join(os.path.dirname(__file__), "lang")
_translations = {}
for _fname in os.listdir(_lang_dir):
    if _fname.endswith(".json"):
        _code = _fname[:-5].upper()
        with open(os.path.join(_lang_dir, _fname), encoding="utf-8") as _f:
            _translations[_code] = json.load(_f)


def get_language():
    """Active language: DB setting > ENV > DE."""
    try:
        db = get_db()
        row = db.execute("SELECT value FROM settings WHERE key = 'language'").fetchone()
        db.close()
        if row and row["value"].upper() in _translations:
            return row["value"].upper()
    except Exception:
        pass
    return config.LANGUAGE if config.LANGUAGE in _translations else "DE"


MAP_STYLES = {
    "carto_dark":    "https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png",
    "carto_light":   "https://{s}.basemaps.cartocdn.com/light_all/{z}/{x}/{y}{r}.png",
    "carto_voyager": "https://{s}.basemaps.cartocdn.com/rastertiles/voyager/{z}/{x}/{y}{r}.png",
    "osm":           "https://tile.openstreetmap.org/{z}/{x}/{y}.png",
    "esri_sat":      "https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}",
    "esri_topo":     "https://server.arcgisonline.com/ArcGIS/rest/services/World_Topo_Map/MapServer/tile/{z}/{y}/{x}",
}


def get_map_tile_url():
    """Read map style from DB setting."""
    try:
        db = get_db()
        row = db.execute("SELECT value FROM settings WHERE key = 'map_style'").fetchone()
        db.close()
        if row and row["value"] in MAP_STYLES:
            return MAP_STYLES[row["value"]]
    except Exception:
        pass
    return MAP_STYLES["carto_dark"]


@app.context_processor
def inject_translations():
    lang = get_language()
    t = _translations.get(lang, _translations["DE"])
    return {"t": t, "current_lang": lang, "map_tile_url": get_map_tile_url()}


@app.context_processor
def inject_today():
    from datetime import date
    return {"today": date.today().isoformat()}
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
log = logging.getLogger("triplog.app")

# ── Encryption for personal settings ─────────────────────────

ENCRYPTED_SETTINGS = {
    "invoice_sender", "invoice_recipient", "invoice_intro",
    "invoice_meter_text", "invoice_meter_info", "invoice_tariff_ref",
    "invoice_data_info",
}

def _settings_fernet():
    """Fernet instance derived from the stored SECRET_KEY."""
    if not _FERNET_AVAILABLE:
        return None
    try:
        db = sqlite3.connect(config.DB_PATH, timeout=10)
        row = db.execute("SELECT value FROM settings WHERE key='secret_key'").fetchone()
        db.close()
        if not row:
            return None
        key = base64.urlsafe_b64encode(hashlib.sha256(row[0].encode()).digest())
        return _Fernet(key)
    except Exception:
        return None


def _encrypt_setting(f, value):
    if f is None:
        return value
    return f.encrypt(value.encode()).decode()


def _decrypt_setting(f, value):
    if f is None:
        return value
    try:
        return f.decrypt(value.encode()).decode()
    except Exception:
        return value  # Not yet encrypted or wrong key


# ── Login Manager ────────────────────────────────────────────

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


def _validate_password(pw):
    """Password minimum requirements. Returns error text or None."""
    if len(pw) < 8:
        return "Passwort muss mindestens 8 Zeichen haben"
    if pw.isdigit():
        return "Passwort darf nicht nur aus Ziffern bestehen"
    if pw.lower() in ("password", "passwort", "12345678", "123456789", "1234567890", "abcdefgh", "qwertzui", "qwertyui"):
        return "Dieses Passwort ist zu einfach"
    if len(set(pw)) < 3:
        return "Passwort muss mindestens 3 verschiedene Zeichen enthalten"
    return None


class User(UserMixin):
    def __init__(self, id, username, is_admin=False, default_trip_purpose=None):
        self.id = id
        self.username = username
        self.is_admin = is_admin
        self.default_trip_purpose = default_trip_purpose or ""


def _user_from_row(row):
    return User(row["id"], row["username"], bool(row["is_admin"]),
                row["default_trip_purpose"] if "default_trip_purpose" in row.keys() else None)


@login_manager.user_loader
def load_user(user_id):
    db = get_db()
    row = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    db.close()
    if row:
        return _user_from_row(row)
    return None


def admin_required(f):
    @wraps(f)
    @login_required
    def decorated(*args, **kwargs):
        if not current_user.is_admin:
            return jsonify({"error": "Admin-Rechte erforderlich"}), 403
        return f(*args, **kwargs)
    return decorated


def debug_required(f):
    """Requires admin + ENABLE_DEBUG=1."""
    @wraps(f)
    @admin_required
    def decorated(*args, **kwargs):
        if not config.ENABLE_DEBUG:
            return jsonify({"error": "Debug-Modus deaktiviert (ENABLE_DEBUG=0)"}), 403
        return f(*args, **kwargs)
    return decorated


_setup_required = False


def _check_setup():
    """Check if first-run setup is needed (no users in DB)."""
    global _setup_required
    db = get_db()
    row = db.execute("SELECT COUNT(*) AS c FROM users").fetchone()
    db.close()
    if row["c"] == 0:
        _setup_required = True
        log.info("No user found — setup wizard activated at /setup")


# ── Login / Logout ───────────────────────────────────────────

# Rate-Limiting: max 5 attempts per IP, then 60s cooldown
_login_attempts = {}  # {ip: [timestamp, ...]}
_LOGIN_MAX = 5
_LOGIN_COOLDOWN = 60  # seconds

def _is_rate_limited(ip):
    now = time.time()
    attempts = _login_attempts.get(ip, [])
    # Remove old entries
    attempts = [t for t in attempts if now - t < _LOGIN_COOLDOWN]
    _login_attempts[ip] = attempts
    return len(attempts) >= _LOGIN_MAX

def _record_attempt(ip):
    _login_attempts.setdefault(ip, []).append(time.time())

@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    error = None
    if request.method == "POST":
        ip = request.remote_addr
        if _is_rate_limited(ip):
            remaining = int(_LOGIN_COOLDOWN - (time.time() - _login_attempts[ip][0]))
            error = f"Zu viele Versuche. Bitte {max(remaining, 1)}s warten."
            return render_template("login.html", error=error)

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        db = get_db()
        row = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        db.close()

        if row and check_password_hash(row["password_hash"], password):
            # Auto-upgrade pbkdf2 → argon2 on successful login
            if _needs_rehash(row["password_hash"]):
                db2 = get_db()
                db2.execute("UPDATE users SET password_hash = ? WHERE id = ?",
                            (generate_password_hash(password), row["id"]))
                db2.commit()
                db2.close()
            _login_attempts.pop(ip, None)  # Reset on success
            next_page = request.args.get("next", "/")
            if row["totp_enabled"]:
                session["pending_user_id"] = row["id"]
                session["pending_user_next"] = next_page
                return redirect(url_for("login_totp"))
            user = _user_from_row(row)
            login_user(user, remember=True)
            return redirect(next_page)
        _record_attempt(ip)
        lang = get_language()
        error = _translations.get(lang, _translations["DE"])["login_error"]

    return render_template("login.html", error=error)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


# ── TOTP Login ────────────────────────────────────────────────

@app.route("/login/totp", methods=["GET", "POST"])
def login_totp():
    if "pending_user_id" not in session:
        return redirect(url_for("login"))
    error = None
    if request.method == "POST":
        code = request.form.get("code", "").strip()
        uid = session.get("pending_user_id")
        db = get_db()
        row = db.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
        verified = False
        if row and _TOTP_AVAILABLE:
            # Try TOTP code first (6 digits)
            if row["totp_secret"] and pyotp.TOTP(row["totp_secret"]).verify(code, valid_window=1):
                verified = True
            # Try recovery code (8 hex chars)
            elif len(code) == 8 and _consume_recovery_code(db, uid, code):
                verified = True
        db.close()
        if verified:
            user = _user_from_row(row)
            login_user(user, remember=True)
            next_page = session.pop("pending_user_next", "/")
            session.pop("pending_user_id", None)
            return redirect(next_page)
        error = "Ungültiger Code. Bitte erneut versuchen."
    return render_template("login_totp.html", error=error)


# ── First-run Setup ───────────────────────────────────────────

@app.route("/setup", methods=["GET", "POST"])
def setup():
    global _setup_required
    if request.method == "GET":
        if not _setup_required:
            if not current_user.is_authenticated:
                return redirect(url_for("login"))
            return abort(404)
        return render_template("setup.html", error=None)

    # POST
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    password_confirm = request.form.get("password_confirm", "")

    if not username:
        return render_template("setup.html", error="Benutzername darf nicht leer sein.")
    pw_err = _validate_password(password)
    if pw_err:
        return render_template("setup.html", error=pw_err)
    if password != password_confirm:
        return render_template("setup.html", error="Passwörter stimmen nicht überein.")

    language = request.form.get("language", "DE").upper()
    if language not in ("DE", "EN"):
        language = "DE"

    db = get_db()
    db.execute(
        "INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, 1)",
        (username, generate_password_hash(password)),
    )
    db.execute(
        "INSERT INTO settings (key, value) VALUES ('language', ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (language,),
    )
    db.commit()
    row = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    db.close()
    _setup_required = False
    user = _user_from_row(row)
    login_user(user, remember=True)
    return redirect(url_for("setup_2fa"))


@app.route("/setup/2fa", methods=["GET", "POST"])
def setup_2fa():
    if not current_user.is_authenticated:
        return redirect(url_for("login"))
    if not _TOTP_AVAILABLE:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        action = request.form.get("action", "")
        if action == "skip":
            return redirect(url_for("dashboard"))
        code = request.form.get("code", "").strip()
        # Prefer hidden-field secret (works on iOS Safari where session cookies may be lost)
        secret = request.form.get("secret", "").strip() or session.get("pending_totp_secret")
        if secret and pyotp.TOTP(secret).verify(code, valid_window=1):
            db = get_db()
            db.execute("UPDATE users SET totp_secret = ?, totp_enabled = 1 WHERE id = ?",
                       (secret, current_user.id))
            # Generate and store recovery codes
            codes = _generate_recovery_codes()
            _store_recovery_codes(db, current_user.id, codes)
            db.close()
            session.pop("pending_totp_secret", None)
            session["show_recovery_codes"] = codes
            return redirect(url_for("show_recovery_codes"))
        # Invalid code — keep same secret to avoid QR mismatch
        error = "Ungültiger Code. Bitte erneut versuchen."
        secret = (request.form.get("secret", "").strip()
                  or session.get("pending_totp_secret")
                  or pyotp.random_base32())
        session["pending_totp_secret"] = secret
        totp = pyotp.TOTP(secret)
        uri = totp.provisioning_uri(name=current_user.username, issuer_name="ID·Mate")
        img = qrcode.make(uri)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        qr_b64 = base64.b64encode(buf.getvalue()).decode()
        return render_template("setup_2fa.html", qr_b64=qr_b64, secret=secret, error=error)

    # GET
    secret = pyotp.random_base32()
    session["pending_totp_secret"] = secret
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=current_user.username, issuer_name="ID·Mate")
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode()
    return render_template("setup_2fa.html", qr_b64=qr_b64, secret=secret, error=None)


@app.route("/setup/recovery-codes")
@login_required
def show_recovery_codes():
    codes = session.pop("show_recovery_codes", None)
    if not codes:
        return redirect(url_for("dashboard"))
    return render_template("recovery_codes.html", codes=codes)


@app.route("/api/user/2fa/disable", methods=["POST"])
@login_required
def disable_2fa():
    target_id = request.get_json(silent=True, force=True) or {}
    uid = target_id.get("user_id", current_user.id)
    # Only admin can disable for others
    if uid != current_user.id and not current_user.is_admin:
        return jsonify({"error": "Keine Berechtigung"}), 403
    db = get_db()
    db.execute("UPDATE users SET totp_secret = NULL, totp_enabled = 0 WHERE id = ?", (uid,))
    db.commit()
    db.close()
    return jsonify({"ok": True})


@app.route("/healthz")
def healthz():
    """Liveness probe — used by docker healthcheck."""
    return "ok", 200, {"Content-Type": "text/plain"}


@app.before_request
def require_login():
    """All routes except /login require authentication."""
    if request.endpoint in ("login", "static", "charge_webhook", "setup", "setup_2fa", "login_totp", "healthz"):
        return
    if _setup_required:
        return redirect(url_for("setup"))
    if not current_user.is_authenticated:
        if request.path.startswith("/api/"):
            return jsonify({"error": "Nicht angemeldet"}), 401
        return redirect(url_for("login", next=request.path))


# ── Global date range selection ──────────────────────────────

@app.route("/api/daterange", methods=["POST"])
def set_daterange():
    """Store date range in session (global for all pages)."""
    data = request.get_json()
    session["date_from"] = data.get("from", "")
    session["date_to"] = data.get("to", "")
    return jsonify({"ok": True})


@app.route("/api/daterange")
def get_daterange():
    return jsonify({"from": session.get("date_from", ""), "to": session.get("date_to", "")})

# ── Trip log categories ──────────────────────────────────────



def get_purpose_meta(db):
    """All trip purposes with color and is_private from the DB."""
    rows = db.execute("SELECT * FROM purpose_meta ORDER BY sort_order, name").fetchall()
    return [dict(r) for r in rows]


def haversine_m(lat1, lon1, lat2, lon2):
    """Distance in meters between two GPS coordinates."""
    R = 6371000
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = math.sin(dlat/2)**2 + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(dlon/2)**2
    return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))


def _operator_icon_map(db):
    """Returns {name.lower(): {color, icon_url}} from the operators table."""
    rows = db.execute("SELECT name, color, icon_filename FROM operators").fetchall()
    result = {}
    for r in rows:
        icon_url = f"/media/operator-icons/{r['icon_filename']}" if r['icon_filename'] else None
        result[r['name'].lower()] = {"color": r['color'] or '#8b949e', "icon_url": icon_url}
    return result


def match_location(db, lat, lon):
    """Find the nearest saved location within its radius."""
    if not lat or not lon:
        return None
    locations = db.execute("SELECT * FROM locations").fetchall()
    best = None
    best_dist = float('inf')
    for loc in locations:
        dist = haversine_m(lat, lon, loc["lat"], loc["lon"])
        if dist <= loc["radius_m"] and dist < best_dist:
            best = loc
            best_dist = dist
    return best


_schema_initialized = False

def get_db():
    global _schema_initialized
    db = sqlite3.connect(config.DB_PATH, timeout=10)
    db.row_factory = sqlite3.Row
    if _schema_initialized:
        return db
    with open("schema.sql") as f:
        db.executescript(f.read())
    # Migration: is_gpx flag for GPX-imported trips
    cols = [r[1] for r in db.execute("PRAGMA table_info(trips)").fetchall()]
    if "is_gpx" not in cols:
        db.execute("ALTER TABLE trips ADD COLUMN is_gpx INTEGER DEFAULT 0")
        db.commit()
    # Migration: odo_start/odo_end columns
    if "odo_start" not in cols:
        db.execute("ALTER TABLE trips ADD COLUMN odo_start REAL")
        db.execute("ALTER TABLE trips ADD COLUMN odo_end REAL")
        db.commit()
    if "country_code" not in cols:
        db.execute("ALTER TABLE trips ADD COLUMN country_code TEXT")
        db.commit()
        # Backfill from start_address (format: "DE - City - Street")
        db.execute("""
            UPDATE trips SET country_code = UPPER(SUBSTR(start_address, 1, 2))
            WHERE country_code IS NULL AND start_address IS NOT NULL
              AND LENGTH(start_address) >= 2
              AND SUBSTR(start_address, 3, 3) IN (' - ', ' –', ' — ')
        """)
        db.commit()
        log.info("Migration: trips.country_code added")
    # Migration: recalculate consumption where SoC exists but energy/consumption is missing
    missing = db.execute(
        """SELECT id, device, soc_start, soc_end, distance_km FROM trips
           WHERE energy_kwh IS NULL AND soc_start IS NOT NULL AND soc_end IS NOT NULL
             AND soc_start > soc_end"""
    ).fetchall()
    for t in missing:
        bat_kwh = get_bat_kwh(db, t["device"])
        energy = round((t["soc_start"] - t["soc_end"]) / 100 * bat_kwh, 2)
        cons = round(energy / t["distance_km"] * 100, 1) if t["distance_km"] and t["distance_km"] >= 10 else None
        db.execute("UPDATE trips SET energy_kwh = ?, consumption = ? WHERE id = ?",
                    (energy, cons, t["id"]))
    if missing:
        db.commit()
        log.info("Consumption recalculated: %d trips", len(missing))
    # Migration: default_device in users
    u_cols = [r[1] for r in db.execute("PRAGMA table_info(users)").fetchall()]
    if "default_device" not in u_cols:
        db.execute("ALTER TABLE users ADD COLUMN default_device TEXT")
        db.commit()
    # Migration: active_vehicle_id (temporary selection, persisted in DB)
    if "active_vehicle_id" not in u_cols:
        db.execute("ALTER TABLE users ADD COLUMN active_vehicle_id INTEGER")
        db.commit()
    # Migration: TOTP 2FA columns
    if "totp_secret" not in u_cols:
        db.execute("ALTER TABLE users ADD COLUMN totp_secret TEXT")
        db.execute("ALTER TABLE users ADD COLUMN totp_enabled INTEGER DEFAULT 0")
        db.execute("ALTER TABLE users ADD COLUMN setup_required INTEGER DEFAULT 0")
        db.commit()
    # Migration: recovery codes for 2FA
    if "recovery_codes" not in u_cols:
        db.execute("ALTER TABLE users ADD COLUMN recovery_codes TEXT")
        db.commit()
    # Migration: default_trip_purpose per user
    if "default_trip_purpose" not in u_cols:
        db.execute("ALTER TABLE users ADD COLUMN default_trip_purpose TEXT")
        db.commit()
    # Migration: session_number, is_external, note, cost_total in charge_sessions
    cs_cols = [r[1] for r in db.execute("PRAGMA table_info(charge_sessions)").fetchall()]
    if "session_number" not in cs_cols:
        db.execute("ALTER TABLE charge_sessions ADD COLUMN session_number TEXT")
        db.execute("ALTER TABLE charge_sessions ADD COLUMN is_external INTEGER DEFAULT 0")
        db.commit()
    if "note" not in cs_cols:
        db.execute("ALTER TABLE charge_sessions ADD COLUMN note TEXT")
        db.execute("ALTER TABLE charge_sessions ADD COLUMN cost_total REAL")
        db.commit()
    if "lat" not in cs_cols:
        db.execute("ALTER TABLE charge_sessions ADD COLUMN lat REAL")
        db.execute("ALTER TABLE charge_sessions ADD COLUMN lon REAL")
        db.execute("ALTER TABLE charge_sessions ADD COLUMN location_name TEXT")
        db.commit()
    # Migration: is_main column in purpose_meta
    pm_cols = [r[1] for r in db.execute("PRAGMA table_info(purpose_meta)").fetchall()]
    if "is_main" not in pm_cols:
        db.execute("ALTER TABLE purpose_meta ADD COLUMN is_main INTEGER NOT NULL DEFAULT 0")
        db.commit()
    # Migration: route_rules – make from/to nullable (wildcard rules)
    rr_info = db.execute("PRAGMA table_info(route_rules)").fetchall()
    rr_cols = {r[1]: r[3] for r in rr_info}  # name -> notnull
    if rr_cols.get("from_location_id") == 1:  # still NOT NULL
        db.executescript("""
            CREATE TABLE route_rules_new (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                from_location_id INTEGER REFERENCES locations(id) ON DELETE CASCADE,
                to_location_id   INTEGER REFERENCES locations(id) ON DELETE CASCADE,
                purpose          TEXT NOT NULL,
                destination      TEXT,
                visit_reason     TEXT,
                created_at       TEXT DEFAULT (datetime('now')),
                UNIQUE(from_location_id, to_location_id)
            );
            INSERT INTO route_rules_new SELECT * FROM route_rules;
            DROP TABLE route_rules;
            ALTER TABLE route_rules_new RENAME TO route_rules;
        """)
        log.info("Migration: route_rules – from/to nullable")
    # Migration: device column in vehicles
    v_cols = [r[1] for r in db.execute("PRAGMA table_info(vehicles)").fetchall()]
    if "device" not in v_cols:
        db.execute("ALTER TABLE vehicles ADD COLUMN device TEXT")
        db.commit()
        log.info("Migration: vehicles.device added")
    if "model" not in v_cols:
        db.execute("ALTER TABLE vehicles ADD COLUMN model TEXT")
        db.commit()
    if "battery_capacity_kwh" not in v_cols:
        db.execute("ALTER TABLE vehicles ADD COLUMN battery_capacity_kwh REAL")
        db.commit()
        log.info("Migration: vehicles.battery_capacity_kwh added")
    # Migration: default_vehicle_id in users
    if "default_vehicle_id" not in u_cols:
        db.execute("ALTER TABLE users ADD COLUMN default_vehicle_id INTEGER")
        db.commit()
        log.info("Migration: users.default_vehicle_id added")
    # Migration: color (badge background color) in locations
    loc_cols = [r[1] for r in db.execute("PRAGMA table_info(locations)").fetchall()]
    if loc_cols and "color" not in loc_cols:
        db.execute("ALTER TABLE locations ADD COLUMN color TEXT DEFAULT '#21262d'")
        db.commit()
        log.info("Migration: locations.color added")
    # Migration: color, shape, lat2/lon2, icon_filename in charge_locations
    cl_cols = [r[1] for r in db.execute("PRAGMA table_info(charge_locations)").fetchall()]
    if cl_cols and "icon_filename" not in cl_cols:
        db.execute("ALTER TABLE charge_locations ADD COLUMN icon_filename TEXT")
        db.commit()
    if cl_cols and "country_code" not in cl_cols:
        db.execute("ALTER TABLE charge_locations ADD COLUMN country_code TEXT DEFAULT 'DE'")
        db.commit()
    if cl_cols and "color" not in cl_cols:
        db.execute("ALTER TABLE charge_locations ADD COLUMN color TEXT DEFAULT '#8b949e'")
        db.commit()
    if cl_cols and "shape" not in cl_cols:
        db.execute("ALTER TABLE charge_locations ADD COLUMN shape TEXT DEFAULT 'circle'")
        db.execute("ALTER TABLE charge_locations ADD COLUMN lat2 REAL")
        db.execute("ALTER TABLE charge_locations ADD COLUMN lon2 REAL")
        db.commit()
    # Migration: operator in charge_sessions
    if "operator" not in cs_cols:
        db.execute("ALTER TABLE charge_sessions ADD COLUMN operator TEXT")
        db.commit()
    # Migration: soc in charge_readings, soc_start/soc_end in charge_sessions
    cr_cols = [r[1] for r in db.execute("PRAGMA table_info(charge_readings)").fetchall()]
    if "soc" not in cr_cols:
        db.execute("ALTER TABLE charge_readings ADD COLUMN soc REAL")
        db.commit()
    if "soc_start" not in cs_cols:
        db.execute("ALTER TABLE charge_sessions ADD COLUMN soc_start REAL")
        db.execute("ALTER TABLE charge_sessions ADD COLUMN soc_end REAL")
        db.commit()
    # Migration: operators table (operators with custom icon/color)
    existing_tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
    if "operators" not in existing_tables:
        db.execute("""CREATE TABLE operators (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            color TEXT DEFAULT '#8b949e',
            icon_filename TEXT
        )""")
        db.commit()
        log.info("Migration: operators table created")
    # Migration: operator_id FK in charge_locations
    _cl_cols2 = [r[1] for r in db.execute("PRAGMA table_info(charge_locations)").fetchall()]
    if _cl_cols2 and "operator_id" not in _cl_cols2:
        db.execute("ALTER TABLE charge_locations ADD COLUMN operator_id INTEGER REFERENCES operators(id) ON DELETE SET NULL")
        db.commit()
        log.info("Migration: charge_locations.operator_id added")
    _schema_initialized = True
    return db


# ── Vehicle selection (active vehicle) ───────────────────────────

def active_vehicle(db=None):
    """Active vehicle: last header pick > user default > first vehicle."""
    close = False
    if db is None:
        db = get_db()
        close = True
    vehicle = None
    if current_user.is_authenticated:
        row = db.execute(
            "SELECT active_vehicle_id, default_vehicle_id FROM users WHERE id = ?",
            (current_user.id,)
        ).fetchone()
        # Last picked via header (persisted in DB)
        vid = row["active_vehicle_id"] if row else None
        if vid:
            vehicle = db.execute("SELECT * FROM vehicles WHERE id = ?", (vid,)).fetchone()
        # Permanent admin default
        if not vehicle:
            vid = row["default_vehicle_id"] if row else None
            if vid:
                vehicle = db.execute("SELECT * FROM vehicles WHERE id = ?", (vid,)).fetchone()
    if not vehicle:
        vehicle = db.execute("SELECT * FROM vehicles ORDER BY id LIMIT 1").fetchone()
    if close:
        db.close()
    return dict(vehicle) if vehicle else None


def active_device():
    """InfluxDB device tag of the active vehicle."""
    v = active_vehicle()
    if v and v.get("device"):
        return v["device"]
    return config.INFLUX_DEVICE


def get_bat_kwh(db, device=None):
    """Battery capacity (kWh) — vehicle-specific, then global setting, then 86.5."""
    if device:
        row = db.execute(
            "SELECT battery_capacity_kwh FROM vehicles WHERE device = ? AND battery_capacity_kwh IS NOT NULL",
            (device,)
        ).fetchone()
        if row and row["battery_capacity_kwh"]:
            return float(row["battery_capacity_kwh"])
    bat_row = db.execute("SELECT value FROM settings WHERE key = 'battery_capacity_kwh'").fetchone()
    return float(bat_row["value"]) if bat_row else 86.5


@app.context_processor
def inject_device_info():
    """Inject vehicle info into all templates."""
    if not current_user.is_authenticated:
        return {}
    v = active_vehicle()
    return {
        "active_device": v["device"] if v else config.INFLUX_DEVICE,
        "active_vehicle": v,
        "vehicle_name": v["name"] or v["plate"] if v else "",
    }


@app.route("/api/user/default-vehicle", methods=["POST"])
@login_required
def set_default_vehicle():
    """Set default vehicle for the user."""
    data = request.get_json()
    vehicle_id = data.get("vehicle_id")
    db = get_db()
    db.execute("UPDATE users SET default_vehicle_id = ? WHERE id = ?",
               (int(vehicle_id) if vehicle_id else None, current_user.id))
    db.commit()
    db.close()
    return jsonify({"ok": True})


@app.route("/api/user/active-vehicle", methods=["POST"])
@login_required
def set_active_vehicle():
    """Save active vehicle persistently in DB (survives browser reload)."""
    data = request.get_json()
    vehicle_id = data.get("vehicle_id")
    db = get_db()
    db.execute("UPDATE users SET active_vehicle_id = ? WHERE id = ?",
               (int(vehicle_id) if vehicle_id else None, current_user.id))
    db.commit()
    db.close()
    return jsonify({"ok": True})


@app.route("/api/user/default-trip-purpose", methods=["POST"])
@login_required
def set_default_trip_purpose():
    """Save default trip purpose for new uncategorized trips."""
    data = request.get_json()
    purpose = (data.get("purpose") or "").strip()
    db = get_db()
    db.execute("UPDATE users SET default_trip_purpose = ? WHERE id = ?",
               (purpose or None, current_user.id))
    db.commit()
    db.close()
    current_user.default_trip_purpose = purpose
    return jsonify({"ok": True})


# ── Vehicle state cache (background poller) ─────────────────
# Keeps the last known InfluxDB values per device in RAM.
# The poller runs every 10 seconds and updates the cache.
# /api/vehicle-state reads only from this cache → dashboard
# responds immediately, independent of InfluxDB latency.

_state_cache: dict = {}          # device -> state-dict
_state_lock = threading.Lock()

# ── SSE: real-time push of MQTT data to dashboard ───────────────
# One queue per connected client; MQTT callback pushes decoded data in.
_sse_clients: dict = {}          # client_id -> {"queue": Queue, "device": str}
_sse_lock = threading.Lock()
_sse_next_id = 0


def sse_publish(device: str, data: dict):
    """Push MQTT data to all SSE clients watching this device."""
    import json
    # Map field names (short → long) for dashboard compatibility
    mapped = {}
    for k, v in data.items():
        if k in _ALL_FIELDS:
            mapped[_ALL_FIELDS[k]] = v
        else:
            mapped[k] = v
    # Add per-field timestamps + global time so dashboard can track freshness
    now_iso = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
    ft = {field: now_iso for field in mapped if field not in ("field_times", "time")}
    mapped["field_times"] = ft
    mapped["time"] = now_iso
    # Also update in-memory state cache so fullRefresh stays consistent
    with _state_lock:
        cached = _state_cache.get(device, {})
        merged = dict(cached)
        for k, v in mapped.items():
            if k == "field_times":
                old_ft = merged.get("field_times", {})
                old_ft.update(ft)
                merged["field_times"] = old_ft
            else:
                merged[k] = v
        merged["time"] = now_iso
        _state_cache[device] = merged
    payload = json.dumps(mapped)
    with _sse_lock:
        for cid, client in list(_sse_clients.items()):
            if client["device"] == device:
                try:
                    client["queue"].put_nowait(payload)
                except Exception:
                    pass  # Queue full → client too slow, skipped

_ALL_FIELDS = {
    "s": "soc", "la": "lat", "lo": "lon", "hd": "heading",
    "od": "odometer", "r": "range_km",
    "v": "speed", "p": "power", "u": "voltage", "i": "current",
    "bt": "bat_temp", "et": "ext_temp", "c": "charging",
    "dc": "dc_charging", "pk": "parked", "ls": "lte_signal",
    "bd": "esp_battery", "ig": "ignition", "lp": "plmn",
}

# PLMN (MCC+MNC) → carrier name mapping for German networks
_PLMN_CARRIERS = {
    26201: "Telekom", 26206: "Telekom",
    26202: "Vodafone", 26204: "Vodafone", 26209: "Vodafone", 26242: "Vodafone",
    26203: "O2", 26207: "O2", 26208: "O2", 26211: "O2", 26220: "O2",
    26212: "Dolphin", 26213: "Mobilcom", 26214: "Quam", 26216: "E-Plus",
    26217: "E-Plus", 26218: "E-Plus", 26219: "E-Plus",
    26243: "1&1", 26277: "Lyca",
}

def _plmn_name(plmn):
    try:
        return _PLMN_CARRIERS.get(int(plmn), f"PLMN {int(plmn)}")
    except (TypeError, ValueError):
        return None


def _fetch_influx_state(device: str) -> dict:
    """Get the last known state of a device from InfluxDB."""
    client = detector.get_influx()
    if not client:
        return {}
    try:
        filt = " or ".join(f'r._field == "{f}"' for f in _ALL_FIELDS)
        # Get last value per field — group by _field is required
        # so last() returns a value PER field (not just the very last one)
        q = f'''
        from(bucket: "{config.INFLUX_BUCKET}")
          |> range(start: -365d)
          |> filter(fn: (r) => r._measurement == "v" and r.d == "{device}")
          |> filter(fn: (r) => {filt})
          |> group(columns: ["_field"])
          |> last()
        '''
        tables = client.query_api().query(q, org=config.INFLUX_ORG)
        state: dict = {}
        field_times: dict = {}
        latest_time = None
        for table in tables:
            for record in table.records:
                key = _ALL_FIELDS.get(record.get_field())
                if key:
                    state[key] = record.get_value()
                    t = record.get_time()
                    if t:
                        if t.tzinfo is None:
                            t = t.replace(tzinfo=timezone.utc)
                        field_times[key] = t.strftime('%Y-%m-%dT%H:%M:%SZ')
                        if latest_time is None or t > latest_time:
                            latest_time = t

        # Mobile carrier: read from `op` tag (legacy, still works)
        q_op = f'''
        from(bucket: "{config.INFLUX_BUCKET}")
          |> range(start: -365d)
          |> filter(fn: (r) => r._measurement == "v" and r.d == "{device}" and r._field == "ls")
          |> last()
          |> keep(columns: ["op"])
        '''
        try:
            op_tables = client.query_api().query(q_op, org=config.INFLUX_ORG)
            for table in op_tables:
                for record in table.records:
                    op_val = record.values.get("op")
                    if op_val:
                        state["operator"] = op_val
        except Exception:
            pass
        # Fallback: derive from PLMN field if no op tag found
        if "operator" not in state and "plmn" in state:
            name = _plmn_name(state["plmn"])
            if name:
                state["operator"] = name

        # Power: average of last 10 minutes instead of last single value
        q_power = f'''
        from(bucket: "{config.INFLUX_BUCKET}")
          |> range(start: -10m)
          |> filter(fn: (r) => r._measurement == "v" and r.d == "{device}" and r._field == "p")
          |> mean()
        '''
        try:
            power_tables = client.query_api().query(q_power, org=config.INFLUX_ORG)
            for table in power_tables:
                for record in table.records:
                    v = record.get_value()
                    if v is not None:
                        state["power"] = v
        except Exception:
            pass  # Fallback: single value from last() remains

        if field_times:
            state["field_times"] = field_times
        if latest_time:
            if latest_time.tzinfo is None:
                latest_time = latest_time.replace(tzinfo=timezone.utc)
            state["time"] = latest_time.strftime('%Y-%m-%dT%H:%M:%SZ')
        return state
    except Exception as e:
        log.warning("InfluxDB state-poll failed for %s: %s", device, e)
        return {}
    finally:
        client.close()


def _state_poller():
    """Background thread: update state cache every 10 seconds."""
    log.warning("State poller started")
    first = True
    while True:
        if not first:
            with _state_lock:
                cache_empty = not _state_cache
            time.sleep(2 if cache_empty else 10)
        first = False
        try:
            db = detector.get_db()
            rows = db.execute(
                "SELECT DISTINCT device FROM vehicles WHERE device IS NOT NULL AND device != ''"
            ).fetchall()
            devices = [r["device"] for r in rows] or [config.INFLUX_DEVICE]
            db.close()

            for dev in devices:
                fresh = _fetch_influx_state(dev)
                if fresh:
                    with _state_lock:
                        merged = dict(_state_cache.get(dev, {}))
                        merged.update(fresh)
                        _state_cache[dev] = merged
                        log.debug("State cache updated for %s: soc=%s",
                                  dev, fresh.get("soc"))
        except Exception as e:
            log.warning("State poller error: %s", e, exc_info=True)
            time.sleep(2)


# ── Home page: vehicle status ────────────────────────────────

@app.route("/")
def dashboard():
    return render_template("index.html", device=active_device())


@app.route("/api/vehicle-state")
def vehicle_state():
    """Current vehicle state — from cache (updated every 10s in background)."""
    device = active_device()

    with _state_lock:
        state = dict(_state_cache.get(device, {}))

    # If cache is still empty (first start): query directly
    if not state:
        state = _fetch_influx_state(device)
        if state:
            with _state_lock:
                _state_cache[device] = dict(state)

    # SQLite: last trip + calculated ranges
    db = get_db()
    last_trip = db.execute(
        "SELECT * FROM trips WHERE device = ? ORDER BY end_time DESC LIMIT 1",
        (device,),
    ).fetchone()
    if last_trip:
        state["last_trip"] = {
            "start_address": last_trip["start_address"],
            "end_address": last_trip["end_address"],
            "distance_km": last_trip["distance_km"],
            "consumption": last_trip["consumption"],
        }

    # Consumption: km-weighted average of last 20 trips >= 20 km
    # → stable moving average, no short-trip distortion
    cons_rows = db.execute(
        """SELECT energy_kwh, distance_km FROM trips
           WHERE device = ? AND energy_kwh IS NOT NULL AND energy_kwh > 0
             AND distance_km >= 20
           ORDER BY end_time DESC LIMIT 20""",
        (device,),
    ).fetchall()
    if cons_rows:
        total_kwh = sum(r["energy_kwh"] for r in cons_rows)
        total_km = sum(r["distance_km"] for r in cons_rows)
        avg_cons = total_kwh / total_km * 100 if total_km > 0 else None
    else:
        avg_cons = None

    # Charge tracker override: if a more recent SoC reading exists in charge_readings
    # (e.g. while charging at home), use that. InfluxDB data still has priority
    # if it's newer than the charge reading.
    v = db.execute("SELECT plate FROM vehicles WHERE device = ?", (device,)).fetchone()
    if v and v["plate"]:
        cr = db.execute(
            "SELECT soc, timestamp FROM charge_readings "
            "WHERE vehicle_plate = ? AND soc IS NOT NULL "
            "ORDER BY datetime(timestamp) DESC LIMIT 1",
            (v["plate"],)
        ).fetchone()
        if cr and cr["soc"] is not None:
            ft = state.get("field_times", {})
            influx_soc_ts = ft.get("soc")  # ISO-Z format
            # Normalize charge reading timestamp to same format (assume local → UTC naive comparable)
            cr_ts = cr["timestamp"]
            if cr_ts and (not influx_soc_ts or cr_ts.replace(" ", "T") > influx_soc_ts):
                state["soc"] = round(cr["soc"], 1)
                # Update field_times so dashboard shows fresh timestamp
                now_iso = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
                if "field_times" not in state:
                    state["field_times"] = {}
                state["field_times"]["soc"] = now_iso

    if avg_cons and state.get("soc") is not None:
        capacity = get_bat_kwh(db, device)
        available_kwh = state["soc"] / 100.0 * capacity
        state["calc_range"] = round(available_kwh / avg_cons * 100, 0)
        state["avg_consumption"] = round(avg_cons, 1)

    best = db.execute(
        """SELECT consumption FROM trips
           WHERE device = ? AND consumption IS NOT NULL AND consumption > 0
             AND distance_km >= 20
           ORDER BY end_time DESC LIMIT 50""",
        (device,),
    ).fetchall()
    if best:
        avg_cons = sum(r["consumption"] for r in best) / len(best)
        capacity = get_bat_kwh(db, device)
        state["max_range"] = round(capacity / avg_cons * 100, 0)

    db.close()
    return jsonify(state)


# ── SSE stream: real-time vehicle data via MQTT ──────────────

@app.route("/api/vehicle-stream")
def vehicle_stream():
    """Server-Sent Events: push MQTT telegrams to dashboard in real-time."""
    import queue
    global _sse_next_id
    device = active_device()

    with _sse_lock:
        _sse_next_id += 1
        cid = _sse_next_id
        q = queue.Queue(maxsize=50)
        _sse_clients[cid] = {"queue": q, "device": device}

    def stream():
        try:
            while True:
                try:
                    payload = q.get(timeout=30)
                    yield f"data: {payload}\n\n"
                except queue.Empty:
                    # Keepalive — prevents timeout
                    yield ": keepalive\n\n"
        except GeneratorExit:
            pass
        finally:
            with _sse_lock:
                _sse_clients.pop(cid, None)

    return app.response_class(stream(), mimetype="text/event-stream",
                              headers={"Cache-Control": "no-cache",
                                       "X-Accel-Buffering": "no"})


# ── GPS trail (last 10 minutes) ──────────────────────────────

@app.route("/api/trail")
def trail():
    """GPS points from the last 10 minutes for the map trail."""
    device = active_device()
    client = detector.get_influx()
    points = []
    if client:
        try:
            query = f'''
            from(bucket: "{config.INFLUX_BUCKET}")
              |> range(start: -10m)
              |> filter(fn: (r) => r._measurement == "v" and r.d == "{device}")
              |> filter(fn: (r) => r._field == "la" or r._field == "lo")
              |> pivot(rowKey: ["_time"], columnKey: ["_field"], valueColumn: "_value")
              |> sort(columns: ["_time"])
            '''
            tables = client.query_api().query(query, org=config.INFLUX_ORG)
            for table in tables:
                for record in table.records:
                    la = record.values.get("la")
                    lo = record.values.get("lo")
                    if la and lo:
                        points.append([la, lo])
        except Exception as e:
            log.warning("InfluxDB query failed in trail: %s", e)
        finally:
            client.close()
    return jsonify(points)


# ── Trip list ────────────────────────────────────────────────

@app.route("/trips")
def trips_list():
    db = get_db()
    device = active_device()

    date_from = request.args.get("from", "") or session.get("date_from", "")
    date_to = request.args.get("to", "") or session.get("date_to", "")
    filter_mode = request.args.get("filter", "")

    # Sync to session
    if request.args.get("from") or request.args.get("to"):
        session["date_from"] = date_from
        session["date_to"] = date_to

    if filter_mode == "uncategorized":
        trips = db.execute(
            """SELECT * FROM trips WHERE device = ?
               AND (purpose IS NULL OR purpose = '')
               ORDER BY start_time DESC""",
            (device,),
        ).fetchall()
    elif filter_mode and filter_mode != "uncategorized":
        trips = db.execute(
            """SELECT * FROM trips WHERE device = ?
               AND purpose = ?
               ORDER BY start_time DESC""",
            (device, filter_mode),
        ).fetchall()
    elif date_from and date_to:
        trips = db.execute(
            """SELECT * FROM trips WHERE device = ?
               AND start_time >= ? AND start_time <= ?
               ORDER BY start_time DESC""",
            (device, date_from, date_to + "T23:59:59"),
        ).fetchall()
    else:
        trips = db.execute(
            """SELECT * FROM trips WHERE device = ?
               ORDER BY start_time DESC LIMIT 20""",
            (device,),
        ).fetchall()

    # Count uncategorized trips (purpose empty or NULL)
    uncategorized = db.execute(
        """SELECT COUNT(*) AS c FROM trips WHERE device = ?
           AND (purpose IS NULL OR purpose = '')""",
        (device,),
    ).fetchone()["c"]

    # Private purposes for template
    priv_names = {r["name"] for r in db.execute(
        "SELECT name FROM purpose_meta WHERE is_private = 1"
    ).fetchall()}

    db.close()
    return render_template("trips.html", trips=trips,
                           date_from=date_from, date_to=date_to,
                           filter_mode=filter_mode,
                           uncategorized=uncategorized,
                           private_purposes=priv_names,
                           user_default_purpose=current_user.default_trip_purpose)


# ── Analysis ─────────────────────────────────────────────────

@app.route("/analysis")
def analysis_page():
    date_from = session.get("date_from", "")
    date_to = session.get("date_to", "")
    return render_template("analysis.html", date_from=date_from, date_to=date_to)


@app.route("/api/visited-countries")
@login_required
def visited_countries():
    """Return all country codes where trips have taken place."""
    device = active_device()
    db = get_db()
    rows = db.execute(
        """SELECT DISTINCT country_code FROM trips
           WHERE country_code IS NOT NULL AND country_code != ''
             AND device = ?""",
        (device,)
    ).fetchall()
    codes = [r["country_code"] for r in rows]
    # Fallback: parse from start_address for older entries without country_code
    if not codes:
        rows2 = db.execute(
            """SELECT DISTINCT UPPER(SUBSTR(start_address, 1, 2)) as cc FROM trips
               WHERE start_address IS NOT NULL AND LENGTH(start_address) >= 5
                 AND SUBSTR(start_address, 3, 3) IN (' - ', ' –')
                 AND device = ?""",
            (device,)
        ).fetchall()
        codes = [r["cc"] for r in rows2 if r["cc"]]
    db.close()
    return jsonify({"countries": sorted(set(codes))})


@app.route("/api/trip-coords")
@login_required
def trip_coords():
    """All GPS points from InfluxDB for heatmap (aggressively downsampled)."""
    device = active_device()
    client = detector.get_influx()
    if not client:
        return jsonify([])
    coords = []
    seen = set()
    try:
        # 5-minute windows, last-value instead of mean (mean averages over GPS drops → 0,0)
        query = f'''
        from(bucket: "{config.INFLUX_BUCKET}")
          |> range(start: -180d)
          |> filter(fn: (r) => r._measurement == "v" and r.d == "{device}")
          |> filter(fn: (r) => r._field == "la" or r._field == "lo")
          |> filter(fn: (r) => r._value != 0.0)
          |> aggregateWindow(every: 5m, fn: last, createEmpty: false)
          |> pivot(rowKey: ["_time"], columnKey: ["_field"], valueColumn: "_value")
          |> filter(fn: (r) => exists r.la and exists r.lo)
        '''
        raw = []
        tables = client.query_api().query(query, org=config.INFLUX_ORG)
        for table in tables:
            for record in table.records:
                la = record.values.get("la")
                lo = record.values.get("lo")
                if la is None or lo is None:
                    continue
                if abs(la) < 0.5 or abs(lo) < 0.5 or abs(la) > 90 or abs(lo) > 180:
                    continue
                raw.append((la, lo))
        # Outlier filter: keep only points within 3° of median lat/lon
        if raw:
            lats = sorted(p[0] for p in raw)
            lons = sorted(p[1] for p in raw)
            med_la = lats[len(lats) // 2]
            med_lo = lons[len(lons) // 2]
            log.info("Heatmap: %d raw points, median=(%.4f, %.4f)", len(raw), med_la, med_lo)
            for la, lo in raw:
                if abs(la - med_la) > 3.0 or abs(lo - med_lo) > 5.0:
                    continue  # drop outliers far from cluster
                key = (round(la, 4), round(lo, 4))
                if key in seen:
                    continue
                seen.add(key)
                coords.append([la, lo])
                if len(coords) >= 10000:
                    break
    except Exception:
        log.exception("Error loading heatmap coords")
    finally:
        client.close()
    return jsonify(coords)


@app.route("/api/analysis")
def analysis_data():
    date_from = request.args.get("from", "") or session.get("date_from", "")
    date_to = request.args.get("to", "") or session.get("date_to", "")

    db = get_db()
    query = """SELECT start_time, end_time, distance_km, soc_start, soc_end,
                      energy_kwh, consumption, purpose, destination,
                      visit_reason, odo_start, odo_end, kw_start, kw_end,
                      ROUND((julianday(end_time) - julianday(start_time)) * 1440, 1) AS duration_min
               FROM trips WHERE device = ?"""
    params = [active_device()]

    if date_from and date_to:
        query += " AND start_time >= ? AND start_time <= ?"
        params += [date_from, date_to + "T23:59:59"]

    query += " ORDER BY start_time"
    rows = db.execute(query, params).fetchall()
    db.close()

    trips = []
    for r in rows:
        dist = r["distance_km"] or 0
        dur = r["duration_min"] or 0
        trips.append({
            "date": r["start_time"][:10],
            "time": r["start_time"][11:16],
            "km": dist,
            "odo": r["odo_end"] if r["odo_end"] is not None else r["odo_start"],
            "soc_start": r["soc_start"],
            "soc_end": r["soc_end"],
            "kwh": r["energy_kwh"],
            "consumption": r["consumption"],
            "purpose": r["purpose"] or "",
            "destination": r["destination"] or "",
            "visit_reason": r["visit_reason"] or "",
            "duration_min": round(dur, 1) if dur else None,
            "kw_start": r["kw_start"],
            "kw_end": r["kw_end"],
        })

    # Calculate charge cycles: kw jump OR SoC jump between trips = charge
    db2 = get_db()
    bat_kwh = get_bat_kwh(db2, active_device())
    db2.close()

    charge_cycles = []
    cycle_km = 0
    for i, t in enumerate(trips):
        cycle_km += t["km"] or 0
        if i == 0:
            continue
        prev = trips[i - 1]
        charged_kwh = None

        # Primary: kw meter jump
        if t.get("kw_start") is not None and prev.get("kw_end") is not None:
            kw_jump = t["kw_start"] - prev["kw_end"]
            if kw_jump >= 5:
                charged_kwh = round(kw_jump, 1)
        # Fallback: SOC-Sprung (soc_start[i] > soc_end[i-1])
        if charged_kwh is None and t.get("soc_start") is not None and prev.get("soc_end") is not None:
            soc_jump = t["soc_start"] - prev["soc_end"]
            if soc_jump >= 5:
                charged_kwh = round(soc_jump / 100.0 * bat_kwh, 1) if bat_kwh else None

        if charged_kwh is not None and cycle_km >= 1:
            charge_cycles.append({
                "date": t["date"],
                "charged_kwh": charged_kwh,
                "km": round(cycle_km, 1),
                "consumption": round(charged_kwh / cycle_km * 100, 1) if cycle_km >= 1 else None,
            })
            cycle_km = 0

    return jsonify({"trips": trips, "charge_cycles": charge_cycles, "bat_kwh": bat_kwh})


@app.route("/api/charge/stats")
@login_required
def charge_stats():
    """Charge statistics: home/external, AC/DC, operator (external only)."""
    date_from = request.args.get("from", "")
    date_to   = request.args.get("to", "")

    db = get_db()
    params = []
    where  = "WHERE 1=1"
    if date_from and date_to:
        where += " AND cs.start_time >= ? AND cs.start_time <= ?"
        params += [date_from, date_to + "T23:59:59"]

    rows = db.execute(f"""
        SELECT cs.is_external, cs.location_name, cs.operator AS sess_operator,
               cl.type AS loc_type, cl.operator AS loc_operator,
               op.name AS op_name,
               cs.total_kwh, cs.cost_tibber, cs.cost_pauschale, cs.cost_total,
               cs.avg_kw, cs.duration_minutes, cs.start_time
        FROM charge_sessions cs
        LEFT JOIN charge_locations cl ON cl.name = cs.location_name
        LEFT JOIN operators op ON cl.operator_id = op.id
        {where}
    """, params).fetchall()
    db.close()

    home_count = 0
    ext_count  = 0
    ac_count   = 0
    dc_count   = 0
    operators  = {}   # external only
    total_kwh  = 0.0
    total_cost = 0.0
    total_dur  = 0.0
    cost_count = 0
    monthly_kwh_home = {}
    monthly_kwh_ext  = {}
    monthly_cost     = {}
    avg_kw_ac = []
    avg_kw_dc = []

    for r in rows:
        is_ext = r["is_external"]
        loc_type = (r["loc_type"] or "ac").lower()
        operator = (r["sess_operator"] or r["op_name"] or r["loc_operator"] or "").strip()
        kwh = r["total_kwh"] or 0
        cost = r["cost_total"] or r["cost_pauschale"] or r["cost_tibber"] or 0
        month = (r["start_time"] or "")[:7]

        if is_ext:
            ext_count += 1
        else:
            home_count += 1

        if loc_type == "dc":
            dc_count += 1
        else:
            ac_count += 1

        if operator:
            operators[operator] = operators.get(operator, 0) + 1

        # Aggregated values
        total_kwh += kwh
        if cost:
            total_cost += cost
            cost_count += 1
        if r["duration_minutes"]:
            total_dur += r["duration_minutes"]
        if r["avg_kw"] and r["avg_kw"] > 0:
            (avg_kw_dc if loc_type == "dc" else avg_kw_ac).append(r["avg_kw"])

        # Monthly
        if month:
            if is_ext:
                monthly_kwh_ext[month] = monthly_kwh_ext.get(month, 0) + kwh
            else:
                monthly_kwh_home[month] = monthly_kwh_home.get(month, 0) + kwh
            monthly_cost[month] = monthly_cost.get(month, 0) + cost

    operators_sorted = dict(sorted(operators.items(), key=lambda x: x[1], reverse=True))
    session_count = home_count + ext_count

    return jsonify({
        "home_vs_ext": {"Zuhause": home_count, "Extern": ext_count},
        "ac_dc": {"AC": ac_count, "DC": dc_count},
        "operators": operators_sorted,
        "totals": {
            "kwh": round(total_kwh, 1),
            "cost": round(total_cost, 2),
            "avg_cost_kwh": round(total_cost / total_kwh, 4) if total_kwh else 0,
            "avg_duration_min": round(total_dur / session_count, 0) if session_count else 0,
            "sessions": session_count,
        },
        "monthly_kwh_home": monthly_kwh_home,
        "monthly_kwh_ext": monthly_kwh_ext,
        "monthly_cost": monthly_cost,
        "avg_kw_ac": sorted(avg_kw_ac),
        "avg_kw_dc": sorted(avg_kw_dc),
    })


@app.route("/api/battery-history")
def battery_history():
    """Range at 100% SoC and capacity over time from InfluxDB."""
    device = active_device()
    date_from = request.args.get("from", "") or session.get("date_from", "")
    date_to = request.args.get("to", "") or session.get("date_to", "")

    # Time range for Flux
    if date_from and date_to:
        start = f"{date_from}T00:00:00Z"
        stop = f"{date_to}T23:59:59Z"
        range_clause = f'|> range(start: {start}, stop: {stop})'
    else:
        range_clause = '|> range(start: -365d)'

    # Estimated range from trips: capacity / consumption * 100
    db = get_db()
    bat_kwh = get_bat_kwh(db, device)
    trip_rows = db.execute(
        """SELECT start_time, consumption FROM trips
           WHERE device = ? AND consumption IS NOT NULL AND consumption > 0
             AND distance_km >= 20
           ORDER BY start_time""",
        (device,)
    ).fetchall()
    db.close()

    range_data = []
    for tr in trip_rows:
        d = tr["start_time"][:10]
        if date_from and d < date_from:
            continue
        if date_to and d > date_to:
            continue
        est = round(bat_kwh / tr["consumption"] * 100, 1)
        range_data.append({"date": d, "value": est})

    cap_data = []
    client = detector.get_influx()
    if client:
        try:
            q_cap = f'''
            from(bucket: "{config.INFLUX_BUCKET}")
              {range_clause}
              |> filter(fn: (r) => r._measurement == "v" and r.d == "{device}" and r._field == "ca")
              |> aggregateWindow(every: 1d, fn: mean, createEmpty: false)
            '''
            for table in client.query_api().query(q_cap, org=config.INFLUX_ORG):
                for rec in table.records:
                    v = rec.get_value()
                    if v is not None:
                        cap_data.append({
                            "date": rec.get_time().strftime("%Y-%m-%d"),
                            "value": round(v, 2)
                        })
        except Exception as e:
            log.warning("InfluxDB query failed in battery_history: %s", e)
        finally:
            client.close()

    # Nominal capacity for SoH calculation
    db = get_db()
    nominal = get_bat_kwh(db, device)
    db.close()

    return jsonify({
        "range": range_data,
        "capacity": cap_data,
        "nominal_kwh": nominal,
    })


@app.route("/api/between-charges")
def between_charges():
    """Energy consumption between charge sessions — grouped by charge segments."""
    device = active_device()
    date_from = request.args.get("from", "") or session.get("date_from", "")
    date_to = request.args.get("to", "") or session.get("date_to", "")

    db = get_db()

    # Last known capacity from InfluxDB (ca field), fallback to settings
    bat_kwh = None
    client = detector.get_influx()
    if client:
        try:
            q = f'''
            from(bucket: "{config.INFLUX_BUCKET}")
              |> range(start: -30d)
              |> filter(fn: (r) => r._measurement == "v" and r.d == "{device}" and r._field == "ca")
              |> group(columns: ["_field"])
              |> last()
            '''
            for table in client.query_api().query(q, org=config.INFLUX_ORG):
                for rec in table.records:
                    v = rec.get_value()
                    if v and v > 0:
                        bat_kwh = round(v, 2)
        except Exception as e:
            log.warning("InfluxDB ca query failed in between_charges: %s", e)
        finally:
            client.close()

    if not bat_kwh:
        bat_kwh = get_bat_kwh(db, device)

    # Trips with SoC for this device
    tq = """SELECT start_time, end_time, energy_kwh, soc_start, soc_end, distance_km
            FROM trips WHERE device = ?"""
    tp = [device]
    if date_from and date_to:
        tq += " AND start_time >= ? AND start_time <= ?"
        tp += [date_from, date_to + "T23:59:59"]
    tq += " ORDER BY start_time"
    trip_rows = db.execute(tq, tp).fetchall()
    db.close()

    # Detect segments from SoC jumps between trips
    # If soc_start of next trip > soc_end of previous + 5% → charge session in between
    SOC_JUMP = 5.0
    segments = []
    current_seg = []

    for i, t in enumerate(trip_rows):
        current_seg.append(t)
        if i + 1 < len(trip_rows):
            next_t = trip_rows[i + 1]
            soc_end_cur = t["soc_end"]
            soc_start_next = next_t["soc_start"]
            if (soc_end_cur is not None and soc_start_next is not None
                    and soc_start_next > soc_end_cur + SOC_JUMP):
                # Charge detected — close segment
                seg_kwh = 0.0
                seg_dist = 0.0
                for tr in current_seg:
                    if tr["energy_kwh"] is not None:
                        seg_kwh += tr["energy_kwh"]
                    elif tr["soc_start"] is not None and tr["soc_end"] is not None and tr["soc_start"] > tr["soc_end"]:
                        seg_kwh += (tr["soc_start"] - tr["soc_end"]) / 100.0 * bat_kwh
                    if tr["distance_km"]:
                        seg_dist += tr["distance_km"]
                if seg_kwh > 0 or seg_dist > 0:
                    segments.append({
                        "label": current_seg[0]["start_time"][:10],
                        "kwh": round(seg_kwh, 2),
                        "pct": round(seg_kwh / bat_kwh * 100, 1) if bat_kwh else None,
                        "km": round(seg_dist, 1),
                        "trip_count": len(current_seg),
                        "charged_pct": round(soc_start_next - soc_end_cur, 1),
                    })
                current_seg = []

    # Last open segment (no new charge yet)
    if current_seg:
        seg_kwh = 0.0
        seg_dist = 0.0
        for tr in current_seg:
            if tr["energy_kwh"] is not None:
                seg_kwh += tr["energy_kwh"]
            elif tr["soc_start"] is not None and tr["soc_end"] is not None and tr["soc_start"] > tr["soc_end"]:
                seg_kwh += (tr["soc_start"] - tr["soc_end"]) / 100.0 * bat_kwh
            if tr["distance_km"]:
                seg_dist += tr["distance_km"]
        if seg_kwh > 0 or seg_dist > 0:
            segments.append({
                "label": current_seg[0]["start_time"][:10],
                "kwh": round(seg_kwh, 2),
                "pct": round(seg_kwh / bat_kwh * 100, 1) if bat_kwh else None,
                "km": round(seg_dist, 1),
                "trip_count": len(current_seg),
                "charged_pct": None,
            })

    return jsonify({"segments": segments, "bat_kwh": bat_kwh})


@app.route("/api/efficiency-data")
def efficiency_data():
    """Outside temperature (daily avg) and electricity tariffs for efficiency charts."""
    device = active_device()
    date_from = request.args.get("from", "") or session.get("date_from", "")
    date_to = request.args.get("to", "") or session.get("date_to", "")

    # Time range for Flux
    if date_from and date_to:
        start = f"{date_from}T00:00:00Z"
        stop = f"{date_to}T23:59:59Z"
        range_clause = f'|> range(start: {start}, stop: {stop})'
    else:
        range_clause = '|> range(start: -365d)'

    # Daily average temperature from InfluxDB
    temp_data = []
    client = detector.get_influx()
    if client:
        try:
            q_temp = f'''
            from(bucket: "{config.INFLUX_BUCKET}")
              {range_clause}
              |> filter(fn: (r) => r._measurement == "v" and r.d == "{device}" and r._field == "et")
              |> aggregateWindow(every: 1d, fn: mean, createEmpty: false)
            '''
            for table in client.query_api().query(q_temp, org=config.INFLUX_ORG):
                for rec in table.records:
                    v = rec.get_value()
                    if v is not None:
                        temp_data.append({
                            "date": rec.get_time().strftime("%Y-%m-%d"),
                            "value": round(v, 1)
                        })
        except Exception as e:
            log.warning("InfluxDB query failed in efficiency_data: %s", e)
        finally:
            client.close()

    # Electricity tariffs
    db = get_db()
    tariff_rows = db.execute(
        "SELECT valid_from, pauschale_kwh FROM charge_tariffs ORDER BY valid_from"
    ).fetchall()
    db.close()

    tariffs = [{"valid_from": t["valid_from"], "eur_kwh": t["pauschale_kwh"]} for t in tariff_rows]

    return jsonify({
        "temperatures": {d["date"]: d["value"] for d in temp_data},
        "tariffs": tariffs,
    })


# ── Trip log constants ────────────────────────────────────────

@app.route("/api/fahrtenbuch/options")
def fahrtenbuch_options():
    """All selection options for the trip log."""
    db = get_db()
    locations = db.execute("SELECT * FROM locations ORDER BY name").fetchall()
    pmeta = get_purpose_meta(db)
    db.close()
    return jsonify({
        "purposes": [p["name"] for p in pmeta],
        "purpose_meta": pmeta,
        "visit_reasons": [],
        "private_purposes": [p["name"] for p in pmeta if p["is_private"]],
        "locations": [dict(r) for r in locations],
    })


# ── Edit trip ────────────────────────────────────────────────

@app.route("/api/trips/<int:trip_id>", methods=["POST"])
def update_trip(trip_id):
    data = request.get_json()
    db = get_db()

    allowed = ("purpose", "destination", "visit_reason", "note")
    sets = []
    params = []
    for field in allowed:
        if field in data:
            sets.append(f"{field} = ?")
            params.append(data[field])

    if not sets:
        return jsonify({"error": "Keine Felder"}), 400

    params.append(trip_id)
    db.execute(f"UPDATE trips SET {', '.join(sets)} WHERE id = ?", params)
    db.commit()
    db.close()
    return jsonify({"ok": True, "id": trip_id})


# ── Batch: tag multiple trips at once ─────────────────────────

@app.route("/api/trips/batch", methods=["POST"])
def batch_update():
    data = request.get_json()
    ids = data.get("ids", [])
    if not ids:
        return jsonify({"error": "Keine Fahrten"}), 400

    db = get_db()
    allowed = ("purpose", "destination", "visit_reason")
    sets = []
    params_base = []
    for field in allowed:
        if field in data:
            sets.append(f"{field} = ?")
            params_base.append(data[field])

    if not sets:
        return jsonify({"error": "Keine Felder"}), 400

    for trip_id in ids:
        db.execute(f"UPDATE trips SET {', '.join(sets)} WHERE id = ?", params_base + [trip_id])
    db.commit()
    db.close()
    return jsonify({"ok": True, "count": len(ids)})


# ── Re-tag trip (destination from end coordinates) ───────────

@app.route("/api/trips/<int:trip_id>/retag", methods=["POST"])
@login_required
def retag_trip(trip_id):
    """Re-detect destination/purpose from end coordinates."""
    db = get_db()
    trip = db.execute("SELECT * FROM trips WHERE id = ?", (trip_id,)).fetchone()
    if not trip:
        return jsonify({"error": "Fahrt nicht gefunden"}), 404
    start_loc = detector.match_location(db, trip["start_lat"], trip["start_lon"])
    end_loc = detector.match_location(db, trip["end_lat"], trip["end_lon"])
    rule = detector.match_route_rule(db, start_loc, end_loc)
    if rule:
        dest = rule.get("destination") or (end_loc["name"] if end_loc else "")
        purp = rule["purpose"]
        vr = rule.get("visit_reason") or ""
    elif end_loc:
        dest = end_loc["name"]
        purp = ""
        vr = end_loc["default_reason"] or "" if end_loc["default_reason"] else ""
    else:
        dest = ""
        purp = ""
        vr = ""
    db.execute(
        "UPDATE trips SET destination = ?, purpose = ?, visit_reason = ? WHERE id = ?",
        (dest, purp, vr, trip_id),
    )
    db.commit()
    db.close()
    return jsonify({"ok": True, "destination": dest, "purpose": purp, "visit_reason": vr})


# ── Merge trips ──────────────────────────────────────────────

@app.route("/api/trips/merge", methods=["POST"])
@login_required
def merge_trips():
    data = request.get_json()
    ids = data.get("ids", [])
    if len(ids) != 2:
        return jsonify({"error": "Genau 2 Fahrten erforderlich"}), 400

    db = get_db()
    rows = [db.execute("SELECT * FROM trips WHERE id = ?", (i,)).fetchone() for i in ids]
    if any(r is None for r in rows):
        db.close()
        return jsonify({"error": "Fahrt nicht gefunden"}), 404

    t = [dict(r) for r in rows]
    # Sort chronologically
    t.sort(key=lambda x: x["start_time"])
    a, b = t[0], t[1]

    if a["device"] != b["device"]:
        db.close()
        return jsonify({"error": "Fahrten gehören zu verschiedenen Fahrzeugen"}), 400

    # Distance: prefer odometer difference, otherwise sum
    dist = None
    if a.get("odo_start") is not None and b.get("odo_end") is not None:
        dist = round(b["odo_end"] - a["odo_start"], 1)
    elif a.get("distance_km") is not None and b.get("distance_km") is not None:
        dist = round(a["distance_km"] + b["distance_km"], 1)
    # Energy: prefer SoC difference of total distance
    energy = None
    soc_s = a.get("soc_start")
    soc_e = b.get("soc_end")
    if soc_s and soc_e and soc_s > soc_e:
        # Get battery capacity from settings
        db_v = db.execute(
            "SELECT battery_capacity_kwh FROM vehicles WHERE device = ? AND battery_capacity_kwh IS NOT NULL",
            (a["device"],)
        ).fetchone()
        if not db_v:
            db_v = db.execute("SELECT value FROM settings WHERE key = 'battery_capacity_kwh'").fetchone()
            bat_kwh = float(db_v["value"]) if db_v else 86.5
        else:
            bat_kwh = float(db_v["battery_capacity_kwh"])
        energy = round((soc_s - soc_e) / 100.0 * bat_kwh, 2)
    elif a.get("energy_kwh") is not None and b.get("energy_kwh") is not None:
        energy = round(a["energy_kwh"] + b["energy_kwh"], 2)
    consumption = None
    if energy and dist and dist >= 1:
        consumption = round(energy / dist * 100, 1)

    merged = {
        "device":       a["device"],
        "start_time":   a["start_time"],
        "end_time":     b["end_time"],
        "start_lat":    a["start_lat"],
        "start_lon":    a["start_lon"],
        "end_lat":      b["end_lat"],
        "end_lon":      b["end_lon"],
        "odo_start":    a.get("odo_start"),
        "odo_end":      b.get("odo_end"),
        "distance_km":  dist,
        "soc_start":    a.get("soc_start"),
        "soc_end":      b.get("soc_end"),
        "energy_kwh":   energy,
        "consumption":  consumption,
        "purpose":      b.get("purpose") or a.get("purpose") or "",
        "destination":  b.get("destination") or a.get("destination") or "",
        "visit_reason": b.get("visit_reason") or a.get("visit_reason") or "",
    }

    db.execute("DELETE FROM gpx_waypoints WHERE trip_id IN (?, ?)", (a["id"], b["id"]))
    db.execute("DELETE FROM journey_trips WHERE trip_id IN (?, ?)", (a["id"], b["id"]))
    db.execute("DELETE FROM trips WHERE id IN (?, ?)", (a["id"], b["id"]))
    cur = db.execute(
        """INSERT INTO trips
           (device, start_time, end_time, start_lat, start_lon, end_lat, end_lon,
            odo_start, odo_end, distance_km, soc_start, soc_end, energy_kwh, consumption,
            purpose, destination, visit_reason)
           VALUES (:device, :start_time, :end_time, :start_lat, :start_lon, :end_lat, :end_lon,
                   :odo_start, :odo_end, :distance_km, :soc_start, :soc_end,
                   :energy_kwh, :consumption, :purpose, :destination, :visit_reason)""",
        merged,
    )
    db.commit()
    new_id = cur.lastrowid
    db.close()
    return jsonify({"ok": True, "id": new_id})


# ── Locations (geofencing) ────────────────────────────────────

@app.route("/api/locations")
def list_locations():
    db = get_db()
    rows = db.execute("SELECT * FROM locations ORDER BY name").fetchall()
    db.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/locations", methods=["POST"])
def create_location():
    data = request.get_json()
    name = data.get("name", "").strip()
    lat = data.get("lat")
    lon = data.get("lon")
    if not name or lat is None or lon is None:
        return jsonify({"error": "name, lat, lon erforderlich"}), 400

    db = get_db()
    cur = db.execute(
        """INSERT INTO locations (name, lat, lon, radius_m, category, default_reason, icon, color, icon_color)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (name, lat, lon,
         data.get("radius_m", 200),
         data.get("category", "kunde"),
         data.get("default_reason", ""),
         data.get("icon", "pin"),
         data.get("color", "#21262d"),
         data.get("icon_color", "white")),
    )
    db.commit()
    loc_id = cur.lastrowid
    db.close()
    return jsonify({"ok": True, "id": loc_id})


@app.route("/api/locations/<int:loc_id>", methods=["POST"])
def update_location(loc_id):
    data = request.get_json()
    db = get_db()
    allowed = ("name", "lat", "lon", "radius_m", "category", "default_reason", "icon", "color", "icon_color")
    sets = []
    params = []
    for field in allowed:
        if field in data:
            sets.append(f"{field} = ?")
            params.append(data[field])
    if not sets:
        return jsonify({"error": "Keine Felder"}), 400
    params.append(loc_id)
    db.execute(f"UPDATE locations SET {', '.join(sets)} WHERE id = ?", params)
    db.commit()
    db.close()
    return jsonify({"ok": True, "id": loc_id})


@app.route("/api/locations/<int:loc_id>", methods=["DELETE"])
def delete_location(loc_id):
    db = get_db()
    db.execute("DELETE FROM locations WHERE id = ?", (loc_id,))
    db.commit()
    db.close()
    return jsonify({"ok": True})


# ── Route rules ──────────────────────────────────────────────

@app.route("/api/route-rules")
def list_route_rules():
    db = get_db()
    rows = db.execute(
        """SELECT r.*, lf.name AS from_name, lt.name AS to_name
           FROM route_rules r
           LEFT JOIN locations lf ON r.from_location_id = lf.id
           LEFT JOIN locations lt ON r.to_location_id = lt.id
           ORDER BY lf.name, lt.name"""
    ).fetchall()
    db.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/route-rules", methods=["POST"])
@admin_required
def create_route_rule():
    data = request.get_json()
    from_id = data.get("from_location_id") or None
    to_id = data.get("to_location_id") or None
    purpose = data.get("purpose", "").strip()
    if not from_id and not to_id:
        return jsonify({"error": "Mindestens Von oder Nach erforderlich"}), 400
    if not purpose:
        return jsonify({"error": "Fahrtzweck erforderlich"}), 400

    db = get_db()
    try:
        db.execute(
            """INSERT INTO route_rules (from_location_id, to_location_id, purpose, destination, visit_reason)
               VALUES (?, ?, ?, ?, ?)""",
            (from_id, to_id, purpose,
             data.get("destination", "").strip() or None,
             data.get("visit_reason", "").strip() or None),
        )
        db.commit()
    except db.IntegrityError:
        db.close()
        return jsonify({"error": "Regel für diese Route existiert bereits"}), 409
    db.close()
    return jsonify({"ok": True})


@app.route("/api/route-rules/<int:rule_id>", methods=["DELETE"])
@admin_required
def delete_route_rule(rule_id):
    db = get_db()
    db.execute("DELETE FROM route_rules WHERE id = ?", (rule_id,))
    db.commit()
    db.close()
    return jsonify({"ok": True})


@app.route("/api/locations/match")
def match_location_api():
    """Find saved location for GPS coordinates."""
    lat = request.args.get("lat", type=float)
    lon = request.args.get("lon", type=float)
    if lat is None or lon is None:
        return jsonify(None)
    db = get_db()
    loc = match_location(db, lat, lon)
    db.close()
    return jsonify(dict(loc) if loc else None)


# ── Administration (Admin) ────────────────────────────────────

@app.route("/admin")
def admin_page():
    prefill_lat = request.args.get("lat", "")
    prefill_lon = request.args.get("lon", "")
    prefill_tab = request.args.get("tab", "")
    prefill_name = request.args.get("name", "")
    db = get_db()
    vehicles = db.execute("SELECT * FROM vehicles ORDER BY id").fetchall()
    tariffs = db.execute("SELECT * FROM charge_tariffs ORDER BY valid_from DESC").fetchall()
    start_row = db.execute("SELECT value FROM settings WHERE key = 'charge_session_start'").fetchone()
    session_start = int(start_row['value']) if start_row else 1
    db.close()
    return render_template("admin.html",
                           prefill_lat=prefill_lat,
                           prefill_lon=prefill_lon,
                           prefill_tab=prefill_tab,
                           prefill_name=prefill_name,
                           vehicles=vehicles,
                           tariffs=tariffs,
                           session_start=session_start)


@app.route("/api/admin/values")
def admin_values():
    """All used values with counts for purposes, destinations, reasons."""
    db = get_db()

    purposes = db.execute(
        """SELECT purpose AS name, COUNT(*) AS count FROM trips
           WHERE purpose IS NOT NULL AND purpose != ''
           GROUP BY purpose ORDER BY purpose"""
    ).fetchall()

    destinations = db.execute(
        """SELECT destination AS name, COUNT(*) AS count FROM trips
           WHERE destination IS NOT NULL AND destination != ''
           GROUP BY destination ORDER BY destination"""
    ).fetchall()

    reasons = db.execute(
        """SELECT visit_reason AS name, COUNT(*) AS count FROM trips
           WHERE visit_reason IS NOT NULL AND visit_reason != ''
           GROUP BY visit_reason ORDER BY visit_reason"""
    ).fetchall()

    locations = db.execute(
        "SELECT * FROM locations ORDER BY name"
    ).fetchall()

    # Visit count per location (by geofence match on end coordinates)
    loc_visits = {}
    trips_with_coords = db.execute(
        "SELECT end_lat, end_lon FROM trips WHERE end_lat IS NOT NULL AND end_lon IS NOT NULL AND device = ?",
        (active_device(),),
    ).fetchall()
    for loc in locations:
        count = 0
        for t in trips_with_coords:
            if haversine_m(t["end_lat"], t["end_lon"], loc["lat"], loc["lon"]) <= loc["radius_m"]:
                count += 1
        loc_visits[loc["id"]] = count

    # Preset values (pre-saved suggestions)
    presets_dest = db.execute(
        "SELECT value AS name FROM preset_values WHERE field = 'destination' ORDER BY value"
    ).fetchall()
    presets_reason = db.execute(
        "SELECT value AS name FROM preset_values WHERE field = 'visit_reason' ORDER BY value"
    ).fetchall()

    # Merge presets into used values (deduplicated)
    dest_names = {d["name"] for d in destinations}
    for p in presets_dest:
        if p["name"] not in dest_names:
            destinations.append({"name": p["name"], "count": 0})

    reason_names = {r["name"] for r in reasons}
    for p in presets_reason:
        if p["name"] not in reason_names:
            reasons.append({"name": p["name"], "count": 0})

    pmeta = get_purpose_meta(db)
    db.close()
    return jsonify({
        "purposes": [dict(r) if isinstance(r, sqlite3.Row) else r for r in purposes],
        "destinations": [dict(r) if isinstance(r, sqlite3.Row) else r for r in destinations],
        "visit_reasons": [dict(r) if isinstance(r, sqlite3.Row) else r for r in reasons],
        "locations": [dict(r) for r in locations],
        "location_visits": loc_visits,
        "purpose_meta": pmeta,
        "default_visit_reasons": [],
    })


@app.route("/api/settings")
def get_settings():
    """All settings as key-value object (sensitive fields decrypted)."""
    db = get_db()
    rows = db.execute("SELECT key, value FROM settings").fetchall()
    db.close()
    f = _settings_fernet()
    result = {}
    for r in rows:
        v = r["value"]
        if r["key"] in ENCRYPTED_SETTINGS:
            v = _decrypt_setting(f, v)
        result[r["key"]] = v
    return jsonify(result)


@app.route("/api/settings", methods=["POST"])
def save_settings():
    """Save settings — sensitive fields are stored encrypted."""
    data = request.get_json()
    db = get_db()
    f = _settings_fernet()
    for key, value in data.items():
        v = str(value)
        if key in ENCRYPTED_SETTINGS:
            v = _encrypt_setting(f, v)
        db.execute(
            "INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = ?",
            (key, v, v),
        )
    db.commit()
    db.close()
    return jsonify({"ok": True})



@app.route("/api/trips/<int:trip_id>/clear-address", methods=["POST"])
def clear_trip_address(trip_id):
    """Clear address(es) of a single trip."""
    data = request.get_json() or {}
    which = data.get("which", "both")  # 'start', 'end', 'both'
    db = get_db()
    if which == "start":
        db.execute("UPDATE trips SET start_address = NULL WHERE id = ?", (trip_id,))
    elif which == "end":
        db.execute("UPDATE trips SET end_address = NULL WHERE id = ?", (trip_id,))
    else:
        db.execute("UPDATE trips SET start_address = NULL, end_address = NULL WHERE id = ?", (trip_id,))
    db.commit()
    db.close()
    return jsonify({"ok": True})


@app.route("/api/geocode-missing", methods=["POST"])
def geocode_missing():
    """Geocode missing addresses in the background."""
    import threading
    def _geocode():
        import geocoder as geo
        geo.run_once()
    threading.Thread(target=_geocode, daemon=True).start()
    return jsonify({"ok": True})


@app.route("/api/purpose-meta", methods=["POST"])
def update_purpose_meta():
    """Create or update trip purpose (color, is_private)."""
    data = request.get_json()
    name = data.get("name", "").strip()
    if not name:
        return jsonify({"error": "Name erforderlich"}), 400

    db = get_db()
    is_main = int(data.get("is_main", 0))
    if is_main:
        db.execute("UPDATE purpose_meta SET is_main = 0")
    db.execute(
        """INSERT INTO purpose_meta (name, color, is_private, is_main, sort_order)
           VALUES (?, ?, ?, ?, (SELECT COALESCE(MAX(sort_order),0)+1 FROM purpose_meta))
           ON CONFLICT(name) DO UPDATE SET color = ?, is_private = ?, is_main = ?""",
        (name, data.get("color", "#8b949e"), int(data.get("is_private", 0)), is_main,
         data.get("color", "#8b949e"), int(data.get("is_private", 0)), is_main),
    )
    db.commit()
    db.close()
    return jsonify({"ok": True})


@app.route("/api/preset-values", methods=["POST"])
@admin_required
def add_preset_value():
    """Save new preset value (destination or visit_reason)."""
    data = request.get_json()
    field = data.get("field", "").strip()
    value = data.get("value", "").strip()
    if field not in ("destination", "visit_reason") or not value:
        return jsonify({"error": "field und value erforderlich"}), 400

    db = get_db()
    db.execute(
        "INSERT OR IGNORE INTO preset_values (field, value) VALUES (?, ?)",
        (field, value),
    )
    db.commit()
    db.close()
    return jsonify({"ok": True})


@app.route("/api/admin/rename", methods=["POST"])
def admin_rename():
    """Rename a value in all trips."""
    data = request.get_json()
    field = data.get("field")
    old_name = data.get("old_name", "").strip()
    new_name = data.get("new_name", "").strip()

    if field not in ("purpose", "destination", "visit_reason"):
        return jsonify({"error": "Ungültiges Feld"}), 400
    if not old_name or not new_name:
        return jsonify({"error": "Name darf nicht leer sein"}), 400

    db = get_db()
    cur = db.execute(
        f"UPDATE trips SET {field} = ? WHERE {field} = ?",
        (new_name, old_name)
    )
    # Also update related tables
    if field == "destination":
        db.execute("UPDATE locations SET name = ? WHERE name = ?", (new_name, old_name))
    elif field == "purpose":
        db.execute("UPDATE purpose_meta SET name = ? WHERE name = ?", (new_name, old_name))
        db.execute("UPDATE route_rules SET purpose = ? WHERE purpose = ?", (new_name, old_name))
    if field in ("destination", "visit_reason"):
        db.execute("UPDATE preset_values SET value = ? WHERE field = ? AND value = ?",
                    (new_name, field, old_name))
    db.commit()
    count = cur.rowcount
    db.close()
    return jsonify({"ok": True, "updated": count})


@app.route("/api/admin/merge", methods=["POST"])
def admin_merge():
    """Merge two values (source → target)."""
    data = request.get_json()
    field = data.get("field")
    source = data.get("source", "").strip()
    target = data.get("target", "").strip()

    if field not in ("purpose", "destination", "visit_reason"):
        return jsonify({"error": "Ungültiges Feld"}), 400
    if not source or not target:
        return jsonify({"error": "Beide Namen erforderlich"}), 400

    db = get_db()
    cur = db.execute(
        f"UPDATE trips SET {field} = ? WHERE {field} = ?",
        (target, source)
    )
    if field == "destination":
        db.execute("DELETE FROM locations WHERE name = ?", (source,))
    elif field == "purpose":
        db.execute("DELETE FROM purpose_meta WHERE name = ?", (source,))
        db.execute("UPDATE route_rules SET purpose = ? WHERE purpose = ?", (target, source))
    if field in ("destination", "visit_reason"):
        db.execute("DELETE FROM preset_values WHERE field = ? AND value = ?", (field, source))
    db.commit()
    count = cur.rowcount
    db.close()
    return jsonify({"ok": True, "merged": count})


@app.route("/api/admin/delete-value", methods=["POST"])
def admin_delete_value():
    """Delete a value from all trips (set to empty)."""
    data = request.get_json()
    field = data.get("field")
    name = data.get("name", "").strip()
    confirm = data.get("confirm", "").strip()

    if field not in ("purpose", "destination", "visit_reason"):
        return jsonify({"error": "Ungültiges Feld"}), 400
    if not name:
        return jsonify({"error": "Name erforderlich"}), 400
    if confirm != name:
        return jsonify({"error": "Bestätigung stimmt nicht überein"}), 400

    db = get_db()
    cur = db.execute(
        f"UPDATE trips SET {field} = '' WHERE {field} = ?",
        (name,)
    )
    if field == "destination":
        db.execute("DELETE FROM locations WHERE name = ?", (name,))
    elif field == "purpose":
        db.execute("DELETE FROM purpose_meta WHERE name = ?", (name,))
    if field in ("destination", "visit_reason"):
        db.execute("DELETE FROM preset_values WHERE field = ? AND value = ?", (field, name))
    db.commit()
    count = cur.rowcount
    db.close()
    return jsonify({"ok": True, "cleared": count})


# ── Delete single trip ───────────────────────────────────────

@app.route("/api/trips/<int:trip_id>", methods=["DELETE"])
@admin_required
def delete_trip(trip_id):
    db = get_db()
    db.execute("DELETE FROM gpx_waypoints WHERE trip_id = ?", (trip_id,))
    db.execute("DELETE FROM journey_trips WHERE trip_id = ?", (trip_id,))
    db.execute("DELETE FROM trips WHERE id = ? AND device = ?", (trip_id, active_device()))
    db.commit()
    db.close()
    return jsonify({"ok": True})


@app.route("/api/trips/delete-range", methods=["POST"])
@admin_required
def delete_trip_range():
    """Delete trips by ID range."""
    data = request.get_json()
    id_from = data.get("from")
    id_to = data.get("to")
    if id_from is None or id_to is None:
        return jsonify({"error": "from und to erforderlich"}), 400
    db = get_db()
    db.execute("DELETE FROM gpx_waypoints WHERE trip_id IN (SELECT id FROM trips WHERE id >= ? AND id <= ? AND device = ?)",
               (id_from, id_to, active_device()))
    db.execute("DELETE FROM journey_trips WHERE trip_id IN (SELECT id FROM trips WHERE id >= ? AND id <= ? AND device = ?)",
               (id_from, id_to, active_device()))
    cur = db.execute(
        "DELETE FROM trips WHERE id >= ? AND id <= ? AND device = ?",
        (id_from, id_to, active_device()),
    )
    deleted = cur.rowcount
    db.commit()
    db.close()
    return jsonify({"ok": True, "deleted": deleted})


@app.route("/api/charges/delete-range", methods=["POST"])
@admin_required
def delete_charge_range():
    """Delete charge readings by ID range and rebuild sessions."""
    data = request.get_json()
    id_from = data.get("from")
    id_to = data.get("to")
    if id_from is None or id_to is None:
        return jsonify({"error": "from und to erforderlich"}), 400
    db = get_db()
    cur = db.execute(
        "DELETE FROM charge_readings WHERE id >= ? AND id <= ?",
        (id_from, id_to),
    )
    deleted = cur.rowcount
    db.commit()
    rebuild_charge_sessions(db)
    db.close()
    return jsonify({"ok": True, "deleted": deleted})


# ── CSV-Import ──────────────────────────────────────────────

def _parse_coord(s):
    """'53,546541' or '53.546541' -> 53.546541 or None"""
    s = s.strip().strip('"')
    if not s:
        return None
    return float(s.replace(",", "."))


def _parse_num(s):
    """Parse number with comma or dot decimal, return None if empty."""
    s = s.strip().strip('"')
    if not s:
        return None
    return float(s.replace(",", "."))


def _parse_german_num(s):
    """Parse German number: dot=thousands, comma=decimal. '156.449' -> 156449, '0,1234' -> 0.1234."""
    if s is None:
        return None
    s = str(s).strip().strip('"')
    if not s or s == '-':
        return None
    # Remove unit suffixes like " kWh", " €", " %"
    import re
    s = re.sub(r'\s*[a-zA-Z€£$/%°]+$', '', s)
    if not s:
        return None
    # If both dot and comma present: dot=thousands, comma=decimal
    if ',' in s and '.' in s:
        s = s.replace('.', '').replace(',', '.')
    elif ',' in s:
        # Only comma: could be decimal separator
        # If comma separates 3+ digits at end -> thousands sep (rare for single comma)
        parts = s.split(',')
        if len(parts) == 2 and len(parts[1]) == 3 and len(parts[0]) > 0:
            s = s.replace(',', '')  # thousands separator
        else:
            s = s.replace(',', '.')  # decimal separator
    elif '.' in s:
        # Only dot: could be decimal or thousands separator
        # "156.449" (1 dot, exactly 3 digits after, non-zero integer part) -> thousands
        parts = s.split('.')
        if len(parts) == 2 and len(parts[1]) == 3 and len(parts[0]) > 0 and parts[0].lstrip('-') != '0':
            s = s.replace('.', '')  # thousands separator
    # else: no separator -> standard float
    try:
        return float(s)
    except ValueError:
        return None


@app.route("/api/import", methods=["POST"])
@admin_required
def import_csv_upload():
    """Import trips from CSV upload.

    Expected columns:
      created, Datum, Uhrzeit Start, Uhrzeit Ende,
      Start LAT, Start LON, Ende LAT, Ende LON,
      Start ODO, Ende ODO, Start SOC, Ende SOC, Aussen Temp
    """
    device = active_device()
    f = request.files.get("file")
    if not f:
        return jsonify({"error": "Keine Datei"}), 400

    text = f.read().decode("utf-8-sig")
    reader = csv.DictReader(io.StringIO(text))

    db = get_db()
    bat_kwh = get_bat_kwh(db, device)
    count = 0
    skipped = 0

    for row in reader:
        datum = row.get("Datum", "").strip()
        if not datum:
            continue

        # Parse date + time -> ISO 8601
        d, m, y = datum.split(".")
        start_h = row.get("Uhrzeit Start", "00:00").strip()
        end_h = row.get("Uhrzeit Ende", "00:00").strip()
        start_time = f"{y}-{m}-{d}T{start_h}:00"
        end_time = f"{y}-{m}-{d}T{end_h}:00"

        # Duplicate check
        existing = db.execute(
            "SELECT id FROM trips WHERE device = ? AND start_time = ?",
            (device, start_time),
        ).fetchone()
        if existing:
            skipped += 1
            continue

        # Coordinates
        start_lat = _parse_coord(row.get("Start LAT", ""))
        start_lon = _parse_coord(row.get("Start LON", ""))
        end_lat = _parse_coord(row.get("Ende LAT", ""))
        end_lon = _parse_coord(row.get("Ende LON", ""))

        # Distance from odometer
        odo_start = _parse_num(row.get("Start ODO", ""))
        odo_end = _parse_num(row.get("Ende ODO", ""))
        distance = round(odo_end - odo_start, 1) if odo_start is not None and odo_end is not None else None

        # SoC
        soc_start = _parse_num(row.get("Start SOC", ""))
        soc_end = _parse_num(row.get("Ende SOC", ""))

        # Estimate energy + consumption from SoC difference
        energy = None
        consumption = None
        if soc_start is not None and soc_end is not None and soc_start > soc_end:
            energy = round((soc_start - soc_end) / 100 * bat_kwh, 2)
            if distance and distance > 0:
                consumption = round(energy / distance * 100, 1)

        db.execute(
            """INSERT INTO trips
               (device, start_time, end_time,
                start_lat, start_lon, end_lat, end_lon,
                odo_start, odo_end,
                distance_km, soc_start, soc_end, energy_kwh, consumption)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (device, start_time, end_time,
             start_lat, start_lon, end_lat, end_lon,
             odo_start, odo_end,
             distance, soc_start, soc_end, energy, consumption),
        )
        count += 1

    db.commit()

    # Trigger geocoding directly (background thread)
    if count > 0:
        import threading
        def _geocode():
            import geocoder as geo
            gdb = get_db()
            geo.geocode_trips(gdb)
            gdb.close()
        threading.Thread(target=_geocode, daemon=True).start()

    db.close()
    return jsonify({"ok": True, "imported": count, "skipped": skipped})


# ── GPX-Import ──────────────────────────────────────────────

@app.route("/api/gpx-import", methods=["POST"])
@admin_required
def gpx_import():
    """Import GPX file (hikes, bike tours, etc.)."""
    import xml.etree.ElementTree as ET

    f = request.files.get("file")
    if not f:
        return jsonify({"error": "Keine Datei"}), 400
    vehicle_plate = request.form.get("vehicle", "").strip()
    if not vehicle_plate:
        return jsonify({"error": "Kein Fahrzeug ausgewählt"}), 400

    try:
        raw = f.read().decode("utf-8-sig")
        root = ET.fromstring(raw)
    except Exception as e:
        return jsonify({"error": f"GPX-Parsing fehlgeschlagen: {e}"}), 400

    ns = {"g": "http://www.topografix.com/GPX/1/1"}
    # Fallback for files without namespace
    if root.tag == "gpx":
        ns = {"g": ""}

    def _find(el, tag):
        """Find child element with or without namespace."""
        r = el.find(f"g:{tag}", ns)
        if r is None:
            r = el.find(tag)
        return r

    def _findall(el, tag):
        r = el.findall(f"g:{tag}", ns)
        if not r:
            r = el.findall(tag)
        return r

    db = get_db()
    veh = db.execute("SELECT device, name FROM vehicles WHERE plate = ?",
                     (vehicle_plate,)).fetchone()
    if veh and veh["device"]:
        device = veh["device"]
    elif veh and veh["name"]:
        # Vehicle name as device (DB-compatible: lowercase, no special characters)
        import re
        device = re.sub(r"[^a-z0-9]+", "_", veh["name"].lower()).strip("_")
        db.execute("UPDATE vehicles SET device = ? WHERE plate = ?", (device, vehicle_plate))
    else:
        device = "gpx"

    imported = 0
    for trk in _findall(root, "trk"):
        # Collect all points across segments
        waypoints = []
        for seg in _findall(trk, "trkseg"):
            for pt in _findall(seg, "trkpt"):
                lat = float(pt.get("lat"))
                lon = float(pt.get("lon"))
                ts_el = _find(pt, "time")
                ele_el = _find(pt, "ele")
                spd_el = _find(pt, "speed")
                # Extensions speed (Garmin etc.)
                if spd_el is None:
                    ext = _find(pt, "extensions")
                    if ext is not None:
                        spd_el = ext.find(".//{*}speed")
                wp = {
                    "lat": lat, "lon": lon,
                    "ts": ts_el.text.strip() if ts_el is not None else None,
                    "ele": float(ele_el.text) if ele_el is not None else None,
                    "speed": float(spd_el.text) if spd_el is not None else None,
                }
                waypoints.append(wp)

        if len(waypoints) < 2:
            continue

        first, last = waypoints[0], waypoints[-1]
        start_time = first["ts"] or "1970-01-01T00:00:00"
        end_time = last["ts"] or start_time

        # Clean ISO timestamps (remove trailing Z for consistency)
        start_time = start_time.replace("Z", "")
        end_time = end_time.replace("Z", "")

        # Duplicate check
        dup = db.execute(
            "SELECT id FROM trips WHERE device = ? AND start_time = ? AND is_gpx = 1",
            (device, start_time)
        ).fetchone()
        if dup:
            continue

        # Calculate distance from waypoints (haversine sum)
        total_dist = 0
        for i in range(1, len(waypoints)):
            total_dist += haversine_m(
                waypoints[i-1]["lat"], waypoints[i-1]["lon"],
                waypoints[i]["lat"], waypoints[i]["lon"]
            )
        dist_km = round(total_dist / 1000, 2)

        # Track name
        name_el = _find(trk, "name")
        note = name_el.text.strip() if name_el is not None else None

        cur = db.execute(
            """INSERT INTO trips
               (device, start_time, end_time, start_lat, start_lon,
                end_lat, end_lon, distance_km, note, is_gpx)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)""",
            (device, start_time, end_time,
             first["lat"], first["lon"], last["lat"], last["lon"],
             dist_km, note)
        )
        trip_id = cur.lastrowid

        # Insert waypoints
        for seq, wp in enumerate(waypoints):
            db.execute(
                """INSERT INTO gpx_waypoints (trip_id, lat, lon, timestamp, elevation, speed, seq)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (trip_id, wp["lat"], wp["lon"], wp["ts"], wp["ele"], wp["speed"], seq)
            )
        imported += 1

    db.commit()

    # Geocode start/end addresses
    if imported > 0:
        def _geocode():
            gdb = get_db()
            geo.geocode_trips(gdb)
            gdb.close()
        threading.Thread(target=_geocode, daemon=True).start()

    db.close()
    return jsonify({"ok": True, "imported": imported})


# ── CSV-Export ───────────────────────────────────────────────

@app.route("/export/csv")
def export_csv():
    date_from = request.args.get("from", "")
    date_to = request.args.get("to", "")

    db = get_db()
    query = "SELECT * FROM trips WHERE device = ?"
    params = [active_device()]

    if date_from and date_to:
        query += " AND start_time >= ? AND start_time <= ?"
        params += [date_from, date_to + "T23:59:59"]

    query += " ORDER BY start_time"
    trips = db.execute(query, params).fetchall()
    db.close()

    def _dec(v):
        """Number → German decimal comma for Excel."""
        if v is None or v == "":
            return ""
        return str(v).replace(".", ",")

    output = io.StringIO()
    writer = csv.writer(output, delimiter=";")
    writer.writerow([
        "Datum", "Startzeit", "Endzeit",
        "Start-Adresse", "Ziel-Adresse",
        "Strecke (km)", "SoC Start (%)", "SoC Ende (%)",
        "Verbrauch (kWh)", "kWh/100km",
        "Fahrtzweck", "Fahrziel", "Besuchsgrund", "Bemerkung",
    ])
    for t in trips:
        start = t["start_time"][:10] if t["start_time"] else ""
        stime = t["start_time"][11:16] if t["start_time"] else ""
        etime = t["end_time"][11:16] if t["end_time"] else ""
        writer.writerow([
            start, stime, etime,
            t["start_address"] or "", t["end_address"] or "",
            _dec(t["distance_km"]), _dec(t["soc_start"]), _dec(t["soc_end"]),
            _dec(t["energy_kwh"]), _dec(t["consumption"]),
            t["purpose"] or "Privatfahrt", t["destination"] or "",
            t["visit_reason"] or "", t["note"] or "",
        ])

    label = f"{date_from}_{date_to}" if date_from else "alle"
    filename = f"fahrtenlog_{label}.csv"
    # UTF-8 BOM so Excel correctly recognizes umlauts
    bom = b"\xef\xbb\xbf"
    return Response(
        bom + output.getvalue().encode("utf-8"),
        mimetype="text/csv; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


# ── GPX-Export ────────────────────────────────────────────────

GPX_MAX_DAYS = 90

@app.route("/export/gpx")
def export_gpx():
    date_from = request.args.get("from", "")
    date_to = request.args.get("to", "")

    if not date_from or not date_to:
        return jsonify({"error": "Zeitraum (from/to) erforderlich"}), 400

    from datetime import datetime, timedelta
    d_from = datetime.fromisoformat(date_from)
    d_to = datetime.fromisoformat(date_to)
    if (d_to - d_from).days > GPX_MAX_DAYS:
        return jsonify({"error": f"GPX-Export max. {GPX_MAX_DAYS} Tage"}), 400

    device = active_device()
    client = detector.get_influx()
    points = []
    if not client:
        return jsonify({"error": "InfluxDB nicht konfiguriert"}), 503
    try:
        query = f'''
        from(bucket: "{config.INFLUX_BUCKET}")
          |> range(start: {date_from}T00:00:00Z, stop: {date_to}T23:59:59Z)
          |> filter(fn: (r) => r._measurement == "v" and r.d == "{device}")
          |> filter(fn: (r) => r._field == "la" or r._field == "lo" or r._field == "v" or r._field == "s")
          |> pivot(rowKey: ["_time"], columnKey: ["_field"], valueColumn: "_value")
          |> filter(fn: (r) => exists r.la and exists r.lo)
          |> sort(columns: ["_time"])
        '''
        tables = client.query_api().query(query, org=config.INFLUX_ORG)
        for table in tables:
            for record in table.records:
                points.append(record.values)
    except Exception as e:
        log.warning("InfluxDB query failed in GPX export: %s", e)
        return jsonify({"error": "InfluxDB-Abfrage fehlgeschlagen"}), 503
    finally:
        client.close()

    # Build GPX
    gpx_lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<gpx version="1.1" creator="ID·Mate"',
        '     xmlns="http://www.topografix.com/GPX/1/1">',
        f'  <metadata><name>ID·Mate {date_from} - {date_to}</name></metadata>',
        '  <trk>',
        f'    <name>ID·Mate {date_from} - {date_to}</name>',
        '    <trkseg>',
    ]
    for pt in points:
        la = pt.get("la")
        lo = pt.get("lo")
        t = pt.get("_time")
        if la and lo:
            time_str = t.isoformat() if t else ""
            line = f'      <trkpt lat="{la}" lon="{lo}">'
            if time_str:
                line += f'<time>{time_str}</time>'
            speed = pt.get("v")
            if speed is not None:
                line += f'<speed>{speed / 3.6:.1f}</speed>'
            line += '</trkpt>'
            gpx_lines.append(line)

    gpx_lines += ['    </trkseg>', '  </trk>', '</gpx>']

    filename = f"idmate_{date_from}_{date_to}.gpx"
    return Response(
        "\n".join(gpx_lines),
        mimetype="application/gpx+xml",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


# ── GPS route of a trip from InfluxDB ────────────────────────

@app.route("/api/trips/<int:trip_id>/route")
def trip_route(trip_id):
    """Load GPS points of a trip from InfluxDB + matched geofence locations."""
    db = get_db()
    trip = db.execute("SELECT * FROM trips WHERE id = ?", (trip_id,)).fetchone()
    if not trip:
        db.close()
        return jsonify({"points": [], "locations": []})

    # Geofence matches for start/end
    locs = []
    start_loc = match_location(db, trip["start_lat"], trip["start_lon"])
    end_loc = match_location(db, trip["end_lat"], trip["end_lon"])
    if start_loc:
        sk = start_loc.keys()
        locs.append({"lat": start_loc["lat"], "lon": start_loc["lon"],
                      "name": start_loc["name"], "icon": start_loc["icon"] or "pin",
                      "color": start_loc["color"] if "color" in sk else None,
                      "icon_color": start_loc["icon_color"] if "icon_color" in sk else None,
                      "pos": "start"})
    if end_loc:
        ek = end_loc.keys()
        locs.append({"lat": end_loc["lat"], "lon": end_loc["lon"],
                      "name": end_loc["name"], "icon": end_loc["icon"] or "pin",
                      "color": end_loc["color"] if "color" in ek else None,
                      "icon_color": end_loc["icon_color"] if "icon_color" in ek else None,
                      "pos": "end"})
    # GPX-imported trips: waypoints from SQLite instead of InfluxDB
    if trip["is_gpx"]:
        wps = db.execute(
            "SELECT lat, lon FROM gpx_waypoints WHERE trip_id = ? ORDER BY seq",
            (trip_id,)
        ).fetchall()
        db.close()
        points = [[round(w["lat"], 6), round(w["lon"], 6)] for w in wps]
        return jsonify({"points": points, "locations": locs})

    db.close()

    points = []
    client = detector.get_influx()
    if client:
        try:
            device = trip["device"] or active_device()

            query = f'''
            from(bucket: "{config.INFLUX_BUCKET}")
              |> range(start: {_to_rfc3339(trip["start_time"])}, stop: {_to_rfc3339_padded(trip["end_time"])})
              |> filter(fn: (r) => r._measurement == "v" and r.d == "{device}")
              |> filter(fn: (r) => r._field == "la" or r._field == "lo")
              |> pivot(rowKey: ["_time"], columnKey: ["_field"], valueColumn: "_value")
              |> sort(columns: ["_time"])
            '''
            tables = client.query_api().query(query, org=config.INFLUX_ORG)
            raw = []
            for table in tables:
                for rec in table.records:
                    raw.append(rec.values)
            raw.sort(key=lambda r: r.get("_time") or datetime.min.replace(tzinfo=timezone.utc))
            raw = detector._merge_rows(raw)
            # Filter GPS jumps
            raw = detector._filter_gps_jumps(raw)
            for rec in raw:
                lat = rec.get("la")
                lon = rec.get("lo")
                if lat and lon and lat != 0 and lon != 0:
                    points.append([round(lat, 6), round(lon, 6)])
        except Exception:
            log.exception("Error loading GPS route for trip %d", trip_id)
        finally:
            client.close()

    flux_start = _to_rfc3339(trip["start_time"])
    flux_stop = _to_rfc3339_padded(trip["end_time"])
    log.info("Route Trip %d: stored=%s→%s flux=%s→%s device=%s points=%d",
             trip_id, trip["start_time"], trip["end_time"],
             flux_start, flux_stop, trip["device"] or active_device(), len(points))

    return jsonify({"points": points, "locations": locs,
                    "_debug": {"stored_start": trip["start_time"], "stored_end": trip["end_time"],
                               "flux_start": flux_start, "flux_stop": flux_stop,
                               "device": trip["device"] or active_device(),
                               "points_count": len(points)}})


# ── Trip detail page ─────────────────────────────────────────

@app.route("/trips/<int:trip_id>")
def trip_detail(trip_id):
    db = get_db()
    trip = db.execute("SELECT * FROM trips WHERE id = ?", (trip_id,)).fetchone()
    if not trip:
        db.close()
        return redirect(url_for("trips_list"))

    start_loc = match_location(db, trip["start_lat"], trip["start_lon"])
    end_loc = match_location(db, trip["end_lat"], trip["end_lon"])
    db.close()
    return render_template("trip_detail.html", trip=dict(trip),
                           start_loc=dict(start_loc) if start_loc else None,
                           end_loc=dict(end_loc) if end_loc else None)


@app.route("/api/trips/<int:trip_id>/chart-data")
def trip_chart_data(trip_id):
    """Telemetry data of a trip from InfluxDB for Chart.js."""
    db = get_db()
    trip = db.execute("SELECT * FROM trips WHERE id = ?", (trip_id,)).fetchone()
    if not trip:
        db.close()
        return jsonify({"labels": [], "datasets": {}})
    db.close()

    data = {"labels": [], "speed": [], "power": [], "soc": [],
            "range": [], "bat_temp": [], "ext_temp": [], "elevation": [],
            "odometer": [], "lat": [], "lon": [], "lte": [], "carrier": [],
            "heading": []}
    client = detector.get_influx()
    if client:
        try:
            query = f'''
            from(bucket: "{config.INFLUX_BUCKET}")
              |> range(start: {_to_rfc3339(trip["start_time"])}, stop: {_to_rfc3339_padded(trip["end_time"])})
              |> filter(fn: (r) => r._measurement == "v" and r.d == "{trip["device"] or active_device()}")
              |> filter(fn: (r) => r._field == "v" or r._field == "p" or r._field == "s"
                                or r._field == "r" or r._field == "bt" or r._field == "et"
                                or r._field == "al" or r._field == "od"
                                or r._field == "la" or r._field == "lo"
                                or r._field == "ls" or r._field == "lp"
                                or r._field == "hd")
              |> pivot(rowKey: ["_time"], columnKey: ["_field"], valueColumn: "_value")
              |> sort(columns: ["_time"])
            '''
            tables = client.query_api().query(query, org=config.INFLUX_ORG)
            for table in tables:
                for rec in table.records:
                    t = rec.get_time()
                    if t:
                        from zoneinfo import ZoneInfo
                        t = t.astimezone(ZoneInfo("Europe/Berlin"))
                    data["labels"].append(t.strftime("%H:%M:%S") if t else "")
                    data["speed"].append(rec.values.get("v"))
                    data["power"].append(rec.values.get("p"))
                    data["soc"].append(rec.values.get("s"))
                    data["range"].append(rec.values.get("r"))
                    data["bat_temp"].append(rec.values.get("bt"))
                    data["ext_temp"].append(rec.values.get("et"))
                    data["elevation"].append(rec.values.get("al"))
                    data["odometer"].append(rec.values.get("od"))
                    data["lat"].append(rec.values.get("la"))
                    data["lon"].append(rec.values.get("lo"))
                    data["lte"].append(rec.values.get("ls"))
                    data["carrier"].append(_plmn_name(rec.values.get("lp")))
                    data["heading"].append(rec.values.get("hd"))
            # Python-side forward-fill for null values at the start
            for key in ("speed", "power", "soc", "range", "bat_temp", "ext_temp",
                        "elevation", "odometer", "lat", "lon", "lte", "carrier", "heading"):
                last = None
                for i, v in enumerate(data[key]):
                    if v is not None:
                        last = v
                    elif last is not None:
                        data[key][i] = last
        except Exception:
            log.exception("Error loading chart data for trip %d", trip_id)
        finally:
            client.close()

    return jsonify(data)


# ── Journeys (trips/travel) ──────────────────────────────────

@app.route("/journeys")
@login_required
def journeys_list():
    device = active_device()
    db = get_db()
    rows = db.execute(
        """SELECT j.*, COUNT(jt.trip_id) AS trip_count,
                  COALESCE(SUM(t.distance_km), 0) AS total_km
           FROM journeys j
           LEFT JOIN journey_trips jt ON jt.journey_id = j.id
           LEFT JOIN trips t ON t.id = jt.trip_id
           WHERE j.device = ?
           GROUP BY j.id ORDER BY j.date_from DESC""",
        (device,),
    ).fetchall()
    db.close()
    return render_template("journeys.html", journeys=[dict(r) for r in rows])


@app.route("/journeys/<int:journey_id>")
@login_required
def journey_detail(journey_id):
    db = get_db()
    journey = db.execute("SELECT * FROM journeys WHERE id = ?", (journey_id,)).fetchone()
    if not journey:
        db.close()
        return redirect(url_for("journeys_list"))
    trips = db.execute(
        """SELECT t.* FROM trips t
           JOIN journey_trips jt ON jt.trip_id = t.id
           WHERE jt.journey_id = ?
           ORDER BY t.start_time""",
        (journey_id,),
    ).fetchall()
    # Filter charge sessions: link vehicle via device -> plate
    veh = db.execute("SELECT * FROM vehicles WHERE device = ?",
                     (journey["device"],)).fetchone()
    if veh:
        charges = db.execute(
            """SELECT * FROM charge_sessions
               WHERE vehicle_plate = ? AND date(start_time) >= ? AND date(start_time) <= ?
               ORDER BY start_time""",
            (veh["plate"], journey["date_from"], journey["date_to"]),
        ).fetchall()
    else:
        charges = db.execute(
            """SELECT * FROM charge_sessions
               WHERE date(start_time) >= ? AND date(start_time) <= ?
               ORDER BY start_time""",
            (journey["date_from"], journey["date_to"]),
        ).fetchall()
    vehicles = db.execute("SELECT plate, name FROM vehicles").fetchall()
    vehicle_names = {v["plate"]: v["name"] or v["plate"] for v in vehicles}
    op_icon_map = _operator_icon_map(db)
    # loc_operators for charge icons (like charges.html)
    loc_operators = {}
    for cl in db.execute("""SELECT cl.name, cl.operator, cl.type, cl.color, cl.icon_filename,
                                   op.icon_filename AS op_icon_filename, op.color AS op_color
                            FROM charge_locations cl
                            LEFT JOIN operators op ON cl.operator_id = op.id""").fetchall():
        if cl['icon_filename']:
            icon_url = f"/media/charge-icons/{cl['icon_filename']}"
        elif cl['op_icon_filename']:
            icon_url = f"/media/operator-icons/{cl['op_icon_filename']}"
        else:
            icon_url = None
        loc_operators[cl['name']] = {
            'color': cl['op_color'] or cl['color'] or '#8b949e',
            'icon_url': icon_url,
        }
    # Calculate drive time, charge time, average speed
    drive_minutes = 0
    for t in trips:
        if t["start_time"] and t["end_time"]:
            try:
                t0 = datetime.fromisoformat(t["start_time"])
                t1 = datetime.fromisoformat(t["end_time"])
                drive_minutes += (t1 - t0).total_seconds() / 60
            except Exception:
                pass
    # Split charge times by AC/DC
    loc_types = {}
    for cl in db.execute("SELECT name, type FROM charge_locations").fetchall():
        loc_types[cl["name"]] = (cl["type"] or "ac").lower()
    ac_minutes = 0
    dc_minutes = 0
    for c in charges:
        dur = c["duration_minutes"] or 0
        if loc_types.get(c["location_name"]) == "dc":
            dc_minutes += dur
        else:
            ac_minutes += dur
    total_km = sum(t["distance_km"] or 0 for t in trips)
    avg_speed = round(total_km / (drive_minutes / 60), 1) if drive_minutes > 0 else None

    db.close()
    return render_template("journey_detail.html",
                           journey=dict(journey),
                           trips=[dict(t) for t in trips],
                           charges=[dict(c) for c in charges],
                           vehicle_names=vehicle_names,
                           op_icon_map=op_icon_map,
                           loc_operators=loc_operators,
                           drive_minutes=round(drive_minutes),
                           ac_minutes=round(ac_minutes),
                           dc_minutes=round(dc_minutes),
                           avg_speed=avg_speed)


@app.route("/api/journeys", methods=["POST"])
@login_required
def create_journey():
    data = request.get_json(force=True)
    title = (data.get("title") or "").strip()
    date_from = (data.get("date_from") or "").strip()
    date_to = (data.get("date_to") or "").strip()
    notes = (data.get("notes") or "").strip()
    trip_ids = data.get("trip_ids", [])
    if not title or not date_from or not date_to:
        return jsonify({"error": "Titel, Von und Bis sind Pflicht"}), 400
    device = active_device()
    db = get_db()
    cur = db.execute(
        "INSERT INTO journeys (device, title, date_from, date_to, notes) VALUES (?,?,?,?,?)",
        (device, title, date_from, date_to, notes),
    )
    jid = cur.lastrowid
    for tid in trip_ids:
        db.execute("INSERT OR IGNORE INTO journey_trips (journey_id, trip_id) VALUES (?,?)",
                    (jid, int(tid)))
    db.commit()
    db.close()
    return jsonify({"ok": True, "id": jid})


@app.route("/api/journeys/<int:journey_id>", methods=["POST"])
@login_required
def update_journey(journey_id):
    data = request.get_json(force=True)
    db = get_db()
    sets, vals = [], []
    for col in ("title", "date_from", "date_to", "notes"):
        if col in data:
            sets.append(f"{col} = ?")
            vals.append(data[col])
    if sets:
        vals.append(journey_id)
        db.execute(f"UPDATE journeys SET {', '.join(sets)} WHERE id = ?", vals)
    if "trip_ids" in data:
        db.execute("DELETE FROM journey_trips WHERE journey_id = ?", (journey_id,))
        for tid in data["trip_ids"]:
            db.execute("INSERT OR IGNORE INTO journey_trips (journey_id, trip_id) VALUES (?,?)",
                        (journey_id, int(tid)))
    db.commit()
    db.close()
    return jsonify({"ok": True})


@app.route("/api/journeys/<int:journey_id>", methods=["DELETE"])
@login_required
def delete_journey(journey_id):
    db = get_db()
    db.execute("DELETE FROM journeys WHERE id = ?", (journey_id,))
    db.commit()
    db.close()
    return jsonify({"ok": True})


@app.route("/api/journeys/<int:journey_id>/trips")
@login_required
def journey_trips_list(journey_id):
    """All trips of a journey with GPS data."""
    db = get_db()
    trips = db.execute(
        """SELECT t.* FROM trips t
           JOIN journey_trips jt ON jt.trip_id = t.id
           WHERE jt.journey_id = ?
           ORDER BY t.start_time""",
        (journey_id,),
    ).fetchall()
    db.close()
    return jsonify([dict(t) for t in trips])


@app.route("/api/journeys/<int:journey_id>/route")
@login_required
def journey_route(journey_id):
    """GPS points of all trips in a journey.
    Priority: 1) InfluxDB time series  2) GPX waypoints  3) start/end coordinates of the trip
    """
    db = get_db()
    if not db.execute("SELECT id FROM journeys WHERE id = ?", (journey_id,)).fetchone():
        db.close()
        return jsonify({"segments": []})

    trips = db.execute(
        """SELECT t.id, t.device, t.start_time, t.end_time,
                  t.start_lat, t.start_lon, t.end_lat, t.end_lon, t.is_gpx
           FROM trips t
           JOIN journey_trips jt ON jt.trip_id = t.id
           WHERE jt.journey_id = ?
           ORDER BY t.start_time""",
        (journey_id,),
    ).fetchall()

    # Pre-load GPX waypoints (trip_id → [[lat,lon], ...])
    gpx_tracks = {}
    gpx_trip_ids = [t["id"] for t in trips if t["is_gpx"]]
    if gpx_trip_ids:
        placeholders = ",".join("?" * len(gpx_trip_ids))
        wpts = db.execute(
            f"SELECT trip_id, lat, lon FROM gpx_waypoints WHERE trip_id IN ({placeholders}) ORDER BY trip_id, timestamp",
            gpx_trip_ids,
        ).fetchall()
        for w in wpts:
            gpx_tracks.setdefault(w["trip_id"], []).append([round(w["lat"], 6), round(w["lon"], 6)])

    db.close()

    segments = []

    # 1) InfluxDB: query grouped by trip device
    client = detector.get_influx()
    if client:
        try:
            from collections import defaultdict
            by_device = defaultdict(list)
            for trip in trips:
                if trip["device"]:
                    by_device[trip["device"]].append(trip)

            for device, dev_trips in by_device.items():
                for trip in dev_trips:
                    query = f'''
                    from(bucket: "{config.INFLUX_BUCKET}")
                      |> range(start: {_to_rfc3339(trip["start_time"])}, stop: {_to_rfc3339_padded(trip["end_time"])})
                      |> filter(fn: (r) => r._measurement == "v" and r.d == "{device}")
                      |> filter(fn: (r) => r._field == "la" or r._field == "lo")
                      |> pivot(rowKey: ["_time"], columnKey: ["_field"], valueColumn: "_value")
                      |> sort(columns: ["_time"])
                    '''
                    tables = client.query_api().query(query, org=config.INFLUX_ORG)
                    raw = []
                    for table in tables:
                        for rec in table.records:
                            raw.append(rec.values)
                    raw.sort(key=lambda r: r.get("_time") or datetime.min.replace(tzinfo=timezone.utc))
                    raw = detector._merge_rows(raw)
                    raw = detector._filter_gps_jumps(raw)
                    pts = []
                    for rec in raw:
                        lat = rec.get("la")
                        lon = rec.get("lo")
                        if lat and lon and lat != 0 and lon != 0:
                            pts.append([round(lat, 6), round(lon, 6)])
                    if pts:
                        segments.append(pts)
        except Exception:
            log.exception("Error loading journey route %d", journey_id)
        finally:
            client.close()

    # 2) Fallback: GPX waypoints for trips without InfluxDB data
    if not segments:
        for trip in trips:
            if trip["id"] in gpx_tracks:
                pts = gpx_tracks[trip["id"]]
                if pts:
                    segments.append(pts)

    # 3) Fallback: start/end coordinates of trips
    if not segments:
        for trip in trips:
            pts = []
            if trip["start_lat"] and trip["start_lon"]:
                pts.append([round(trip["start_lat"], 6), round(trip["start_lon"], 6)])
            if trip["end_lat"] and trip["end_lon"]:
                pts.append([round(trip["end_lat"], 6), round(trip["end_lon"], 6)])
            if pts:
                segments.append(pts)

    return jsonify({"segments": segments, "source": "influx" if segments and client else ("gpx" if gpx_tracks else "coords")})


@app.route("/api/journeys/<int:journey_id>/chart-data")
@login_required
def journey_chart_data(journey_id):
    """Daily kilometers of the journey trips."""
    db = get_db()
    rows = db.execute(
        """SELECT date(t.start_time) AS day, SUM(t.distance_km) AS km
           FROM trips t
           JOIN journey_trips jt ON jt.trip_id = t.id
           WHERE jt.journey_id = ?
           GROUP BY day ORDER BY day""",
        (journey_id,),
    ).fetchall()
    db.close()
    labels = [r["day"] for r in rows]
    values = [round(r["km"], 1) if r["km"] else 0 for r in rows]
    return jsonify({"labels": labels, "values": values})


@app.route("/api/journeys/<int:journey_id>/gpx")
@login_required
def journey_gpx(journey_id):
    """GPX export of all trips in a journey."""
    db = get_db()
    journey = db.execute("SELECT * FROM journeys WHERE id = ?", (journey_id,)).fetchone()
    if not journey:
        db.close()
        return jsonify({"error": "Journey nicht gefunden"}), 404
    trips = db.execute(
        """SELECT t.start_time, t.end_time FROM trips t
           JOIN journey_trips jt ON jt.trip_id = t.id
           WHERE jt.journey_id = ?
           ORDER BY t.start_time""",
        (journey_id,),
    ).fetchall()
    db.close()

    device = journey["device"]
    gpx_lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<gpx version="1.1" creator="ID·Mate"',
        '     xmlns="http://www.topografix.com/GPX/1/1">',
        f'  <metadata><name>{journey["title"]}</name></metadata>',
    ]

    client = detector.get_influx()
    if client:
        try:
            for i, trip in enumerate(trips):
                query = f'''
                from(bucket: "{config.INFLUX_BUCKET}")
                  |> range(start: {_to_rfc3339(trip["start_time"])}, stop: {_to_rfc3339_padded(trip["end_time"])})
                  |> filter(fn: (r) => r._measurement == "v" and r.d == "{device}")
                  |> filter(fn: (r) => r._field == "la" or r._field == "lo" or r._field == "v" or r._field == "s")
                  |> pivot(rowKey: ["_time"], columnKey: ["_field"], valueColumn: "_value")
                  |> filter(fn: (r) => exists r.la and exists r.lo)
                  |> sort(columns: ["_time"])
                '''
                tables = client.query_api().query(query, org=config.INFLUX_ORG)
                gpx_lines.append(f'  <trk>')
                gpx_lines.append(f'    <name>Fahrt {i+1} ({trip["start_time"][:10]})</name>')
                gpx_lines.append(f'    <trkseg>')
                for table in tables:
                    for rec in table.records:
                        la = rec.values.get("la")
                        lo = rec.values.get("lo")
                        t = rec.values.get("_time")
                        if la and lo:
                            time_str = t.isoformat() if t else ""
                            line = f'      <trkpt lat="{la}" lon="{lo}">'
                            if time_str:
                                line += f'<time>{time_str}</time>'
                            speed = rec.values.get("v")
                            if speed is not None:
                                line += f'<speed>{speed / 3.6:.1f}</speed>'
                            line += '</trkpt>'
                            gpx_lines.append(line)
                gpx_lines += ['    </trkseg>', '  </trk>']
        except Exception:
            log.exception("Error in GPX export of journey %d", journey_id)
        finally:
            client.close()

    gpx_lines.append('</gpx>')
    safe_title = journey["title"].replace(" ", "_")
    filename = f"journey_{safe_title}_{journey['date_from']}_{journey['date_to']}.gpx"
    return Response(
        "\n".join(gpx_lines),
        mimetype="application/gpx+xml",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@app.route("/api/journeys/available-trips")
@login_required
def journey_available_trips():
    """Trips in date range for journey assignment."""
    date_from = request.args.get("from", "")
    date_to = request.args.get("to", "")
    device = active_device()
    db = get_db()
    trips = db.execute(
        """SELECT id, start_time, end_time, start_address, end_address, distance_km
           FROM trips
           WHERE device = ? AND date(start_time) >= ? AND date(start_time) <= ?
           ORDER BY start_time""",
        (device, date_from, date_to),
    ).fetchall()
    db.close()
    return jsonify([dict(t) for t in trips])


# ── Statistics API (for Grafana JSON datasource) ─────────────

@app.route("/api/stats")
def stats():
    device = active_device()
    db = get_db()
    # Read private purposes from purpose_meta
    priv_rows = db.execute("SELECT name FROM purpose_meta WHERE is_private = 1").fetchall()
    priv_names = {r["name"] for r in priv_rows}

    row = db.execute(
        "SELECT COUNT(*) as total, SUM(distance_km) as km_total FROM trips WHERE device = ?",
        (device,),
    ).fetchone()

    # Calculate km per category
    all_trips = db.execute(
        "SELECT purpose, distance_km FROM trips WHERE device = ?",
        (device,),
    ).fetchall()
    db.close()

    km_privat = 0.0
    km_dienstlich = 0.0
    for t in all_trips:
        km = t["distance_km"] or 0
        p = t["purpose"] or ""
        if not p:
            continue
        if p in priv_names:
            km_privat += km
        else:
            km_dienstlich += km

    return jsonify({
        "total": row["total"],
        "km_total": row["km_total"],
        "km_privat": km_privat,
        "km_dienstlich": km_dienstlich,
    })


# ── Debug pages (ENABLE_DEBUG=1) ─────────────────────────────

@app.route("/api/admin/scan-debug")
@debug_required
def admin_scan_debug():
    """Show what the detector would see — without saving."""
    device = request.args.get("device") or active_device()
    hours = int(request.args.get("hours", 24))
    since = datetime.now(timezone.utc) - timedelta(hours=hours)

    db = detector.get_db()
    client = detector.get_influx()
    if not client:
        db.close()
        return jsonify({"error": "InfluxDB nicht erreichbar"}), 503

    last_end = detector.last_trip_end(db, device)
    rows_raw = detector.query_drive_data(client, since, device)
    client.close()

    rows = detector.expand_rows(rows_raw) if rows_raw else []
    has_ig = any(r.get("ig") is not None for r in rows)

    bat_row = db.execute(
        "SELECT battery_capacity_kwh FROM vehicles WHERE device = ? AND battery_capacity_kwh IS NOT NULL", (device,)
    ).fetchone()
    bat_kwh = float(bat_row["battery_capacity_kwh"]) if bat_row else 86.5

    trips = detector.detect_trips(rows, bat_kwh, device=device) if rows else []
    db.close()

    return jsonify({
        "device": device,
        "since_used": since.isoformat(),
        "last_trip_end_in_db": str(last_end),
        "raw_rows_count": len(rows_raw),
        "expanded_rows_count": len(rows),
        "has_ig": has_ig,
        "trips_detected": len(trips),
        "trips": [
            {
                "start": t["start_time"],
                "end": t["end_time"],
                "distance_km": t.get("distance_km"),
                "soc": f"{t.get('soc_start')}→{t.get('soc_end')}",
            }
            for t in trips
        ],
        "first_row_time": str(rows[0].get("_time")) if rows else None,
        "last_row_time": str(rows[-1].get("_time")) if rows else None,
    })


@app.route("/mqtt-monitor")
@debug_required
def mqtt_monitor():
    """Live view of MQTT messages."""
    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>MQTT Monitor</title>
<style>
  body {{ background:#0d1117; color:#c9d1d9; font-family:monospace; margin:1rem }}
  h1 {{ font-size:1.2rem; color:#58a6ff }}
  .status {{ padding:0.5rem 0.8rem; border-radius:6px; margin:0.5rem 0; font-size:0.85rem }}
  .online {{ background:#122d1a; border:1px solid #238636; color:#3fb950 }}
  .offline {{ background:#3d1214; border:1px solid #f85149; color:#f85149 }}
  table {{ border-collapse:collapse; width:100%; font-size:0.8rem; margin-top:1rem }}
  th {{ background:#21262d; color:#8b949e; padding:6px 8px; text-align:left; position:sticky; top:0 }}
  td {{ padding:4px 8px; border-bottom:1px solid #21262d; max-width:600px; word-break:break-all }}
  tr:hover {{ background:#3d1f4e !important }}
  .topic {{ color:#58a6ff }}
  .time {{ color:#8b949e }}
</style>
</head><body>
<h1>MQTT Monitor</h1>
<div id="status" class="status offline">Verbinde…</div>
<div style="font-size:0.75rem;color:#484f58;margin:0.3rem 0">
  Broker: {config.MQTT_BROKER}:{config.MQTT_PORT} | Topic: {config.MQTT_TOPIC} | TLS: {'✓' if config.MQTT_TLS else '✗'}
</div>
<table><thead><tr><th>Zeit</th><th>Topic</th><th>Payload</th><th>QoS</th></tr></thead>
<tbody id="msgs"></tbody></table>

<script>
async function refresh() {{
  try {{
    const res = await fetch('/api/mqtt-messages');
    const data = await res.json();
    const el = document.getElementById('status');
    if (data.connected) {{
      el.className = 'status online';
      el.textContent = '● Verbunden — ' + data.count + ' Nachrichten empfangen';
    }} else {{
      el.className = 'status offline';
      el.textContent = '● Nicht verbunden';
    }}
    const tbody = document.getElementById('msgs');
    tbody.innerHTML = data.messages.map(m =>
      `<tr><td class="time">${{m.time}}</td><td class="topic">${{m.topic}}</td><td>${{m.payload}}</td><td>${{m.qos}}</td></tr>`
    ).join('');
  }} catch(e) {{}}
}}
refresh();
setInterval(refresh, 2000);
</script>
</body></html>"""


@app.route("/api/mqtt-messages")
@debug_required
def mqtt_messages():
    """JSON: recent MQTT messages."""
    # Count by status across the deque for diagnostics
    stats = {"data": 0, "non_data": 0, "decode_fail": 0, "written_ok": 0, "written_fail": 0}
    for m in _mqtt_messages:
        if m.get("topic", "").endswith("/data"):
            stats["data"] += 1
            if m.get("decoded") is None:
                stats["decode_fail"] += 1
            elif m.get("written") == "ok":
                stats["written_ok"] += 1
            elif m.get("written"):
                stats["written_fail"] += 1
        else:
            stats["non_data"] += 1
    return jsonify({
        "connected": _mqtt_connected,
        "count": len(_mqtt_messages),
        "influx_written": _mqtt_influx_count,
        "influx_failed": _mqtt_influx_failed,
        "stats": stats,
        "messages": list(_mqtt_messages),
    })


@app.route("/api/mqtt-replay", methods=["POST"])
@debug_required
def mqtt_replay():
    """Replay failed messages from the deque into InfluxDB (with v→int fix)."""
    from influxdb_client import InfluxDBClient, WritePrecision
    from influxdb_client.client.write_api import SYNCHRONOUS

    client = InfluxDBClient(url=config.INFLUX_URL, token=config.INFLUX_TOKEN, org=config.INFLUX_ORG)
    writer = client.write_api(write_options=SYNCHRONOUS)
    from influxdb_client import Point

    ok = 0
    fail = 0
    for m in _mqtt_messages:
        decoded = m.get("decoded")
        ts = m.get("ts") or (decoded.get("ts") if decoded else None)
        if not decoded or not ts:
            continue
        # Skip already successful writes
        if m.get("written") == "ok":
            continue

        fields = {k: v for k, v in decoded.items() if isinstance(v, (int, float)) and k != "ts"}
        if not fields:
            continue

        topic = m.get("topic", "")
        parts = topic.split("/")
        device = parts[1] if len(parts) >= 3 else "vw_nox"

        point = Point("v").tag("d", device)
        for k, val in fields.items():
            if k == 'v' and isinstance(val, float):
                val = int(round(val))
            point.field(k, val)
        point.time(int(ts * 1_000_000_000), WritePrecision.NS)

        try:
            writer.write(bucket=config.INFLUX_BUCKET, record=point)
            ok += 1
        except Exception:
            fail += 1

    client.close()
    return jsonify({"replayed_ok": ok, "replayed_fail": fail})


@app.route("/api/admin/stats/stick-battery")
@admin_required
def stats_stick_battery():
    """ESP-stick battery (bd field) per device for last 48h."""
    client = detector.get_influx()
    if not client:
        return jsonify({"devices": []})
    try:
        query = f'''
        from(bucket: "{config.INFLUX_BUCKET}")
          |> range(start: -48h)
          |> filter(fn: (r) => r._measurement == "v" and r._field == "bd")
          |> aggregateWindow(every: 15m, fn: mean, createEmpty: false)
          |> sort(columns: ["_time"])
        '''
        tables = client.query_api().query(query, org=config.INFLUX_ORG)
        # Group by device tag
        by_device = {}
        for table in tables:
            for rec in table.records:
                dev = rec.values.get("d") or "unknown"
                t = rec.get_time()
                v = rec.get_value()
                if t is None or v is None:
                    continue
                ts_ms = int(t.timestamp() * 1000)
                by_device.setdefault(dev, []).append([ts_ms, round(v, 1)])
    finally:
        client.close()

    # Stable colors per device
    palette = ["#58a6ff", "#f85149", "#3fb950", "#d29922", "#bc8cff", "#f0883e"]
    devices = []
    for i, (dev, points) in enumerate(sorted(by_device.items())):
        devices.append({
            "name": dev,
            "color": palette[i % len(palette)],
            "data": points,
        })
    return jsonify({"devices": devices})


@app.route("/api/admin/stats/data-volume")
@admin_required
def stats_data_volume():
    """Hourly count of telemetry points per device (last 48h)."""
    client = detector.get_influx()
    if not client:
        return jsonify({"hours": [], "devices": []})
    try:
        # Use a single field (la) to count "rows" — multi-field points share a timestamp
        query = f'''
        from(bucket: "{config.INFLUX_BUCKET}")
          |> range(start: -48h)
          |> filter(fn: (r) => r._measurement == "v" and r._field == "la")
          |> aggregateWindow(every: 1h, fn: count, createEmpty: true)
        '''
        tables = client.query_api().query(query, org=config.INFLUX_ORG)
        # Build matrix: hour timestamp -> device -> count
        by_device = {}
        all_hours = set()
        for table in tables:
            for rec in table.records:
                dev = rec.values.get("d") or "unknown"
                t = rec.get_time()
                cnt = rec.get_value() or 0
                if t is None:
                    continue
                ts_ms = int(t.timestamp() * 1000)
                all_hours.add(ts_ms)
                by_device.setdefault(dev, {})[ts_ms] = cnt
    finally:
        client.close()

    hours = sorted(all_hours)
    palette = ["#58a6ff", "#f85149", "#3fb950", "#d29922", "#bc8cff", "#f0883e"]
    devices = []
    for i, dev in enumerate(sorted(by_device.keys())):
        # ~80 bytes per point estimate
        data = [round(by_device[dev].get(h, 0) * 80 / 1024, 1) for h in hours]  # KB
        devices.append({
            "name": dev,
            "color": palette[i % len(palette)],
            "data": data,
        })
    return jsonify({"hours": hours, "devices": devices})


# Carrier name lookup table for German PLMNs is _PLMN_CARRIERS (defined earlier)

@app.route("/api/admin/stats/carrier-coverage")
@admin_required
def stats_carrier_coverage():
    """LTE signal strength per carrier on a coordinate grid (last 30 days).

    Returns clusters of points grouped by carrier with average signal.
    """
    client = detector.get_influx()
    if not client:
        return jsonify({"carriers": []})
    try:
        query = f'''
        from(bucket: "{config.INFLUX_BUCKET}")
          |> range(start: -30d)
          |> filter(fn: (r) => r._measurement == "v")
          |> filter(fn: (r) => r._field == "la" or r._field == "lo" or r._field == "ls" or r._field == "lp")
          |> aggregateWindow(every: 5m, fn: mean, createEmpty: false)
          |> pivot(rowKey: ["_time"], columnKey: ["_field"], valueColumn: "_value")
          |> filter(fn: (r) => exists r.la and exists r.lo and exists r.ls and exists r.lp)
        '''
        tables = client.query_api().query(query, org=config.INFLUX_ORG)
        # Group by carrier + grid cell (3 decimal places ≈ 110m)
        cells = {}  # (plmn, lat_grid, lon_grid) -> {"sum": ls, "count": n, "lat": avg, "lon": avg}
        for table in tables:
            for rec in table.records:
                la = rec.values.get("la")
                lo = rec.values.get("lo")
                ls = rec.values.get("ls")
                lp = rec.values.get("lp")
                if la is None or lo is None or ls is None or lp is None:
                    continue
                if abs(la) < 0.5 or abs(lo) < 0.5 or ls > 31:
                    continue
                lp_int = int(lp)
                key = (lp_int, round(la, 3), round(lo, 3))
                if key not in cells:
                    cells[key] = {"sum": 0, "n": 0, "la_sum": 0, "lo_sum": 0}
                c = cells[key]
                c["sum"] += ls
                c["n"] += 1
                c["la_sum"] += la
                c["lo_sum"] += lo
    finally:
        client.close()

    # Group cells by carrier
    carriers_dict = {}
    for (plmn, _, _), c in cells.items():
        avg_ls = c["sum"] / c["n"]
        avg_la = c["la_sum"] / c["n"]
        avg_lo = c["lo_sum"] / c["n"]
        carriers_dict.setdefault(plmn, []).append({
            "lat": round(avg_la, 5),
            "lon": round(avg_lo, 5),
            "csq": round(avg_ls, 1),
            "n": c["n"],
        })

    # Carrier color palette
    carrier_colors = {
        26201: "#e20074",  # Telekom magenta
        26206: "#e20074",
        26202: "#e60000",  # Vodafone red
        26204: "#e60000",
        26209: "#e60000",
        26242: "#e60000",
        26203: "#0050ad",  # O2 blue
        26207: "#0050ad",
        26208: "#0050ad",
        26211: "#0050ad",
        26220: "#0050ad",
    }

    carriers = []
    for plmn, points in sorted(carriers_dict.items()):
        carriers.append({
            "plmn": plmn,
            "name": _plmn_name(plmn) or f"PLMN {plmn}",
            "color": carrier_colors.get(plmn, "#8b949e"),
            "points": points,
            "total_n": sum(p["n"] for p in points),
        })
    return jsonify({"carriers": carriers})


@app.route("/debug")
@debug_required
def debug_page():
    """Debug page: shows InfluxDB raw data + detected trips."""
    device = request.args.get("device") or active_device()
    date_from = request.args.get("from", "")
    date_to = request.args.get("to", "")
    hours = int(request.args.get("hours", 48))

    if date_from:
        since = datetime.fromisoformat(date_from).replace(tzinfo=detector.LOCAL_TZ).astimezone(timezone.utc)
    else:
        since = datetime.now(timezone.utc) - timedelta(hours=hours)
    if date_to:
        until = datetime.fromisoformat(date_to).replace(tzinfo=detector.LOCAL_TZ).astimezone(timezone.utc)
    else:
        until = None

    db = detector.get_db()
    client = detector.get_influx()
    if not client:
        db.close()
        return "<h1>InfluxDB nicht erreichbar</h1>", 503

    last_end = detector.last_trip_end(db, device)
    # Get all fields (without field filter) for debug view
    ts = since.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    stop_clause = f", stop: {until.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}" if until else ""
    flux_query = f'''
    from(bucket: "{config.INFLUX_BUCKET}")
      |> range(start: {ts}{stop_clause})
      |> filter(fn: (r) => r._measurement == "v" and r.d == "{device}")
      |> pivot(rowKey: ["_time"], columnKey: ["_field"], valueColumn: "_value")
      |> sort(columns: ["_time"])
    '''
    tables = client.query_api().query(flux_query, org=config.INFLUX_ORG)
    rows_raw = []
    for table in tables:
        for record in table.records:
            rows_raw.append(record.values)
    rows_raw.sort(key=lambda r: r.get("_time") or datetime.min.replace(tzinfo=timezone.utc))
    rows_raw = detector._merge_rows(rows_raw)
    client.close()

    rows = detector.expand_rows(rows_raw) if rows_raw else []
    has_ig = any(r.get("ig") is not None for r in rows)

    bat_row = db.execute(
        "SELECT battery_capacity_kwh FROM vehicles WHERE device = ? AND battery_capacity_kwh IS NOT NULL", (device,)
    ).fetchone()
    bat_kwh = float(bat_row["battery_capacity_kwh"]) if bat_row else 86.5

    trips = detector.detect_trips(rows, bat_kwh, device=device) if rows else []

    # All devices for dropdown
    vehicle_rows = db.execute(
        "SELECT DISTINCT device FROM vehicles WHERE device IS NOT NULL AND device != ''"
    ).fetchall()
    devices = [r["device"] for r in vehicle_rows] or [config.INFLUX_DEVICE]
    db.close()

    # Dynamically determine all fields from the data
    skip_fields = {"result", "table", "_start", "_stop", "_measurement", "d", "_eq", "_na"}
    all_keys = set()
    for r in rows:
        all_keys.update(k for k in r.keys() if k not in skip_fields)
    # _time always first, rest sorted
    fields = ["_time"] + sorted(all_keys - {"_time"})

    html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Debug — {device}</title>
<style>
  body {{ background:#0d1117; color:#c9d1d9; font-family:monospace; margin:1rem }}
  h1 {{ font-size:1.2rem; color:#58a6ff }}
  h2 {{ font-size:1rem; color:#8b949e; margin-top:2rem }}
  .meta {{ background:#161b22; padding:0.8rem; border-radius:6px; margin:1rem 0; font-size:0.85rem; line-height:1.8 }}
  .meta b {{ color:#58a6ff }}
  table {{ border-collapse:collapse; width:100%; font-size:0.75rem }}
  th {{ background:#21262d; color:#8b949e; padding:4px 6px; text-align:left; position:sticky; top:0; cursor:pointer }}
  th:hover {{ color:#58a6ff }}
  td {{ padding:3px 6px; border-bottom:1px solid #21262d }}
  tr:hover {{ background:#3d1f4e !important }}
  .trip {{ background:#122d1a; border:1px solid #238636; border-radius:6px; padding:0.5rem 0.8rem; margin:0.3rem 0; font-size:0.8rem }}
  select, input {{ background:#21262d; color:#c9d1d9; border:1px solid #30363d; padding:4px 8px; border-radius:4px }}
  form {{ display:flex; gap:0.5rem; align-items:center; margin:0.5rem 0 }}
  .toolbar {{ background:#161b22; padding:0.5rem 0.8rem; border-radius:6px; margin:0.5rem 0; display:flex; gap:0.5rem; align-items:center }}
  .btn {{ background:#21262d; color:#c9d1d9; border:1px solid #30363d; padding:4px 12px; border-radius:4px; cursor:pointer; font-size:0.8rem }}
  .btn:hover {{ background:#30363d }}
  .btn-danger {{ background:#3d1214; border-color:#f85149; color:#f85149 }}
  .btn-danger:hover {{ background:#5a1d21 }}
  .sel-count {{ color:#58a6ff; font-size:0.8rem }}
  input[type=checkbox] {{ accent-color:#58a6ff }}
  .filter-row input {{ background:#0d1117; color:#c9d1d9; border:1px solid #30363d; padding:2px 4px; width:100%; box-sizing:border-box; font-size:0.7rem; font-family:monospace }}
  .filter-row input:focus {{ border-color:#58a6ff; outline:none }}
  .filter-row td {{ padding:2px }}
</style></head><body>
<h1>Debug: InfluxDB Rohdaten</h1>
<form method="get" style="flex-wrap:wrap">
  <label>Device:</label>
  <select name="device" onchange="this.form.submit()">
    {''.join(f'<option value="{d}" {"selected" if d==device else ""}>{d}</option>' for d in devices)}
  </select>
  <label>Stunden:</label>
  <input type="number" name="hours" value="{hours}" style="width:60px">
  <span style="color:#484f58">oder</span>
  <label>Von:</label>
  <input type="datetime-local" name="from" value="{date_from}" style="width:180px">
  <label>Bis:</label>
  <input type="datetime-local" name="to" value="{date_to}" style="width:180px">
  <button type="submit" class="btn">Laden</button>
</form>

<div class="meta">
  <b>Device:</b> {device} &nbsp;|&nbsp;
  <b>Zeitraum:</b> {since.astimezone(detector.LOCAL_TZ).strftime('%Y-%m-%d %H:%M')} → {until.astimezone(detector.LOCAL_TZ).strftime('%Y-%m-%d %H:%M') if until else 'jetzt'} &nbsp;|&nbsp;
  <b>last_trip_end:</b> {last_end.astimezone(detector.LOCAL_TZ).strftime('%Y-%m-%d %H:%M')}<br>
  <b>Rows:</b> {len(rows)} &nbsp;|&nbsp;
  <b>Erkannte Fahrten:</b> {len(trips)} &nbsp;|&nbsp;
  <b>DATA_GAP_MINUTES:</b> {detector.DATA_GAP_MINUTES} &nbsp;|&nbsp;
  <b>STOP_MINUTES:</b> {detector.STOP_MINUTES} &nbsp;|&nbsp;
  <b>SOC_JUMP_MIN:</b> {detector.SOC_JUMP_MIN}% &nbsp;|&nbsp;
  <b>TRIP_MIN_DISTANCE_KM:</b> {config.TRIP_MIN_DISTANCE_KM}
</div>
"""

    if trips:
        html += "<h2>Erkannte Fahrten</h2>"
        for i, t in enumerate(trips, 1):
            html += f'<div class="trip">#{i}: {t["start_time"]} → {t["end_time"]} | {t.get("distance_km", "?")} km | SoC {t.get("soc_start", "?")}→{t.get("soc_end", "?")}%</div>'
    else:
        html += '<h2 style="color:#f85149">Keine Fahrten erkannt</h2>'

    # Trip time ranges for assignment in the table
    trip_ranges = []
    for i, t in enumerate(trips, 1):
        trip_ranges.append((t["start_time"], t["end_time"], i))

    def _to_local(dt):
        """UTC datetime → local time."""
        return dt.astimezone(detector.LOCAL_TZ) if dt else None

    def _trip_nr(row_time):
        if not row_time:
            return ""
        rt = _to_local(row_time).strftime("%Y-%m-%dT%H:%M:%S")
        for start, end, nr in trip_ranges:
            if start <= rt <= end:
                return str(nr)
        return ""

    html += f'<h2>Rohdaten ({len(rows)} Zeilen)</h2>'
    html += f"""<div class="toolbar">
  <input type="checkbox" id="selAll" onchange="toggleAll(this)">
  <span class="sel-count" id="selCount">0 ausgewählt</span>
  <button class="btn btn-danger" onclick="deleteSelected()">Ausgewählte löschen</button>
</div>"""
    html += "<div style='max-height:70vh;overflow:auto'><table id='dtable'><thead><tr>"
    html += '<th><input type="checkbox" onchange="toggleAll(this)"></th><th>trip</th>'
    for f in fields:
        html += f"<th>{f}</th>"
    n_cols = 2 + len(fields) + 3  # checkbox + trip + fields + gap + stop + gps
    html += "<th>gap</th><th>stop</th><th>gps Δm</th></tr>"
    html += '<tr class="filter-row">'
    for ci in range(n_cols):
        if ci == 0:
            html += "<td></td>"  # checkbox col — no filter
        else:
            html += f'<td><input type="text" data-col="{ci}" oninput="applyFilters()" placeholder="…"></td>'
    html += "</tr></thead><tbody>"

    prev_time = None
    prev_lat = None
    prev_lon = None
    last_moving_time = None
    for idx, row in enumerate(rows):
        t = row.get("_time")
        v = row.get("v")
        la = row.get("la")
        lo = row.get("lo")
        # Movement: v > 0 OR GPS progress as fallback when v is missing
        if v is not None:
            moving = v > 0
        elif la and lo and prev_lat and prev_lon and prev_time and t:
            dt_sec = (t - prev_time).total_seconds()
            gps_dist = detector.haversine_m(prev_lat, prev_lon, la, lo)
            moving = gps_dist > 50 and dt_sec > 0
        else:
            moving = False
        gap = ""
        gap_class = ""
        if prev_time and t:
            gap_min = (t - prev_time).total_seconds() / 60
            gap = f"{gap_min:.0f}m"
            if gap_min >= detector.DATA_GAP_MINUTES:
                gap_class = ' style="color:#f85149;font-weight:bold"'

        stop = ""
        if not moving and last_moving_time and t:
            stop_min = (t - last_moving_time).total_seconds() / 60
            if stop_min >= 1:
                stop = f"{stop_min:.0f}m"
        if moving:
            last_moving_time = t

        gps_delta = ""
        gps_delta_cls = ""
        if la and lo and prev_lat and prev_lon:
            dist_m = detector.haversine_m(prev_lat, prev_lon, la, lo)
            gps_delta = f"{dist_m:.0f}"
            if dist_m > 10000:
                gps_delta_cls = ' style="color:#f85149;font-weight:bold"'
            elif dist_m > 1000:
                gps_delta_cls = ' style="color:#d29922"'
        if la and lo:
            prev_lat = la
            prev_lon = lo

        # UTC ISO for delete API
        utc_iso = t.strftime("%Y-%m-%dT%H:%M:%S.%fZ") if t else ""
        tnr = _trip_nr(t)
        row_style = ' style="background:#122d1a"' if tnr else ""
        html += f'<tr{row_style} data-ts="{utc_iso}">'
        html += '<td><input type="checkbox" class="rowsel" onchange="updateCount()"></td>'
        html += f'<td style="color:#3fb950;font-weight:bold">{tnr}</td>'
        for fld in fields:
            val = row.get(fld)
            if fld == "_time" and val:
                val = _to_local(val).strftime("%m-%d %H:%M:%S")
            elif fld in ("la", "lo") and isinstance(val, float):
                val = f"{val:.5f}"
            elif isinstance(val, float):
                val = f"{val:.2f}"
            html += f"<td>{val if val is not None else ''}</td>"
        html += f"<td{gap_class}>{gap}</td>"
        html += f"<td>{stop}</td>"
        html += f"<td{gps_delta_cls}>{gps_delta}</td></tr>"
        prev_time = t

    html += "</tbody></table></div>"

    # JavaScript: Sort, Select, Delete
    html += f"""<script>
const device = '{device}';

function updateCount() {{
  const n = document.querySelectorAll('.rowsel:checked').length;
  document.getElementById('selCount').textContent = n + ' ausgewählt';
}}

function toggleAll(cb) {{
  document.querySelectorAll('.rowsel').forEach(c => c.checked = cb.checked);
  document.getElementById('selAll').checked = cb.checked;
  updateCount();
}}

async function deleteSelected() {{
  const checked = document.querySelectorAll('.rowsel:checked');
  if (!checked.length) return;
  if (!confirm('Wirklich ' + checked.length + ' Zeilen unwiderruflich aus InfluxDB löschen?')) return;

  const timestamps = [];
  checked.forEach(cb => {{
    const tr = cb.closest('tr');
    timestamps.push(tr.dataset.ts);
  }});

  const resp = await fetch('/api/admin/influx-delete', {{
    method: 'POST',
    headers: {{'Content-Type': 'application/json'}},
    body: JSON.stringify({{device: device, timestamps: timestamps}})
  }});
  const data = await resp.json();
  if (data.ok) {{
    checked.forEach(cb => cb.closest('tr').remove());
    updateCount();
    alert('Gelöscht: ' + data.deleted + ' Zeitpunkte');
  }} else {{
    alert('Fehler: ' + (data.error || 'Unbekannt'));
  }}
}}

// Column filters
function applyFilters() {{
  const inputs = document.querySelectorAll('.filter-row input');
  const filters = {{}};
  inputs.forEach(inp => {{
    const v = inp.value.trim().toLowerCase();
    if (v) {{
      const col = parseInt(inp.dataset.col);
      // Support operators: >N, <N, >=N, <=N, =N, !text
      filters[col] = v;
    }}
  }});
  document.querySelectorAll('#dtable tbody tr').forEach(row => {{
    let show = true;
    for (const [col, fv] of Object.entries(filters)) {{
      const cell = row.cells[col]?.textContent || '';
      const cv = cell.trim().toLowerCase();
      const num = parseFloat(cv);
      if (fv.startsWith('>=') && !isNaN(num)) {{ show = num >= parseFloat(fv.slice(2)); }}
      else if (fv.startsWith('<=') && !isNaN(num)) {{ show = num <= parseFloat(fv.slice(2)); }}
      else if (fv.startsWith('>') && !isNaN(num)) {{ show = num > parseFloat(fv.slice(1)); }}
      else if (fv.startsWith('<') && !isNaN(num)) {{ show = num < parseFloat(fv.slice(1)); }}
      else if (fv.startsWith('=')) {{ show = cv === fv.slice(1); }}
      else if (fv.startsWith('!')) {{ show = !cv.includes(fv.slice(1)); }}
      else {{ show = cv.includes(fv); }}
      if (!show) break;
    }}
    row.style.display = show ? '' : 'none';
  }});
  // Update count of visible rows
  const vis = document.querySelectorAll('#dtable tbody tr:not([style*="display: none"])').length;
  const total = document.querySelectorAll('#dtable tbody tr').length;
  document.getElementById('selCount').textContent = vis + '/' + total + ' sichtbar';
}}

// Table sort
document.querySelectorAll('#dtable thead th').forEach((th, idx) => {{
  if (idx === 0) return; // checkbox column
  th.addEventListener('click', () => {{
    const tbody = document.querySelector('#dtable tbody');
    const rows = Array.from(tbody.querySelectorAll('tr'));
    const asc = th.dataset.sort !== 'asc';
    th.dataset.sort = asc ? 'asc' : 'desc';
    rows.sort((a, b) => {{
      let va = a.cells[idx]?.textContent || '';
      let vb = b.cells[idx]?.textContent || '';
      const na = parseFloat(va), nb = parseFloat(vb);
      if (!isNaN(na) && !isNaN(nb)) return asc ? na - nb : nb - na;
      return asc ? va.localeCompare(vb) : vb.localeCompare(va);
    }});
    rows.forEach(r => tbody.appendChild(r));
  }});
}});
</script></body></html>"""
    return html


@app.route("/api/admin/influx-delete", methods=["POST"])
@debug_required
def admin_influx_delete():
    """Delete individual data points from InfluxDB (by exact timestamp)."""
    data = request.get_json() or {}
    device = data.get("device", "")
    timestamps = data.get("timestamps", [])
    if not device or not timestamps:
        return jsonify({"ok": False, "error": "device und timestamps erforderlich"}), 400

    client = detector.get_influx()
    if not client:
        return jsonify({"ok": False, "error": "InfluxDB nicht erreichbar"}), 503

    delete_api = client.delete_api()
    deleted = 0
    try:
        for ts in timestamps:
            # Delete exact timestamp: start = ts, stop = ts + 1µs
            start = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            stop = start + timedelta(microseconds=1)
            delete_api.delete(
                start, stop,
                predicate=f'_measurement="v" AND d="{device}"',
                bucket=config.INFLUX_BUCKET,
                org=config.INFLUX_ORG,
            )
            deleted += 1
    except Exception as e:
        log.exception("InfluxDB delete failed")
        return jsonify({"ok": False, "error": str(e)}), 500
    finally:
        client.close()

    return jsonify({"ok": True, "deleted": deleted})


@app.route("/api/admin/rescan", methods=["POST"])
@admin_required
def admin_rescan():
    """Rescan trips and charges for active vehicle.
    Deletes all trips/charges in the period first, then re-detects."""
    data = request.get_json() or {}
    date_from = data.get("date_from", "")
    date_to = data.get("date_to", "")
    try:
        since = datetime.fromisoformat(date_from).replace(tzinfo=detector.LOCAL_TZ).astimezone(timezone.utc) if date_from else datetime.now(timezone.utc) - timedelta(days=30)
        until = (datetime.fromisoformat(date_to).replace(tzinfo=detector.LOCAL_TZ).astimezone(timezone.utc) + timedelta(days=1)) if date_to else None
    except ValueError:
        return jsonify({"error": "Ungültiges Datumsformat"}), 400

    dev = active_device()
    since_local = since.astimezone(detector.LOCAL_TZ).strftime("%Y-%m-%dT%H:%M:%S")
    until_local = until.astimezone(detector.LOCAL_TZ).strftime("%Y-%m-%dT%H:%M:%S") if until else "9999-12-31T23:59:59"

    db = detector.get_db()
    client = detector.get_influx()
    if not client:
        db.close()
        return jsonify({"error": "InfluxDB nicht erreichbar"}), 503

    # Delete all existing trips + charges in the period for this device
    deleted_trips = db.execute(
        """DELETE FROM trips WHERE device = ?
           AND datetime(start_time) >= datetime(?)
           AND datetime(start_time) <= datetime(?)""",
        (dev, since_local, until_local),
    ).rowcount
    # Clean up GPX waypoints and journey assignments
    db.execute(
        """DELETE FROM gpx_waypoints WHERE trip_id NOT IN (SELECT id FROM trips)""")
    db.execute(
        """DELETE FROM journey_trips WHERE trip_id NOT IN (SELECT id FROM trips)""")

    deleted_charges = db.execute(
        """DELETE FROM charges WHERE device = ?
           AND datetime(start_time) >= datetime(?)
           AND datetime(start_time) <= datetime(?)""",
        (dev, since_local, until_local),
    ).rowcount
    db.commit()
    log.info("Rescan %s: %d trips + %d charges deleted in period", dev, deleted_trips, deleted_charges)

    # Re-detect
    trips_found = 0
    charges_found = 0
    try:
        rows = detector.query_drive_data(client, since, dev, until=until)
        if rows:
            rows = detector.expand_rows(rows)
            bat_kwh = get_bat_kwh(db, dev)
            trips = detector.detect_trips(rows, bat_kwh, device=dev)
            charges = detector.detect_charges(rows, device=dev)
            if trips:
                detector.save_trips(db, trips)
                trips_found = len(trips)
            if charges:
                detector.save_charges(db, charges)
                charges_found = len(charges)
        detector.auto_categorize(db)
    except Exception as e:
        log.exception("Error during rescan")
        db.close()
        client.close()
        return jsonify({"error": str(e)}), 500

    db.close()
    client.close()
    return jsonify({
        "device": dev,
        "deleted_trips": deleted_trips,
        "deleted_charges": deleted_charges,
        "trips_found": trips_found,
        "charges_found": charges_found,
    })


# ── User management (admin only) ─────────────────────────────

@app.route("/api/admin/users")
@admin_required
def list_users():
    db = get_db()
    rows = db.execute("SELECT id, username, is_admin, created_at, totp_enabled FROM users ORDER BY id").fetchall()
    db.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/admin/users", methods=["POST"])
@admin_required
def create_user():
    data = request.get_json()
    username = data.get("username", "").strip()
    password = data.get("password", "")
    is_admin = 1 if data.get("is_admin") else 0

    if not username or not password:
        return jsonify({"error": "Benutzername und Passwort erforderlich"}), 400
    pw_err = _validate_password(password)
    if pw_err:
        return jsonify({"error": pw_err}), 400

    db = get_db()
    existing = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
    if existing:
        db.close()
        return jsonify({"error": "Benutzername existiert bereits"}), 400

    db.execute(
        "INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)",
        (username, generate_password_hash(password), is_admin),
    )
    db.commit()
    db.close()
    return jsonify({"ok": True})


@app.route("/api/admin/users/<int:user_id>", methods=["DELETE"])
@admin_required
def delete_user(user_id):
    if user_id == current_user.id:
        return jsonify({"error": "Eigenen Account nicht loeschbar"}), 400
    db = get_db()
    db.execute("DELETE FROM users WHERE id = ?", (user_id,))
    db.commit()
    db.close()
    return jsonify({"ok": True})


@app.route("/api/admin/users/<int:user_id>/password", methods=["POST"])
@admin_required
def change_password(user_id):
    data = request.get_json()
    password = data.get("password", "")
    pw_err = _validate_password(password)
    if pw_err:
        return jsonify({"error": pw_err}), 400
    db = get_db()
    db.execute("UPDATE users SET password_hash = ? WHERE id = ?",
               (generate_password_hash(password), user_id))
    db.commit()
    db.close()
    return jsonify({"ok": True})


@app.route("/api/admin/db-stats")
@admin_required
def admin_db_stats():
    import time
    import os
    result = {"sqlite": {}, "influx": {}}

    db = get_db()
    try:
        try:
            result["sqlite"]["file_bytes"] = os.path.getsize(config.DB_PATH)
        except Exception:
            result["sqlite"]["file_bytes"] = 0

        pc = db.execute("PRAGMA page_count").fetchone()[0]
        ps = db.execute("PRAGMA page_size").fetchone()[0]
        fl = db.execute("PRAGMA freelist_count").fetchone()[0]
        result["sqlite"]["fragmentation_pct"] = round(fl / pc * 100, 1) if pc > 0 else 0

        tables = [
            "trips", "locations", "charges", "route_rules", "users",
            "purpose_meta", "preset_values", "settings", "vehicles",
            "charge_tariffs", "charge_readings", "charge_sessions",
            "charge_locations", "journeys", "journey_trips",
        ]
        counts = {}
        for tbl in tables:
            try:
                counts[tbl] = db.execute(f"SELECT COUNT(*) FROM {tbl}").fetchone()[0]
            except Exception:
                counts[tbl] = None
        result["sqlite"]["tables"] = counts
        result["sqlite"]["total_rows"] = sum(v for v in counts.values() if v is not None)

        t0 = time.time()
        ic = db.execute("PRAGMA integrity_check(20)").fetchall()
        result["sqlite"]["integrity_ms"] = round((time.time() - t0) * 1000)
        result["sqlite"]["integrity_ok"] = ic[0][0] == "ok"
        result["sqlite"]["integrity_issues"] = [r[0] for r in ic if r[0] != "ok"]

        t0 = time.time()
        db.execute("CREATE TEMP TABLE _spd (x INTEGER)")
        for i in range(100):
            db.execute("INSERT INTO _spd VALUES (?)", (i,))
        db.execute("SELECT COUNT(*) FROM _spd")
        db.execute("DROP TABLE _spd")
        result["sqlite"]["write_100_ms"] = round((time.time() - t0) * 1000)
    finally:
        db.close()

    if not config.INFLUX_TOKEN:
        result["influx"]["status"] = "not_configured"
    else:
        try:
            from influxdb_client import InfluxDBClient
            client = InfluxDBClient(url=config.INFLUX_URL, token=config.INFLUX_TOKEN, org=config.INFLUX_ORG)
            t0 = time.time()
            health = client.health()
            result["influx"]["ping_ms"] = round((time.time() - t0) * 1000)
            result["influx"]["status"] = str(health.status)
            result["influx"]["version"] = getattr(health, "version", None)

            q_api = client.query_api()
            t0 = time.time()
            tbl_l = q_api.query(
                f'from(bucket:"{config.INFLUX_BUCKET}") |> range(start:-90d)'
                f' |> filter(fn:(r)=>r._measurement=="v") |> last() |> keep(columns:["_time"])',
                org=config.INFLUX_ORG,
            )
            result["influx"]["query_ms"] = round((time.time() - t0) * 1000)
            latest = None
            for tbl in tbl_l:
                for rec in tbl.records:
                    ts = rec.get_time()
                    if ts and (latest is None or ts > latest):
                        latest = ts
            result["influx"]["latest_record"] = latest.isoformat() if latest else None

            t0 = time.time()
            tbl_c = q_api.query(
                f'from(bucket:"{config.INFLUX_BUCKET}") |> range(start:-7d)'
                f' |> filter(fn:(r)=>r._measurement=="v") |> count() |> sum(column:"_value")',
                org=config.INFLUX_ORG,
            )
            result["influx"]["count_query_ms"] = round((time.time() - t0) * 1000)
            pts = 0
            for tbl in tbl_c:
                for rec in tbl.records:
                    v = rec.get_value()
                    if v:
                        pts += int(v)
            result["influx"]["points_7d"] = pts
            client.close()

            # Disk size via Prometheus /metrics endpoint
            import urllib.request as _ur
            try:
                _req = _ur.Request(
                    f"{config.INFLUX_URL}/metrics",
                    headers={"Authorization": f"Token {config.INFLUX_TOKEN}"},
                )
                with _ur.urlopen(_req, timeout=5) as _resp:
                    _metrics = _resp.read().decode("utf-8", errors="replace")
                _disk = 0
                for _line in _metrics.splitlines():
                    if not _line.startswith("#") and "disk_bytes" in _line:
                        _parts = _line.split()
                        if len(_parts) >= 2:
                            try:
                                _disk += float(_parts[-1])
                            except ValueError:
                                pass
                result["influx"]["disk_bytes"] = int(_disk) if _disk else None
            except Exception:
                result["influx"]["disk_bytes"] = None
        except Exception as e:
            result["influx"]["status"] = "error"
            result["influx"]["error"] = str(e)

    return jsonify(result)


@app.route("/api/change-password", methods=["POST"])
@login_required
def change_own_password():
    """Change own password."""
    data = request.get_json()
    old_pw = data.get("old_password", "")
    new_pw = data.get("new_password", "")

    pw_err = _validate_password(new_pw)
    if pw_err:
        return jsonify({"error": pw_err}), 400

    db = get_db()
    row = db.execute("SELECT password_hash FROM users WHERE id = ?", (current_user.id,)).fetchone()
    if not check_password_hash(row["password_hash"], old_pw):
        db.close()
        return jsonify({"error": "Altes Passwort falsch"}), 400

    db.execute("UPDATE users SET password_hash = ? WHERE id = ?",
               (generate_password_hash(new_pw), current_user.id))
    db.commit()
    db.close()
    return jsonify({"ok": True})


# ── Detector + geocoder in background ────────────────────────

# ── MQTT Monitor ─────────────────────────────────────────────

import collections
_mqtt_messages = collections.deque(maxlen=500)  # last 500 messages
_mqtt_connected = False
_mqtt_influx_count = 0  # Counter: successfully written InfluxDB points
_mqtt_influx_failed = 0  # Counter: failed InfluxDB writes


def background_mqtt():
    """MQTT subscriber: connects to Mosquitto, collects messages and
    writes telemetry data (tele/+/data) to InfluxDB.
    Receives AES-256-CBC encrypted binary telegrams (protocol v1)."""
    global _mqtt_connected, _mqtt_influx_count, _mqtt_influx_failed

    try:
        import paho.mqtt.client as mqtt
    except ImportError:
        log.warning("MQTT: paho-mqtt nicht installiert")
        return

    from influxdb_client import InfluxDBClient, WritePrecision
    from influxdb_client.client.write_api import SYNCHRONOUS
    import struct
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.padding import PKCS7

    aes_key = bytes.fromhex(config.MQTT_AES_KEY)

    # Binary field schema: (bit, key, struct_fmt, byte_count, divisor)
    # Bool fields (fmt=None, bytes=0): bit set in field_mask = true
    _BIN_FIELDS = [
        (0,  'la', '<i', 4, 1_000_000),
        (1,  'lo', '<i', 4, 1_000_000),
        (2,  'hd', '<H', 2, None),
        (3,  's',  '<H', 2, 10),
        (4,  'u',  '<H', 2, None),
        (5,  'i',  '<h', 2, None),
        (6,  'p',  '<h', 2, 10),
        (7,  'v',  '<H', 2, 10),
        (8,  'c',  None,  0, None),
        (9,  'dc', None,  0, None),
        (10, 'bt', '<b', 1, None),
        (11, 'et', '<b', 1, None),
        (12, 'r',  '<H', 2, 10),
        (13, 'ca', '<H', 2, 10),
        (14, 'kw', '<H', 2, 10),
        (15, 'pk', None,  0, None),
        (16, 'od', '<I', 4, 10),
        (17, 'ls', '<B', 1, None),
        (18, 'bd', '<B', 1, None),
        (19, 'lp', '<H', 2, None),  # LTE PLMN (MCC*100+MNC, e.g. 26201 = Telekom DE)
    ]

    def _decrypt_payload(raw):
        """Decrypt binary v1 telegram → dict with fields + ts."""
        if len(raw) < 17 or raw[0] != 0x01:
            return None
        iv = raw[1:17]
        ciphertext = raw[17:]
        try:
            cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
            decryptor = cipher.decryptor()
            padded = decryptor.update(ciphertext) + decryptor.finalize()
            unpadder = PKCS7(128).unpadder()
            plaintext = unpadder.update(padded) + unpadder.finalize()
        except Exception:
            return None  # Decryption failed → not authentic

        if len(plaintext) < 8:
            return None
        field_mask = struct.unpack_from('<I', plaintext, 0)[0]
        ts = struct.unpack_from('<I', plaintext, 4)[0]

        fields = {}
        offset = 8
        for bit, key, fmt, size, divisor in _BIN_FIELDS:
            if not (field_mask & (1 << bit)):
                continue
            if fmt is None:
                # Bool field: bit set = true
                fields[key] = 1
            else:
                if offset + size > len(plaintext):
                    return None  # incomplete telegram
                val = struct.unpack_from(fmt, plaintext, offset)[0]
                if divisor:
                    val = val / divisor
                fields[key] = val
                offset += size

        fields['ts'] = ts
        return fields

    # InfluxDB Write-Client (langlebig, Thread-safe)
    influx_write = None
    if config.INFLUX_TOKEN:
        _influx = InfluxDBClient(
            url=config.INFLUX_URL,
            token=config.INFLUX_TOKEN,
            org=config.INFLUX_ORG,
        )
        influx_write = _influx.write_api(write_options=SYNCHRONOUS)
        log.info("MQTT→InfluxDB Bridge aktiv (bucket=%s)", config.INFLUX_BUCKET)
    else:
        log.warning("MQTT: No INFLUX_TOKEN — data will not be written to InfluxDB")

    def on_connect(client, userdata, flags, reason_code, properties=None):
        global _mqtt_connected
        _mqtt_connected = True
        client.subscribe(config.MQTT_TOPIC)
        client.subscribe(config.MQTT_DATA_TOPIC)
        log.info("MQTT connected, subscribed to %s + %s",
                 config.MQTT_TOPIC, config.MQTT_DATA_TOPIC)

    def on_disconnect(client, userdata, flags, reason_code, properties=None):
        global _mqtt_connected
        _mqtt_connected = False
        log.warning("MQTT disconnected (rc=%s)", reason_code)

    def _write_to_influx(topic, data):
        """Write decoded telemetry fields as InfluxDB point. Returns status string."""
        global _mqtt_influx_count, _mqtt_influx_failed
        if not influx_write:
            return "no_client"

        parts = topic.split("/")
        if len(parts) < 3:
            return "bad_topic"
        device = parts[1]

        ts = data.pop("ts", None)

        fields = {k: v for k, v in data.items() if isinstance(v, (int, float))}
        if not fields:
            return "no_fields"

        from influxdb_client import Point
        point = Point("v").tag("d", device)
        # InfluxDB rejects type changes per field. Only 'v' (speed) is historically
        # integer — all other /10 fields (p, s, od, r, ca, kw) are float in DB.
        for k, val in fields.items():
            if k == 'v' and isinstance(val, float):
                val = int(round(val))
            point.field(k, val)
        if ts is not None:
            point.time(int(ts * 1_000_000_000), WritePrecision.NS)

        try:
            influx_write.write(bucket=config.INFLUX_BUCKET, record=point)
            _mqtt_influx_count += 1
            log.debug("MQTT→InfluxDB: %s → %d fields written, ts=%s", device, len(fields), ts)
            return "ok"
        except Exception as exc:
            _mqtt_influx_failed += 1
            log.warning("MQTT→InfluxDB write error: %s", exc)
            return f"error: {exc}"

    # ── MQTT→Detector trigger: 5 min silence = trigger scan ──
    import threading
    _device_timers = {}   # device → threading.Timer

    def _trigger_scan(device):
        """Called when no data has arrived for 5 minutes."""
        _device_timers.pop(device, None)
        log.info("MQTT: No data for 5 min for %s — triggering detector scan", device)
        try:
            detector.run_once()
        except Exception:
            log.exception("MQTT-triggered detector scan failed")

    def _reset_device_timer(device):
        """Reset timer for device — new countdown from now."""
        old = _device_timers.get(device)
        if old:
            old.cancel()
        t = threading.Timer(5 * 60, _trigger_scan, args=(device,))
        t.daemon = True
        t.start()
        _device_timers[device] = t

    def on_message(client, userdata, msg):
        raw = msg.payload
        entry = {
            "time": datetime.now().strftime("%H:%M:%S"),
            "topic": msg.topic,
            "payload": raw[:40].hex() if len(raw) > 0 and raw[0] == 0x01 else raw.decode("utf-8", errors="replace"),
            "qos": msg.qos,
            "size": len(raw),
        }
        # Decrypt telemetry data and forward to InfluxDB
        if msg.topic.endswith("/data"):
            data = _decrypt_payload(raw)
            if data is None:
                log.debug("MQTT: Decryption failed on %s (%d bytes)", msg.topic, len(raw))
                entry["decoded"] = None
            else:
                # Include ts in decoded for debug visibility
                entry["decoded"] = dict(data)
                entry["ts"] = data.get("ts")
                write_ok = _write_to_influx(msg.topic, data)
                entry["written"] = write_ok
                parts = msg.topic.split("/")
                if len(parts) >= 3:
                    device = parts[1]
                    _reset_device_timer(device)
                    # SSE: real-time push to connected dashboard clients
                    sse_publish(device, dict(data))
        _mqtt_messages.appendleft(entry)

    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id="triplog-monitor")
    if config.MQTT_USER:
        client.username_pw_set(config.MQTT_USER, config.MQTT_PASS)
    if config.MQTT_TLS:
        import ssl
        client.tls_set(cert_reqs=ssl.CERT_NONE)
        client.tls_insecure_set(True)
    client.on_connect = on_connect
    client.on_disconnect = on_disconnect
    client.on_message = on_message

    while True:
        try:
            client.connect(config.MQTT_BROKER, config.MQTT_PORT, 60)
            client.loop_forever()
        except Exception as e:
            log.warning("MQTT connection failed: %s — retry in 30s", e)
            _mqtt_connected = False
            time.sleep(30)


def background_detector():
    detector.run_loop()


def background_geocoder():
    """Geocode missing addresses every 10 minutes."""
    import time
    while True:
        try:
            geo.run_once()
        except Exception:
            logging.exception("Geocoder error")
        time.sleep(600)


# ── Ladetracker ──────────────────────────────────────────────


def rebuild_charge_sessions(db):
    """Session detection: groups readings by vehicle + odometer.

    External sessions (is_external=1) are preserved, only automatic
    sessions are recalculated.
    """
    from collections import defaultdict
    from datetime import datetime

    # Save user-assigned fields before deletion (key: vehicle_plate + odometer)
    _saved = {}
    for row in db.execute("""SELECT vehicle_plate, odometer, location_name, operator, note, cost_total
                             FROM charge_sessions WHERE is_external = 0""").fetchall():
        key = (row['vehicle_plate'], row['odometer'])
        if row['location_name'] or row['operator'] or row['note'] or row['cost_total']:
            _saved[key] = {
                'location_name': row['location_name'],
                'operator': row['operator'],
                'note': row['note'],
                'cost_total': row['cost_total'],
            }

    # Preserve external sessions
    db.execute("DELETE FROM charge_sessions WHERE is_external = 0")
    db.execute("UPDATE charge_readings SET session_id = NULL")

    readings = db.execute("""
        SELECT * FROM charge_readings
        WHERE vehicle_plate NOT IN ('free', '')
        ORDER BY vehicle_plate, timestamp
    """).fetchall()

    groups = defaultdict(list)
    for r in readings:
        odo = round(r['odometer']) if r['odometer'] is not None else 0
        key = (r['vehicle_plate'], odo)
        groups[key].append(dict(r))

    for (plate, odo), reads in groups.items():
        reads.sort(key=lambda x: x['timestamp'])
        start_time = reads[0]['timestamp']
        end_time = reads[-1]['timestamp']
        total_kwh = sum(r['kwh'] or 0 for r in reads)
        m_start = reads[0]['meter_start']
        m_end = reads[-1]['meter_end']

        try:
            t0 = datetime.fromisoformat(start_time)
            t1 = datetime.fromisoformat(end_time)
            # Estimate actual end time within last 15-min interval:
            # Use avg kW from previous reading to calculate how many minutes
            # the last reading's kWh actually took.
            last_kwh = reads[-1]['kwh'] or 0
            if len(reads) >= 2 and last_kwh > 0:
                prev_kwh = reads[-2]['kwh'] or 0
                if prev_kwh > 0:
                    prev_kw = prev_kwh * 4  # kWh per 15min -> kW
                    last_minutes = min((last_kwh / prev_kw) * 60, 15)
                else:
                    last_minutes = 15
            else:
                last_minutes = 15
            t1_adj = t1 + timedelta(minutes=round(last_minutes))
            end_time = t1_adj.isoformat()
            duration_min = max(int((t1_adj - t0).total_seconds() / 60), 15)
        except Exception:
            duration_min = 15

        avg_kw = round(total_kwh / (duration_min / 60), 2) if duration_min > 0 else 0

        cost_tibber = sum(
            (r['kwh'] or 0) * (r['tibber_price'] or 0) + (r['tibber_grundgebuehr'] or 0)
            for r in reads
        )

        tariff = db.execute(
            "SELECT pauschale_kwh FROM charge_tariffs WHERE valid_from <= ? ORDER BY valid_from DESC LIMIT 1",
            (start_time[:10],)
        ).fetchone()
        pauschale = tariff['pauschale_kwh'] if tariff else 0.34

        cost_pauschale = total_kwh * pauschale
        cost_diff = cost_pauschale - cost_tibber
        avg_tibber = cost_tibber / total_kwh if total_kwh > 0 else 0

        # SOC: first and last non-null soc value in this session
        soc_vals = [r['soc'] for r in reads if r.get('soc') is not None]
        soc_start = soc_vals[0] if soc_vals else None
        soc_end = soc_vals[-1] if soc_vals else None

        cur = db.execute("""
            INSERT INTO charge_sessions
            (vehicle_plate, start_time, end_time, meter_start, meter_end,
             total_kwh, duration_minutes, avg_kw, odometer, cost_tibber,
             cost_pauschale, cost_diff, avg_tibber_price, soc_start, soc_end)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (plate, start_time, end_time, m_start, m_end,
              round(total_kwh, 3), duration_min, avg_kw, odo,
              round(cost_tibber, 4), round(cost_pauschale, 4),
              round(cost_diff, 4), round(avg_tibber, 4),
              soc_start, soc_end))

        session_id = cur.lastrowid
        reading_ids = [r['id'] for r in reads]
        placeholders = ','.join('?' * len(reading_ids))
        db.execute(
            f"UPDATE charge_readings SET session_id = ? WHERE id IN ({placeholders})",
            [session_id] + reading_ids
        )

    # Restore user-assigned fields
    if _saved:
        for row in db.execute("SELECT id, vehicle_plate, odometer FROM charge_sessions WHERE is_external = 0").fetchall():
            key = (row['vehicle_plate'], row['odometer'])
            saved = _saved.get(key)
            if saved:
                sets = []
                params = []
                for field in ('location_name', 'operator', 'note', 'cost_total'):
                    if saved[field] is not None:
                        sets.append(f"{field} = ?")
                        params.append(saved[field])
                if sets:
                    db.execute(f"UPDATE charge_sessions SET {', '.join(sets)} WHERE id = ?",
                               params + [row['id']])

    # Assign session numbers (regular only, external remain empty)
    start_row = db.execute("SELECT value FROM settings WHERE key = 'charge_session_start'").fetchone()
    start_num = int(start_row['value']) if start_row else 1

    all_sessions = db.execute("""
        SELECT id, is_external, session_number FROM charge_sessions ORDER BY datetime(start_time)
    """).fetchall()
    num = start_num
    for s in all_sessions:
        if s['is_external']:
            db.execute("UPDATE charge_sessions SET session_number = NULL WHERE id = ?",
                       (s['id'],))
        else:
            db.execute("UPDATE charge_sessions SET session_number = ? WHERE id = ?",
                       (str(num), s['id']))
            num += 1

    # Calculate distances (per vehicle, sorted by start time)
    # Distance = km driven FROM this charge TO the next charge
    # (last/newest session has no distance — next charge unknown)
    vehicles = db.execute("SELECT DISTINCT vehicle_plate FROM charge_sessions").fetchall()
    for v in vehicles:
        sessions = db.execute("""
            SELECT id, odometer FROM charge_sessions
            WHERE vehicle_plate = ? ORDER BY datetime(start_time)
        """, (v['vehicle_plate'],)).fetchall()
        for i, s in enumerate(sessions):
            if s['odometer'] is not None and i + 1 < len(sessions):
                next_s = sessions[i + 1]
                if next_s['odometer'] is not None:
                    dist = next_s['odometer'] - s['odometer']
                    db.execute("UPDATE charge_sessions SET distance = ? WHERE id = ?",
                               (round(dist, 1), s['id']))
                    continue
            db.execute("UPDATE charge_sessions SET distance = NULL WHERE id = ?",
                       (s['id'],))

    # Determine location from trips (end of last trip before charge start)
    plate_device = {}
    for v in db.execute("SELECT plate, device FROM vehicles WHERE device IS NOT NULL").fetchall():
        plate_device[v['plate']] = v['device']

    loc_sessions = db.execute("""
        SELECT id, vehicle_plate, start_time, end_time, lat, lon, is_external
        FROM charge_sessions ORDER BY datetime(start_time)
    """).fetchall()
    for s in loc_sessions:
        # Skip external sessions with already set position
        if s['lat'] and s['lon']:
            loc = match_charge_location(db, s['lat'], s['lon']) or match_location(db, s['lat'], s['lon'])
            if loc and not db.execute("SELECT location_name FROM charge_sessions WHERE id = ?", (s['id'],)).fetchone()['location_name']:
                db.execute("UPDATE charge_sessions SET location_name = ? WHERE id = ?",
                           (loc['name'], s['id']))
            continue

        device = plate_device.get(s['vehicle_plate'])
        if not device:
            continue

        # Calculate midpoint of charge session
        mid_time = s['start_time']
        if s['start_time'] and s['end_time']:
            try:
                t0 = datetime.fromisoformat(s['start_time'])
                t1 = datetime.fromisoformat(s['end_time'])
                mid = t0 + (t1 - t0) / 2
                mid_time = mid.isoformat()
            except Exception:
                pass

        # Last trip before/during charge session with end position
        trip = db.execute("""
            SELECT end_lat, end_lon FROM trips
            WHERE device = ? AND end_time <= ? AND end_lat IS NOT NULL AND end_lon IS NOT NULL
            ORDER BY end_time DESC LIMIT 1
        """, (device, mid_time)).fetchone()

        if not trip:
            continue

        lat, lon = trip['end_lat'], trip['end_lon']
        loc = match_charge_location(db, lat, lon) or match_location(db, lat, lon)
        loc_name = loc['name'] if loc else None
        # Do not overwrite manual assignment
        existing = db.execute("SELECT location_name FROM charge_sessions WHERE id = ?", (s['id'],)).fetchone()
        if existing and existing['location_name']:
            db.execute("UPDATE charge_sessions SET lat = ?, lon = ? WHERE id = ?",
                       (lat, lon, s['id']))
        else:
            db.execute("UPDATE charge_sessions SET lat = ?, lon = ?, location_name = ? WHERE id = ?",
                       (lat, lon, loc_name, s['id']))

    # Auto-create vehicles
    plates = db.execute("""
        SELECT DISTINCT vehicle_plate FROM charge_readings
        WHERE vehicle_plate NOT IN ('free', 'error', 'unknown', '')
    """).fetchall()
    for p in plates:
        db.execute("INSERT OR IGNORE INTO vehicles (plate) VALUES (?)", (p['vehicle_plate'],))

    db.commit()


# ── Webhook: HA sends quarter-hourly data ────────────────────

@app.route("/api/charge/reading", methods=["POST"])
def charge_webhook():
    """Receive 15-min readings from Home Assistant."""
    # Token auth (optional, if CHARGE_WEBHOOK_TOKEN is set)
    token = config.CHARGE_WEBHOOK_TOKEN
    if token:
        auth = request.headers.get("Authorization", "")
        if auth != f"Bearer {token}" and request.args.get("token") != token:
            return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json(force=True, silent=True)
    if not data:
        return jsonify({"error": "JSON erwartet"}), 400

    vehicle = str(data.get("vehicle", "")).strip()
    if not vehicle or vehicle == "free":
        return jsonify({"ok": True, "skipped": True})
    if vehicle in ("error", "unknown"):
        vehicle = "unknown"

    kwh = float(data.get("kwh", 0) or 0)
    if kwh <= 0:
        return jsonify({"ok": True, "skipped": True})

    timestamp = data.get("timestamp", "")
    # HA sends UTC — convert to local time (trips are Europe/Berlin)
    if timestamp:
        try:
            from zoneinfo import ZoneInfo
            dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=ZoneInfo("UTC"))
            timestamp = dt.astimezone(ZoneInfo("Europe/Berlin")).strftime("%Y-%m-%dT%H:%M:%S")
        except Exception:
            pass
    odometer_raw = data.get("odometer", "")
    odometer = float(odometer_raw) if odometer_raw not in ("", None) else None

    tibber_price_raw = data.get("tibber_price", 0)
    tibber_grund_raw = data.get("tibber_grundgebuehr", 0)
    soc_raw = data.get("soc", None)
    soc = float(soc_raw) if soc_raw not in ("", None) else None

    db = get_db()
    db.execute("""
        INSERT INTO charge_readings
        (timestamp, vehicle_plate, meter_start, meter_end, kwh,
         tibber_price, tibber_grundgebuehr, odometer, soc)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        timestamp,
        vehicle,
        float(data.get("meter_start", 0) or 0),
        float(data.get("meter_end", 0) or 0),
        kwh,
        float(tibber_price_raw) if tibber_price_raw not in ("", None) else None,
        float(tibber_grund_raw) if tibber_grund_raw not in ("", None) else None,
        odometer,
        soc,
    ))
    db.commit()

    rebuild_charge_sessions(db)
    db.close()
    return jsonify({"ok": True})


# ── Charge sessions page ────────────────────────────────────

@app.route("/charges")
def charges_list():
    filter_vehicle = request.args.get("vehicle", "")
    date_from = request.args.get("from", "") or session.get("charges_date_from", "")
    date_to = request.args.get("to", "") or session.get("charges_date_to", "")

    # Persist filter in session: explicit URL params (incl. empty for reset) override
    if "from" in request.args or "to" in request.args:
        session["charges_date_from"] = request.args.get("from", "")
        session["charges_date_to"] = request.args.get("to", "")

    # Default: active vehicle from global filter
    if not filter_vehicle:
        v = active_vehicle()
        if v:
            filter_vehicle = v["plate"]

    db = get_db()

    query = "SELECT * FROM charge_sessions WHERE 1=1"
    params = []

    if filter_vehicle:
        query += " AND vehicle_plate = ?"
        params.append(filter_vehicle)
    if date_from:
        query += " AND start_time >= ?"
        params.append(date_from)
    if date_to:
        query += " AND start_time <= ?"
        params.append(date_to + "T23:59:59")

    query += " ORDER BY datetime(start_time) DESC"
    sessions = db.execute(query, params).fetchall()

    vehicles = db.execute("SELECT * FROM vehicles ORDER BY plate").fetchall()
    tariffs = db.execute("SELECT * FROM charge_tariffs ORDER BY valid_from DESC").fetchall()

    vehicle_names = {}
    for v in vehicles:
        vehicle_names[v['plate']] = v['name'] or v['plate']

    # Charge location operators (name → operator key + color + icon)
    loc_operators = {}
    for cl in db.execute("""SELECT cl.name, cl.operator, cl.type, cl.color, cl.icon_filename,
                                   op.icon_filename AS op_icon_filename, op.color AS op_color
                            FROM charge_locations cl
                            LEFT JOIN operators op ON cl.operator_id = op.id""").fetchall():
        if cl['icon_filename']:
            icon_url = f"/media/charge-icons/{cl['icon_filename']}"
        elif cl['op_icon_filename']:
            icon_url = f"/media/operator-icons/{cl['op_icon_filename']}"
        else:
            icon_url = None
        loc_operators[cl['name']] = {
            'operator': cl['operator'] or '',
            'type': cl['type'] or 'ac',
            'color': cl['op_color'] or cl['color'] or '#8b949e',
            'icon_url': icon_url,
        }

    # All charge locations with operator names for dropdown
    all_locations_list = db.execute(
        """SELECT cl.name, op.name AS op_name FROM charge_locations cl
           LEFT JOIN operators op ON cl.operator_id = op.id
           ORDER BY cl.name"""
    ).fetchall()

    # Webhook URL hint
    webhook_url = f"http://<HOST>:{request.host.split(':')[-1] if ':' in request.host else '3004'}"

    # Session start number
    start_row = db.execute("SELECT value FROM settings WHERE key = 'charge_session_start'").fetchone()
    session_start = int(start_row['value']) if start_row else 1

    db.close()
    return render_template("charges.html",
                           sessions=sessions,
                           vehicles=vehicles,
                           tariffs=tariffs,
                           vehicle_names=vehicle_names,
                           loc_operators=loc_operators,
                           all_locations=all_locations_list,
                           filter_vehicle=filter_vehicle,
                           date_from=date_from,
                           date_to=date_to,
                           webhook_url=webhook_url,
                           session_start=session_start)


# ── Charge print view ────────────────────────────────────

@app.route("/charges/print")
@login_required
def charges_print():
    MONTH_NAMES_DE = ['', 'Januar', 'Februar', 'März', 'April', 'Mai', 'Juni',
                      'Juli', 'August', 'September', 'Oktober', 'November', 'Dezember']

    month = request.args.get("month", "")
    year = request.args.get("year", "")

    # Vehicle always from global filter
    filter_vehicle = ""
    v = active_vehicle()
    if v:
        filter_vehicle = v["plate"]

    db = get_db()

    # Vehicle data
    vehicle = db.execute("SELECT * FROM vehicles WHERE plate = ?",
                         (filter_vehicle,)).fetchone() if filter_vehicle else None

    # ALL sessions in the month (all vehicles) for excluded hint
    all_query = "SELECT * FROM charge_sessions WHERE 1=1"
    all_params = []
    if year:
        all_query += " AND strftime('%Y', start_time) = ?"
        all_params.append(year)
    if month:
        all_query += " AND strftime('%m', start_time) = ?"
        all_params.append(month.zfill(2))
    all_query += " ORDER BY datetime(start_time)"
    all_sessions = db.execute(all_query, all_params).fetchall()

    # Own sessions (this vehicle)
    sessions = [s for s in all_sessions if s['vehicle_plate'] == filter_vehicle] if filter_vehicle else all_sessions

    # Excluded sessions (other vehicles)
    excluded_sessions = [s['session_number'] or str(s['id']) for s in all_sessions
                         if filter_vehicle and s['vehicle_plate'] != filter_vehicle
                         and not s['is_external']]

    # Determine flat rate
    tariff_date = f"{year}-{month.zfill(2)}-01" if year and month else None
    tariff = None
    if tariff_date:
        tariff = db.execute(
            "SELECT pauschale_kwh FROM charge_tariffs WHERE valid_from <= ? ORDER BY valid_from DESC LIMIT 1",
            (tariff_date,)).fetchone()
    if not tariff:
        tariff = db.execute("SELECT pauschale_kwh FROM charge_tariffs ORDER BY valid_from DESC LIMIT 1").fetchone()
    pauschale_kwh = tariff['pauschale_kwh'] if tariff else 0.34

    # Totals only for own (non-external) sessions
    own_sessions = [s for s in sessions if not s['is_external']]
    own_total_kwh = sum(s['total_kwh'] or 0 for s in own_sessions)
    own_total_cost = sum(
        (s['cost_pauschale'] if s['cost_pauschale'] is not None else (s['total_kwh'] or 0) * pauschale_kwh)
        for s in own_sessions
    )

    # Month/year display
    month_int = int(month) if month else datetime.now().month
    year_str = year or str(datetime.now().year)
    month_name = MONTH_NAMES_DE[month_int]
    # First and last day of the month
    last_day = calendar.monthrange(int(year_str), month_int)[1]
    date_from = f"01.{month.zfill(2)}.{year_str}" if month and year else ""
    date_to = f"{last_day}.{month.zfill(2)}.{year_str}" if month and year else ""

    # Date formatting per session
    sessions_fmt = []
    for s in sessions:
        d = dict(s)
        try:
            dt = datetime.fromisoformat(s['start_time'])
            d['start_fmt'] = f"{dt.day}. {MONTH_NAMES_DE[dt.month]}"
            d['start_time_fmt'] = dt.strftime("%H:%M")
        except Exception:
            d['start_fmt'] = s['start_time'][:10] if s['start_time'] else '--'
            d['start_time_fmt'] = None
        try:
            et = datetime.fromisoformat(s['end_time'])
            d['end_time_fmt'] = et.strftime("%H:%M")
        except Exception:
            d['end_time_fmt'] = None
        sessions_fmt.append(d)

    # Available years
    years_rows = db.execute(
        "SELECT DISTINCT strftime('%Y', start_time) AS y FROM charge_sessions ORDER BY y DESC"
    ).fetchall()

    # Invoice defaults from settings
    settings_rows = db.execute("SELECT key, value FROM settings").fetchall()
    _f = _settings_fernet()
    settings = {}
    for r in settings_rows:
        v = r["value"]
        if r["key"] in ENCRYPTED_SETTINGS:
            v = _decrypt_setting(_f, v)
        settings[r["key"]] = v

    plate = vehicle['plate'] if vehicle else filter_vehicle
    model = vehicle['model'] if vehicle and vehicle['model'] else ''

    lang = get_language()
    if lang == "EN":
        _def_sender = 'Company / Name<br>Street No.<br>ZIP City'
        _def_recipient = 'Recipient Name<br>Street No.<br>ZIP City'
        _def_intro = (
            f'Dear Sir or Madam,<br><br>'
            f'please find below the charging cost statement for the above-mentioned '
            f'electric vehicle for the period from {date_from} to {date_to}.')
        _def_meter = (
            'Charging sessions are assigned to the vehicle by '
            'technical identification at the charging location.')
        _def_meter_info = 'Meter type / serial number'
        _def_tariff_ref = 'Electricity tariff as agreed'
        _def_data_info = (
            'Energy consumption is recorded by the electricity meter at the charging station. '
            'Meter readings are collected automatically and assigned to the vehicle. '
            'Costs are calculated based on the agreed electricity rate.')
    else:
        _def_sender = 'Firma / Name<br>Straße Nr.<br>PLZ Ort'
        _def_recipient = 'Empfänger Name<br>Straße Nr.<br>PLZ Ort'
        _def_intro = (
            'Sehr geehrte Damen und Herren,<br><br>'
            'hiermit erfolgt die Abrechnung der Stromkosten für das oben genannte '
            f'Elektrofahrzeug im Zeitraum vom {date_from} bis zum {date_to}.')
        _def_meter = (
            'Die Zuordnung der Ladevorgänge erfolgt durch technische '
            'Identifizierung des Fahrzeugs am Ladestandort.')
        _def_meter_info = 'Zähler Typ / Seriennummer'
        _def_tariff_ref = 'Stromtarif laut Vereinbarung'
        _def_data_info = (
            'Die Energiemenge wird über den Stromzähler an der Ladestation erfasst. '
            'Zählerstände werden automatisch ausgelesen und dem Fahrzeug zugeordnet. '
            'Die Kosten werden auf Basis des vereinbarten Strompreises berechnet.')

    invoice_sender = settings.get('invoice_sender', _def_sender)
    invoice_recipient = settings.get('invoice_recipient', _def_recipient)
    invoice_intro = settings.get('invoice_intro', _def_intro)
    invoice_meter_text = settings.get('invoice_meter_text', _def_meter)
    invoice_meter_info = settings.get('invoice_meter_info', _def_meter_info)
    invoice_tariff_ref = settings.get('invoice_tariff_ref', _def_tariff_ref)
    invoice_data_info = settings.get('invoice_data_info', _def_data_info)

    # Replace variables in stored texts
    replacements = {
        '{date_from}': date_from, '{date_to}': date_to,
        '{month}': month_name, '{year}': year_str,
        '{plate}': plate or '', '{model}': model,
        '{kwh}': f"{own_total_kwh:.2f}", '{cost}': f"{own_total_cost:.2f}",
        '{pauschale}': f"{pauschale_kwh:.2f}",
    }
    for key, val in replacements.items():
        invoice_intro = invoice_intro.replace(key, val)
        invoice_meter_text = invoice_meter_text.replace(key, val)

    # ── Statistics for optional print page ──
    show_stats = request.args.get("stats") == "1"
    stats_data = {}
    if show_stats and filter_vehicle and year and month:
        device = active_device()
        end_ym = f"{year_str}-{month.zfill(2)}"

        # Find earliest month with data (trips or charges)
        first_trip = db.execute(
            "SELECT strftime('%Y-%m', start_time) AS ym FROM trips "
            "WHERE device = ? AND odo_end IS NOT NULL ORDER BY start_time LIMIT 1",
            (device,)
        ).fetchone()
        first_charge = db.execute(
            "SELECT strftime('%Y-%m', start_time) AS ym FROM charge_sessions "
            "WHERE vehicle_plate = ? AND NOT is_external ORDER BY start_time LIMIT 1",
            (filter_vehicle,)
        ).fetchone()
        earliest_yms = [r['ym'] for r in [first_trip, first_charge] if r and r['ym']]
        # At most 12 months back
        end_val = int(year_str) * 12 + int(month)
        start_12 = end_val - 11
        start_12_ym = f"{(start_12 - 1) // 12}-{(start_12 - 1) % 12 + 1:02d}"
        first_ym = min(earliest_yms) if earliest_yms else start_12_ym
        if first_ym < start_12_ym:
            first_ym = start_12_ym

        # Build month list from first_ym to end_ym
        stats_months = []
        fy, fm = int(first_ym[:4]), int(first_ym[5:7])
        ey, em = int(end_ym[:4]), int(end_ym[5:7])
        cy, cm = fy, fm
        while cy * 12 + cm <= ey * 12 + em:
            stats_months.append((cy, cm))
            cm += 1
            if cm > 12:
                cm = 1
                cy += 1

        # Odometer from trips (odo_end, max per month)
        odo_rows = db.execute(
            "SELECT strftime('%Y-%m', start_time) AS ym, MAX(odo_end) AS max_odo "
            "FROM trips WHERE device = ? AND odo_end IS NOT NULL "
            "GROUP BY ym ORDER BY ym",
            (device,)
        ).fetchall()
        odo_by_month = {r['ym']: r['max_odo'] for r in odo_rows}

        # Charge energy from charge_sessions (meter-based, non-external)
        charge_rows = db.execute(
            "SELECT strftime('%Y-%m', start_time) AS ym, "
            "SUM(meter_end - meter_start) AS meter_kwh, "
            "SUM(total_kwh) AS sum_kwh, "
            "SUM(CASE WHEN cost_pauschale IS NOT NULL THEN cost_pauschale "
            "    ELSE COALESCE(total_kwh, 0) * ? END) AS sum_cost "
            "FROM charge_sessions WHERE vehicle_plate = ? AND NOT is_external "
            "GROUP BY ym ORDER BY ym",
            (pauschale_kwh, filter_vehicle)
        ).fetchall()
        charge_by_month = {}
        for r in charge_rows:
            charge_by_month[r['ym']] = {'kwh': r['sum_kwh'] or 0, 'cost': r['sum_cost'] or 0}

        # Consumption per 100km: only use intervals with no external charge in between
        all_sessions_ordered = db.execute(
            "SELECT strftime('%Y-%m', start_time) AS ym, odometer, is_external, "
            "total_kwh, "
            "CASE WHEN cost_pauschale IS NOT NULL THEN cost_pauschale "
            "     ELSE COALESCE(total_kwh, 0) * ? END AS session_cost "
            "FROM charge_sessions "
            "WHERE vehicle_plate = ? AND odometer IS NOT NULL "
            "ORDER BY datetime(start_time)",
            (pauschale_kwh, filter_vehicle)
        ).fetchall()
        # Walk through all sessions in order; only count an interval
        # if both current and previous session are wallbox (non-external).
        # The current session's energy/cost replenishes what was consumed
        # driving the km since the previous charge.
        # Skip implausible intervals (< 8 kWh/100km) — indicates untracked
        # external charging between sessions.
        cons_by_month = {}  # ym -> {'kwh': ..., 'dist': ...}
        prev_session = None
        for s in all_sessions_ordered:
            if prev_session is not None and not s['is_external'] and not prev_session['is_external']:
                d = s['odometer'] - prev_session['odometer']
                kwh = s['total_kwh'] or 0
                if d > 0 and kwh > 0:
                    cons_check = kwh / d * 100
                    if cons_check >= 8:  # plausible EV consumption
                        ym = s['ym']
                        if ym not in cons_by_month:
                            cons_by_month[ym] = {'kwh': 0, 'dist': 0, 'cost': 0}
                        cons_by_month[ym]['kwh'] += kwh
                        cons_by_month[ym]['dist'] += d
                        cons_by_month[ym]['cost'] += (s['session_cost'] or 0)
            prev_session = s

        monthly = []
        for sy, sm in stats_months:
            ym_key = f"{sy}-{sm:02d}"
            label = f"{sm:02d}/{sy}"
            m_kwh = charge_by_month.get(ym_key, {}).get('kwh', 0)
            m_cost = charge_by_month.get(ym_key, {}).get('cost', 0)
            m_odo = odo_by_month.get(ym_key)
            cm = cons_by_month.get(ym_key, {})
            cm_dist = cm.get('dist', 0)
            cm_kwh = cm.get('kwh', 0)
            cm_cost = cm.get('cost', 0)
            cons_100 = (cm_kwh / cm_dist * 100) if cm_dist > 0 and cm_kwh > 0 else None
            cost_100 = (cm_cost / cm_dist * 100) if cm_dist > 0 and cm_cost > 0 else None
            monthly.append({
                'label': label, 'kwh': round(m_kwh, 2), 'dist': round(cm_dist, 1),
                'cost': round(m_cost, 2), 'odo': round(m_odo) if m_odo else None,
                'cons_100': round(cons_100, 2) if cons_100 is not None else None,
                'cost_100': round(cost_100, 2) if cost_100 is not None else None,
            })

        # Current month values for tiles
        cur_ym = f"{year_str}-{month.zfill(2)}"
        cur_month = charge_by_month.get(cur_ym, {})
        cur_cons = cons_by_month.get(cur_ym, {})
        stats_data = {
            'monthly': monthly,
            'month_kwh': round(cur_month.get('kwh', 0), 2),
            'month_dist': round(cur_cons.get('dist', 0), 1),
            'month_cost': round(cur_month.get('cost', 0), 2),
        }

    db.close()
    return render_template("charge_print.html",
                           sessions=sessions_fmt,
                           vehicle=vehicle,
                           filter_vehicle=filter_vehicle,
                           month=month,
                           year=year_str,
                           years=[r['y'] for r in years_rows],
                           month_name=month_name,
                           date_from=date_from,
                           date_to=date_to,
                           pauschale_kwh=pauschale_kwh,
                           own_total_kwh=own_total_kwh,
                           own_total_cost=own_total_cost,
                           excluded_sessions=excluded_sessions,
                           invoice_sender=invoice_sender,
                           invoice_recipient=invoice_recipient,
                           invoice_intro=invoice_intro,
                           invoice_meter_text=invoice_meter_text,
                           invoice_meter_info=invoice_meter_info,
                           invoice_tariff_ref=invoice_tariff_ref,
                           invoice_data_info=invoice_data_info,
                           show_stats=show_stats,
                           stats_data=stats_data,
                           now=datetime.now().strftime("%d.%m.%Y"))




# ── Charge session detail ───────────────────────────────────

@app.route("/charges/<int:session_id>")
def charge_detail(session_id):
    db = get_db()
    sess = db.execute("SELECT * FROM charge_sessions WHERE id = ?", (session_id,)).fetchone()
    if not sess:
        db.close()
        return redirect(url_for("charges_list"))

    readings = db.execute(
        "SELECT * FROM charge_readings WHERE session_id = ? ORDER BY timestamp",
        (session_id,)
    ).fetchall()

    vehicles = db.execute("SELECT * FROM vehicles ORDER BY plate").fetchall()

    vehicle_name = sess['vehicle_plate']
    for v in vehicles:
        if v['plate'] == sess['vehicle_plate']:
            vehicle_name = v['name'] or v['plate']
            break

    # Current flat rate for cost display
    tariff = db.execute(
        "SELECT pauschale_kwh FROM charge_tariffs WHERE valid_from <= ? ORDER BY valid_from DESC LIMIT 1",
        (sess['start_time'][:10] if sess['start_time'] else '9999',)
    ).fetchone()
    pauschale = tariff['pauschale_kwh'] if tariff else 0.34

    # All charge locations with operator names for dropdown — charge_detail
    all_locations = db.execute(
        """SELECT cl.name, op.name AS op_name FROM charge_locations cl
           LEFT JOIN operators op ON cl.operator_id = op.id
           ORDER BY cl.name"""
    ).fetchall()

    # All known operators for datalist
    all_operators = db.execute(
        """SELECT DISTINCT operator FROM charge_locations WHERE operator IS NOT NULL AND operator != ''
           UNION
           SELECT DISTINCT operator FROM charge_sessions WHERE operator IS NOT NULL AND operator != ''
           ORDER BY operator"""
    ).fetchall()

    op_icon_map = _operator_icon_map(db)

    # Operator icon for this session: first session.operator → op_icon_map,
    # then fallback via location_name → charge_locations → operators JOIN
    session_op_info = op_icon_map.get((sess['operator'] or '').lower())
    if not session_op_info and sess['location_name']:
        loc_row = db.execute(
            """SELECT op.color, op.icon_filename
               FROM charge_locations cl
               LEFT JOIN operators op ON cl.operator_id = op.id
               WHERE cl.name = ? AND op.id IS NOT NULL LIMIT 1""",
            (sess['location_name'],)
        ).fetchone()
        if loc_row:
            icon_url = f"/media/operator-icons/{loc_row['icon_filename']}" if loc_row['icon_filename'] else None
            session_op_info = {"color": loc_row['color'] or '#8b949e', "icon_url": icon_url}

    # Location type (ac/dc) for warning indicator
    loc_type = 'ac'
    if sess['location_name']:
        lt_row = db.execute("SELECT type FROM charge_locations WHERE name = ?", (sess['location_name'],)).fetchone()
        if lt_row:
            loc_type = lt_row['type'] or 'ac'

    db.close()
    return render_template("charge_detail.html",
                           session=sess,
                           readings=readings,
                           vehicles=vehicles,
                           vehicle_name=vehicle_name,
                           pauschale=pauschale,
                           all_locations=all_locations,
                           all_operators=all_operators,
                           op_icon_map=op_icon_map,
                           session_op_info=session_op_info,
                           loc_type=loc_type)


# ── Charge readings JSON API ──────────────────────────────────

@app.route("/api/charge/sessions/<int:session_id>/readings")
@login_required
def charge_session_readings(session_id):
    """Return readings for a session as JSON."""
    db = get_db()
    rows = db.execute(
        "SELECT * FROM charge_readings WHERE session_id = ? ORDER BY timestamp",
        (session_id,)
    ).fetchall()
    db.close()
    return jsonify([dict(r) for r in rows])


# ── Edit charge readings ─────────────────────────────────────

@app.route("/api/charge/readings", methods=["PUT"])
def insert_charge_reading():
    """Manually insert a single reading (fill data gaps)."""
    data = request.get_json()
    ts = data.get("timestamp")
    plate = data.get("vehicle_plate")
    if not ts or not plate:
        return jsonify({"error": "timestamp und vehicle_plate sind Pflicht"}), 400

    db = get_db()
    db.execute(
        """INSERT INTO charge_readings
           (timestamp, vehicle_plate, meter_start, meter_end, kwh,
            tibber_price, tibber_grundgebuehr, odometer)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (ts, plate,
         float(data["meter_start"]) if data.get("meter_start") not in ("", None) else None,
         float(data["meter_end"]) if data.get("meter_end") not in ("", None) else None,
         float(data.get("kwh") or 0),
         float(data["tibber_price"]) if data.get("tibber_price") not in ("", None) else None,
         float(data["tibber_grundgebuehr"]) if data.get("tibber_grundgebuehr") not in ("", None) else None,
         float(data["odometer"]) if data.get("odometer") not in ("", None) else None)
    )
    db.commit()
    rid = db.execute("SELECT last_insert_rowid()").fetchone()[0]
    db.close()
    return jsonify({"ok": True, "id": rid})


@app.route("/api/charge/readings/<int:reading_id>", methods=["DELETE"])
def delete_charge_reading(reading_id):
    """Delete a single reading."""
    db = get_db()
    row = db.execute("SELECT id FROM charge_readings WHERE id = ?", (reading_id,)).fetchone()
    if not row:
        db.close()
        return jsonify({"error": "Nicht gefunden"}), 404
    db.execute("DELETE FROM charge_readings WHERE id = ?", (reading_id,))
    db.commit()
    db.close()
    return jsonify({"ok": True})


@app.route("/api/charge/readings/<int:reading_id>", methods=["POST"])
def update_charge_reading(reading_id):
    data = request.get_json()
    db = get_db()

    allowed = ("vehicle_plate", "odometer", "meter_start", "meter_end",
               "kwh", "tibber_price", "tibber_grundgebuehr", "timestamp")
    sets = []
    params = []
    for field in allowed:
        if field in data:
            val = data[field]
            if field in ("odometer", "meter_start", "meter_end", "kwh",
                         "tibber_price", "tibber_grundgebuehr"):
                val = float(val) if val not in ("", None) else None
            sets.append(f"{field} = ?")
            params.append(val)

    if not sets:
        db.close()
        return jsonify({"error": "Keine Felder"}), 400

    params.append(reading_id)
    db.execute(f"UPDATE charge_readings SET {', '.join(sets)} WHERE id = ?", params)
    db.commit()
    db.close()
    return jsonify({"ok": True})


# ── Edit / delete session ─────────────────────────────────────

@app.route("/api/charge/sessions/<int:session_id>", methods=["POST"])
@login_required
def update_charge_session(session_id):
    """Edit charge session."""
    data = request.get_json()
    db = get_db()
    sess = db.execute("SELECT * FROM charge_sessions WHERE id = ?", (session_id,)).fetchone()
    if not sess:
        db.close()
        return jsonify({"error": "Session nicht gefunden"}), 404

    allowed = ("start_time", "end_time", "total_kwh", "cost_total", "odometer", "note", "operator", "soc_start", "soc_end")
    sets = []
    params = []
    for field in allowed:
        if field in data:
            val = data[field]
            if field in ("total_kwh", "cost_total", "odometer", "soc_start", "soc_end"):
                val = float(val) if val not in ("", None) else None
            sets.append(f"{field} = ?")
            params.append(val)

    # Recalculate duration + avg_kw
    start = data.get("start_time", sess["start_time"])
    end = data.get("end_time", sess["end_time"])
    kwh = data.get("total_kwh", sess["total_kwh"])
    if start and end:
        try:
            dt_start = datetime.fromisoformat(start)
            dt_end = datetime.fromisoformat(end)
            dur = int((dt_end - dt_start).total_seconds() / 60)
            if dur > 0:
                sets.append("duration_minutes = ?")
                params.append(dur)
                if kwh:
                    avg = float(kwh) / (dur / 60)
                    sets.append("avg_kw = ?")
                    params.append(round(avg, 2))
        except Exception:
            pass

    if sets:
        params.append(session_id)
        db.execute(f"UPDATE charge_sessions SET {', '.join(sets)} WHERE id = ?", params)
        db.commit()

    db.close()
    return jsonify({"ok": True})


@app.route("/api/charge/sessions/<int:session_id>/location", methods=["POST"])
@login_required
def update_charge_session_location(session_id):
    """Manually change charge session location, auto-assign operator from charge location."""
    data = request.get_json()
    name = data.get("location_name", "").strip() or None
    db = get_db()
    operator_name = None
    lat = None
    lon = None
    if name:
        row = db.execute(
            """SELECT cl.lat, cl.lon, op.name AS op_name FROM charge_locations cl
               LEFT JOIN operators op ON cl.operator_id = op.id
               WHERE cl.name = ? LIMIT 1""",
            (name,)
        ).fetchone()
        if row:
            operator_name = row["op_name"]
            lat = row["lat"]
            lon = row["lon"]
    sets = ["location_name = ?"]
    params = [name]
    if operator_name:
        sets.append("operator = ?")
        params.append(operator_name)
    if lat is not None and lon is not None:
        sets.append("lat = ?")
        sets.append("lon = ?")
        params += [lat, lon]
    params.append(session_id)
    db.execute(f"UPDATE charge_sessions SET {', '.join(sets)} WHERE id = ?", params)
    db.commit()
    db.close()
    return jsonify({"ok": True, "operator": operator_name})


@app.route("/api/charge/sessions/batch-location", methods=["POST"])
@login_required
def batch_update_charge_session_location():
    """Set location for multiple charge sessions at once."""
    data = request.get_json()
    ids = data.get("ids", [])
    name = data.get("location_name", "").strip() or None
    if not ids:
        return jsonify({"ok": False, "error": "Keine IDs"}), 400
    db = get_db()
    operator_name = None
    lat = None
    lon = None
    if name:
        row = db.execute(
            """SELECT cl.lat, cl.lon, op.name AS op_name FROM charge_locations cl
               LEFT JOIN operators op ON cl.operator_id = op.id
               WHERE cl.name = ? LIMIT 1""",
            (name,)
        ).fetchone()
        if row:
            operator_name = row["op_name"]
            lat = row["lat"]
            lon = row["lon"]
    sets = ["location_name = ?"]
    base_params = [name]
    if operator_name:
        sets.append("operator = ?")
        base_params.append(operator_name)
    if lat is not None and lon is not None:
        sets.append("lat = ?")
        sets.append("lon = ?")
        base_params += [lat, lon]
    for sid in ids:
        db.execute(f"UPDATE charge_sessions SET {', '.join(sets)} WHERE id = ?", base_params + [sid])
    db.commit()
    db.close()
    return jsonify({"ok": True, "updated": len(ids), "operator": operator_name})


@app.route("/api/charge/sessions/list")
@login_required
def list_charge_sessions():
    """List charge sessions with optional date filter for admin reassignment."""
    date_from = request.args.get("from", "")
    date_to = request.args.get("to", "")
    db = get_db()
    sql = """SELECT cs.id, cs.start_time, cs.end_time, cs.total_kwh, cs.vehicle_plate,
                    cs.location_name, cs.odometer, cs.is_external, cs.session_number
             FROM charge_sessions cs WHERE 1=1"""
    params = []
    if date_from:
        sql += " AND cs.start_time >= ?"
        params.append(date_from)
    if date_to:
        sql += " AND cs.start_time <= ?"
        params.append(date_to + " 23:59:59")
    sql += " ORDER BY cs.start_time DESC"
    rows = db.execute(sql, params).fetchall()
    db.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/charge/sessions/batch-vehicle", methods=["POST"])
@login_required
def batch_update_charge_session_vehicle():
    """Reassign vehicle_plate for multiple charge sessions."""
    data = request.get_json()
    ids = data.get("ids", [])
    plate = data.get("vehicle_plate", "").strip()
    if not ids:
        return jsonify({"ok": False, "error": "Keine IDs"}), 400
    if not plate:
        return jsonify({"ok": False, "error": "Kein Kennzeichen"}), 400
    db = get_db()
    veh = db.execute("SELECT plate FROM vehicles WHERE plate = ?", (plate,)).fetchone()
    if not veh:
        db.close()
        return jsonify({"ok": False, "error": "Fahrzeug nicht gefunden"}), 404
    for sid in ids:
        db.execute("UPDATE charge_sessions SET vehicle_plate = ? WHERE id = ?", (plate, sid))
    db.commit()
    db.close()
    return jsonify({"ok": True, "updated": len(ids)})


@app.route("/api/charge/sessions/<int:session_id>", methods=["DELETE"])
@login_required
def delete_charge_session(session_id):
    """Delete charge session (external only)."""
    db = get_db()
    sess = db.execute("SELECT * FROM charge_sessions WHERE id = ?", (session_id,)).fetchone()
    if not sess:
        db.close()
        return jsonify({"error": "Session nicht gefunden"}), 404
    if not sess["is_external"]:
        db.close()
        return jsonify({"error": "Nur externe Sessions können gelöscht werden"}), 400

    db.execute("DELETE FROM charge_sessions WHERE id = ?", (session_id,))
    db.commit()
    db.close()
    return jsonify({"ok": True})


# ── Recalculate sessions ─────────────────────────────────────

@app.route("/api/charge/session-start", methods=["POST"])
@login_required
def charge_session_start():
    data = request.get_json()
    val = int(data.get("value", 1))
    db = get_db()
    db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('charge_session_start', ?)", (str(val),))
    db.commit()
    rebuild_charge_sessions(db)
    db.close()
    return jsonify({"ok": True})


@app.route("/api/charge/rebuild", methods=["POST"])
def charge_rebuild():
    db = get_db()
    rebuild_charge_sessions(db)
    # Return all session IDs so client can find the right one
    rows = db.execute("SELECT id, vehicle_plate, odometer FROM charge_sessions ORDER BY id").fetchall()
    sessions = [{"id": r["id"], "plate": r["vehicle_plate"], "odo": r["odometer"]} for r in rows]
    db.close()
    return jsonify({"ok": True, "sessions": sessions})


@app.route("/api/charge/recalc", methods=["POST"])
@login_required
def charge_recalc():
    """Recalculate session numbers and distances without full rebuild."""
    db = get_db()

    # Assign session numbers
    start_row = db.execute("SELECT value FROM settings WHERE key = 'charge_session_start'").fetchone()
    start_num = int(start_row['value']) if start_row else 1
    all_sessions = db.execute(
        "SELECT id, is_external FROM charge_sessions ORDER BY datetime(start_time)"
    ).fetchall()
    num = start_num
    for s in all_sessions:
        if s['is_external']:
            db.execute("UPDATE charge_sessions SET session_number = NULL WHERE id = ?", (s['id'],))
        else:
            db.execute("UPDATE charge_sessions SET session_number = ? WHERE id = ?", (str(num), s['id']))
            num += 1

    # Recalculate distances
    vehicles = db.execute("SELECT DISTINCT vehicle_plate FROM charge_sessions").fetchall()
    for v in vehicles:
        sessions = db.execute(
            "SELECT id, odometer FROM charge_sessions WHERE vehicle_plate = ? ORDER BY datetime(start_time)",
            (v['vehicle_plate'],)
        ).fetchall()
        for i, s in enumerate(sessions):
            if s['odometer'] is not None and i + 1 < len(sessions):
                next_s = sessions[i + 1]
                if next_s['odometer'] is not None:
                    dist = next_s['odometer'] - s['odometer']
                    db.execute("UPDATE charge_sessions SET distance = ? WHERE id = ?",
                               (round(dist, 1), s['id']))
                    continue
            db.execute("UPDATE charge_sessions SET distance = NULL WHERE id = ?", (s['id'],))

    db.commit()
    db.close()
    return jsonify({"ok": True})


# ── CSV import for charge data ───────────────────────────────

@app.route("/api/charge/import", methods=["POST"])
@login_required
def charge_import():
    """Import charge readings from CSV (German number format).

    Expected columns:
      Datum, Auto, Zaehlerstand_Anfang, Zaehlerstand_Ende,
      Verbrauch_kWh, Tibber_Preis_kWh, Tibber_Grundgebuehr_15m, Odometer
    """
    f = request.files.get("file")
    if not f:
        return jsonify({"error": "Keine Datei"}), 400

    text = f.read().decode("utf-8-sig")
    reader = csv.DictReader(io.StringIO(text))

    db = get_db()
    count = 0
    skipped = 0
    errors = []

    for i, row in enumerate(reader, start=2):
        timestamp = row.get("Datum", "").strip()
        if not timestamp:
            continue

        vehicle = row.get("Auto", "").strip()
        if not vehicle or vehicle.lower() in ("free", "error"):
            skipped += 1
            continue

        kwh = _parse_german_num(row.get("Verbrauch_kWh", ""))
        if kwh is None or kwh <= 0:
            skipped += 1
            continue

        # Duplicate check: same timestamp + vehicle
        existing = db.execute(
            "SELECT id FROM charge_readings WHERE timestamp = ? AND vehicle_plate = ?",
            (timestamp, vehicle)
        ).fetchone()
        if existing:
            skipped += 1
            continue

        meter_start = _parse_german_num(row.get("Zaehlerstand_Anfang", ""))
        meter_end = _parse_german_num(row.get("Zaehlerstand_Ende", ""))
        tibber_price = _parse_german_num(row.get("Tibber_Preis_kWh", ""))
        tibber_grund = _parse_german_num(row.get("Tibber_Grundgebuehr_15m", ""))
        odometer = _parse_german_num(row.get("Odometer", ""))

        try:
            db.execute("""
                INSERT INTO charge_readings
                (timestamp, vehicle_plate, meter_start, meter_end, kwh,
                 tibber_price, tibber_grundgebuehr, odometer)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (timestamp, vehicle, meter_start, meter_end,
                  round(kwh, 4), tibber_price, tibber_grund, odometer))
            count += 1
        except Exception as e:
            errors.append(f"Zeile {i}: {e}")

    db.commit()

    # Rebuild sessions after import
    rebuild_charge_sessions(db)
    db.close()

    return jsonify({
        "ok": True,
        "imported": count,
        "skipped": skipped,
        "errors": errors[:10]
    })


# ── Manually record external charge ──────────────────────────

@app.route("/api/charge/external", methods=["POST"])
@login_required
def charge_external():
    """Create an external charge session (e.g. DC fast charger on the road)."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "JSON erwartet"}), 400

    vehicle = str(data.get("vehicle_plate", "")).strip()
    kwh = float(data.get("kwh", 0) or 0)
    if not vehicle or kwh <= 0:
        return jsonify({"error": "Fahrzeug und kWh erforderlich"}), 400

    timestamp = data.get("timestamp", "")
    end_time = data.get("end_time", "") or timestamp
    odometer = float(data["odometer"]) if data.get("odometer") not in ("", None) else None
    cost_total = float(data["cost_total"]) if data.get("cost_total") not in ("", None) else None
    note = str(data.get("note", "")).strip() or None

    # Calculate duration and average power
    duration_minutes = None
    avg_kw = None
    if timestamp and end_time:
        from datetime import datetime
        fmt = "%Y-%m-%d %H:%M"
        try:
            dt_start = datetime.strptime(timestamp[:16], fmt)
            dt_end = datetime.strptime(end_time[:16], fmt)
            duration_minutes = max(0, int((dt_end - dt_start).total_seconds() / 60))
            if duration_minutes > 0:
                avg_kw = round(kwh / (duration_minutes / 60), 2)
        except ValueError:
            pass

    db = get_db()

    # Interpolate odometer from trip if not provided
    if odometer is None and timestamp:
        dev = db.execute(
            "SELECT device FROM vehicles WHERE plate = ?", (vehicle,)
        ).fetchone()
        if dev and dev["device"]:
            trip_row = db.execute(
                """SELECT odo_end FROM trips WHERE device = ?
                   AND odo_end IS NOT NULL
                   AND datetime(end_time) <= datetime(?)
                   ORDER BY end_time DESC LIMIT 1""",
                (dev["device"], timestamp),
            ).fetchone()
            if trip_row:
                odometer = trip_row["odo_end"]

    db.execute("""
        INSERT INTO charge_sessions
        (session_number, is_external, vehicle_plate, start_time, end_time,
         total_kwh, duration_minutes, avg_kw, odometer, cost_total, note)
        VALUES (NULL, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (vehicle, timestamp, end_time,
          round(kwh, 3), duration_minutes, avg_kw, odometer, cost_total, note))

    # Auto-create vehicle if needed
    db.execute("INSERT OR IGNORE INTO vehicles (plate) VALUES (?)", (vehicle,))

    # Recalc distances for all sessions
    rebuild_charge_sessions(db)
    db.close()

    return jsonify({"ok": True, "session_number": "ext"})


# ── Auto-detect external charges from trip SoC ───────────────

def detect_external_from_trips(db):
    """Detect external charges from SoC increases between trips.

    If after a trip the SoC has increased by the next trip and
    no charge session covers this period, an external session
    is created (charge on the road).
    """
    vehicles = db.execute("SELECT plate, device FROM vehicles WHERE device IS NOT NULL AND device != ''").fetchall()
    created = 0

    for vehicle in vehicles:
        plate = vehicle['plate']
        device = vehicle['device']
        bat_kwh = get_bat_kwh(db, device)

        trips = db.execute("""
            SELECT start_time, end_time, soc_start, soc_end,
                   end_lat, end_lon, odo_end
            FROM trips
            WHERE device = ?
              AND soc_start IS NOT NULL AND soc_end IS NOT NULL
              AND end_time IS NOT NULL
              AND datetime(end_time) >= datetime('now', '-24 hours')
            ORDER BY start_time
        """, (device,)).fetchall()

        for i in range(len(trips) - 1):
            t_before = trips[i]
            t_after  = trips[i + 1]

            soc_before = t_before['soc_end']
            soc_after  = t_after['soc_start']

            # At least 3% SoC increase required
            if soc_after - soc_before < 3:
                continue

            window_start = t_before['end_time']
            window_end   = t_after['start_time']

            # Already a session in this time window? (datetime() normalizes T/Z formats)
            existing = db.execute("""
                SELECT id FROM charge_sessions
                WHERE vehicle_plate = ?
                  AND datetime(start_time) < datetime(?)
                  AND (end_time IS NULL OR datetime(end_time) > datetime(?))
            """, (plate, window_end, window_start)).fetchone()
            if existing:
                continue

            soc_diff = soc_after - soc_before
            kwh = round(soc_diff / 100.0 * bat_kwh, 3)

            lat = t_before['end_lat']
            lon = t_before['end_lon']
            loc = match_charge_location(db, lat, lon) or match_location(db, lat, lon)
            loc_name = loc['name'] if loc else None
            odometer = t_before['odo_end']

            duration_min = None
            avg_kw = None
            try:
                t0 = datetime.fromisoformat(window_start)
                t1 = datetime.fromisoformat(window_end)
                duration_min = max(1, int((t1 - t0).total_seconds() / 60))
                avg_kw = round(kwh / (duration_min / 60.0), 2) if duration_min > 0 else None
            except Exception:
                pass

            note = f"Automatisch erkannt (SoC {soc_before:.0f}%→{soc_after:.0f}%)"

            db.execute("""
                INSERT INTO charge_sessions
                (session_number, is_external, vehicle_plate, start_time, end_time,
                 total_kwh, duration_minutes, avg_kw, odometer, lat, lon, location_name, note)
                VALUES (NULL, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (plate, window_start, window_end, kwh, duration_min, avg_kw,
                  odometer, lat, lon, loc_name, note))
            created += 1

    if created:
        db.commit()

    # Clean up duplicates: external sessions with overlapping time windows (same plate)
    # → delete the newer one (higher ID)
    dupes = db.execute("""
        SELECT a.id FROM charge_sessions a
        JOIN charge_sessions b ON a.vehicle_plate = b.vehicle_plate
          AND a.id > b.id
          AND a.is_external = 1 AND b.is_external = 1
          AND datetime(a.start_time) < datetime(b.end_time)
          AND (a.end_time IS NULL OR datetime(a.end_time) > datetime(b.start_time))
    """).fetchall()
    if dupes:
        ids = [r['id'] for r in dupes]
        db.execute(f"DELETE FROM charge_sessions WHERE id IN ({','.join('?'*len(ids))})", ids)
        db.commit()
        log.info("detect_external: %d duplicates removed", len(ids))

    return created


@app.route("/api/charge/detect-external", methods=["POST"])
@login_required
def api_detect_external():
    """Detect external charges from SoC changes between trips."""
    db = get_db()
    count = detect_external_from_trips(db)
    if count:
        rebuild_charge_sessions(db)
    db.close()
    return jsonify({"ok": True, "created": count})


# ── Vehicles CRUD ────────────────────────────────────────────

@app.route("/api/vehicles")
def list_vehicles():
    db = get_db()
    rows = db.execute("SELECT * FROM vehicles ORDER BY plate").fetchall()
    db.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/vehicles", methods=["POST"])
def create_vehicle():
    data = request.get_json()
    plate = data.get("plate", "").strip()
    if not plate:
        return jsonify({"error": "Kennzeichen erforderlich"}), 400

    db = get_db()
    try:
        db.execute(
            "INSERT INTO vehicles (plate, name, model, device, vin, battery_capacity_kwh) VALUES (?, ?, ?, ?, ?, ?)",
            (plate, data.get("name", "").strip() or None,
             data.get("model", "").strip() or None,
             data.get("device", "").strip() or None,
             data.get("vin", "").strip() or None,
             data.get("battery_capacity_kwh") or None)
        )
        db.commit()
    except db.IntegrityError:
        db.close()
        return jsonify({"error": "Kennzeichen existiert bereits"}), 409
    db.close()
    return jsonify({"ok": True})


@app.route("/api/vehicles/<int:vehicle_id>", methods=["POST"])
def update_vehicle(vehicle_id):
    data = request.get_json()
    db = get_db()
    allowed = ("plate", "name", "model", "device", "vin", "battery_capacity_kwh")
    sets = []
    params = []
    for field in allowed:
        if field in data:
            sets.append(f"{field} = ?")
            params.append(data[field])
    if not sets:
        db.close()
        return jsonify({"error": "Keine Felder"}), 400
    params.append(vehicle_id)
    db.execute(f"UPDATE vehicles SET {', '.join(sets)} WHERE id = ?", params)
    db.commit()
    db.close()
    return jsonify({"ok": True})


@app.route("/api/vehicles/<int:vehicle_id>", methods=["DELETE"])
def delete_vehicle(vehicle_id):
    db = get_db()
    db.execute("DELETE FROM vehicles WHERE id = ?", (vehicle_id,))
    db.commit()
    db.close()
    return jsonify({"ok": True})


@app.route("/api/vehicles/available-filters")
@login_required
def vehicle_available_filters():
    """Available device tags (InfluxDB + vehicles) and plates (charges) for dropdowns."""
    db = get_db()
    veh_devs = {r[0] for r in db.execute("SELECT DISTINCT device FROM vehicles WHERE device IS NOT NULL AND device != ''").fetchall()}
    plates = [r[0] for r in db.execute("SELECT DISTINCT vehicle_plate FROM charge_readings WHERE vehicle_plate IS NOT NULL ORDER BY vehicle_plate").fetchall()]
    db.close()

    # Actual device tags from InfluxDB
    influx_devs: set = set()
    client = detector.get_influx()
    if client:
        try:
            q = f'''
            import "influxdata/influxdb/schema"
            schema.tagValues(
              bucket: "{config.INFLUX_BUCKET}",
              tag: "d",
              predicate: (r) => r._measurement == "v",
              start: -365d
            )
            '''
            for table in client.query_api().query(q, org=config.INFLUX_ORG):
                for record in table.records:
                    v = record.get_value()
                    if v:
                        influx_devs.add(v)
        except Exception as e:
            log.warning("InfluxDB tag-values failed: %s", e)
        finally:
            client.close()

    devices = sorted(veh_devs | influx_devs)
    return jsonify({"devices": devices, "influx_devices": sorted(influx_devs), "plates": plates})


# ── Tariffs CRUD ─────────────────────────────────────────────

@app.route("/api/charge/tariffs")
def list_tariffs():
    db = get_db()
    rows = db.execute("SELECT * FROM charge_tariffs ORDER BY valid_from DESC").fetchall()
    db.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/charge/tariffs", methods=["POST"])
def create_tariff():
    data = request.get_json()
    valid_from = data.get("valid_from", "").strip()
    pauschale = data.get("pauschale_kwh")
    if not valid_from or pauschale is None:
        return jsonify({"error": "valid_from und pauschale_kwh erforderlich"}), 400

    db = get_db()
    db.execute(
        """INSERT INTO charge_tariffs (valid_from, pauschale_kwh) VALUES (?, ?)
           ON CONFLICT(valid_from) DO UPDATE SET pauschale_kwh = ?""",
        (valid_from, float(pauschale), float(pauschale))
    )
    db.commit()
    db.close()
    return jsonify({"ok": True})


@app.route("/api/charge/tariffs/<int:tariff_id>", methods=["DELETE"])
def delete_tariff(tariff_id):
    db = get_db()
    db.execute("DELETE FROM charge_tariffs WHERE id = ?", (tariff_id,))
    db.commit()
    db.close()
    return jsonify({"ok": True})


# ── Charge locations CRUD ─────────────────────────────────────

def _point_in_polygon(lat, lon, coords):
    """Ray-casting: True if (lat,lon) is inside polygon coords=[[lat,lon],...]."""
    n = len(coords)
    inside = False
    j = n - 1
    for i in range(n):
        xi, yi = coords[i][1], coords[i][0]
        xj, yj = coords[j][1], coords[j][0]
        if ((yi > lon) != (yj > lon)) and (lat < (xj - xi) * (lon - yi) / (yj - yi + 1e-12) + xi):
            inside = not inside
        j = i
    return inside


def match_charge_location(db, lat, lon):
    """Find the nearest charge location (circle or polygon)."""
    if not lat or not lon:
        return None
    locations = db.execute("SELECT * FROM charge_locations").fetchall()
    best = None
    best_dist = float('inf')
    for loc in locations:
        if loc["shape"] == "polygon" and loc["polygon_coords"]:
            import json as _json
            try:
                coords = _json.loads(loc["polygon_coords"])
            except Exception:
                continue
            if _point_in_polygon(lat, lon, coords):
                dist = haversine_m(lat, lon, loc["lat"], loc["lon"])
                if dist < best_dist:
                    best = loc
                    best_dist = dist
        elif loc["shape"] == "rect" and loc["lat2"] is not None and loc["lon2"] is not None:
            # Legacy rectangle
            lat_min = min(loc["lat"], loc["lat2"])
            lat_max = max(loc["lat"], loc["lat2"])
            lon_min = min(loc["lon"], loc["lon2"])
            lon_max = max(loc["lon"], loc["lon2"])
            if lat_min <= lat <= lat_max and lon_min <= lon <= lon_max:
                center_lat = (lat_min + lat_max) / 2
                center_lon = (lon_min + lon_max) / 2
                dist = haversine_m(lat, lon, center_lat, center_lon)
                if dist < best_dist:
                    best = loc
                    best_dist = dist
        else:
            # Circle
            dist = haversine_m(lat, lon, loc["lat"], loc["lon"])
            if dist <= loc["radius_m"] and dist < best_dist:
                best = loc
                best_dist = dist
    return best


@app.route("/api/charge/locations")
def list_charge_locations():
    db = get_db()
    rows = db.execute("""
        SELECT cl.*, op.name AS op_name, op.color AS op_color, op.icon_filename AS op_icon_filename
        FROM charge_locations cl
        LEFT JOIN operators op ON cl.operator_id = op.id
        ORDER BY cl.name
    """).fetchall()
    counts = {r['location_name']: r['cnt'] for r in db.execute(
        "SELECT location_name, COUNT(*) as cnt FROM charge_sessions WHERE location_name IS NOT NULL GROUP BY location_name"
    ).fetchall()}
    db.close()
    result = []
    for r in rows:
        d = dict(r)
        d['charge_count'] = counts.get(r['name'], 0)
        if r['icon_filename']:
            d['icon_url'] = f"/media/charge-icons/{r['icon_filename']}"
        elif r['op_icon_filename']:
            d['icon_url'] = f"/media/operator-icons/{r['op_icon_filename']}"
        else:
            d['icon_url'] = None
        result.append(d)
    return jsonify(result)


@app.route("/api/charge/locations", methods=["POST"])
@login_required
def create_charge_location():
    data = request.get_json()
    name = data.get("name", "").strip()
    lat = data.get("lat")
    lon = data.get("lon")
    if not name or lat is None or lon is None:
        return jsonify({"error": "name, lat, lon erforderlich"}), 400

    db = get_db()
    cur = db.execute(
        """INSERT INTO charge_locations (name, lat, lon, radius_m, shape, lat2, lon2, polygon_coords, type, operator, color, note, country_code, operator_id)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (name, float(lat), float(lon),
         data.get("radius_m", 200),
         data.get("shape", "circle"),
         float(data["lat2"]) if data.get("lat2") not in (None, "", 0) else None,
         float(data["lon2"]) if data.get("lon2") not in (None, "", 0) else None,
         data.get("polygon_coords"),
         data.get("type", "ac"),
         data.get("operator", ""),
         data.get("color", "#8b949e"),
         data.get("note", ""),
         (data.get("country_code", "DE") or "DE").upper()[:2],
         int(data["operator_id"]) if data.get("operator_id") else None),
    )
    db.commit()
    loc_id = cur.lastrowid
    db.close()
    return jsonify({"ok": True, "id": loc_id})


@app.route("/api/charge/locations/<int:loc_id>", methods=["POST"])
@login_required
def update_charge_location(loc_id):
    data = request.get_json()
    db = get_db()
    allowed = ("name", "lat", "lon", "radius_m", "shape", "lat2", "lon2", "polygon_coords", "type", "operator", "color", "note", "country_code", "operator_id")
    sets = []
    params = []
    for field in allowed:
        if field in data:
            val = data[field]
            if field in ("lat", "lon"):
                val = float(val)
            elif field in ("lat2", "lon2"):
                val = float(val) if val not in (None, "", 0) else None
            elif field == "radius_m":
                val = int(val)
            elif field == "operator_id":
                val = int(val) if val else None
            sets.append(f"{field} = ?")
            params.append(val)
    if not sets:
        return jsonify({"error": "Keine Felder"}), 400
    params.append(loc_id)
    db.execute(f"UPDATE charge_locations SET {', '.join(sets)} WHERE id = ?", params)
    db.commit()
    db.close()
    return jsonify({"ok": True})


@app.route("/api/charge/locations/<int:loc_id>", methods=["DELETE"])
@login_required
def delete_charge_location(loc_id):
    db = get_db()
    # Remove icon file if present
    row = db.execute("SELECT icon_filename FROM charge_locations WHERE id = ?", (loc_id,)).fetchone()
    if row and row["icon_filename"]:
        _delete_charge_icon_file(row["icon_filename"])
    db.execute("DELETE FROM charge_locations WHERE id = ?", (loc_id,))
    db.commit()
    db.close()
    return jsonify({"ok": True})


MEDIA_DIR = os.path.join(os.path.dirname(config.DB_PATH), "media")
_CHARGE_ICON_DIR = os.path.join(os.path.dirname(config.DB_PATH), "media", "charge-icons")
_OPERATOR_ICON_DIR = os.path.join(os.path.dirname(config.DB_PATH), "media", "operator-icons")
_ALLOWED_IMAGE_EXTS = {".png", ".jpg", ".jpeg", ".webp", ".svg", ".gif"}
_MAX_ICON_BYTES = 200 * 1024  # 200 KB


# ── Operators ─────────────────────────────────────────────────────────────


@app.route("/api/operators")
def list_operators():
    db = get_db()
    rows = db.execute("SELECT * FROM operators ORDER BY name").fetchall()
    counts = {r['operator_id']: r['cnt'] for r in db.execute(
        "SELECT operator_id, COUNT(*) as cnt FROM charge_locations WHERE operator_id IS NOT NULL GROUP BY operator_id"
    ).fetchall()}
    db.close()
    result = []
    for r in rows:
        d = dict(r)
        d['icon_url'] = f"/media/operator-icons/{r['icon_filename']}" if r['icon_filename'] else None
        d['location_count'] = counts.get(r['id'], 0)
        result.append(d)
    return jsonify(result)


@app.route("/api/operators", methods=["POST"])
@login_required
def create_operator():
    data = request.get_json()
    name = (data.get("name") or "").strip()
    if not name:
        return jsonify({"error": "Name erforderlich"}), 400
    db = get_db()
    try:
        cur = db.execute(
            "INSERT INTO operators (name, color) VALUES (?, ?)",
            (name, data.get("color", "#8b949e"))
        )
        db.commit()
        op_id = cur.lastrowid
    except sqlite3.IntegrityError:
        db.close()
        return jsonify({"error": "Betreiber existiert bereits"}), 409
    db.close()
    return jsonify({"ok": True, "id": op_id})


@app.route("/api/operators/<int:op_id>", methods=["POST"])
@login_required
def update_operator(op_id):
    data = request.get_json()
    db = get_db()
    sets, params = [], []
    for field in ("name", "color"):
        if field in data:
            sets.append(f"{field} = ?")
            params.append(data[field])
    if not sets:
        return jsonify({"error": "Keine Felder"}), 400
    params.append(op_id)
    db.execute(f"UPDATE operators SET {', '.join(sets)} WHERE id = ?", params)
    db.commit()
    db.close()
    return jsonify({"ok": True})


@app.route("/api/operators/<int:op_id>", methods=["DELETE"])
@login_required
def delete_operator(op_id):
    db = get_db()
    row = db.execute("SELECT icon_filename FROM operators WHERE id = ?", (op_id,)).fetchone()
    if row and row["icon_filename"]:
        _delete_operator_icon_file(row["icon_filename"])
    db.execute("DELETE FROM operators WHERE id = ?", (op_id,))
    db.commit()
    db.close()
    return jsonify({"ok": True})


@app.route("/api/operators/<int:op_id>/icon", methods=["POST"])
@login_required
def upload_operator_icon(op_id):
    db = get_db()
    row = db.execute("SELECT id, icon_filename FROM operators WHERE id = ?", (op_id,)).fetchone()
    if not row:
        db.close()
        return jsonify({"error": "Nicht gefunden"}), 404
    f = request.files.get("icon")
    if not f or not f.filename:
        db.close()
        return jsonify({"error": "Keine Datei"}), 400
    ext = os.path.splitext(secure_filename(f.filename))[1].lower()
    if ext not in _ALLOWED_IMAGE_EXTS:
        db.close()
        return jsonify({"error": "Ungültiges Format"}), 400
    data = f.read(_MAX_ICON_BYTES + 1)
    if len(data) > _MAX_ICON_BYTES:
        db.close()
        return jsonify({"error": "Datei zu groß (max. 200 KB)"}), 400
    os.makedirs(_OPERATOR_ICON_DIR, exist_ok=True)
    if row["icon_filename"]:
        _delete_operator_icon_file(row["icon_filename"])
    filename = f"operator_{op_id}{ext}"
    with open(os.path.join(_OPERATOR_ICON_DIR, filename), "wb") as fh:
        fh.write(data)
    db.execute("UPDATE operators SET icon_filename = ? WHERE id = ?", (filename, op_id))
    db.commit()
    db.close()
    return jsonify({"ok": True, "icon_url": f"/media/operator-icons/{filename}"})


@app.route("/api/operators/<int:op_id>/icon", methods=["DELETE"])
@login_required
def delete_operator_icon(op_id):
    db = get_db()
    row = db.execute("SELECT icon_filename FROM operators WHERE id = ?", (op_id,)).fetchone()
    if row and row["icon_filename"]:
        _delete_operator_icon_file(row["icon_filename"])
        db.execute("UPDATE operators SET icon_filename = NULL WHERE id = ?", (op_id,))
        db.commit()
    db.close()
    return jsonify({"ok": True})


def _delete_operator_icon_file(filename):
    try:
        path = os.path.join(_OPERATOR_ICON_DIR, filename)
        if os.path.isfile(path):
            os.remove(path)
    except OSError:
        pass


def _delete_charge_icon_file(filename):
    try:
        path = os.path.join(_CHARGE_ICON_DIR, filename)
        if os.path.isfile(path):
            os.remove(path)
    except OSError:
        pass


@app.route("/api/charge/locations/<int:loc_id>/icon", methods=["POST"])
@login_required
def upload_charge_location_icon(loc_id):
    db = get_db()
    row = db.execute("SELECT id, icon_filename FROM charge_locations WHERE id = ?", (loc_id,)).fetchone()
    if not row:
        db.close()
        return jsonify({"error": "Nicht gefunden"}), 404

    f = request.files.get("icon")
    if not f or not f.filename:
        db.close()
        return jsonify({"error": "Keine Datei"}), 400

    ext = os.path.splitext(secure_filename(f.filename))[1].lower()
    if ext not in _ALLOWED_IMAGE_EXTS:
        db.close()
        return jsonify({"error": "Ungültiges Format (erlaubt: PNG, JPG, WEBP, SVG, GIF)"}), 400

    data = f.read(_MAX_ICON_BYTES + 1)
    if len(data) > _MAX_ICON_BYTES:
        db.close()
        return jsonify({"error": "Datei zu groß (max. 200 KB)"}), 400

    os.makedirs(_CHARGE_ICON_DIR, exist_ok=True)

    # Remove old icon
    if row["icon_filename"]:
        _delete_charge_icon_file(row["icon_filename"])

    filename = f"charge_{loc_id}{ext}"
    dest = os.path.join(_CHARGE_ICON_DIR, filename)
    with open(dest, "wb") as fh:
        fh.write(data)

    db.execute("UPDATE charge_locations SET icon_filename = ? WHERE id = ?", (filename, loc_id))
    db.commit()
    db.close()
    return jsonify({"ok": True, "icon_url": f"/media/charge-icons/{filename}"})


@app.route("/api/charge/locations/<int:loc_id>/icon", methods=["DELETE"])
@login_required
def delete_charge_location_icon(loc_id):
    db = get_db()
    row = db.execute("SELECT icon_filename FROM charge_locations WHERE id = ?", (loc_id,)).fetchone()
    if row and row["icon_filename"]:
        _delete_charge_icon_file(row["icon_filename"])
        db.execute("UPDATE charge_locations SET icon_filename = NULL WHERE id = ?", (loc_id,))
        db.commit()
    db.close()
    return jsonify({"ok": True})


@app.route("/media/<path:filename>")
def media_file(filename):
    """Serve static media from /data/media/ (icons, photos, etc.)."""
    return send_from_directory(MEDIA_DIR, filename)


if __name__ == "__main__":
    # Create media directories
    icons_dir = os.path.join(MEDIA_DIR, "icons")
    os.makedirs(icons_dir, exist_ok=True)
    os.makedirs(os.path.join(MEDIA_DIR, "photos"), exist_ok=True)

    # Copy default icons from static/icons/ to MEDIA_DIR/icons/ (only if not present)
    bundled_icons = os.path.join(os.path.dirname(__file__), "static", "icons")
    if os.path.isdir(bundled_icons):
        for icon_file in os.listdir(bundled_icons):
            dest = os.path.join(icons_dir, icon_file)
            if not os.path.exists(dest):
                shutil.copy2(os.path.join(bundled_icons, icon_file), dest)

    # Check if setup wizard is needed
    with app.app_context():
        _check_setup()

    # Start background threads
    threading.Thread(target=background_detector, daemon=True).start()
    threading.Thread(target=background_geocoder, daemon=True).start()
    threading.Thread(target=_state_poller, daemon=True).start()
    threading.Thread(target=background_mqtt, daemon=True).start()

    app.run(host="0.0.0.0", port=5000)
