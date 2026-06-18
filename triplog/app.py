"""IDmate Triplog — Flask Web-UI + CSV-Export."""

import sys
# Started as `python app.py` (the container CMD) this module is named
# '__main__'. The blueprints (registered at the bottom) do `from app import …`;
# without this alias Python would import app.py a SECOND time under the name
# 'app', re-run it, and hit a circular import on the not-yet-defined blueprints.
# Aliasing makes 'app' and '__main__' resolve to this one running module.
# No-op when imported as 'app' (pytest / WSGI): setdefault keeps the real one.
sys.modules.setdefault("app", sys.modules["__main__"])

import base64
import csv
import hashlib
import secrets
import hmac
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

from flask import Flask, render_template, request, jsonify, Response, redirect, url_for, session, send_from_directory, abort, g
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf.csrf import CSRFProtect, generate_csrf
from werkzeug.security import generate_password_hash as _werkzeug_hash, check_password_hash as _werkzeug_check
from argon2 import PasswordHasher as _Argon2Hasher
from argon2.exceptions import VerificationError, VerifyMismatchError
from werkzeug.utils import secure_filename
from werkzeug.middleware.proxy_fix import ProxyFix

import config
import detector
import teslamate_import
import import_job
import geocoder as geo
from plmn import PLMN_INFO, plmn_info, plmn_color

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

# ProxyFix: honours X-Forwarded-For/-Proto/-Host from the reverse proxy
# (Nginx/Caddy/Traefik in front of the container). Without this wrapper Flask
# sees only the proxy IP as the client IP -- login rate limits, CSRF origin
# checks and audit logs become worthless. x_for=1 trusts one proxy hop depth;
# raise it accordingly for multi-stage proxies.
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

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


from detector import sanitize_soc as _sanitize_soc


def _sanitize_range(v):
    """Clamp telemetry range readings. The firmware packs range as u16/10, same
    as SoC — a negative BMS value (e.g. -1 km when prediction model fails) wraps
    to ~6553 km. Anything above 1500 km is treated as bogus (no production EV
    has that range), negatives become 0, None passes through unchanged."""
    if v is None:
        return None
    try:
        v = float(v)
    except (TypeError, ValueError):
        return None
    if math.isnan(v) or math.isinf(v):
        return None
    if v < 0:
        return 0
    if v > 1500:
        return None
    return v

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


@app.template_filter("invoice_safe")
def _invoice_safe(value):
    """Render invoice template fields safely: HTML-escape everything, allow
    only <br> as a line break. Replaces the former |safe, through which a user
    could plant <script>/<img onerror> as persistent stored XSS.

    Additionally, contenteditable artefacts are normalized: browsers store
    Enter as <div>...</div>/<p>...</p> blocks and spaces as &nbsp; — existing
    values from the innerHTML-storage era otherwise showed up as a literal
    "<div>" in the field. Block starts become <br>, block ends are removed."""
    from markupsafe import escape, Markup
    esc = str(escape(value or ""))
    for br in ("&lt;br&gt;", "&lt;br/&gt;", "&lt;br /&gt;"):
        esc = esc.replace(br, "<br>")
    for opener in ("&lt;div&gt;", "&lt;p&gt;"):
        esc = esc.replace(opener, "<br>")
    for closer in ("&lt;/div&gt;", "&lt;/p&gt;"):
        esc = esc.replace(closer, "")
    esc = esc.replace("&amp;nbsp;", " ")
    # <div><br></div> empty lines produce 3 breaks -> collapse to max. 2
    import re as _re
    esc = _re.sub(r"(?:<br>){3,}", "<br><br>", esc)
    # don't show leading breaks (first <div> right at the start)
    while esc.startswith("<br>"):
        esc = esc[4:]
    return Markup(esc)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = True
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=7)
app.config["REMEMBER_COOKIE_DURATION"] = timedelta(days=7)
# Harden the remember-me cookie just like the session cookie — Flask-Login
# defaults are Secure=False/SameSite=None, otherwise the 7-day auth token could
# leak over an HTTP request.
app.config["REMEMBER_COOKIE_SECURE"] = True
app.config["REMEMBER_COOKIE_HTTPONLY"] = True
app.config["REMEMBER_COOKIE_SAMESITE"] = "Lax"
# Reject any request body larger than 50 MiB before Flask buffers it. Caps the
# damage from an unauthenticated upload-DoS even though most endpoints are auth-
# guarded; individual upload routes still apply their own tighter per-file caps.
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024

csrf = CSRFProtect(app)
# Global CSRF protection. JSON-API call sites get the token via the fetch
# wrapper injected below; HTML form templates carry a {{ csrf_token() }} field.
# Exemptions (charge_webhook) are declared at the route via @csrf.exempt.

# Fetch wrapper injected into every HTML response. Reads the csrf_token cookie
# and attaches X-CSRFToken to any non-GET fetch() call site, so existing
# templates (170+ fetch calls) don't need per-call changes.
_CSRF_FETCH_SNIPPET = (
    "<script nonce=\"__CSP_NONCE__\">(function(){function g(){var m=document.cookie.match("
    "/(?:^|;\\s*)csrf_token=([^;]+)/);return m?decodeURIComponent(m[1]):''}"
    "var o=window.fetch;window.fetch=function(u,i){i=i||{};var m=(i.method||"
    "'GET').toUpperCase();if(m!=='GET'&&m!=='HEAD'&&m!=='OPTIONS'){"
    "var h=new Headers(i.headers||{});if(!h.has('X-CSRFToken'))"
    "h.set('X-CSRFToken',g());i.headers=h}return o(u,i)}})();</script>"
)


@app.before_request
def _gen_csp_nonce():
    """Per-request nonce for inline <script> (FIXES 7.2). With a nonce in
    script-src, CSP3 browsers ignore 'unsafe-inline' — inline handler
    attributes are thus blocked; 'unsafe-inline' stays only as a fallback
    for legacy browsers in the header."""
    g.csp_nonce = secrets.token_urlsafe(16)


@app.context_processor
def _inject_csp_nonce():
    return {"csp_nonce": g.get("csp_nonce", "")}


@app.after_request
def set_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    # HSTS: tell the browser to never downgrade to plain HTTP for 2 years.
    # Browsers ignore this header on plaintext HTTP responses, so it's safe to
    # send unconditionally — only takes effect once the request was HTTPS.
    response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        f"script-src 'self' 'unsafe-inline' 'nonce-{g.get('csp_nonce', '')}' https://cdn.jsdelivr.net https://unpkg.com; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://unpkg.com; "
        "img-src 'self' data: blob: https://tile.openstreetmap.org "
        "https://tile.openstreetmap.de https://*.tile.openstreetmap.fr "
        "https://maps.wikimedia.org "
        "https://*.basemaps.cartocdn.com https://server.arcgisonline.com; "
        "connect-src 'self' https://nominatim.openstreetmap.org https://cdn.jsdelivr.net https://unpkg.com; "
        "font-src 'self' https://cdn.jsdelivr.net https://unpkg.com; "
        "frame-ancestors 'none'"
    )
    # CSRF: refresh cookie + inject fetch-wrapper into HTML responses.
    # direct_passthrough = files (send_from_directory) — must not touch body.
    if not response.direct_passthrough:
        response.set_cookie(
            "csrf_token", generate_csrf(),
            secure=True, httponly=False, samesite="Strict",
            max_age=int(timedelta(days=7).total_seconds()),
        )
        ctype = response.headers.get("Content-Type", "")
        if ctype.startswith("text/html"):
            body = response.get_data(as_text=True)
            if "</head>" in body and "X-CSRFToken" not in body:
                snippet = _CSRF_FETCH_SNIPPET.replace("__CSP_NONCE__", g.get("csp_nonce", ""))
                response.set_data(body.replace("</head>", snippet + "</head>", 1))
    return response

# ── i18n ─────────────────────────────────────────────────────

_lang_dir = os.path.join(os.path.dirname(__file__), "lang")
_translations = {}
for _fname in os.listdir(_lang_dir):
    if _fname.endswith(".json"):
        _code = _fname[:-5].upper()
        with open(os.path.join(_lang_dir, _fname), encoding="utf-8") as _f:
            _translations[_code] = json.load(_f)


def get_language():
    """Active language: per-user (FIXES 15.5) > global DB setting > ENV > DE."""
    # Per-user preference. current_user is only meaningful inside a request with
    # an authenticated session — guard against background threads / anonymous.
    try:
        if current_user and current_user.is_authenticated:
            lang = getattr(current_user, "language", None)
            if lang and lang.upper() in _translations:
                return lang.upper()
    except Exception:
        pass
    try:
        db = get_db()
        row = db.execute("SELECT value FROM settings WHERE key = 'language'").fetchone()
        db.close()
        if row and row["value"].upper() in _translations:
            return row["value"].upper()
    except Exception:
        log.exception("get_language: DB read failed, falling back to default")
    return config.LANGUAGE if config.LANGUAGE in _translations else "DE"


MAP_STYLES = {
    "carto_dark":    "https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png",
    "carto_light":   "https://{s}.basemaps.cartocdn.com/light_all/{z}/{x}/{y}{r}.png",
    "carto_voyager": "https://{s}.basemaps.cartocdn.com/rastertiles/voyager/{z}/{x}/{y}{r}.png",
    "osm":           "https://tile.openstreetmap.org/{z}/{x}/{y}.png",
    "osm_de":        "https://tile.openstreetmap.de/{z}/{x}/{y}.png",
    "esri_sat":      "https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}",
    "esri_topo":     "https://server.arcgisonline.com/ArcGIS/rest/services/World_Topo_Map/MapServer/tile/{z}/{y}/{x}",
}


def get_map_tile_url():
    """Map style: user preference > DB setting > osm_de."""
    try:
        if current_user.is_authenticated and getattr(current_user, "map_style", None) in MAP_STYLES:
            return MAP_STYLES[current_user.map_style]
    except Exception:
        log.exception("get_map_tile_url: user preference read failed")
    try:
        db = get_db()
        row = db.execute("SELECT value FROM settings WHERE key = 'map_style'").fetchone()
        db.close()
        if row and row["value"] in MAP_STYLES:
            return MAP_STYLES[row["value"]]
    except Exception:
        log.exception("get_map_tile_url: DB read failed, falling back to osm_de")
    return MAP_STYLES["osm_de"]


@app.context_processor
def inject_translations():
    lang = get_language()
    t = _translations.get(lang, _translations["DE"])
    return {"t": t, "current_lang": lang, "map_tile_url": get_map_tile_url()}


@app.context_processor
def inject_today():
    from datetime import date
    return {"today": date.today().isoformat()}


UI_THEMES = {"", "light", "gt"}  # '' = dark (default)


@app.context_processor
def inject_user_theme():
    theme = getattr(current_user, "theme", None) or ""
    return {"user_theme": theme if theme in UI_THEMES else ""}
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
log = logging.getLogger("triplog.app")

# ── Encryption for personal settings ─────────────────────────

ENCRYPTED_SETTINGS = {
    "invoice_sender", "invoice_recipient", "invoice_intro",
    "invoice_meter_text", "invoice_meter_info", "invoice_tariff_ref",
    "invoice_data_info",
    # Home Assistant export read-token — a secret, stored encrypted at rest.
    "ha_export_token",
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
login_manager.login_view = "auth.login"


def _validate_password(pw):
    """Password minimum requirements. Returns error text or None."""
    lang = get_language()
    _t = _translations.get(lang, _translations["DE"])
    if len(pw) < 8:
        return _t["pw_min_length"]
    if pw.isdigit():
        return _t["pw_not_only_digits"]
    if pw.lower() in ("password", "passwort", "12345678", "123456789", "1234567890", "abcdefgh", "qwertzui", "qwertyui"):
        return _t["pw_too_simple"]
    if len(set(pw)) < 3:
        return _t["pw_min_distinct"]
    return None


class User(UserMixin):
    def __init__(self, id, username, is_admin=False, default_trip_purpose=None, avatar_filename=None, map_style=None, theme=None, language=None):
        self.id = id
        self.username = username
        self.is_admin = is_admin
        self.default_trip_purpose = default_trip_purpose or ""
        self.avatar_filename = avatar_filename
        self.map_style = map_style
        self.theme = theme
        self.language = language


def _user_from_row(row):
    return User(row["id"], row["username"], bool(row["is_admin"]),
                row["default_trip_purpose"] if "default_trip_purpose" in row.keys() else None,
                row["avatar_filename"] if "avatar_filename" in row.keys() else None,
                row["map_style"] if "map_style" in row.keys() else None,
                row["theme"] if "theme" in row.keys() else None,
                row["language"] if "language" in row.keys() else None)


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
            _t = _translations.get(get_language(), _translations["DE"])
            return jsonify({"error": _t["err_admin_required"]}), 403
        return f(*args, **kwargs)
    return decorated


def debug_required(f):
    """Requires admin + ENABLE_DEBUG=1."""
    @wraps(f)
    @admin_required
    def decorated(*args, **kwargs):
        if not config.ENABLE_DEBUG:
            _t = _translations.get(get_language(), _translations["DE"])
            return jsonify({"error": _t["err_debug_disabled"]}), 403
        return f(*args, **kwargs)
    return decorated


_setup_required = False


def is_setup_required():
    """Live read of the first-run-setup flag. Blueprints can't see this
    module's global directly, so they call this instead of importing the name
    (which would snapshot the value)."""
    return _setup_required


def clear_setup_required():
    """Mark first-run setup complete. Called from the auth blueprint once the
    admin user exists — keeps the flag's single owner in this module."""
    global _setup_required
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
# Second counter per username (lowercase/strip) — throttles brute-force
# across rotating IPs. Same mechanism, username as the key.
_login_attempts_user = {}  # {username_key: [timestamp, ...]}
_LOGIN_MAX = 5
_LOGIN_COOLDOWN = 60  # seconds

def _user_key(username):
    """Normalized rate-limit key for a username (lowercase/strip)."""
    return (username or "").strip().lower()

def _is_rate_limited(ip):
    now = time.time()
    # Remove old entries; drop empty keys entirely, otherwise the dict grows
    # unbounded with rotating IPs (memory leak).
    attempts = [t for t in _login_attempts.get(ip, []) if now - t < _LOGIN_COOLDOWN]
    if attempts:
        _login_attempts[ip] = attempts
    else:
        _login_attempts.pop(ip, None)
    return len(attempts) >= _LOGIN_MAX

def _is_rate_limited_user(username):
    now = time.time()
    key = _user_key(username)
    if not key:
        return False
    attempts = [t for t in _login_attempts_user.get(key, []) if now - t < _LOGIN_COOLDOWN]
    if attempts:
        _login_attempts_user[key] = attempts
    else:
        _login_attempts_user.pop(key, None)
    return len(attempts) >= _LOGIN_MAX

def _record_attempt(ip):
    _login_attempts.setdefault(ip, []).append(time.time())

def _record_attempt_user(username):
    key = _user_key(username)
    if not key:
        return
    _login_attempts_user.setdefault(key, []).append(time.time())


def _safe_next(target):
    """Open-redirect protection: only allow local paths as redirect targets.
    Rejects absolute/protocol-relative URLs and the backslash trick."""
    if (not target or not target.startswith("/")
            or target.startswith("//") or target.startswith("/\\")):
        return "/"
    return target


# Auth & first-run-setup routes moved to blueprints/auth.py (FIXES 6.1),
# registered at the bottom of this module.

@app.route("/healthz")
def healthz():
    """Liveness probe — used by docker healthcheck."""
    return "ok", 200, {"Content-Type": "text/plain"}


@app.before_request
def require_login():
    """All routes except /login require authentication."""
    if request.endpoint in ("auth.login", "static", "charges.charge_webhook", "auth.setup", "auth.setup_2fa", "auth.login_totp", "healthz", "ha_export_vehicles"):
        return
    if _setup_required:
        return redirect(url_for("auth.setup"))
    if not current_user.is_authenticated:
        if request.path.startswith("/api/"):
            _t = _translations.get(get_language(), _translations["DE"])
            return jsonify({"error": _t["err_not_logged_in"]}), 401
        return redirect(url_for("auth.login", next=request.path))


# ── Global date range selection ──────────────────────────────

# Default window and how long a manually picked range survives before it snaps
# back to the default. With 5y of imported Tesla data a full-history query makes
# every list + the dashboard crawl, so the steady state must stay at 30 days —
# a custom range is only an exception that auto-expires.
DATE_RANGE_DEFAULT_DAYS = 30
DATE_RANGE_TTL_MIN = 60


def effective_date_range(default_days=DATE_RANGE_DEFAULT_DAYS):
    """Return (date_from, date_to) for the shared picker, as ISO 'YYYY-MM-DD'.

    Default = last `default_days` days. A range chosen via the picker is honoured
    for DATE_RANGE_TTL_MIN minutes, then auto-reverts to the default so heavy
    full-history queries never become the steady state. Returns ('','') only
    while an explicit "Alle"/custom selection is still fresh.
    """
    set_at = session.get("date_set_at")
    fresh = False
    if set_at:
        try:
            fresh = (datetime.now() - datetime.fromisoformat(set_at)) < timedelta(minutes=DATE_RANGE_TTL_MIN)
        except (TypeError, ValueError):
            fresh = False
    if fresh:
        return session.get("date_from", ""), session.get("date_to", "")
    # Nothing set, or the picked range expired → fall back to the default and
    # clear the stale selection so the picker label snaps back to "Letzte 30 Tage".
    if set_at is not None:
        session.pop("date_from", None)
        session.pop("date_to", None)
        session.pop("date_set_at", None)
    today = datetime.now().date()
    return (today - timedelta(days=default_days)).strftime("%Y-%m-%d"), today.strftime("%Y-%m-%d")


@app.route("/api/daterange", methods=["POST"])
def set_daterange():
    """Store date range in session (global for all pages). Stamped with the
    selection time so effective_date_range() can expire it after 60 min."""
    data = request.get_json()
    session["date_from"] = data.get("from", "")
    session["date_to"] = data.get("to", "")
    session["date_set_at"] = datetime.now().isoformat()
    return jsonify({"ok": True})


@app.route("/api/daterange")
def get_daterange():
    return jsonify({"from": session.get("date_from", ""), "to": session.get("date_to", "")})

# ── Trip log categories ──────────────────────────────────────


def get_purpose_meta(db, user_id=None, device=None):
    """All trip purposes with color and is_private from the DB.

    is_main first (the user's pinned default), then alphabetical case-insensitive.
    sort_order is intentionally dropped — it used to push every newly added
    purpose to the bottom even though the UI expects "fits-in-alphabet" placement.

    FIXES 15.2 — vehicle-driven visibility: if *device* is set, only purposes
    relevant to that vehicle are returned: already used on a trip of the vehicle
    (automatic), OR `is_main` (pinned default), OR explicitly assigned to the
    user (purpose_visibility, admin matrix). So each vehicle shows only its own
    vocabulary. *device=None* (default) returns the full catalogue — for the
    admin/management view (sees everything).
    """
    if device is None:
        rows = db.execute(
            "SELECT * FROM purpose_meta ORDER BY is_main DESC, name COLLATE NOCASE"
        ).fetchall()
    else:
        rows = db.execute(
            """SELECT * FROM purpose_meta
                WHERE is_main = 1
                   OR name IN (SELECT DISTINCT purpose FROM trips
                               WHERE device = ? AND purpose IS NOT NULL AND purpose != '')
                   OR name IN (SELECT name FROM purpose_visibility WHERE user_id = ?)
                ORDER BY is_main DESC, name COLLATE NOCASE""",
            (device, user_id),
        ).fetchall()
    return [dict(r) for r in rows]


def get_preset_values(db, field, device=None, user_id=None):
    """Suggestion values (destination | visit_reason). FIXES 15.2: vehicle-driven
    analogous to get_purpose_meta — values used on the vehicle (from trips) plus
    explicitly assigned ones (preset_value_visibility). device=None = full catalogue."""
    if device is None:
        rows = db.execute(
            "SELECT value FROM preset_values WHERE field = ? ORDER BY value COLLATE NOCASE",
            (field,),
        ).fetchall()
    else:
        col = "destination" if field == "destination" else "visit_reason"
        rows = db.execute(
            f"""SELECT value FROM preset_values
                 WHERE field = ?
                   AND (value IN (SELECT DISTINCT {col} FROM trips
                                  WHERE device = ? AND {col} IS NOT NULL AND {col} != '')
                        OR id IN (SELECT value_id FROM preset_value_visibility WHERE user_id = ?))
                 ORDER BY value COLLATE NOCASE""",
            (field, device, user_id),
        ).fetchall()
    return [r["value"] for r in rows]


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
    """Find the nearest saved location whose geofence contains (lat,lon).

    Circle: within radius_m. Polygon: inside the ray-cast polygon. For ranking
    overlapping matches, distance to the centre (lat/lon = polygon centroid) is
    used in both cases."""
    if not lat or not lon:
        return None
    locations = db.execute("SELECT * FROM locations").fetchall()
    best = None
    best_dist = float('inf')
    for loc in locations:
        keys = loc.keys()
        shape = loc["shape"] if "shape" in keys else "circle"
        if shape == "polygon" and "polygon_coords" in keys and loc["polygon_coords"]:
            try:
                coords = json.loads(loc["polygon_coords"])
            except (TypeError, ValueError):
                continue
            if _point_in_polygon(lat, lon, coords):
                dist = haversine_m(lat, lon, loc["lat"], loc["lon"])
                if dist < best_dist:
                    best = loc
                    best_dist = dist
        else:
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
    # FOREIGN_KEYS is per-connection — must be set every time, otherwise
    # ON DELETE CASCADE in schema.sql silently does nothing (was the source
    # of orphan charge_readings). WAL/synchronous are DB-level but cheap to re-set.
    db.execute("PRAGMA foreign_keys=ON")
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA synchronous=NORMAL")
    if _schema_initialized:
        return db
    with open("schema.sql") as f:
        db.executescript(f.read())
    # Schema migrations are versioned via PRAGMA user_version and live in
    # migrations.py (lazy import avoids a circular load: migrations.py pulls
    # get_bat_kwh from this module). See migrations.run_migrations for the
    # fresh-vs-legacy-DB safety contract.
    from migrations import run_migrations
    run_migrations(db, log)

    _schema_initialized = True
    return db


# ── Vehicle selection (active vehicle) ───────────────────────────

def allowed_vehicle_ids(db, user):
    """FIXES — per-user vehicle visibility: the set of vehicle IDs *user* is
    allowed to see. None = no restriction (all). Admins always see all; users
    without assignment rows also see all (backward compatibility)."""
    if user is None or not getattr(user, "is_authenticated", False):
        return None
    if getattr(user, "is_admin", False):
        return None
    rows = db.execute("SELECT vehicle_id FROM user_vehicle_access WHERE user_id = ?", (user.id,)).fetchall()
    if not rows:
        return None
    return {r[0] for r in rows}


def active_vehicle(db=None):
    """Active vehicle: last header pick > user default > first vehicle.
    Respects per-user vehicle visibility (allowed_vehicle_ids): a disallowed
    active/default vehicle is ignored, fallback = first allowed one."""
    close = False
    if db is None:
        db = get_db()
        close = True
    allowed = allowed_vehicle_ids(db, current_user) if current_user.is_authenticated else None

    def _ok(v):
        return v is not None and (allowed is None or v["id"] in allowed)

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
            if not _ok(vehicle):
                vehicle = None
        # Permanent admin default
        if not vehicle:
            vid = row["default_vehicle_id"] if row else None
            if vid:
                vehicle = db.execute("SELECT * FROM vehicles WHERE id = ?", (vid,)).fetchone()
                if not _ok(vehicle):
                    vehicle = None
    if not vehicle:
        if allowed is None:
            vehicle = db.execute("SELECT * FROM vehicles ORDER BY id LIMIT 1").fetchone()
        elif allowed:
            qs = ",".join("?" * len(allowed))
            vehicle = db.execute(
                f"SELECT * FROM vehicles WHERE id IN ({qs}) ORDER BY id LIMIT 1",
                tuple(allowed)
            ).fetchone()
    if close:
        db.close()
    return dict(vehicle) if vehicle else None


def active_device():
    """InfluxDB device tag of the active vehicle."""
    v = active_vehicle()
    if v and v.get("device"):
        return v["device"]
    return config.INFLUX_DEVICE


def get_bat_kwh(db, device=None, at_time=None):
    """Battery capacity (kWh).

    With ``at_time`` (ISO string): reads the capacity off the robust
    capacity-vs-time trend at that timestamp, so consumption tracks
    degradation as a smooth, gap-free line. Falls back to the vehicle's
    manual anchor (or the global setting) when there are too few charges.

    Without ``at_time``: returns the manual anchor value (unchanged)."""
    if device and at_time:
        prow = db.execute("SELECT plate FROM vehicles WHERE device = ?", (device,)).fetchone()
        if prow and prow["plate"]:
            tr = _capacity_trend(db, prow["plate"])
            if tr.get("cap_now") is not None:
                try:
                    ts = datetime.fromisoformat(at_time).timestamp()
                    return round(tr["cap_at"](ts), 2)
                except (ValueError, TypeError):
                    return tr["cap_now"]
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


# ── Dashboard notes (per-user scratchpad) ──────────────────

@app.route("/api/notes")
@login_required
def list_notes():
    db = get_db()
    veh = active_vehicle(db)
    plate = veh.get("plate") if veh else None
    # Show notes pinned to the current vehicle + legacy notes without plate
    # (NULL = global, visible everywhere — created before per-vehicle scope).
    rows = db.execute(
        "SELECT id, content, pinned, vehicle_plate, created_at, updated_at "
        "FROM user_notes "
        "WHERE user_id = ? AND (vehicle_plate = ? OR vehicle_plate IS NULL) "
        "ORDER BY pinned DESC, id DESC",
        (current_user.id, plate)
    ).fetchall()
    db.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/notes", methods=["POST"])
@login_required
def add_note():
    content = (request.get_json() or {}).get("content", "").strip()
    db = get_db()
    veh = active_vehicle(db)
    plate = veh.get("plate") if veh else None
    cur = db.execute(
        "INSERT INTO user_notes (user_id, vehicle_plate, content) VALUES (?, ?, ?)",
        (current_user.id, plate, content)
    )
    db.commit()
    nid = cur.lastrowid
    row = db.execute(
        "SELECT id, content, pinned, vehicle_plate, created_at, updated_at "
        "FROM user_notes WHERE id = ?",
        (nid,)
    ).fetchone()
    db.close()
    return jsonify(dict(row))


@app.route("/api/notes/<int:nid>", methods=["PUT"])
@login_required
def update_note(nid):
    data = request.get_json() or {}
    db = get_db()
    own = db.execute("SELECT user_id FROM user_notes WHERE id = ?", (nid,)).fetchone()
    if not own or own["user_id"] != current_user.id:
        db.close()
        return jsonify({"error": "not found"}), 404
    if "content" in data:
        db.execute(
            "UPDATE user_notes SET content = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
            (data["content"].strip(), nid)
        )
    if "pinned" in data:
        db.execute(
            "UPDATE user_notes SET pinned = ? WHERE id = ?",
            (1 if data["pinned"] else 0, nid)
        )
    db.commit()
    db.close()
    return jsonify({"ok": True})


@app.route("/api/notes/<int:nid>", methods=["DELETE"])
@login_required
def delete_note(nid):
    db = get_db()
    own = db.execute("SELECT user_id FROM user_notes WHERE id = ?", (nid,)).fetchone()
    if not own or own["user_id"] != current_user.id:
        db.close()
        return jsonify({"error": "not found"}), 404
    db.execute("DELETE FROM user_notes WHERE id = ?", (nid,))
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
    # Don't set a disallowed vehicle as active (per-user visibility).
    allowed = allowed_vehicle_ids(db, current_user)
    if vehicle_id and allowed is not None and int(vehicle_id) not in allowed:
        db.close()
        _t = _translations.get(get_language(), _translations["DE"])
        return jsonify({"error": _t["err_no_vehicle_access"]}), 403
    db.execute("UPDATE users SET active_vehicle_id = ? WHERE id = ?",
               (int(vehicle_id) if vehicle_id else None, current_user.id))
    db.commit()
    db.close()
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
_sse_clients: dict = {}          # client_id -> {"queue": Queue, "device": str, "stop": Event}
_sse_lock = threading.Lock()
_sse_next_id = 0
# Cap concurrent SSE streams: each open stream permanently parks one waitress
# worker thread (endless keepalive generator). Without a cap, a handful of open
# dashboard tabs starve the whole app (login included). When the cap is hit we
# evict the OLDEST stream (lowest cid) — a reopened/refreshed tab then always
# gets through instead of being permanently rejected.
_SSE_MAX_CLIENTS = 4


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
    # Defensive sanitize — MQTT-decode already cleans these, but any future
    # path that calls sse_publish with raw values must not poison the dashboard.
    if "soc" in mapped:
        mapped["soc"] = _sanitize_soc(mapped["soc"])
    if "range_km" in mapped:
        mapped["range_km"] = _sanitize_range(mapped["range_km"])
    # Derive operator from PLMN so the dashboard updates the carrier name
    # in real-time (the device telegram carries `lp`, not `operator`).
    if "plmn" in mapped:
        name = _plmn_name(mapped["plmn"])
        if name:
            mapped["operator"] = name
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

# PLMN (MCC*100 + MNC) → (carrier name, brand color) lives in plmn.py.
# Thin alias so older call sites keep working.
def _plmn_name(plmn):
    name, _ = plmn_info(plmn)
    return name


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

        # InfluxDB may carry historical u16-underflow garbage from MQTT writes
        # that pre-date the decode-side sanitize (~6553% SoC / ~6553 km range).
        # Cleanse on read so the dashboard never surfaces a 28000 km calc_range.
        if "soc" in state:
            state["soc"] = _sanitize_soc(state["soc"])
        if "range_km" in state:
            state["range_km"] = _sanitize_range(state["range_km"])

        # Mobile carrier: PLMN field is authoritative — the device transmits it
        # on every telegram. The legacy `op` tag on `ls` records (from pre-PLMN
        # writes) is only used as a last resort, since old series can survive
        # in the bucket and `last()` would surface a stale "O2" tag that
        # outvotes the correct current PLMN.
        if "plmn" in state:
            name = _plmn_name(state["plmn"])
            if name:
                state["operator"] = name
        if "operator" not in state:
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
                log.warning("live state: operator query failed for device=%s", device, exc_info=True)

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


# ── Home Assistant export: read-API for selected vehicles ────
# Lets a Home Assistant integration pull the latest state of *selected*
# vehicles (token-protected). Vehicles whose data originates in HA are simply
# not selected here, so there is no loopback.

def _ha_export_token() -> str:
    """The configured HA export read-token (decrypted), or '' if unset."""
    try:
        db = sqlite3.connect(config.DB_PATH, timeout=10)
        row = db.execute(
            "SELECT value FROM settings WHERE key = 'ha_export_token'"
        ).fetchone()
        db.close()
    except Exception:
        return ""
    if not row or not row[0]:
        return ""
    return _decrypt_setting(_settings_fernet(), row[0])


def _ha_export_devices() -> list:
    """Device tags selected for HA export (JSON list in settings)."""
    try:
        db = sqlite3.connect(config.DB_PATH, timeout=10)
        row = db.execute(
            "SELECT value FROM settings WHERE key = 'ha_export_devices'"
        ).fetchone()
        db.close()
    except Exception:
        return []
    if not row or not row[0]:
        return []
    try:
        val = json.loads(row[0])
        return [str(d) for d in val] if isinstance(val, list) else []
    except Exception:
        return []


@app.route("/api/ha/vehicles")
def ha_export_vehicles():
    """Latest state of the vehicles selected for Home Assistant export.

    Auth: ``Authorization: Bearer <ha_export_token>``. Exempt from the global
    login gate (see require_login) — external, token-authenticated caller.
    """
    token = _ha_export_token()
    if not token:
        return jsonify({"error": "HA export not configured"}), 503
    auth = request.headers.get("Authorization", "")
    if not hmac.compare_digest(auth, f"Bearer {token}"):
        return jsonify({"error": "Unauthorized"}), 401

    selected = set(_ha_export_devices())
    if not selected:
        return jsonify({"server": "IDMate", "vehicles": []})

    db = get_db()
    rows = db.execute(
        "SELECT plate, name, model, device FROM vehicles "
        "WHERE device IS NOT NULL AND device != '' ORDER BY plate"
    ).fetchall()
    db.close()

    vehicles = []
    for r in rows:
        dev = r["device"]
        if dev not in selected:
            continue
        with _state_lock:
            state = dict(_state_cache.get(dev, {}))
        if not state:
            state = _fetch_influx_state(dev)
        vehicles.append({
            "device": dev,
            "plate": r["plate"],
            "name": r["name"] or r["plate"],
            "model": r["model"] or "",
            "state": state,
        })
    return jsonify({"server": "IDMate", "vehicles": vehicles})


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

    # Consumption: rolling window of the last ~1000 km of driving.
    # Walks back trip-by-trip until accumulated distance reaches 1000 km, then
    # trims top/bottom 10% by per-trip consumption to drop outliers (e.g. cold
    # starts, single-leg detours), and km-weights the remainder.
    RANGE_WINDOW_KM = 1000
    recent_trips = db.execute(
        """SELECT energy_kwh, distance_km, consumption FROM trips
           WHERE device = ? AND energy_kwh IS NOT NULL AND energy_kwh > 0
             AND distance_km >= 20
             AND consumption IS NOT NULL AND consumption > 0
           ORDER BY end_time DESC LIMIT 100""",
        (device,),
    ).fetchall()
    window = []
    acc_km = 0.0
    for r in recent_trips:
        window.append(r)
        acc_km += r['distance_km']
        if acc_km >= RANGE_WINDOW_KM:
            break

    avg_cons = None
    if window:
        n = len(window)
        by_cons = sorted(window, key=lambda r: r['consumption'])
        trim = max(1, n // 10) if n >= 5 else 0
        trimmed = by_cons[trim:n - trim] if n > 2 * trim else by_cons
        if trimmed:
            tk = sum(r['energy_kwh'] for r in trimmed)
            tkm = sum(r['distance_km'] for r in trimmed)
            avg_cons = (tk / tkm * 100) if tkm > 0 else None

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
            influx_soc_ts = ft.get("soc")  # ISO-Z (UTC) format
            # Compare as tz-aware datetimes, not lexically: the charge reading is
            # local (Europe/Berlin) while influx_soc_ts is UTC-Z. A naive string
            # compare let an up-to-2-h-older wallbox reading "win" over a fresher
            # CAN SoC. _parse_local handles both naive-local and Z-suffixed input.
            cr_ts = cr["timestamp"]
            cr_dt = _parse_local(cr_ts) if cr_ts else None
            influx_dt = _parse_local(influx_soc_ts) if influx_soc_ts else None
            if cr_dt is not None and (influx_dt is None or cr_dt > influx_dt):
                state["soc"] = round(cr["soc"], 1)
                # Update field_times so dashboard shows fresh timestamp
                now_iso = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
                if "field_times" not in state:
                    state["field_times"] = {}
                state["field_times"]["soc"] = now_iso

    if avg_cons:
        state["avg_consumption"] = round(avg_cons, 1)
        if state.get("soc") is not None:
            capacity = get_bat_kwh(db, device)
            available_kwh = state["soc"] / 100.0 * capacity
            state["calc_range"] = round(available_kwh / avg_cons * 100, 0)

    # Max range at 100% SoC uses the same trimmed km-weighted window as
    # calc_range so both numbers stay consistent.
    if avg_cons:
        capacity = get_bat_kwh(db, device)
        state["max_range"] = round(capacity / avg_cons * 100, 0)

    # Charge-anchored "Ø real" (battery + grid side) — same helper as the
    # charges/analysis pages, over all charges of this vehicle.
    if v and v["plate"]:
        real = _real_consumption(db, v["plate"])
        if real and real["cons_batt"] is not None:
            state["real_cons_batt"] = real["cons_batt"]
            state["real_cons_grid"] = real["cons_grid"]

    db.close()
    return jsonify(state)


# ── SSE stream: real-time vehicle data via MQTT ──────────────

@app.route("/api/vehicle-stream")
def vehicle_stream():
    """Server-Sent Events: push MQTT telegrams to dashboard in real-time."""
    import queue
    global _sse_next_id
    device = active_device()

    stop = threading.Event()
    with _sse_lock:
        _sse_next_id += 1
        cid = _sse_next_id
        q = queue.Queue(maxsize=50)
        _sse_clients[cid] = {"queue": q, "device": device, "stop": stop}
        # Evict oldest streams until we're within the cap (this new one included).
        if len(_sse_clients) > _SSE_MAX_CLIENTS:
            for old_cid in sorted(_sse_clients)[:len(_sse_clients) - _SSE_MAX_CLIENTS]:
                if old_cid == cid:
                    continue
                old = _sse_clients[old_cid]
                old["stop"].set()
                # Nudge its generator out of the blocking q.get() at once.
                try:
                    old["queue"].put_nowait(None)
                except Exception:
                    # Full queue → evicted stream wakes on its own 30 s timeout.
                    log.debug("SSE: eviction sentinel put failed for client %s", old_cid, exc_info=True)

    def stream():
        try:
            while not stop.is_set():
                try:
                    payload = q.get(timeout=30)
                    if payload is None:        # eviction wake-up sentinel
                        break
                    yield f"data: {payload}\n\n"
                except queue.Empty:
                    # Keepalive — prevents timeout
                    yield ": keepalive\n\n"
        except GeneratorExit:
            pass
        finally:
            stop.set()
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


# Trip routes moved to blueprints/trips.py (FIXES 6.1).


# ── Analysis ─────────────────────────────────────────────────

@app.route("/analysis")
def analysis_page():
    # Shared picker: defaults to the last 30 days and auto-reverts after 60 min
    # (see effective_date_range) so the steady state never queries full history.
    date_from, date_to = effective_date_range()
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


# Heatmap GPS sanity window — absolute geographic bounds instead of a
# median-relative filter (which discarded every abroad trip as an "outlier",
# same footgun once fixed on the provider map). Wide enough for Europe-wide
# travel: Crete→Nordkapp, Iceland→Caucasus. Widen if trips go beyond Europe
# (e.g. the Canaries sit below 30° N and would be clipped).
_HEATMAP_LAT = (30.0, 72.0)
_HEATMAP_LON = (-30.0, 45.0)


def _heatmap_window(db, device, date_from, date_to):
    """Pick the Flux aggregateWindow size from the span of the requested range
    so all-time stays under the point cap and the query stays affordable."""
    try:
        if date_from and date_to:
            d0 = datetime.strptime(date_from[:10], "%Y-%m-%d").date()
            d1 = datetime.strptime(date_to[:10], "%Y-%m-%d").date()
        else:
            row = db.execute(
                "SELECT MIN(start_time) AS m FROM trips WHERE device = ?", (device,)
            ).fetchone()
            d0 = (datetime.strptime(row["m"][:10], "%Y-%m-%d").date()
                  if row and row["m"] else datetime.now().date())
            d1 = datetime.now().date()
        span = (d1 - d0).days
    except Exception:
        span = 9999
    if span <= 14:
        return "5m"
    if span <= 60:
        return "10m"
    if span <= 180:
        return "30m"
    if span <= 730:
        return "1h"
    return "3h"


@app.route("/api/trip-coords")
@login_required
def trip_coords():
    """All GPS points from InfluxDB for heatmap (aggressively downsampled)."""
    device = active_device()
    date_from = request.args.get("from", "") or session.get("date_from", "")
    date_to = request.args.get("to", "") or session.get("date_to", "")
    # Range + downsampling follow the date toolbar. For "all" we anchor at the
    # oldest trip (see _influx_range_clause) instead of a hard -180d cap that
    # silently hid every older/abroad trip. The aggregateWindow widens with the
    # span so all-time stays under the point cap and the Influx query stays cheap.
    db = get_db()
    range_clause = _influx_range_clause(db, device, date_from, date_to)
    window = _heatmap_window(db, device, date_from, date_to)
    db.close()
    client = detector.get_influx()
    if not client:
        return jsonify([])
    coords = []
    seen = set()
    try:
        # 5-minute windows, last-value instead of mean (mean averages over GPS drops → 0,0)
        query = f'''
        from(bucket: "{config.INFLUX_BUCKET}")
          {range_clause}
          |> filter(fn: (r) => r._measurement == "v" and r.d == "{device}")
          |> filter(fn: (r) => r._field == "la" or r._field == "lo")
          |> filter(fn: (r) => r._value != 0.0)
          |> aggregateWindow(every: {window}, fn: last, createEmpty: false)
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
        # Absolute geographic window instead of a median-relative filter: the
        # old "within 3° of the median" check discarded every abroad trip,
        # because the median sits at the home region. Now only GPS glitches
        # outside the plausible window are dropped; real Europe-wide travel stays.
        if raw:
            lat_lo, lat_hi = _HEATMAP_LAT
            lon_lo, lon_hi = _HEATMAP_LON
            log.info("Heatmap: %d raw points (window=%s)", len(raw), window)
            for la, lo in raw:
                if not (lat_lo <= la <= lat_hi and lon_lo <= lo <= lon_hi):
                    continue  # outside plausible window → GPS glitch
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
    # Charge-anchored "Ø real" (same helper as the charges page) over the
    # selected range — so analysis and charges show the identical figure.
    _pr = db2.execute("SELECT plate FROM vehicles WHERE device = ?", (active_device(),)).fetchone()
    real = _real_consumption(db2, _pr["plate"], date_from or None, date_to or None) if _pr and _pr["plate"] else None
    db2.close()

    # Grid-side efficiency so the SoC fallback (battery-side, lossless) is
    # comparable to the kw-meter jump (wall-side, includes ~7 % charging loss):
    # eff is battery÷grid, so wall = battery ÷ eff.
    db_eff = get_db()
    charge_eff = _get_charge_efficiency(db_eff)
    db_eff.close()

    charge_cycles = []
    cycle_km = 0.0
    carry_kwh = 0.0   # kWh of a charge that immediately followed another charge
    for i, t in enumerate(trips):
        if i > 0:
            prev = trips[i - 1]
            charged_kwh = None

            # Primary: kw meter jump (wall-side)
            if t.get("kw_start") is not None and prev.get("kw_end") is not None:
                kw_jump = t["kw_start"] - prev["kw_end"]
                if kw_jump >= 5:
                    charged_kwh = round(kw_jump, 1)
            # Fallback: SOC-Sprung (soc_start[i] > soc_end[i-1]) — battery-side,
            # normalised to wall-side via charge efficiency so both data paths
            # land on the same (grid) scale.
            if charged_kwh is None and t.get("soc_start") is not None and prev.get("soc_end") is not None:
                soc_jump = t["soc_start"] - prev["soc_end"]
                if soc_jump >= 5 and bat_kwh:
                    bat_charged = soc_jump / 100.0 * bat_kwh
                    wall_charged = bat_charged / charge_eff if charge_eff else bat_charged
                    charged_kwh = round(wall_charged, 1)

            if charged_kwh is not None:
                # The cycle being closed = km driven since the previous charge
                # (accumulated up to and incl. `prev`) refilled by this charge.
                # Close FIRST, add t["km"] AFTER, so the following trip's km do
                # not bleed into the just-finished cycle.
                total_kwh = charged_kwh + carry_kwh
                if cycle_km >= 1:
                    charge_cycles.append({
                        "date": t["date"],
                        "charged_kwh": round(total_kwh, 1),
                        "km": round(cycle_km, 1),
                        "consumption": round(total_kwh / cycle_km * 100, 1),
                    })
                    cycle_km = 0.0
                    carry_kwh = 0.0
                else:
                    # Charge directly after a charge (no km in between): keep the
                    # kWh for the next cycle instead of discarding it.
                    carry_kwh = total_kwh
        cycle_km += t["km"] or 0

    return jsonify({"trips": trips, "charge_cycles": charge_cycles, "bat_kwh": bat_kwh, "real": real})


@app.route("/api/charge/stats")
@login_required
def charge_stats():
    """Charge statistics: home/external, AC/DC, operator (external only)."""
    date_from = request.args.get("from", "")
    date_to   = request.args.get("to", "")

    db = get_db()
    params = []
    where  = "WHERE 1=1"
    # Scope to the active vehicle and exclude unidentified (OFF/UNKNOWN) charges,
    # analogous to the charges page — otherwise this aggregates *all* vehicles
    # while every other source on the analysis page is scoped to one vehicle.
    av = active_vehicle(db)
    if av and av.get("plate"):
        where += (" AND cs.vehicle_plate = ?"
                  " AND UPPER(COALESCE(cs.vehicle_plate,'')) NOT IN ('OFF','UNKNOWN')")
        params.append(av["plate"])
    if date_from and date_to:
        where += " AND cs.start_time >= ? AND cs.start_time <= ?"
        params += [date_from, date_to + "T23:59:59"]

    # Join to a single charge_location per name to avoid fan-out: with two
    # equally-named locations the plain LEFT JOIN cl.name = cs.location_name
    # would duplicate each session row, double-counting kWh/cost/counts. We pick
    # the lowest-id match per name via a subquery before joining operators.
    rows = db.execute(f"""
        SELECT cs.is_external, cs.location_name, cs.operator AS sess_operator,
               cl.type AS loc_type, cl.operator AS loc_operator,
               op.name AS op_name,
               cs.total_kwh, cs.cost_tibber, cs.cost_pauschale, cs.cost_total,
               cs.avg_kw, cs.duration_minutes, cs.start_time
        FROM charge_sessions cs
        LEFT JOIN (
            SELECT name, type, operator, operator_id
            FROM charge_locations
            WHERE id IN (SELECT MIN(id) FROM charge_locations GROUP BY name)
        ) cl ON cl.name = cs.location_name
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
    costed_kwh = 0.0   # kWh only from sessions that actually carry a price
    total_dur  = 0.0
    dur_count  = 0     # sessions that actually carry a duration
    monthly_kwh_home = {}
    monthly_kwh_ext  = {}
    monthly_cost     = {}
    avg_kw_ac = []
    avg_kw_dc = []

    for r in rows:
        is_ext = r["is_external"]
        avg_kw = r["avg_kw"]
        # Sessions at locations that were never set up have no loc_type → default
        # to AC, but treat clearly fast charging (avg_kw > 22) as DC, so ad-hoc
        # DC chargers do not silently land in the AC pie/histogram.
        if r["loc_type"]:
            loc_type = r["loc_type"].lower()
        elif avg_kw and avg_kw > 22:
            loc_type = "dc"
        else:
            loc_type = "ac"
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
            costed_kwh += kwh   # only priced kWh feed the Ø ct/kWh figure
        if r["duration_minutes"]:
            total_dur += r["duration_minutes"]
            dur_count += 1
        if avg_kw and avg_kw > 0:
            (avg_kw_dc if loc_type == "dc" else avg_kw_ac).append(avg_kw)

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
        # Neutral string keys — the frontend maps them onto translations
        # (de/en). Counts/structure unchanged.
        "home_vs_ext": {"home": home_count, "external": ext_count},
        "ac_dc": {"ac": ac_count, "dc": dc_count},
        "operators": operators_sorted,
        "totals": {
            "kwh": round(total_kwh, 1),
            "cost": round(total_cost, 2),
            # Only kWh from priced sessions divide the cost — otherwise free /
            # un-priced kWh dilute the figure ("missing price" ≠ "free").
            "avg_cost_kwh": round(total_cost / costed_kwh, 4) if costed_kwh else 0,
            # Average only over sessions that actually have a duration.
            "avg_duration_min": round(total_dur / dur_count, 0) if dur_count else 0,
            "sessions": session_count,
        },
        "monthly_kwh_home": monthly_kwh_home,
        "monthly_kwh_ext": monthly_kwh_ext,
        "monthly_cost": monthly_cost,
        "avg_kw_ac": sorted(avg_kw_ac),
        "avg_kw_dc": sorted(avg_kw_dc),
    })


def _parse_trip_ts(s):
    """Best-effort parse for trip timestamps. Manual entries can be HH:MM only
    (from <input type=datetime-local>), auto-detected ones have HH:MM:SS, and
    some legacy rows may carry a Z suffix, offset, or fractional seconds.
    Always returns a *naive* datetime in local time so values from different
    sources can be compared without TypeError.
    """
    if not s:
        return None
    s = s.strip().replace("Z", "+00:00")
    # Pad seconds if only HH:MM
    if len(s) == 16:  # 'YYYY-MM-DDTHH:MM'
        s = s + ":00"
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        try:
            dt = datetime.strptime(s[:19], "%Y-%m-%dT%H:%M:%S")
        except Exception:
            return None
    # Normalise to naive local time — datetime.now() is naive, mixing types
    # would raise TypeError on comparison.
    if dt.tzinfo is not None:
        dt = dt.astimezone().replace(tzinfo=None)
    return dt


@app.route("/api/analysis/yearly-purposes")
def yearly_purposes():
    """Per-purpose km YTD + extrapolation to full year, anchored at the first
    trip of the year (so a March-only driving year is not divided by 12)."""
    try:
        device = active_device()
        now = datetime.now()
        year = now.year
        db = get_db()
        rows = db.execute(
            """SELECT purpose, distance_km, start_time FROM trips
               WHERE device = ? AND strftime('%Y', start_time) = ?
                 AND distance_km IS NOT NULL AND distance_km > 0""",
            (device, str(year))
        ).fetchall()
        db.close()
        if not rows:
            return jsonify({"year": year, "purposes": [], "factor": 1.0,
                            "days_elapsed": 0, "days_available": 0,
                            "first_trip_date": None})
        # Earliest trip in current year — start of the "active period"
        parsed = [(_parse_trip_ts(r["start_time"]), r) for r in rows]
        valid = [(t, r) for (t, r) in parsed if t is not None]
        if not valid:
            return jsonify({"year": year, "purposes": [], "factor": 1.0,
                            "days_elapsed": 0, "days_available": 0,
                            "first_trip_date": None})
        first_dt = min(t for (t, _) in valid)
        year_end = datetime(year + 1, 1, 1)
        days_elapsed = max(1, (now - first_dt).days + 1)
        days_available = max(1, (year_end - first_dt).days)
        factor = days_available / days_elapsed if days_elapsed > 0 else 1.0
        by_purpose = {}
        for _, r in valid:
            p = (r["purpose"] or "").strip() or "—"
            by_purpose[p] = by_purpose.get(p, 0) + (r["distance_km"] or 0)
        purposes = sorted(
            [{"purpose": p, "km": round(v, 1), "estimated_year_km": round(v * factor, 0)}
             for p, v in by_purpose.items()],
            key=lambda x: -x["km"]
        )
        return jsonify({
            "year": year,
            "purposes": purposes,
            "factor": round(factor, 2),
            "days_elapsed": days_elapsed,
            "days_available": days_available,
            "first_trip_date": first_dt.strftime("%Y-%m-%d"),
        })
    except Exception as e:
        log.exception("yearly_purposes failed: %s", e)
        return jsonify({"year": datetime.now().year, "purposes": [],
                        "factor": 1.0, "days_elapsed": 0, "days_available": 0,
                        "first_trip_date": None, "error": str(e)}), 200


def _influx_range_clause(db, device, date_from, date_to):
    """Build the Flux range clause so it covers the SAME period as the
    unbounded SQL parts of the same endpoint. With an explicit toolbar range we
    honour it; for the "Alle" case we anchor the start at the oldest trip
    instead of a hard -365d (which would silently drop anything older)."""
    if date_from and date_to:
        return f'|> range(start: {date_from}T00:00:00Z, stop: {date_to}T23:59:59Z)'
    oldest = db.execute(
        "SELECT MIN(start_time) AS m FROM trips WHERE device = ?",
        (device,)
    ).fetchone()
    if oldest and oldest["m"]:
        return f'|> range(start: {oldest["m"][:10]}T00:00:00Z)'
    return '|> range(start: -365d)'


@app.route("/api/battery-history")
def battery_history():
    """Range at 100% SoC and capacity over time from InfluxDB."""
    device = active_device()
    date_from = request.args.get("from", "") or session.get("date_from", "")
    date_to = request.args.get("to", "") or session.get("date_to", "")

    # Estimated range from trips: capacity / consumption * 100
    db = get_db()
    bat_kwh = get_bat_kwh(db, device)
    # Flux range — same period as the unbounded SQL below (oldest trip onward).
    range_clause = _influx_range_clause(db, device, date_from, date_to)
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
              |> aggregateWindow(every: 1d, fn: mean, createEmpty: false, timeSrc: "_start")
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

    # Capacity per qualifying charge session: total_kwh / soc_delta * 100,
    # divided by 1.07 to account for typical AC charging losses → battery cap.
    # Only sessions with delta ≥ 50% are clean enough to use here; smaller
    # deltas have too much relative SoC-noise impact.
    charge_cap_data = []
    plate_row = db.execute(
        "SELECT plate FROM vehicles WHERE device = ? AND plate IS NOT NULL LIMIT 1",
        (device,)
    ).fetchone()
    plate = plate_row['plate'] if plate_row else None
    if plate:
        cs_rows = db.execute(
            """SELECT start_time, total_kwh, soc_start, soc_end FROM charge_sessions
               WHERE vehicle_plate = ? AND is_external = 0
                 AND total_kwh IS NOT NULL
                 AND soc_start IS NOT NULL AND soc_end IS NOT NULL
                 AND (soc_end - soc_start) >= 50
               ORDER BY datetime(start_time)""",
            (plate,)
        ).fetchall()
        for r in cs_rows:
            d = r['start_time'][:10]
            if date_from and d < date_from:
                continue
            if date_to and d > date_to:
                continue
            wall_cap = r['total_kwh'] / (r['soc_end'] - r['soc_start']) * 100
            bat_cap = wall_cap / 1.07
            charge_cap_data.append({"date": d, "value": round(bat_cap, 2)})
    db.close()

    return jsonify({
        "range": range_data,
        "capacity": cap_data,
        "capacity_from_charges": charge_cap_data,
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

    # Flux range — same period as the unbounded SQL/trip data below.
    db_range = get_db()
    range_clause = _influx_range_clause(db_range, device, date_from, date_to)
    db_range.close()

    # Daily average temperature from InfluxDB
    temp_data = []
    client = detector.get_influx()
    if client:
        try:
            q_temp = f'''
            from(bucket: "{config.INFLUX_BUCKET}")
              {range_clause}
              |> filter(fn: (r) => r._measurement == "v" and r.d == "{device}" and r._field == "et")
              |> aggregateWindow(every: 1d, fn: mean, createEmpty: false, timeSrc: "_start")
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


# ── Locations (geofencing) ────────────────────────────────────

@app.route("/api/locations")
def list_locations():
    db = get_db()
    rows = db.execute("SELECT * FROM locations ORDER BY name COLLATE NOCASE").fetchall()
    db.close()
    return jsonify([dict(r) for r in rows])


def _reassign_trips_around(db, name, lat, lon, radius_m):
    """Generic helper: rewrite trips.start_address / end_address to ``name``
    when the trip's start or end coordinates fall inside the circular
    geofence (lat, lon, radius_m). Used by both trip-locations and
    charge-locations after save."""
    if not name or lat is None or lon is None or not radius_m:
        return {"trips_start": 0, "trips_end": 0}
    deg = max(radius_m, 50) / 111000.0 * 1.2
    rows = db.execute(
        """SELECT id, start_lat, start_lon, end_lat, end_lon,
                  start_address, end_address
           FROM trips
           WHERE (start_lat BETWEEN ? AND ? AND start_lon BETWEEN ? AND ?)
              OR (end_lat   BETWEEN ? AND ? AND end_lon   BETWEEN ? AND ?)""",
        (lat - deg, lat + deg, lon - deg, lon + deg,
         lat - deg, lat + deg, lon - deg, lon + deg),
    ).fetchall()
    n_start = n_end = 0
    for t in rows:
        if t["start_lat"] is not None and t["start_lon"] is not None:
            d = detector.haversine_m(t["start_lat"], t["start_lon"], lat, lon)
            if d <= radius_m and t["start_address"] != name:
                # Anchor the geocode position to the trip's own coords so the
                # background geocoder treats this name as current and won't
                # overwrite it (until the point itself moves).
                db.execute(
                    "UPDATE trips SET start_address = ?, start_geo_lat = ?, start_geo_lon = ? WHERE id = ?",
                    (name, t["start_lat"], t["start_lon"], t["id"]))
                n_start += 1
        if t["end_lat"] is not None and t["end_lon"] is not None:
            d = detector.haversine_m(t["end_lat"], t["end_lon"], lat, lon)
            if d <= radius_m and t["end_address"] != name:
                db.execute(
                    "UPDATE trips SET end_address = ?, end_geo_lat = ?, end_geo_lon = ? WHERE id = ?",
                    (name, t["end_lat"], t["end_lon"], t["id"]))
                n_end += 1
    db.commit()
    return {"trips_start": n_start, "trips_end": n_end}


def _kick_geocoder():
    """Start a background geocoder pass at the slower backfill rate. Used after
    clearing addresses (geofence delete) so the freed entries get a street
    address again without burning the Nominatim per-second budget."""
    import threading
    try:
        geo.extend_backfill_window()
    except Exception:
        log.warning("geocoder kick: extend_backfill_window failed", exc_info=True)

    def _run():
        try:
            geo.run_once()
        except Exception:
            log.exception("geocoder kick failed")

    threading.Thread(target=_run, daemon=True).start()


def _clear_trips_for_geofence(db, name, lat, lon, radius_m):
    """Inverse of _reassign_trips_around: drop ``name`` from trip start/end
    addresses (within the geofence radius) and reset the geocode anchor so the
    background geocoder fetches a street address again. Called on geofence delete."""
    if not name:
        return {"trips_start": 0, "trips_end": 0}
    n_start = n_end = 0
    if lat is not None and lon is not None and radius_m:
        deg = max(radius_m, 50) / 111000.0 * 1.2
        rows = db.execute(
            """SELECT id, start_lat, start_lon, end_lat, end_lon, start_address, end_address
               FROM trips
               WHERE (start_address = ? AND start_lat BETWEEN ? AND ? AND start_lon BETWEEN ? AND ?)
                  OR (end_address   = ? AND end_lat   BETWEEN ? AND ? AND end_lon   BETWEEN ? AND ?)""",
            (name, lat - deg, lat + deg, lon - deg, lon + deg,
             name, lat - deg, lat + deg, lon - deg, lon + deg),
        ).fetchall()
        for t in rows:
            if (t["start_address"] == name and t["start_lat"] is not None
                    and detector.haversine_m(t["start_lat"], t["start_lon"], lat, lon) <= radius_m):
                db.execute(
                    "UPDATE trips SET start_address = NULL, start_geo_lat = NULL, start_geo_lon = NULL WHERE id = ?",
                    (t["id"],))
                n_start += 1
            if (t["end_address"] == name and t["end_lat"] is not None
                    and detector.haversine_m(t["end_lat"], t["end_lon"], lat, lon) <= radius_m):
                db.execute(
                    "UPDATE trips SET end_address = NULL, end_geo_lat = NULL, end_geo_lon = NULL WHERE id = ?",
                    (t["id"],))
                n_end += 1
    else:
        # No coordinates/radius — fall back to an exact name match.
        cur = db.execute(
            "UPDATE trips SET start_address = NULL, start_geo_lat = NULL, start_geo_lon = NULL WHERE start_address = ?",
            (name,))
        n_start = cur.rowcount
        cur = db.execute(
            "UPDATE trips SET end_address = NULL, end_geo_lat = NULL, end_geo_lon = NULL WHERE end_address = ?",
            (name,))
        n_end = cur.rowcount
    db.commit()
    return {"trips_start": n_start, "trips_end": n_end}


def _reassign_trips_polygon(db, name, polygon_coords):
    """Polygon variant of _reassign_trips_around: rewrite trips.start_address /
    end_address to ``name`` when the trip's start/end coordinates fall inside the
    polygon. Uses a bbox prefilter (SQL) + Python point-in-polygon."""
    if not name or not polygon_coords:
        return {"trips_start": 0, "trips_end": 0}
    try:
        poly = json.loads(polygon_coords)
    except (TypeError, ValueError):
        return {"trips_start": 0, "trips_end": 0}
    if not poly or len(poly) < 3:
        return {"trips_start": 0, "trips_end": 0}
    lats = [p[0] for p in poly]
    lons = [p[1] for p in poly]
    bb_lat_min, bb_lat_max = min(lats), max(lats)
    bb_lon_min, bb_lon_max = min(lons), max(lons)
    rows = db.execute(
        """SELECT id, start_lat, start_lon, end_lat, end_lon, start_address, end_address
           FROM trips
           WHERE (start_lat BETWEEN ? AND ? AND start_lon BETWEEN ? AND ?)
              OR (end_lat   BETWEEN ? AND ? AND end_lon   BETWEEN ? AND ?)""",
        (bb_lat_min, bb_lat_max, bb_lon_min, bb_lon_max,
         bb_lat_min, bb_lat_max, bb_lon_min, bb_lon_max),
    ).fetchall()
    n_start = n_end = 0
    for t in rows:
        if (t["start_lat"] is not None and t["start_lon"] is not None
                and t["start_address"] != name
                and _point_in_polygon(t["start_lat"], t["start_lon"], poly)):
            db.execute(
                "UPDATE trips SET start_address = ?, start_geo_lat = ?, start_geo_lon = ? WHERE id = ?",
                (name, t["start_lat"], t["start_lon"], t["id"]))
            n_start += 1
        if (t["end_lat"] is not None and t["end_lon"] is not None
                and t["end_address"] != name
                and _point_in_polygon(t["end_lat"], t["end_lon"], poly)):
            db.execute(
                "UPDATE trips SET end_address = ?, end_geo_lat = ?, end_geo_lon = ? WHERE id = ?",
                (name, t["end_lat"], t["end_lon"], t["id"]))
            n_end += 1
    db.commit()
    return {"trips_start": n_start, "trips_end": n_end}


def _reassign_trips_to_location(db, loc_id):
    loc = db.execute(
        "SELECT name, lat, lon, radius_m, shape, polygon_coords FROM locations WHERE id = ?",
        (loc_id,),
    ).fetchone()
    if not loc:
        return {"trips_start": 0, "trips_end": 0}
    if loc["shape"] == "polygon" and loc["polygon_coords"]:
        return _reassign_trips_polygon(db, loc["name"], loc["polygon_coords"])
    return _reassign_trips_around(db, loc["name"], loc["lat"], loc["lon"], loc["radius_m"])


@app.route("/api/locations", methods=["POST"])
def create_location():
    data = request.get_json()
    name = data.get("name", "").strip()
    lat = data.get("lat")
    lon = data.get("lon")
    if not name or lat is None or lon is None:
        _t = _translations.get(get_language(), _translations["DE"])
        return jsonify({"error": _t["err_name_lat_lon_required"]}), 400

    shape = data.get("shape", "circle")
    polygon_coords = data.get("polygon_coords") if shape == "polygon" else None
    db = get_db()
    cur = db.execute(
        """INSERT INTO locations (name, lat, lon, radius_m, shape, polygon_coords, category, default_reason, icon, color, icon_color)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (name, lat, lon,
         data.get("radius_m", 200),
         shape,
         polygon_coords,
         data.get("category", "kunde"),
         data.get("default_reason", ""),
         data.get("icon", "pin"),
         data.get("color", "#21262d"),
         data.get("icon_color", "white")),
    )
    db.commit()
    loc_id = cur.lastrowid
    reassigned = _reassign_trips_to_location(db, loc_id)
    db.close()
    return jsonify({"ok": True, "id": loc_id, "reassigned": reassigned})


@app.route("/api/locations/<int:loc_id>", methods=["POST"])
def update_location(loc_id):
    data = request.get_json()
    db = get_db()
    allowed = ("name", "lat", "lon", "radius_m", "shape", "polygon_coords", "category", "default_reason", "icon", "color", "icon_color")
    sets = []
    params = []
    for field in allowed:
        if field in data:
            sets.append(f"{field} = ?")
            params.append(data[field])
    if not sets:
        _t = _translations.get(get_language(), _translations["DE"])
        return jsonify({"error": _t["err_no_fields"]}), 400
    params.append(loc_id)
    db.execute(f"UPDATE locations SET {', '.join(sets)} WHERE id = ?", params)
    db.commit()
    reassigned = _reassign_trips_to_location(db, loc_id)
    db.close()
    return jsonify({"ok": True, "id": loc_id, "reassigned": reassigned})


@app.route("/api/locations/<int:loc_id>", methods=["DELETE"])
def delete_location(loc_id):
    db = get_db()
    loc = db.execute(
        "SELECT name, lat, lon, radius_m, shape FROM locations WHERE id = ?", (loc_id,)
    ).fetchone()
    db.execute("DELETE FROM locations WHERE id = ?", (loc_id,))
    db.commit()
    cleared = {"trips_start": 0, "trips_end": 0}
    if loc:
        # Strip the geofence name off affected trips and let the geocoder
        # bring back the street addresses. Polygons have no usable circle, so
        # fall back to the exact-name match (assignment set the address to name).
        if loc["shape"] == "polygon":
            cleared = _clear_trips_for_geofence(db, loc["name"], None, None, None)
        else:
            cleared = _clear_trips_for_geofence(db, loc["name"], loc["lat"], loc["lon"], loc["radius_m"])
    db.close()
    if cleared["trips_start"] or cleared["trips_end"]:
        _kick_geocoder()
    return jsonify({"ok": True, "cleared": cleared})


# ── Geofence suggestions ─────────────────────────────────────
# Cluster trip start/end points that don't fall into any existing geofence
# and surface the frequent ones as suggestions. Dismissed suggestions are
# remembered (rounded coords) in the settings table.

_SUGGEST_MIN_VISITS = 5
_SUGGEST_CLUSTER_M = 150.0
_DISMISS_KEY = "dismissed_geofence_suggestions"


def _load_dismissed_suggestions(db):
    row = db.execute("SELECT value FROM settings WHERE key = ?", (_DISMISS_KEY,)).fetchone()
    if not row or not row["value"]:
        return []
    try:
        return json.loads(row["value"])  # [[lat, lon], ...]
    except Exception:
        return []


def _save_dismissed_suggestions(db, items):
    db.execute(
        "INSERT INTO settings (key, value) VALUES (?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (_DISMISS_KEY, json.dumps(items)),
    )
    db.commit()


def _compute_geofence_suggestions(db, device, include_hidden=False):
    """Greedy-cluster trip endpoints outside existing geofences; return the
    clusters with >= _SUGGEST_MIN_VISITS visits, most frequent first."""
    locs = db.execute("SELECT lat, lon, radius_m FROM locations").fetchall()

    def _in_geofence(lat, lon):
        for loc in locs:
            if detector.haversine_m(lat, lon, loc["lat"], loc["lon"]) <= (loc["radius_m"] or 200):
                return True
        return False

    rows = db.execute(
        """SELECT start_lat, start_lon, start_address, end_lat, end_lon, end_address
           FROM trips WHERE device = ?""",
        (device,),
    ).fetchall()

    pts = []  # (lat, lon, addr)
    for r in rows:
        if r["start_lat"] is not None and r["start_lon"] is not None:
            pts.append((r["start_lat"], r["start_lon"], r["start_address"]))
        if r["end_lat"] is not None and r["end_lon"] is not None:
            pts.append((r["end_lat"], r["end_lon"], r["end_address"]))

    clusters = []  # {lat, lon, count, addrs:{}}
    for lat, lon, addr in pts:
        if _in_geofence(lat, lon):
            continue
        found = None
        for c in clusters:
            if detector.haversine_m(lat, lon, c["lat"], c["lon"]) <= _SUGGEST_CLUSTER_M:
                found = c
                break
        if found:
            n = found["count"]
            found["lat"] = (found["lat"] * n + lat) / (n + 1)
            found["lon"] = (found["lon"] * n + lon) / (n + 1)
            found["count"] = n + 1
            if addr:
                found["addrs"][addr] = found["addrs"].get(addr, 0) + 1
        else:
            clusters.append({"lat": lat, "lon": lon, "count": 1,
                             "addrs": ({addr: 1} if addr else {})})

    dismissed = _load_dismissed_suggestions(db)

    def _is_dismissed(lat, lon):
        return any(detector.haversine_m(lat, lon, d[0], d[1]) <= _SUGGEST_CLUSTER_M
                   for d in dismissed)

    out = []
    for c in clusters:
        if c["count"] < _SUGGEST_MIN_VISITS:
            continue
        hidden = _is_dismissed(c["lat"], c["lon"])
        if hidden and not include_hidden:
            continue
        label = max(c["addrs"].items(), key=lambda kv: kv[1])[0] if c["addrs"] else None
        out.append({
            "lat": round(c["lat"], 6),
            "lon": round(c["lon"], 6),
            "count": c["count"],
            "label": label or f'{round(c["lat"], 4)}, {round(c["lon"], 4)}',
            "hidden": hidden,
        })
    out.sort(key=lambda s: s["count"], reverse=True)
    return out


@app.route("/api/locations/suggestions")
def location_suggestions():
    include_hidden = request.args.get("include_hidden") == "1"
    db = get_db()
    suggestions = _compute_geofence_suggestions(db, active_device(), include_hidden)
    db.close()
    return jsonify({"suggestions": suggestions,
                    "min_visits": _SUGGEST_MIN_VISITS})


@app.route("/api/locations/suggestions/dismiss", methods=["POST"])
def dismiss_location_suggestion():
    data = request.get_json() or {}
    lat, lon = data.get("lat"), data.get("lon")
    if lat is None or lon is None:
        _t = _translations.get(get_language(), _translations["DE"])
        return jsonify({"error": _t["err_lat_lon_required"]}), 400
    db = get_db()
    dismissed = _load_dismissed_suggestions(db)
    dismissed.append([float(lat), float(lon)])
    _save_dismissed_suggestions(db, dismissed)
    db.close()
    return jsonify({"ok": True})


@app.route("/api/locations/suggestions/restore", methods=["POST"])
def restore_location_suggestion():
    """Remove a dismissed entry near the given point so it shows up again."""
    data = request.get_json() or {}
    lat, lon = data.get("lat"), data.get("lon")
    if lat is None or lon is None:
        _t = _translations.get(get_language(), _translations["DE"])
        return jsonify({"error": _t["err_lat_lon_required"]}), 400
    db = get_db()
    dismissed = _load_dismissed_suggestions(db)
    kept = [d for d in dismissed
            if detector.haversine_m(float(lat), float(lon), d[0], d[1]) > _SUGGEST_CLUSTER_M]
    _save_dismissed_suggestions(db, kept)
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
    _t = _translations.get(get_language(), _translations["DE"])
    if not from_id and not to_id:
        return jsonify({"error": _t["err_from_or_to_required"]}), 400
    if not purpose:
        return jsonify({"error": _t["err_purpose_required"]}), 400

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
        return jsonify({"error": _t["err_route_rule_exists"]}), 409
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


# Admin/management routes moved to blueprints/admin.py (FIXES 6.1).


# ── Odometer gaps (manual trip backfill) ────────────────────

def _find_odo_gaps(db, plate, min_km=2, date_from="", date_to=""):
    """List odometer gaps for a vehicle.

    Walks only non-manual trips so original gaps stay visible even after the
    user has filled them with manual splits. Each gap is annotated with the
    manual coverage (assigned_km, assigned_trip_ids) so the UI can show
    "open" vs. "assigned" status without losing the entry.

    min_km filters out micro-gaps (default 2 — odometer-rounding noise from
    GPS resync etc.). date_from/date_to filter by gap end time (= start of
    the next trip) to keep large histories scrollable.
    """
    v = db.execute("SELECT device FROM vehicles WHERE plate = ?", (plate,)).fetchone()
    if not v or not v["device"]:
        return []
    # Only auto-detected trips form the spine of the odometer; manual splits
    # filled into gaps shouldn't make the gap disappear from the menu.
    rows = db.execute(
        """SELECT id, start_time, end_time, odo_start, odo_end
           FROM trips WHERE device = ? AND is_manual = 0
           ORDER BY datetime(start_time)""",
        (v["device"],)
    ).fetchall()
    manuals = db.execute(
        """SELECT id, distance_km, odo_start, odo_end, purpose,
                  destination, visit_reason, start_time, end_time
           FROM trips WHERE device = ? AND is_manual = 1
           ORDER BY odo_start""",
        (v["device"],)
    ).fetchall()

    def _coverage(from_km, to_km):
        """Returns (trips[], summed_km) for manual trips covering [from_km, to_km]."""
        trips, km = [], 0.0
        for m in manuals:
            mo_s, mo_e = m["odo_start"], m["odo_end"]
            if mo_s is None or mo_e is None:
                continue
            if mo_s >= from_km - 0.01 and mo_e <= to_km + 0.01:
                trips.append({
                    "id": m["id"],
                    "km": m["distance_km"] or 0,
                    "purpose": m["purpose"] or "",
                    "destination": m["destination"] or "",
                    "visit_reason": m["visit_reason"] or "",
                    "start_time": m["start_time"],
                    "end_time": m["end_time"],
                })
                km += m["distance_km"] or 0
        return trips, round(km, 1)

    # Side data: trip context (start/end address, km, purpose) so the edit
    # modal can show "previous / next trip" for orientation.
    ctx = {}
    for r in db.execute(
        """SELECT id, start_time, end_time, distance_km, start_address,
                  end_address, purpose, destination
           FROM trips WHERE device = ? AND is_manual = 0""",
        (v["device"],)
    ).fetchall():
        ctx[r["id"]] = {
            "id": r["id"],
            "start_time": r["start_time"],
            "end_time": r["end_time"],
            "distance_km": r["distance_km"],
            "start_address": r["start_address"],
            "end_address": r["end_address"],
            "purpose": r["purpose"] or "",
            "destination": r["destination"] or "",
        }

    gaps = []
    prev = None
    for r in rows:
        if r["odo_start"] is None and r["odo_end"] is None:
            continue
        if prev is None:
            if r["odo_start"] is not None and r["odo_start"] > 0:
                a_trips, a_km = _coverage(0, float(r["odo_start"]))
                total_km = round(float(r["odo_start"]), 1)
                gaps.append({
                    "from_km": 0,
                    "to_km": float(r["odo_start"]),
                    "km": total_km,
                    "from_time": None,
                    "to_time": r["start_time"],
                    "prev_trip_id": None,
                    "next_trip_id": r["id"],
                    "prev_trip": None,
                    "next_trip": ctx.get(r["id"]),
                    "assigned_km": a_km,
                    "assigned_trips": a_trips,
                    "assigned": a_km >= total_km - 0.5,
                })
                # Initial gap: keep only if to_time falls inside date range
                if date_from and (r["start_time"] or "") < date_from:
                    gaps.pop()
                elif date_to and (r["start_time"] or "")[:10] > date_to:
                    gaps.pop()
            prev = r
            continue
        if prev["odo_end"] is not None and r["odo_start"] is not None:
            gap_km = r["odo_start"] - prev["odo_end"]
            if gap_km >= min_km:
                a_trips, a_km = _coverage(float(prev["odo_end"]), float(r["odo_start"]))
                gaps.append({
                    "from_km": float(prev["odo_end"]),
                    "to_km": float(r["odo_start"]),
                    "km": round(gap_km, 1),
                    "from_time": prev["end_time"],
                    "to_time": r["start_time"],
                    "prev_trip_id": prev["id"],
                    "next_trip_id": r["id"],
                    "prev_trip": ctx.get(prev["id"]),
                    "next_trip": ctx.get(r["id"]),
                    "assigned_km": a_km,
                    "assigned_trips": a_trips,
                    "assigned": a_km >= gap_km - 0.5,
                })
                if date_from and (r["start_time"] or "") < date_from:
                    gaps.pop()
                elif date_to and (r["start_time"] or "")[:10] > date_to:
                    gaps.pop()
        prev = r
    return gaps


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


# ── GPX-Export ────────────────────────────────────────────────

GPX_MAX_DAYS = 90


# ── Trip split ───────────────────────────────────────────────

def _parse_local(s):
    """ISO time string -> tz-aware datetime in Europe/Berlin.
    Stored trip times are local time without offset."""
    s = str(s).strip().replace(" ", "T")
    if s.endswith("Z") or "+" in s[10:]:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).astimezone(_LOCAL_TZ)
    return datetime.fromisoformat(s).replace(tzinfo=_LOCAL_TZ)


def _trip_telemetry_points(trip, max_points=300):
    """Time-sorted telemetry points of a trip for the split UI:
    [{t: local-ISO, lat, lon, odo, soc}, ...]. InfluxDB for normal trips,
    gpx_waypoints for GPX imports. Forward-filled, downsampled."""
    pts = []
    if trip.get("is_gpx"):
        db = get_db()
        wps = db.execute(
            "SELECT lat, lon, timestamp FROM gpx_waypoints WHERE trip_id = ? ORDER BY seq",
            (trip["id"],)).fetchall()
        db.close()
        for w in wps:
            if w["timestamp"]:
                pts.append({"t": w["timestamp"], "lat": w["lat"], "lon": w["lon"],
                            "odo": None, "soc": None})
    else:
        client = detector.get_influx()
        if client:
            try:
                query = f'''
                from(bucket: "{config.INFLUX_BUCKET}")
                  |> range(start: {_to_rfc3339(trip["start_time"])}, stop: {_to_rfc3339_padded(trip["end_time"])})
                  |> filter(fn: (r) => r._measurement == "v" and r.d == "{trip["device"] or active_device()}")
                  |> filter(fn: (r) => r._field == "s" or r._field == "od" or r._field == "la" or r._field == "lo")
                  |> pivot(rowKey: ["_time"], columnKey: ["_field"], valueColumn: "_value")
                  |> sort(columns: ["_time"])
                '''
                tables = client.query_api().query(query, org=config.INFLUX_ORG)
                last = {"la": None, "lo": None, "od": None, "s": None}
                for table in tables:
                    for rec in table.records:
                        tt = rec.get_time()
                        if tt:
                            tt = tt.astimezone(_LOCAL_TZ)
                        for k in ("la", "lo", "od", "s"):
                            v = rec.values.get(k)
                            if v is not None:
                                last[k] = v
                        pts.append({"t": tt.strftime("%Y-%m-%dT%H:%M:%S") if tt else None,
                                    "lat": last["la"], "lon": last["lo"],
                                    "odo": last["od"], "soc": last["s"]})
            except Exception:
                log.exception("split-points telemetry load failed for trip %s", trip["id"])
            finally:
                client.close()
    pts = [p for p in pts if p["t"] and p["lat"] is not None and p["lon"] is not None]
    if len(pts) > max_points:
        step = len(pts) / max_points
        pts = [pts[int(i * step)] for i in range(max_points)]
    return pts


# Journey routes moved to blueprints/journeys.py (FIXES 6.1).


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
<div id="status" class="status offline">Connecting...</div>
<div style="font-size:0.75rem;color:#484f58;margin:0.3rem 0">
  Broker: {config.MQTT_BROKER}:{config.MQTT_PORT} | Topic: {config.MQTT_TOPIC} | TLS: {'✓' if config.MQTT_TLS else '✗'}
</div>
<table><thead><tr><th>Time</th><th>Topic</th><th>Payload</th><th>QoS</th></tr></thead>
<tbody id="msgs"></tbody></table>

<script>
async function refresh() {{
  try {{
    const res = await fetch('/api/mqtt-messages');
    const data = await res.json();
    const el = document.getElementById('status');
    if (data.connected) {{
      el.className = 'status online';
      el.textContent = '● Connected — ' + data.count + ' messages received';
    }} else {{
      el.className = 'status offline';
      el.textContent = '● Not connected';
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
        device = parts[1] if len(parts) >= 3 else "vw_id"

        point = Point("v").tag("d", device)
        # Enforce field types via the central table (see
        # config.INFLUX_INT_FIELDS) — otherwise a 422 field-type-conflict and the
        # whole batch is discarded.
        for k, val in fields.items():
            point.field(k, config.influx_field_value(k, val))
        point.time(int(ts * 1_000_000_000), WritePrecision.NS)

        try:
            writer.write(bucket=config.INFLUX_BUCKET, record=point)
            ok += 1
        except Exception:
            fail += 1

    client.close()
    return jsonify({"replayed_ok": ok, "replayed_fail": fail})


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

    # Whitelist device against vehicles table. The value lands unquoted in the
    # Flux predicate below (r.d == "{device}"), so anything but a known device
    # opens a predicate-injection.
    valid_devices = {r["device"] for r in db.execute(
        "SELECT device FROM vehicles WHERE device IS NOT NULL AND device != ''"
    ).fetchall()}
    if device not in valid_devices:
        db.close()
        return "<h1>Unknown device</h1>", 400

    client = detector.get_influx()
    if not client:
        db.close()
        return "<h1>InfluxDB not reachable</h1>", 503

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
<h1>Debug: InfluxDB raw data</h1>
<form method="get" style="flex-wrap:wrap">
  <label>Device:</label>
  <select name="device" onchange="this.form.submit()">
    {''.join(f'<option value="{d}" {"selected" if d==device else ""}>{d}</option>' for d in devices)}
  </select>
  <label>Hours:</label>
  <input type="number" name="hours" value="{hours}" style="width:60px">
  <span style="color:#484f58">or</span>
  <label>From:</label>
  <input type="datetime-local" name="from" value="{date_from}" style="width:180px">
  <label>To:</label>
  <input type="datetime-local" name="to" value="{date_to}" style="width:180px">
  <button type="submit" class="btn">Load</button>
</form>

<div class="meta">
  <b>Device:</b> {device} &nbsp;|&nbsp;
  <b>Range:</b> {since.astimezone(detector.LOCAL_TZ).strftime('%Y-%m-%d %H:%M')} → {until.astimezone(detector.LOCAL_TZ).strftime('%Y-%m-%d %H:%M') if until else 'now'} &nbsp;|&nbsp;
  <b>last_trip_end:</b> {last_end.astimezone(detector.LOCAL_TZ).strftime('%Y-%m-%d %H:%M')}<br>
  <b>Rows:</b> {len(rows)} &nbsp;|&nbsp;
  <b>Detected trips:</b> {len(trips)} &nbsp;|&nbsp;
  <b>DATA_GAP_MINUTES:</b> {config.DATA_GAP_MINUTES} &nbsp;|&nbsp;
  <b>TRIP_STOP_MINUTES:</b> {config.TRIP_STOP_MINUTES} &nbsp;|&nbsp;
  <b>SOC_JUMP_MIN:</b> {config.SOC_JUMP_MIN}% &nbsp;|&nbsp;
  <b>TRIP_MIN_DISTANCE_KM:</b> {config.TRIP_MIN_DISTANCE_KM}
</div>
"""

    if trips:
        html += "<h2>Detected trips</h2>"
        for i, t in enumerate(trips, 1):
            html += f'<div class="trip">#{i}: {t["start_time"]} → {t["end_time"]} | {t.get("distance_km", "?")} km | SoC {t.get("soc_start", "?")}→{t.get("soc_end", "?")}%</div>'
    else:
        html += '<h2 style="color:#f85149">No trips detected</h2>'

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

    html += f'<h2>Raw data ({len(rows)} rows)</h2>'
    html += f"""<div class="toolbar">
  <input type="checkbox" id="selAll" onchange="toggleAll(this)">
  <span class="sel-count" id="selCount">0 selected</span>
  <button class="btn btn-danger" onclick="deleteSelected()">Delete selected</button>
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
            if gap_min >= config.DATA_GAP_MINUTES:
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
  document.getElementById('selCount').textContent = n + ' selected';
}}

function toggleAll(cb) {{
  document.querySelectorAll('.rowsel').forEach(c => c.checked = cb.checked);
  document.getElementById('selAll').checked = cb.checked;
  updateCount();
}}

async function deleteSelected() {{
  const checked = document.querySelectorAll('.rowsel:checked');
  if (!checked.length) return;
  if (!confirm('Really permanently delete ' + checked.length + ' rows from InfluxDB?')) return;

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
    alert('Deleted: ' + data.deleted + ' timestamps');
  }} else {{
    alert('Error: ' + (data.error || 'Unknown'));
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
  document.getElementById('selCount').textContent = vis + '/' + total + ' visible';
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
    Receives AES-256-CBC encrypted binary telegrams (protocol v1 + v2)."""
    global _mqtt_connected, _mqtt_influx_count, _mqtt_influx_failed

    try:
        import paho.mqtt.client as mqtt
    except ImportError:
        log.warning("MQTT: paho-mqtt not installed")
        return

    from influxdb_client import InfluxDBClient, WritePrecision
    from influxdb_client.client.write_api import SYNCHRONOUS
    import struct
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.padding import PKCS7

    aes_key = bytes.fromhex(config.MQTT_AES_KEY)

    # Binary field schema: (bit, key, struct_fmt, byte_count, divisor)
    # Bool fields (fmt=None, bytes=0): bit set in field_mask = true
    # v1: legacy — kw is u16/10 (6553.5 kWh cap, wraps silently)
    # v2: kw widened to u32/10 (~429 Mio kWh) — all other fields identical
    _BIN_FIELDS_V1 = [
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
    _BIN_FIELDS_V2 = [
        (bit, key, '<I' if key == 'kw' else fmt,
         4    if key == 'kw' else size,
         divisor)
        for (bit, key, fmt, size, divisor) in _BIN_FIELDS_V1
    ]
    _BIN_FIELDS_BY_VERSION = {0x01: _BIN_FIELDS_V1, 0x02: _BIN_FIELDS_V2}

    def _decrypt_payload(raw):
        """Decrypt binary telegram (v1 or v2) → dict with fields + ts."""
        if len(raw) < 17:
            return None
        version = raw[0]
        schema = _BIN_FIELDS_BY_VERSION.get(version)
        if schema is None:
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
        for bit, key, fmt, size, divisor in schema:
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
                if key == 's':
                    val = _sanitize_soc(val)
                elif key == 'r':
                    val = _sanitize_range(val)
                fields[key] = val
                offset += size

        fields['ts'] = ts
        return fields

    # InfluxDB write client (long-lived, thread-safe)
    influx_write = None
    if config.INFLUX_TOKEN:
        _influx = InfluxDBClient(
            url=config.INFLUX_URL,
            token=config.INFLUX_TOKEN,
            org=config.INFLUX_ORG,
        )
        influx_write = _influx.write_api(write_options=SYNCHRONOUS)
        log.info("MQTT->InfluxDB bridge active (bucket=%s)", config.INFLUX_BUCKET)
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
        # Enforce field types via the central table (see
        # config.INFLUX_INT_FIELDS) — otherwise a 422 field-type-conflict and the
        # whole batch is discarded.
        for k, val in fields.items():
            point.field(k, config.influx_field_value(k, val))
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
            # Binary telegrams (every protocol version the decoder knows, not
            # just v1/0x01) are shown as hex; only genuine text payloads get
            # UTF-8-decoded. Keyed off _BIN_FIELDS_BY_VERSION so a new version
            # (e.g. v2/0x02 with u32 kWh) no longer renders as UTF-8 garbage.
            "payload": raw[:40].hex() if len(raw) > 0 and raw[0] in _BIN_FIELDS_BY_VERSION else raw.decode("utf-8", errors="replace"),
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


_charge_soc_cache = {}  # (device, start_local, end_local) -> (soc_start, soc_end)


def _influx_soc_for_session(device, start_local, end_local, client=None):
    """True start/end SoC of a charge from the CAN telemetry in InfluxDB.

    The car often sleeps while charging and only reports SoC hours before /
    after (e.g. when parked, or first drive a day later). So we do NOT search
    *inside* the charge window — we take the LAST 's' value at/just-before the
    charge start (state going in) and the FIRST 's' value at/just-after the
    charge end (state coming out), reaching up to 7 days in each direction.
    Cached, since rebuild reruns over all sessions on every webhook.
    Returns (soc_start, soc_end), each possibly None."""
    if not device or not start_local or not end_local:
        return (None, None)
    key = (device, start_local, end_local)
    if key in _charge_soc_cache:
        return _charge_soc_cache[key]
    result = (None, None)
    try:
        from zoneinfo import ZoneInfo
        tz = ZoneInfo("Europe/Berlin")
        s = datetime.fromisoformat(start_local).replace(tzinfo=tz)
        e = datetime.fromisoformat(end_local).replace(tzinfo=tz)
        if (datetime.now(tz) - s).days > 730:  # outside typical retention
            _charge_soc_cache[key] = result
            return result
        # Short timeout so a slow/unreachable Influx can't hang the rebuild (and
        # with it the SQLite write lock). Reuse a shared client when the caller
        # passes one (rebuild loop) instead of reconnecting per session.
        own_client = client is None
        client = client if client is not None else detector.get_influx(timeout_ms=2500)
        if client:
            try:
                WIN = timedelta(days=7)

                def _iso(dt):
                    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

                def _one(q):
                    for table in client.query_api().query(q, org=config.INFLUX_ORG):
                        for rec in table.records:
                            v = rec.get_value()
                            if v is not None:
                                # Historical bad writes (~6553%) live in Influx
                                # forever; sanitize on read so rebuild_charge_
                                # sessions doesn't poison charge_sessions again.
                                v = _sanitize_soc(v)
                                if v is not None:
                                    return round(float(v), 1)
                    return None

                base = (f'from(bucket: "{config.INFLUX_BUCKET}")\n'
                        f'  |> range(start: %s, stop: %s)\n'
                        f'  |> filter(fn: (r) => r._measurement == "v" '
                        f'and r.d == "{device}" and r._field == "s")\n  |> %s\n')
                q_start = base % (_iso(s - WIN), _iso(s + timedelta(minutes=5)), "last()")
                q_end = base % (_iso(e - timedelta(minutes=5)), _iso(e + WIN), "first()")
                result = (_one(q_start), _one(q_end))
            finally:
                if own_client:
                    client.close()
    except Exception as e:
        log.debug("influx soc lookup failed: %s", e)
    _charge_soc_cache[key] = result
    return result


def _billed_floor(db):
    """Inclusive lower bound for rebuilds: sessions whose start_time is before
    this are billed (manually set 'charge_billed_until' date) and must NEVER be
    rebuilt. Returns the first instant AFTER the billed day, or None when unset.
    Set strictly manually — never auto-set (e.g. not on invoice/print)."""
    row = db.execute("SELECT value FROM settings WHERE key = 'charge_billed_until'").fetchone()
    if not row or not row["value"]:
        return None
    try:
        d = datetime.fromisoformat(str(row["value"])[:10]).date() + timedelta(days=1)
        return d.isoformat() + "T00:00:00"
    except ValueError:
        return None


def _charge_scope_floor(db, since):
    """Extend a scoped rebuild's `since` back to the start of the charge it
    belongs to, so a charge isn't split. Two cases:
      (a) an existing session already has a reading at/after `since`, or
      (b) the most recent session starting at/before `since` — a new reading
          (e.g. the live webhook) extends this ONGOING charge and must be
          rebuilt together with it, otherwise every 15-min reading would spawn
          its own fragment session.
    Returns an ISO timestamp.

    Both lookups extend back to a session's EARLIEST READING, never its displayed
    start_time. A session's start_time is the *trimmed* first reading (the ~300 Wh
    plug-in handshake is excluded from the visible window, app.py rebuild trim),
    yet the session physically owns those earlier low-energy readings. Using
    start_time as the floor leaves the trimmed leading reading outside the rebuild
    scope: the DELETE drops the session, the unlink (timestamp >= floor) misses
    the earlier reading, and it ends up orphaned (session_id pointing at a deleted
    row) = "unassigned readings" — and its Wh silently vanish from the
    session total. So the floor MUST sit at/below the earliest owned reading."""
    floor = str(since)
    # (a) sessions overlapping [since, ∞): take their earliest reading, not the
    #     trimmed start_time.
    row = db.execute(
        "SELECT MIN(cr2.timestamp) AS m FROM charge_sessions cs "
        "JOIN charge_readings cr  ON cr.session_id  = cs.id AND cr.timestamp >= ? "
        "JOIN charge_readings cr2 ON cr2.session_id = cs.id "
        "WHERE cs.is_external = 0", (since,)
    ).fetchone()
    if row and row["m"] and row["m"] < floor:
        floor = row["m"]
    # (b) the most recent session starting at/before `since` (the ONGOING charge
    #     the new reading extends) — floor = its earliest reading, so a trimmed
    #     leading reading is rebuilt with it instead of being orphaned.
    prev = db.execute(
        "SELECT MIN(cr.timestamp) AS m FROM charge_readings cr "
        "WHERE cr.session_id = ("
        "  SELECT id FROM charge_sessions WHERE is_external = 0 "
        "  AND datetime(start_time) <= datetime(?) "
        "  ORDER BY datetime(start_time) DESC LIMIT 1)", (since,)
    ).fetchone()
    if prev and prev["m"] and prev["m"] < floor:
        floor = prev["m"]
    return floor


def rebuild_charge_sessions(db, since=None):
    """Session detection: groups a vehicle's readings into one charge per
    PLUG-IN. Consecutive readings belong together unless the car was DRIVEN in
    between (a trip occurred → it left and came back = a new charge). This keeps
    Tibber-paused charges together even when the pause spans many hours (the car
    stays plugged in), mirroring the old "same odometer = one charge" logic but
    working without a per-reading odometer (Easee/MID sends none). Odometer is an
    optional attribute, not a grouping key.

    External sessions (is_external=1) are preserved, only automatic
    sessions are recalculated.

    Scope: a rebuild NEVER touches billed sessions (start_time on/before the
    manually set 'charge_billed_until' date). With ``since`` (ISO timestamp) only
    the affected period is rebuilt — extended back to the start of the charge
    ``since`` falls into; everything earlier stays untouched. ``since=None``
    rebuilds from the freeze cutoff (or everything when no cutoff is set).

    Atomicity: the whole rebuild (DELETE of the old sessions, session re-grouping,
    field restore, numbering, distance + location backfill) runs inside one
    ``with db:`` transaction. Without it, an exception after the initial DELETE
    would leave the charge log wiped until the next successful rebuild; the
    context manager rolls everything back so the old sessions survive a failure.
    """
    with db:
        _rebuild_charge_sessions_impl(db, since)


def _rebuild_charge_sessions_impl(db, since=None):
    from collections import defaultdict
    from datetime import datetime

    # Inclusive start of the rebuildable range (None = from the very beginning).
    floor = _billed_floor(db)
    if since is not None:
        scope = _charge_scope_floor(db, since)
        floor = scope if (floor is None or scope > floor) else floor

    def _scope(col):
        """(sql_clause, params) restricting `col` to the rebuildable range."""
        return (f" AND {col} >= ?", [floor]) if floor else ("", [])

    # Save user-assigned fields of the sessions about to be rebuilt, keyed by
    # (plate, start_time) — stable across rebuilds (odometer may be NULL now).
    _c, _p = _scope("start_time")
    _saved = {}
    for row in db.execute(
        "SELECT vehicle_plate, start_time, location_name, operator, note, cost_total, "
        "manual_fields, odometer, soc_start, soc_end "
        "FROM charge_sessions WHERE is_external = 0" + _c, _p
    ).fetchall():
        if (row['location_name'] or row['operator'] or row['note']
                or row['cost_total'] or row['manual_fields']):
            _saved[(row['vehicle_plate'], row['start_time'])] = {
                'location_name': row['location_name'], 'operator': row['operator'],
                'note': row['note'], 'cost_total': row['cost_total'],
                'manual_fields': row['manual_fields'], 'odometer': row['odometer'],
                'soc_start': row['soc_start'], 'soc_end': row['soc_end'],
            }

    # Delete + unlink only the rebuildable range; frozen/earlier sessions stay.
    _c, _p = _scope("start_time")
    db.execute("DELETE FROM charge_sessions WHERE is_external = 0" + _c, _p)
    _c, _p = _scope("timestamp")
    db.execute("UPDATE charge_readings SET session_id = NULL WHERE 1=1" + _c, _p)

    # Build sessions for everything that carries energy in the range, INCLUDING
    # unidentified charges (plate 'OFF'/'unknown') — they must not get lost for
    # billing. Only genuinely idle 'free'/empty readings are skipped.
    _c, _p = _scope("timestamp")
    readings = db.execute(
        "SELECT * FROM charge_readings "
        "WHERE UPPER(COALESCE(vehicle_plate, '')) NOT IN ('FREE', '')" + _c +
        " ORDER BY vehicle_plate, timestamp", _p
    ).fetchall()

    # plate -> device for InfluxDB SoC refinement (CAN telemetry beats the
    # coarse HA webhook SoC)
    plate_device = {row["plate"]: row["device"]
                    for row in db.execute(
                        "SELECT plate, device FROM vehicles "
                        "WHERE plate IS NOT NULL AND device IS NOT NULL AND device != ''"
                    ).fetchall()}

    # Reassign OFF/unknown readings to the nearest real-plate vehicle when no
    # trip occurred between them — the wallbox is the same physical session,
    # only the car identity was unresolved (e.g. the VW-ID integration hangs on
    # the 8 AM handshake and only catches the plate at 11 AM). Otherwise the
    # handshake's energy ends up in a separate OFF session, away from the real
    # vehicle's totals. Reassigned both in memory (for this rebuild) AND in DB
    # (so charge_detail/charges_list see them under the right plate).
    _OFF_PLATES = ('OFF', 'UNKNOWN')
    _MAX_REASSIGN_S = 24 * 3600
    reads_mut = [dict(r) for r in readings]
    real_reads = [r for r in reads_mut
                  if r['vehicle_plate'] and r['vehicle_plate'].upper() not in _OFF_PLATES]
    for r in reads_mut:
        p = (r['vehicle_plate'] or '').upper()
        if p not in _OFF_PLATES:
            continue
        try:
            r_t = datetime.fromisoformat(r['timestamp'])
        except (ValueError, TypeError):
            log.warning("rebuild: OFF reading %s has unparseable timestamp %r — skipped",
                        r.get('id'), r.get('timestamp'))
            continue
        best = None; best_gap = _MAX_REASSIGN_S
        for other in real_reads:
            try:
                o_t = datetime.fromisoformat(other['timestamp'])
            except (ValueError, TypeError):
                log.debug("rebuild: real reading %s has unparseable timestamp %r — skipped",
                          other.get('id'), other.get('timestamp'))
                continue
            gap = abs((o_t - r_t).total_seconds())
            if gap < best_gap:
                best_gap = gap; best = other
        if not best:
            continue
        real_plate = best['vehicle_plate']
        device = plate_device.get(real_plate)
        if device:
            t1, t2 = (r['timestamp'], best['timestamp']) if r['timestamp'] < best['timestamp'] else (best['timestamp'], r['timestamp'])
            moved = db.execute(
                "SELECT 1 FROM trips WHERE device = ? "
                "AND datetime(start_time) > datetime(?) "
                "AND datetime(start_time) < datetime(?) "
                "AND COALESCE(distance_km, 0) >= 0.5 LIMIT 1",
                (device, t1, t2),
            ).fetchone()
            if moved:
                continue  # car drove between OFF reading and real one → keep separate
        r['vehicle_plate'] = real_plate
        db.execute("UPDATE charge_readings SET vehicle_plate = ? WHERE id = ?",
                   (real_plate, r['id']))

    # Group into one charge per plug-in. A new charge starts only when the car
    # was DRIVEN between two readings — detected via a trip in the gap (≈ the
    # odometer would have changed). A Tibber pause leaves no trip → stays one
    # charge. For unidentified charges (OFF/unknown, no device) we cannot check
    # trips, so fall back to a long time gap.
    _GAP_CHECK_MIN = 20    # > one 15-min interval → check whether the car moved
    _OFF_GAP_MIN = 720     # no device → split only on a >12 h gap
    by_plate = defaultdict(list)
    for r in reads_mut:
        by_plate[r['vehicle_plate']].append(r)

    groups = []  # list of (plate, [readings]) — one entry per charge
    for plate, preads in by_plate.items():
        preads.sort(key=lambda x: x['timestamp'])
        device = plate_device.get(plate)
        cur_group, prev = [], None
        for r in preads:
            split = False
            if cur_group and prev is not None:
                try:
                    gap = (datetime.fromisoformat(r['timestamp'])
                           - datetime.fromisoformat(prev['timestamp'])).total_seconds() / 60.0
                except (ValueError, TypeError):
                    gap = 0
                if gap > _OFF_GAP_MIN:
                    # > 12 h gap = the car was away/unplugged for so long that
                    # this is definitely a NEW plug-in charge — regardless of
                    # trip data (which may be missing/incomplete). Without this
                    # hard cap, charges days apart merged into ONE session
                    # (e.g. Jun 5 + Jun 10), which then got mis-sorted.
                    split = True
                elif gap > _GAP_CHECK_MIN and device:
                    # Medium gap (20 min - 12 h): only split when the car
                    # actually drove (a trip in between) — otherwise a Tibber pause.
                    moved = db.execute(
                        "SELECT 1 FROM trips WHERE device = ? "
                        "AND datetime(start_time) >= datetime(?) "
                        "AND datetime(start_time) <  datetime(?) "
                        "AND COALESCE(distance_km, 0) >= 0.5 LIMIT 1",
                        (device, prev['timestamp'], r['timestamp']),
                    ).fetchone()
                    split = moved is not None
            if split:
                groups.append((plate, cur_group))
                cur_group = []
            cur_group.append(r)
            prev = r
        if cur_group:
            groups.append((plate, cur_group))

    # One shared Influx client for all per-session SoC lookups (was reconnecting
    # per session). Short timeout so a slow Influx can't hang the rebuild.
    _soc_client = detector.get_influx(timeout_ms=2500)
    for plate, reads in groups:
        # Trim leading/trailing low-energy readings — the ~300 Wh Easee+Tibber
        # handshake at plug-in, post-charge trickle, and any plug/unplug micro
        # charges around the actual session. The MAIN window drives the visible
        # times (so the log doesn't show when you plugged in at home, only when
        # the wallbox actually charged); the FULL window keeps energy + costs
        # honest (you paid for the handshake too — don't drop it from totals).
        # Threshold = max(30 % of the session's strongest reading, 0.1 kWh):
        # excludes a handshake even at low-power charging while keeping a
        # uniform low-current real charge intact. Interior low-power readings
        # (Tibber pause hours) stay in the main window.
        _max_kwh = max((r['kwh'] or 0) for r in reads)
        _thr = max(_max_kwh * 0.30, 0.1)
        _fi = next((i for i, r in enumerate(reads) if (r['kwh'] or 0) >= _thr), None)
        _li = next((i for i in range(len(reads) - 1, -1, -1) if (reads[i]['kwh'] or 0) >= _thr), None)
        main_reads = reads[_fi:_li + 1] if _fi is not None else reads

        # Display window: main charge only.
        start_time = main_reads[0]['timestamp']
        end_time = main_reads[-1]['timestamp']
        # Energy + costs + meter readings: full plug-in (every kWh you paid for).
        total_kwh = sum(r['kwh'] or 0 for r in reads)
        _odo_vals = [r['odometer'] for r in reads if r['odometer'] is not None]
        odo = round(_odo_vals[-1]) if _odo_vals else None
        m_start = reads[0]['meter_start']
        m_end = reads[-1]['meter_end']

        try:
            t0 = datetime.fromisoformat(start_time)
            t1 = datetime.fromisoformat(end_time)
            # Estimate actual end time within last 15-min interval:
            # Use avg kW from previous reading to calculate how many minutes
            # the last main reading's kWh actually took.
            last_kwh = main_reads[-1]['kwh'] or 0
            if len(main_reads) >= 2 and last_kwh > 0:
                prev_kwh = main_reads[-2]['kwh'] or 0
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

        # Costs over ALL readings — the handshake/trickle is metered and billed.
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

        # SOC: first and last non-null soc value from the webhook readings…
        soc_vals = [r['soc'] for r in main_reads if r.get('soc') is not None]
        soc_start = soc_vals[0] if soc_vals else None
        soc_end = soc_vals[-1] if soc_vals else None
        # …then prefer the CAN telemetry from InfluxDB (state before/after the
        # charge) when the vehicle has a device tag — catches charge starts the
        # webhook missed. Only soc_start/soc_end change; readings stay intact.
        device = plate_device.get(plate)
        if device:
            inf_start, inf_end = _influx_soc_for_session(
                device, main_reads[0]['timestamp'], main_reads[-1]['timestamp'],
                client=_soc_client)
            if inf_start is not None:
                soc_start = inf_start
            if inf_end is not None:
                soc_end = inf_end

        # Trip fallback for missing/stale HA values (VW-ID integration hangs):
        #   - last trip BEFORE the charge → SoC the car was parked at = soc_start,
        #     plus its end odometer (sanity anchor for misassigned charges).
        #   - FIRST trip AFTER the charge → SoC the car drove off with = soc_end
        #     (the "charged to 80%" value the user expects) and its start
        #     odometer. This is the post-charge counterpart, picked up as soon
        #     as the detector saves a new trip; before that the values stay None
        #     and the row remains flagged incomplete (red).
        if device and (not odo or soc_start is None or soc_end is None):
            lt = db.execute(
                "SELECT odo_end, soc_end FROM trips WHERE device = ? "
                "AND end_time IS NOT NULL AND datetime(end_time) <= datetime(?) "
                "ORDER BY datetime(end_time) DESC LIMIT 1",
                (device, start_time),
            ).fetchone()
            nt = db.execute(
                "SELECT odo_start, soc_start FROM trips WHERE device = ? "
                "AND start_time IS NOT NULL AND datetime(start_time) >= datetime(?) "
                "ORDER BY datetime(start_time) ASC LIMIT 1",
                (device, end_time or start_time),
            ).fetchone()
            if lt:
                if not odo and lt["odo_end"] is not None:
                    odo = round(lt["odo_end"])
                if soc_start is None and lt["soc_end"] is not None:
                    soc_start = lt["soc_end"]
            if nt:
                if not odo and nt["odo_start"] is not None:
                    odo = round(nt["odo_start"])
                if soc_end is None and nt["soc_start"] is not None:
                    soc_end = nt["soc_start"]

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

    if _soc_client:
        _soc_client.close()

    # Remove ghost/empty sessions: automatic sessions without any readings (they
    # arise e.g. when a session with a broken/NULL start_time escaped the DELETE
    # and its readings were re-grouped here — the old shell otherwise stays
    # behind empty and poisons sorting/gap detection).
    db.execute(
        "DELETE FROM charge_sessions WHERE is_external = 0 AND id NOT IN "
        "(SELECT session_id FROM charge_readings WHERE session_id IS NOT NULL)"
    )

    # Restore user-assigned fields (only within the rebuilt range).
    #
    # The save/restore key is (plate, start_time). But start_time = first reading
    # above the trim threshold, and that threshold depends on the session's
    # strongest reading (max(0.30·max_kwh, 0.1)). While a charge is still running,
    # max_kwh grows → the trim window's first reading can shift by a 15-min step →
    # the exact key no longer matches and manually set note/location_name/
    # cost_total would silently vanish on the next rebuild.
    #
    # Fix: keep the exact-match fast path, but fall back to a ±30-min tolerance
    # match on (same plate). Each saved entry is consumed at most once so two
    # rebuilt sessions can't both claim the same saved fields.
    if _saved:
        def _parse_dt(s):
            try:
                return datetime.fromisoformat(s)
            except (ValueError, TypeError):
                return None

        _consumed = set()  # keys of _saved already restored
        _TOL = timedelta(minutes=30)
        _c, _p = _scope("start_time")
        for row in db.execute(
            "SELECT id, vehicle_plate, start_time FROM charge_sessions WHERE is_external = 0" + _c, _p
        ).fetchall():
            plate = row['vehicle_plate']
            key = (plate, row['start_time'])
            saved = None
            if key in _saved and key not in _consumed:
                saved = _saved[key]
                _consumed.add(key)
            else:
                # Tolerance fallback: nearest unconsumed saved entry of the same
                # plate within ±30 min of this session's start_time.
                row_dt = _parse_dt(row['start_time'])
                if row_dt is not None:
                    best_key = None
                    best_gap = _TOL
                    for (s_plate, s_start) in _saved:
                        if s_plate != plate or (s_plate, s_start) in _consumed:
                            continue
                        s_dt = _parse_dt(s_start)
                        if s_dt is None:
                            continue
                        gap = abs(s_dt - row_dt)
                        if gap <= best_gap:
                            best_gap = gap
                            best_key = (s_plate, s_start)
                    if best_key is not None:
                        saved = _saved[best_key]
                        _consumed.add(best_key)
            if saved:
                sets = []
                params = []
                for field in ('location_name', 'operator', 'note', 'cost_total'):
                    if saved[field] is not None:
                        sets.append(f"{field} = ?")
                        params.append(saved[field])
                # Restore admin-corrected odometer/SoC (marked manual) over the
                # freshly recomputed values, and carry the marker forward.
                manual = {f for f in (saved.get('manual_fields') or '').split(',') if f}
                for field in ('odometer', 'soc_start', 'soc_end'):
                    if field in manual and saved.get(field) is not None:
                        sets.append(f"{field} = ?")
                        params.append(saved[field])
                if manual:
                    sets.append("manual_fields = ?")
                    params.append(saved['manual_fields'])
                if sets:
                    db.execute(f"UPDATE charge_sessions SET {', '.join(sets)} WHERE id = ?",
                               params + [row['id']])

    # Assign session numbers — PERSISTENT: existing numbers stay fixed (stable
    # for the invoice), only freshly built sessions (session_number IS NULL) get
    # the next free number. On a true full rebuild from scratch there are none
    # preserved, so numbering starts at the configured 'charge_session_start'.
    start_row = db.execute("SELECT value FROM settings WHERE key = 'charge_session_start'").fetchone()
    start_num = int(start_row['value']) if start_row else 1
    maxn_row = db.execute(
        "SELECT MAX(CAST(session_number AS INTEGER)) AS m FROM charge_sessions "
        "WHERE is_external = 0 AND session_number IS NOT NULL AND session_number GLOB '[0-9]*'"
    ).fetchone()
    next_num = (maxn_row["m"] + 1) if (maxn_row and maxn_row["m"] is not None) else start_num
    for s in db.execute(
        "SELECT id FROM charge_sessions WHERE is_external = 0 AND session_number IS NULL "
        "ORDER BY datetime(start_time)"
    ).fetchall():
        db.execute("UPDATE charge_sessions SET session_number = ? WHERE id = ?",
                   (str(next_num), s['id']))
        next_num += 1

    # Calculate distances (per vehicle, sorted by start time)
    # Distance = km driven FROM this charge TO the next charge
    # (last/newest session has no distance — next charge unknown)
    # Read the full chain per vehicle (so each session sees its successor), but
    # only WRITE distances within the rebuilt range — frozen sessions stay as is.
    vehicles = db.execute("SELECT DISTINCT vehicle_plate FROM charge_sessions").fetchall()
    for v in vehicles:
        sessions = db.execute("""
            SELECT id, odometer, start_time FROM charge_sessions
            WHERE vehicle_plate = ? ORDER BY datetime(start_time)
        """, (v['vehicle_plate'],)).fetchall()
        for i, s in enumerate(sessions):
            if floor and s['start_time'] and s['start_time'] < floor:
                continue  # preserved / billed → don't touch its distance
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

    _c, _p = _scope("start_time")
    loc_sessions = db.execute(
        "SELECT id, vehicle_plate, start_time, end_time, lat, lon, is_external "
        "FROM charge_sessions WHERE 1=1" + _c + " ORDER BY datetime(start_time)", _p
    ).fetchall()
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
                log.debug("rebuild: midpoint calc failed for session %s (%r..%r) — using start_time",
                          s['id'], s['start_time'], s['end_time'], exc_info=True)

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
        WHERE UPPER(COALESCE(vehicle_plate, '')) NOT IN ('FREE', 'ERROR', 'UNKNOWN', 'OFF', '')
    """).fetchall()
    for p in plates:
        db.execute("INSERT OR IGNORE INTO vehicles (plate) VALUES (?)", (p['vehicle_plate'],))

    # No explicit commit: rebuild_charge_sessions() runs this impl inside a
    # `with db:` transaction that commits on success / rolls back on exception.


# Charging routes (webhook, sessions, readings, import) moved to
# blueprints/charges.py (FIXES 6.1).


# ── Vehicles CRUD ────────────────────────────────────────────

@app.route("/api/vehicles")
def list_vehicles():
    db = get_db()
    rows = db.execute("SELECT * FROM vehicles ORDER BY plate").fetchall()
    allowed = allowed_vehicle_ids(db, current_user)
    db.close()
    if allowed is not None:
        rows = [r for r in rows if r["id"] in allowed]
    return jsonify([dict(r) for r in rows])


# Lower bound must allow small batteries (e.g. ~48 kWh) — set too high it
# rejects every charge of a small-pack vehicle and the estimate stays empty.
_CAPACITY_PLAUSI_MIN = 40.0   # kWh
_CAPACITY_PLAUSI_MAX = 110.0  # kWh
# B-filter thresholds — shared by the estimate and the audit detail so both
# always apply identical rules.
_CAP_MIN_KWH = 5
_CAP_SOC_START_MIN = 20   # session must START at or above this SoC
_CAP_SOC_END_MAX = 95     # session must END at or below this SoC
_CAP_DELTA_MIN = 20       # minimum SoC delta (after stuck-correction)
# Only TeslaMate imports carry the vehicle's battery-side energy
# (charge_energy_added). Every other source — internal meter sessions AND
# manual/auto-detected external ones — logs grid energy, which is a few %
# above what reached the battery (AC onboard-charger losses). So scale
# everything except real TM imports. The factor can be calibrated against a
# vehicle with a known capacity (see /api/admin/calibrate-efficiency); the
# default ~0.90 is a typical AC value. Used for capacity estimation only.
_CHARGE_GRID_EFFICIENCY_DEFAULT = 0.90


def _get_charge_efficiency(db):
    row = db.execute(
        "SELECT value FROM settings WHERE key = 'charge_grid_efficiency'"
    ).fetchone()
    try:
        return float(row["value"]) if row and row["value"] else _CHARGE_GRID_EFFICIENCY_DEFAULT
    except (TypeError, ValueError):
        return _CHARGE_GRID_EFFICIENCY_DEFAULT


def _is_tm_session(session_number):
    return bool(session_number) and str(session_number).startswith("TM-")


def _battery_kwh(total_kwh, is_tm, efficiency):
    """Energy that reached the battery. TM sessions already report the
    vehicle's battery-side value; everything else logs grid energy → scale
    by the AC charging efficiency."""
    if total_kwh is None:
        return None
    return total_kwh if is_tm else total_kwh * efficiency


# ── "Ø real" consumption (charge-anchored) ───────────────────
# The single source of truth for real consumption across all pages. Energy that
# went back INTO the car at each charge ÷ ODOMETER-km driven since the previous
# charge (odometer is SoC-independent → robust against VW BMS jitter). Energy is
# the metered grid value where it is trustworthy:
#   - internal meter sessions + external charges WITH a price → metered total_kwh
#     (a priced public charge ran over a certified/"geeichter" meter)
#   - external charges WITHOUT a price → SoC-delta × calibrated capacity
#   - TeslaMate imports → vehicle battery-side value as-is
# Returns BOTH battery-side (≈ what the car displays = grid × efficiency) and
# grid-side (what was actually drawn/paid) figures.
def _real_consumption(db, plate, date_from=None, date_to=None):
    """Charge-anchored real consumption for one vehicle over an optional window.

    Returns a dict with kWh/100km battery- and grid-side, total km/kWh and a
    per-session battery-side Wh/km for the table — or None if too little data.
    A single SoC boundary-correction term accounts for the battery being
    fuller/emptier at the window's end than its start; negligible over many
    charges."""
    dev_row = db.execute("SELECT device FROM vehicles WHERE plate = ?", (plate,)).fetchone()
    device = dev_row["device"] if dev_row else None
    eff = _get_charge_efficiency(db)

    _cap_cache = {}                 # 'YYYY-MM' → capacity (trend changes slowly)
    def _cap_at(ts):
        if not (device and ts):
            return None
        key = ts[:7]
        if key not in _cap_cache:
            _cap_cache[key] = get_bat_kwh(db, device, at_time=ts)
        return _cap_cache[key]

    q = ("SELECT id, session_number, is_external, cost_total, total_kwh, "
         "soc_start, soc_end, start_time, distance FROM charge_sessions "
         "WHERE vehicle_plate = ?")
    params = [plate]
    if date_from:
        q += " AND start_time >= ?"; params.append(date_from)
    if date_to:
        q += " AND start_time <= ?"; params.append(date_to + "T23:59:59")
    q += " ORDER BY datetime(start_time)"
    charges = db.execute(q, params).fetchall()
    if len(charges) < 2:
        return None

    def _energy(c):
        """(battery_kwh, grid_kwh) delivered at this charge, or (None, None)."""
        is_tm = _is_tm_session(c["session_number"])
        priced = c["cost_total"] is not None and c["cost_total"] > 0
        metered = (not c["is_external"]) or priced
        tk = c["total_kwh"]
        if is_tm and tk:                       # TM logs battery-side already
            return tk, tk / eff
        if metered and tk:                     # grid meter → battery = ×eff
            return tk * eff, tk
        # external, no price → estimate from SoC × calibrated capacity (battery-side)
        if (c["soc_start"] is not None and c["soc_end"] is not None
                and c["soc_end"] > c["soc_start"]):
            cap = _cap_at(c["start_time"])
            if cap:
                e_batt = (c["soc_end"] - c["soc_start"]) / 100.0 * cap
                return e_batt, e_batt / eff
        return None, None

    # Sub-window with known SoC boundaries: trim charges at the ends whose
    # soc_end is still missing (e.g. the most recent charge waiting for the
    # next-trip backfill). Charges with soc_end=None inside the window are
    # fine — only the boundary terms enter the SoC delta correction.
    first_idx = 0
    while first_idx < len(charges) and charges[first_idx]["soc_end"] is None:
        first_idx += 1
    last_idx = len(charges) - 1
    while last_idx >= 0 and charges[last_idx]["soc_end"] is None:
        last_idx -= 1

    sum_km = sum_batt = sum_grid = 0.0
    per_row = {}                # session id → battery-side Wh/km (table)
    for i in range(len(charges) - 1):
        seg_km = charges[i]["distance"]        # odo km from charges[i] → charges[i+1]
        if not seg_km or seg_km < 1:
            continue
        cur = charges[i + 1]                   # the charge that refilled this drive
        prev = charges[i]
        e_batt, e_grid = _energy(cur)
        # Aggregate only inside the SoC-bounded sub-window (so the recent
        # incomplete charge doesn't drop the whole Ø).
        if e_batt is not None and first_idx <= i and i + 1 <= last_idx:
            sum_km += seg_km
            sum_batt += e_batt
            sum_grid += e_grid
        # Per-row Wh/km: only when SoC at BOTH endpoints of THIS drive is
        # known. Uses the SoC drop (NOT the energy charged at cur, which would
        # inflate it on a full charge).
        if (seg_km >= 20 and prev["soc_end"] is not None and cur["soc_start"] is not None
                and prev["soc_end"] > cur["soc_start"]):
            cap_d = _cap_at(cur["start_time"])
            if cap_d:
                per_row[cur["id"]] = round((prev["soc_end"] - cur["soc_start"]) / 100.0 * cap_d * 1000.0 / seg_km)

    cons_batt = cons_grid = None
    if (sum_km >= 50 and device and first_idx < last_idx):
        first_soc_end = charges[first_idx]["soc_end"]
        last_soc_end = charges[last_idx]["soc_end"]
        cap_mid = _cap_at(charges[(first_idx + last_idx) // 2]["start_time"]) or 0
        bc_batt = (last_soc_end - first_soc_end) / 100.0 * cap_mid
        cb = (sum_batt - bc_batt) / sum_km * 100.0
        cg = (sum_grid - bc_batt / eff) / sum_km * 100.0
        if 5 <= cb <= 80:                      # plausibility check
            cons_batt = round(cb, 1)
            cons_grid = round(cg, 1)

    # Nothing to show at all → caller treats as "no data".
    if cons_batt is None and not per_row:
        return None
    return {
        "km": round(sum_km, 1),
        "batt_kwh": round(sum_batt, 1),
        "grid_kwh": round(sum_grid, 1),
        "cons_batt": cons_batt,
        "cons_grid": cons_grid,
        "per_row": per_row,
        "segments": len(per_row),
    }


def _session_readings(db, plate, s):
    """Charge-readings for a session — by session_id, else time-window match."""
    readings = db.execute(
        """SELECT timestamp, kwh, soc FROM charge_readings
           WHERE session_id = ? AND soc IS NOT NULL AND kwh IS NOT NULL
           ORDER BY timestamp""",
        (s["id"],),
    ).fetchall()
    if not readings:
        readings = db.execute(
            """SELECT timestamp, kwh, soc FROM charge_readings
               WHERE vehicle_plate = ?
                 AND datetime(timestamp) BETWEEN datetime(?) AND datetime(?)
                 AND soc IS NOT NULL AND kwh IS NOT NULL
               ORDER BY timestamp""",
            (plate, s["start_time"], s["end_time"]),
        ).fetchall()
    return readings


def _reconstruct_end_soc(readings):
    """Try to recover the true end-SoC for sessions where the BMS got stuck
    near the top (VW ID often freezes at 76-78% while energy keeps flowing).

    Strategy: walk back from the last reading while SoC is non-increasing,
    take that as the "stuck" tail. Compute kWh/% from the non-stuck head,
    then extrapolate how many extra % the stuck-tail kWh actually filled.
    Returns the corrected SoC or ``None`` if reconstruction isn't possible.

    Readings come at ~15 min cadence in practice, so this is a best-effort
    fix — short sessions just fall back to raw delta.
    """
    if len(readings) < 3:
        return None
    last_non_stuck = len(readings) - 1
    while last_non_stuck > 0 and readings[last_non_stuck]["soc"] <= readings[last_non_stuck - 1]["soc"]:
        last_non_stuck -= 1
    if last_non_stuck >= len(readings) - 1:
        return None  # no stuck tail
    if last_non_stuck < 1:
        return None  # nothing before the stuck phase to compute a rate from
    head_kwh = readings[last_non_stuck]["kwh"] - readings[0]["kwh"]
    head_soc = readings[last_non_stuck]["soc"] - readings[0]["soc"]
    if head_soc <= 0 or head_kwh <= 0:
        return None
    rate = head_kwh / head_soc  # kWh per %
    extra_kwh = readings[-1]["kwh"] - readings[last_non_stuck]["kwh"]
    if extra_kwh <= 0:
        return None
    return min(100.0, readings[last_non_stuck]["soc"] + extra_kwh / rate)


def _capacity_plausi_max(db, plate):
    """Physical upper bound for an implied capacity. A battery never exceeds
    its nominal NET capacity, so anything materially above the manual anchor
    is a measurement artefact (mostly the VW BMS plateau where SoC freezes
    a few % early, inflating kWh/%). Clamp to anchor + 5% tolerance; fall
    back to the global ceiling when no anchor is set."""
    row = db.execute(
        "SELECT battery_capacity_kwh FROM vehicles "
        "WHERE plate = ? AND battery_capacity_kwh IS NOT NULL",
        (plate,),
    ).fetchone()
    if row and row["battery_capacity_kwh"]:
        return min(_CAPACITY_PLAUSI_MAX, float(row["battery_capacity_kwh"]) * 1.05)
    return _CAPACITY_PLAUSI_MAX


def _capacity_points(db, plate):
    """Every qualified capacity data point for a plate (one per charging
    session passing the B-filter), with battery-side energy and stuck-SoC
    correction applied. No date window — the trend spans the full history.

    Returns (points, n_reconstructed) where points = [{ts, cap, date}, ...]
    sorted ascending by time."""
    plausi_max = _capacity_plausi_max(db, plate)
    efficiency = _get_charge_efficiency(db)
    sessions = db.execute(
        f"""SELECT id, start_time, end_time, total_kwh, soc_start, soc_end, session_number
           FROM charge_sessions
           WHERE vehicle_plate = ?
             AND total_kwh IS NOT NULL AND total_kwh > {_CAP_MIN_KWH}
             AND soc_start IS NOT NULL AND soc_end IS NOT NULL
             AND soc_start >= {_CAP_SOC_START_MIN} AND soc_end <= {_CAP_SOC_END_MAX}
             AND (soc_end - soc_start) >= {_CAP_DELTA_MIN}
           ORDER BY start_time""",
        (plate,),
    ).fetchall()
    pts = []
    n_recon = 0
    for s in sessions:
        soc_end_corr = None
        readings = _session_readings(db, plate, s)
        if readings:
            soc_end_corr = _reconstruct_end_soc([dict(r) for r in readings])
            if soc_end_corr is not None:
                n_recon += 1
        soc_end_eff = soc_end_corr if soc_end_corr is not None else s["soc_end"]
        delta = soc_end_eff - s["soc_start"]
        if delta < _CAP_DELTA_MIN:
            continue
        batt = _battery_kwh(s["total_kwh"], _is_tm_session(s["session_number"]), efficiency)
        implied = batt / (delta / 100.0)
        if not (_CAPACITY_PLAUSI_MIN <= implied <= plausi_max):
            continue
        try:
            ts = datetime.fromisoformat(s["start_time"]).timestamp()
        except (ValueError, TypeError):
            log.debug("capacity-trend: bad start_time %r — session skipped", s["start_time"])
            continue
        pts.append({"ts": ts, "cap": implied, "date": s["start_time"]})
    return pts, n_recon


def _theil_sen(xy):
    """Robust line fit: median of all pairwise slopes (outlier-resistant).
    xy = [(x, y), ...]. Returns (slope, intercept) or None."""
    n = len(xy)
    if n < 2:
        return None

    def _median(vals):
        vals = sorted(vals)
        m = len(vals) // 2
        return vals[m] if len(vals) % 2 else (vals[m - 1] + vals[m]) / 2.0

    slopes = []
    for i in range(n):
        for j in range(i + 1, n):
            dx = xy[j][0] - xy[i][0]
            if dx != 0:
                slopes.append((xy[j][1] - xy[i][1]) / dx)
    if not slopes:
        return None
    m = _median(slopes)
    b = _median([y - m * x for x, y in xy])
    return m, b


_trend_cache = {}  # plate -> (expiry_unix, trend_dict)


def _capacity_trend(db, plate, ttl=120):
    """Robust capacity-vs-time trend (Theil-Sen) over ALL qualified charges,
    so consumption tracks degradation as a smooth line and even rarely-charged
    vehicles get an interpolated value. Briefly cached so the per-trip backfill
    doesn't refit for every row.

    Returns dict with: ok, n, n_reconstructed, points, cap_now, slope_per_year,
    and (when ok) a clamped ``cap_at(ts)`` callable. cap values are clamped to
    [PLAUSI_MIN, anchor+5%]."""
    now = time.time()
    cached = _trend_cache.get(plate)
    if cached and cached[0] > now:
        return cached[1]

    pts, n_recon = _capacity_points(db, plate)
    plausi_max = _capacity_plausi_max(db, plate)

    def _clamp(v):
        return max(_CAPACITY_PLAUSI_MIN, min(plausi_max, v))

    if len(pts) < 2:
        cap_now = _clamp(pts[0]["cap"]) if pts else None
        res = {"ok": False, "n": len(pts), "n_reconstructed": n_recon,
               "points": pts, "cap_now": cap_now, "slope_per_year": None,
               "cap_at": (lambda ts, _c=cap_now: _c)}
        _trend_cache[plate] = (now + ttl, res)
        return res

    fit = _theil_sen([(p["ts"] / 86400.0, p["cap"]) for p in pts])
    m, b = fit
    cap_at = lambda ts: _clamp(m * (ts / 86400.0) + b)
    # A slope is only meaningful over a long enough span — the VW BMS jitters
    # SoC enough that over a few months the median-of-slopes is dominated by
    # noise and looks absurd (e.g. +11 kWh/yr). Only report degradation once
    # ≥180 days are covered.
    span_days = (pts[-1]["ts"] - pts[0]["ts"]) / 86400.0
    slope_per_year = round(m * 365.0, 2) if span_days >= 180 else None
    res = {
        "ok": True, "n": len(pts), "n_reconstructed": n_recon, "points": pts,
        "cap_now": round(cap_at(now), 2),
        "slope_per_year": slope_per_year,
        "span_days": round(span_days),
        "cap_at": cap_at,
    }
    _trend_cache[plate] = (now + ttl, res)
    return res


@app.route("/api/vehicles/capacity-estimates")
def vehicles_capacity_estimates():
    """Return the current trend-based capacity estimate per vehicle for the
    admin badge (today's value on the degradation line + sample count)."""
    db = get_db()
    plates = [r["plate"] for r in db.execute(
        "SELECT plate FROM vehicles WHERE plate IS NOT NULL AND plate != ''"
    ).fetchall()]
    out = {}
    for p in plates:
        tr = _capacity_trend(db, p)
        out[p] = {
            "plate": p,
            "estimate_kwh": tr.get("cap_now"),
            "n_used": tr.get("n", 0),
            "n_reconstructed": tr.get("n_reconstructed", 0),
            "trend_ok": tr.get("ok", False),
            "slope_per_year": tr.get("slope_per_year"),
        }
    db.close()
    return jsonify(out)


@app.route("/api/vehicles/<plate>/capacity-detail")
def vehicle_capacity_detail(plate):
    """Audit view for the capacity estimate of one vehicle.

    Returns every charge session in the window with its derived capacity and
    why it was used or rejected, plus a rolling-estimate timeline so the user
    can verify the number is sane."""
    days = request.args.get("days", 365, type=int)
    db = get_db()
    sessions = db.execute(
        """SELECT id, start_time, end_time, total_kwh, soc_start, soc_end,
                  is_external, session_number
           FROM charge_sessions
           WHERE vehicle_plate = ?
             AND datetime(start_time) >= datetime('now', ?)
           ORDER BY start_time DESC""",
        (plate, f'-{int(days)} days'),
    ).fetchall()

    plausi_max = _capacity_plausi_max(db, plate)
    efficiency = _get_charge_efficiency(db)
    detail = []
    for s in sessions:
        soc_start = s["soc_start"]
        soc_end = s["soc_end"]
        kwh = s["total_kwh"]
        is_tm = _is_tm_session(s["session_number"])
        soc_end_corr = None
        if soc_start is not None and soc_end is not None and kwh:
            readings = _session_readings(db, plate, s)
            if readings:
                soc_end_corr = _reconstruct_end_soc([dict(r) for r in readings])
        soc_end_eff = soc_end_corr if soc_end_corr is not None else soc_end
        delta = (soc_end_eff - soc_start) if (soc_end_eff is not None and soc_start is not None) else None
        batt_kwh = _battery_kwh(kwh, is_tm, efficiency)
        implied = (batt_kwh / (delta / 100.0)) if (delta and delta > 0 and batt_kwh) else None

        # Classify with the shared thresholds (same rules as the estimate SQL)
        reason = None
        if kwh is None or kwh <= _CAP_MIN_KWH:
            reason = "kwh"
        elif soc_start is None or soc_end is None:
            reason = "no_soc"
        elif soc_start < _CAP_SOC_START_MIN:
            reason = "soc_start"
        elif soc_end > _CAP_SOC_END_MAX:
            reason = "soc_end"
        elif delta is None or delta < _CAP_DELTA_MIN:
            reason = "delta"
        elif implied is None or not (_CAPACITY_PLAUSI_MIN <= implied <= plausi_max):
            reason = "implausible"
        used = reason is None
        detail.append({
            "date": s["start_time"],
            "soc_start": soc_start,
            "soc_end": soc_end,
            "soc_end_corrected": round(soc_end_corr, 1) if soc_end_corr is not None else None,
            "total_kwh": round(kwh, 2) if kwh is not None else None,
            "battery_kwh": round(batt_kwh, 2) if batt_kwh is not None else None,
            "implied_kwh": round(implied, 1) if implied is not None else None,
            "source": "tm" if is_tm else ("extern" if s["is_external"] else "intern"),
            "used": used,
            "reason": reason,
        })

    # Trend over the full history: today's value + the regression line as two
    # endpoints (first measurement → today), plus the raw measured points so
    # the chart can scatter them under the line.
    tr = _capacity_trend(db, plate)
    measured = [{"date": datetime.fromtimestamp(p["ts"]).strftime("%Y-%m-%d"),
                 "cap": round(p["cap"], 2)} for p in tr.get("points", [])]
    trend_line = []
    if tr.get("ok") and tr.get("points"):
        pts = tr["points"]
        t_first = pts[0]["ts"]
        t_last = max(pts[-1]["ts"], time.time())
        for t in (t_first, t_last):
            trend_line.append({"date": datetime.fromtimestamp(t).strftime("%Y-%m-%d"),
                               "cap": round(tr["cap_at"](t), 2)})
    db.close()
    return jsonify({
        "plate": plate,
        "estimate_kwh": tr.get("cap_now"),
        "trend_ok": tr.get("ok", False),
        "slope_per_year": tr.get("slope_per_year"),
        "n_used": tr.get("n", 0),
        "n_total": len(detail),
        "sessions": detail,
        "measured": measured,
        "trend_line": trend_line,
    })


@app.route("/api/admin/charge-efficiency", methods=["GET", "POST"])
@admin_required
def charge_efficiency():
    """Read or manually set the global AC charging-efficiency factor.
    POST {percent: 50..100} stores it and recomputes all trip consumption."""
    db = get_db()
    if request.method == "GET":
        eff = _get_charge_efficiency(db)
        db.close()
        return jsonify({"percent": round(eff * 100, 1)})
    data = request.get_json() or {}
    try:
        percent = float(data.get("percent"))
    except (TypeError, ValueError):
        db.close()
        return jsonify({"error": "percent required"}), 400
    if not (50.0 <= percent <= 100.0):
        db.close()
        return jsonify({"error": "percent must be 50–100"}), 400
    factor = round(percent / 100.0, 4)
    db.execute(
        "INSERT INTO settings (key, value) VALUES ('charge_grid_efficiency', ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (str(factor),),
    )
    db.commit()
    _trend_cache.clear()
    trips_updated = _recompute_all_consumption(db)
    db.close()
    return jsonify({"ok": True, "percent": percent, "trips_updated": trips_updated})


@app.route("/api/admin/calibrate-efficiency", methods=["POST"])
@admin_required
def calibrate_efficiency():
    """Calibrate the AC charging-efficiency factor against a vehicle with a
    known (trusted) capacity anchor — ideally a new car with ~no degradation.
    factor = anchor / median(raw implied capacity of its internal charges).
    The factor then applies to every internal/external (non-TM) charge."""
    data = request.get_json() or {}
    plate = (data.get("plate") or "").strip()
    if not plate:
        return jsonify({"error": "plate required"}), 400
    db = get_db()
    arow = db.execute(
        "SELECT battery_capacity_kwh FROM vehicles WHERE plate = ?", (plate,)
    ).fetchone()
    anchor = float(arow["battery_capacity_kwh"]) if arow and arow["battery_capacity_kwh"] else None
    if not anchor:
        db.close()
        return jsonify({"error": "vehicle has no capacity anchor set"}), 400
    sessions = db.execute(
        f"""SELECT id, start_time, end_time, total_kwh, soc_start, soc_end, session_number
           FROM charge_sessions
           WHERE vehicle_plate = ?
             AND total_kwh IS NOT NULL AND total_kwh > {_CAP_MIN_KWH}
             AND soc_start IS NOT NULL AND soc_end IS NOT NULL
             AND soc_start >= {_CAP_SOC_START_MIN} AND soc_end <= {_CAP_SOC_END_MAX}
             AND (soc_end - soc_start) >= {_CAP_DELTA_MIN}""",
        (plate,),
    ).fetchall()
    raws = []
    for s in sessions:
        if _is_tm_session(s["session_number"]):
            continue  # TM is already battery-side, not scaled by the factor
        soc_end_corr = None
        readings = _session_readings(db, plate, s)
        if readings:
            soc_end_corr = _reconstruct_end_soc([dict(r) for r in readings])
        soc_end_eff = soc_end_corr if soc_end_corr is not None else s["soc_end"]
        delta = soc_end_eff - s["soc_start"]
        if delta < _CAP_DELTA_MIN:
            continue
        raws.append(s["total_kwh"] / (delta / 100.0))  # grid-side, no factor
    if len(raws) < 3:
        db.close()
        return jsonify({"error": "not enough internal charges to calibrate (need ≥3)"}), 400
    raws.sort()
    mid = len(raws) // 2
    median_raw = raws[mid] if len(raws) % 2 else (raws[mid - 1] + raws[mid]) / 2.0
    factor = max(0.80, min(1.0, anchor / median_raw))
    db.execute(
        "INSERT INTO settings (key, value) VALUES ('charge_grid_efficiency', ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (str(round(factor, 4)),),
    )
    db.commit()
    _trend_cache.clear()  # trends depend on the efficiency factor
    # Recompute every trip's consumption right away so analytics/charges
    # immediately reflect the new factor (no separate button press needed).
    trips_updated = _recompute_all_consumption(db)
    db.close()
    return jsonify({"ok": True, "efficiency": round(factor, 4),
                    "anchor": anchor, "median_raw": round(median_raw, 2),
                    "n": len(raws), "trips_updated": trips_updated})


@app.route("/api/trips/recompute-consumption", methods=["POST"])
@admin_required
def recompute_consumption():
    """Recalculate energy_kwh + consumption for every trip using the rolling
    capacity estimate that applied at each trip's start time. Run after the
    capacity estimate has shifted (e.g. new charges came in) so historical
    consumption tracks the real-world capacity over time.

    Note: this uses the rolling estimate (fallback: manual anchor); the live
    'ca' field that the detector prefers during live detection isn't stored
    per trip, so backfilled values rely on the charge-based estimate."""
    db = get_db()
    updated = _recompute_all_consumption(db)
    db.close()
    return jsonify({"ok": True, "updated": updated})


def _recompute_all_consumption(db):
    """Rewrite energy_kwh + consumption for every trip using the per-vehicle
    capacity trend at each trip's date. Returns the number of trips updated."""
    rows = db.execute(
        "SELECT id, device, start_time, soc_start, soc_end, distance_km FROM trips"
    ).fetchall()
    updated = 0
    cap_cache = {}  # (device, 'YYYY-MM') -> capacity (trend changes slowly)
    for t in rows:
        if not (t["soc_start"] is not None and t["soc_end"] is not None and t["soc_start"] > t["soc_end"]):
            continue
        cap = None
        if t["device"] and t["start_time"]:
            key = (t["device"], t["start_time"][:7])
            if key in cap_cache:
                cap = cap_cache[key]
            else:
                cap = get_bat_kwh(db, t["device"], at_time=t["start_time"])
                cap_cache[key] = cap
        if not cap:
            cap = get_bat_kwh(db, t["device"])
        energy = round((t["soc_start"] - t["soc_end"]) / 100 * cap, 2)
        consumption = None
        if t["distance_km"] and t["distance_km"] >= 10:
            consumption = round(energy / t["distance_km"] * 100, 1)
        db.execute(
            "UPDATE trips SET energy_kwh = ?, consumption = ? WHERE id = ?",
            (energy, consumption, t["id"]),
        )
        updated += 1
    db.commit()
    return updated


@app.route("/api/vehicles", methods=["POST"])
def create_vehicle():
    data = request.get_json()
    plate = data.get("plate", "").strip()
    if not plate:
        _t = _translations.get(get_language(), _translations["DE"])
        return jsonify({"error": _t["err_plate_required"]}), 400

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
        _t = _translations.get(get_language(), _translations["DE"])
        return jsonify({"error": _t["err_plate_exists"]}), 409
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
        _t = _translations.get(get_language(), _translations["DE"])
        return jsonify({"error": _t["err_no_fields"]}), 400
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
@admin_required  # FIXES 15.2: tariffs are system config (cost calculation) -- admin only
def create_tariff():
    data = request.get_json()
    valid_from = data.get("valid_from", "").strip()
    pauschale = data.get("pauschale_kwh")
    if not valid_from or pauschale is None:
        _t = _translations.get(get_language(), _translations["DE"])
        return jsonify({"error": _t["err_tariff_fields_required"]}), 400

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
@admin_required  # FIXES 15.2: tariffs are system config -- admin only
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
        yi, xi = coords[i][0], coords[i][1]
        yj, xj = coords[j][0], coords[j][1]
        if ((yi > lat) != (yj > lat)) and (lon < (xj - xi) * (lat - yi) / ((yj - yi) or 1e-12) + xi):
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
                log.warning("charge location %s: invalid polygon_coords JSON — skipped",
                            loc["name"] if "name" in loc.keys() else loc["id"], exc_info=True)
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
        ORDER BY cl.name COLLATE NOCASE
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


def _reassign_charges_to_location(db, loc_id):
    """Scan charge_sessions and rewrite location_name to this charge_location's
    name when the session's lat/lon is inside its radius. Polygon shapes are
    handled by a bbox prefilter + Python point-in-polygon; circles use the
    haversine distance. Returns count of touched sessions."""
    loc = db.execute(
        """SELECT name, lat, lon, radius_m, shape, polygon_coords
           FROM charge_locations WHERE id = ?""",
        (loc_id,),
    ).fetchone()
    if not loc:
        return {"charges": 0}
    poly = None
    if loc["shape"] == "polygon" and loc["polygon_coords"]:
        try:
            import json as _json
            poly = _json.loads(loc["polygon_coords"])
        except Exception:
            poly = None
    if poly:
        lats = [p[0] for p in poly]
        lons = [p[1] for p in poly]
        bb_lat_min, bb_lat_max = min(lats), max(lats)
        bb_lon_min, bb_lon_max = min(lons), max(lons)
    else:
        deg = max(loc["radius_m"] or 200, 50) / 111000.0 * 1.2
        bb_lat_min, bb_lat_max = loc["lat"] - deg, loc["lat"] + deg
        bb_lon_min, bb_lon_max = loc["lon"] - deg, loc["lon"] + deg

    rows = db.execute(
        """SELECT id, lat, lon, location_name FROM charge_sessions
           WHERE lat BETWEEN ? AND ? AND lon BETWEEN ? AND ?""",
        (bb_lat_min, bb_lat_max, bb_lon_min, bb_lon_max),
    ).fetchall()

    _in_poly = _point_in_polygon  # single shared ray-casting impl (see 9.1)

    n_touched = 0
    for r in rows:
        if r["lat"] is None or r["lon"] is None:
            continue
        if poly:
            hit = _in_poly(r["lat"], r["lon"], poly)
        else:
            hit = detector.haversine_m(r["lat"], r["lon"], loc["lat"], loc["lon"]) <= (loc["radius_m"] or 200)
        if hit and r["location_name"] != loc["name"]:
            db.execute("UPDATE charge_sessions SET location_name = ? WHERE id = ?",
                       (loc["name"], r["id"]))
            n_touched += 1
    db.commit()
    # Charge-Geofences cover places where the user stopped to charge — those
    # are also trip endpoints. Reassign trips that started/ended in the same
    # area so the trip log shows e.g. 'IONITY Hannover' as destination too.
    trip_counts = _reassign_trips_around(
        db, loc["name"], loc["lat"], loc["lon"], loc["radius_m"] or 200
    )
    return {
        "charges": n_touched,
        "trips_start": trip_counts["trips_start"],
        "trips_end": trip_counts["trips_end"],
    }


@app.route("/api/charge/locations", methods=["POST"])
@login_required
def create_charge_location():
    data = request.get_json()
    name = data.get("name", "").strip()
    lat = data.get("lat")
    lon = data.get("lon")
    if not name or lat is None or lon is None:
        _t = _translations.get(get_language(), _translations["DE"])
        return jsonify({"error": _t["err_name_lat_lon_required"]}), 400

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
    reassigned = _reassign_charges_to_location(db, loc_id)
    db.close()
    return jsonify({"ok": True, "id": loc_id, "reassigned": reassigned})


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
        _t = _translations.get(get_language(), _translations["DE"])
        return jsonify({"error": _t["err_no_fields"]}), 400
    params.append(loc_id)
    db.execute(f"UPDATE charge_locations SET {', '.join(sets)} WHERE id = ?", params)
    db.commit()
    reassigned = _reassign_charges_to_location(db, loc_id)
    db.close()
    return jsonify({"ok": True, "reassigned": reassigned})


def _clear_charge_sessions_for_geofence(db, loc):
    """Inverse of _reassign_charges_to_location: drop the geofence ``name`` from
    charge_sessions.location_name inside the (deleted) geofence shape. Sessions
    have no street-geocoding fallback, so the label simply clears."""
    name = loc["name"]
    if not name:
        return 0
    poly = None
    if loc["shape"] == "polygon" and loc["polygon_coords"]:
        try:
            poly = json.loads(loc["polygon_coords"])
        except Exception:
            poly = None
    if poly:
        lats = [p[0] for p in poly]
        lons = [p[1] for p in poly]
        bb_lat_min, bb_lat_max = min(lats), max(lats)
        bb_lon_min, bb_lon_max = min(lons), max(lons)
    elif loc["lat"] is not None and loc["lon"] is not None:
        deg = max(loc["radius_m"] or 200, 50) / 111000.0 * 1.2
        bb_lat_min, bb_lat_max = loc["lat"] - deg, loc["lat"] + deg
        bb_lon_min, bb_lon_max = loc["lon"] - deg, loc["lon"] + deg
    else:
        cur = db.execute(
            "UPDATE charge_sessions SET location_name = NULL WHERE location_name = ?", (name,))
        db.commit()
        return cur.rowcount

    rows = db.execute(
        """SELECT id, lat, lon FROM charge_sessions
           WHERE location_name = ? AND lat BETWEEN ? AND ? AND lon BETWEEN ? AND ?""",
        (name, bb_lat_min, bb_lat_max, bb_lon_min, bb_lon_max),
    ).fetchall()
    n = 0
    for r in rows:
        if r["lat"] is None or r["lon"] is None:
            continue
        if poly:
            hit = _point_in_polygon(r["lat"], r["lon"], poly)
        else:
            hit = detector.haversine_m(r["lat"], r["lon"], loc["lat"], loc["lon"]) <= (loc["radius_m"] or 200)
        if hit:
            db.execute("UPDATE charge_sessions SET location_name = NULL WHERE id = ?", (r["id"],))
            n += 1
    db.commit()
    return n


@app.route("/api/charge/locations/<int:loc_id>", methods=["DELETE"])
@login_required
def delete_charge_location(loc_id):
    db = get_db()
    loc = db.execute(
        """SELECT name, lat, lon, radius_m, shape, polygon_coords, icon_filename
           FROM charge_locations WHERE id = ?""",
        (loc_id,),
    ).fetchone()
    if loc and loc["icon_filename"]:
        _delete_charge_icon_file(loc["icon_filename"])
    db.execute("DELETE FROM charge_locations WHERE id = ?", (loc_id,))
    db.commit()
    cleared_sessions = 0
    cleared_trips = {"trips_start": 0, "trips_end": 0}
    if loc:
        # Charge geofences also tag the trips that start/end there — clear both.
        cleared_sessions = _clear_charge_sessions_for_geofence(db, loc)
        cleared_trips = _clear_trips_for_geofence(db, loc["name"], loc["lat"], loc["lon"], loc["radius_m"])
    db.close()
    if cleared_trips["trips_start"] or cleared_trips["trips_end"]:
        _kick_geocoder()
    return jsonify({"ok": True, "cleared_sessions": cleared_sessions, "cleared_trips": cleared_trips})


MEDIA_DIR = os.path.join(os.path.dirname(config.DB_PATH), "media")
_CHARGE_ICON_DIR = os.path.join(os.path.dirname(config.DB_PATH), "media", "charge-icons")
_OPERATOR_ICON_DIR = os.path.join(os.path.dirname(config.DB_PATH), "media", "operator-icons")
_USER_AVATAR_DIR = os.path.join(os.path.dirname(config.DB_PATH), "media", "user-avatars")
_ALLOWED_IMAGE_EXTS = {".png", ".jpg", ".jpeg", ".webp", ".gif"}
# .svg deliberately excluded: SVGs served same-origin from /media can carry
# <script> and trigger stored XSS. Use a raster format for uploaded icons.
_MAX_ICON_BYTES = 200 * 1024  # 200 KB


# ── Operators ─────────────────────────────────────────────────────────────


@app.route("/api/operators")
def list_operators():
    db = get_db()
    rows = db.execute("SELECT * FROM operators ORDER BY name COLLATE NOCASE").fetchall()
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
    _t = _translations.get(get_language(), _translations["DE"])
    if not name:
        return jsonify({"error": _t["admin_js_name_required_short"]}), 400
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
        return jsonify({"error": _t["err_operator_exists"]}), 409
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
        _t = _translations.get(get_language(), _translations["DE"])
        return jsonify({"error": _t["err_no_fields"]}), 400
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
    _t = _translations.get(get_language(), _translations["DE"])
    db = get_db()
    row = db.execute("SELECT id, icon_filename FROM operators WHERE id = ?", (op_id,)).fetchone()
    if not row:
        db.close()
        return jsonify({"error": _t["err_not_found"]}), 404
    f = request.files.get("icon")
    if not f or not f.filename:
        db.close()
        return jsonify({"error": _t["err_no_file"]}), 400
    ext = os.path.splitext(secure_filename(f.filename))[1].lower()
    if ext not in _ALLOWED_IMAGE_EXTS:
        db.close()
        return jsonify({"error": _t["err_invalid_format"]}), 400
    data = f.read(_MAX_ICON_BYTES + 1)
    if len(data) > _MAX_ICON_BYTES:
        db.close()
        return jsonify({"error": _t["err_file_too_large"]}), 400
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
        log.warning("could not delete operator icon file %r", filename, exc_info=True)


# User avatar routes: moved to blueprints/profile.py during the profile rework
# (same URLs). _USER_AVATAR_DIR stays here (media serving + import).


def _delete_charge_icon_file(filename):
    try:
        path = os.path.join(_CHARGE_ICON_DIR, filename)
        if os.path.isfile(path):
            os.remove(path)
    except OSError:
        log.warning("could not delete charge icon file %r", filename, exc_info=True)


@app.route("/api/charge/locations/<int:loc_id>/icon", methods=["POST"])
@login_required
def upload_charge_location_icon(loc_id):
    _t = _translations.get(get_language(), _translations["DE"])
    db = get_db()
    row = db.execute("SELECT id, icon_filename FROM charge_locations WHERE id = ?", (loc_id,)).fetchone()
    if not row:
        db.close()
        return jsonify({"error": _t["err_not_found"]}), 404

    f = request.files.get("icon")
    if not f or not f.filename:
        db.close()
        return jsonify({"error": _t["err_no_file"]}), 400

    ext = os.path.splitext(secure_filename(f.filename))[1].lower()
    if ext not in _ALLOWED_IMAGE_EXTS:
        db.close()
        return jsonify({"error": _t["err_invalid_image_format"]}), 400

    data = f.read(_MAX_ICON_BYTES + 1)
    if len(data) > _MAX_ICON_BYTES:
        db.close()
        return jsonify({"error": _t["err_file_too_large"]}), 400

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


# ── Blueprint registration (FIXES 6.1) ───────────────────────────
# Imported here, at the end of the module, so the blueprint's `from app import …`
# resolves against a fully-populated namespace. Runs on plain `import app`
# (tests, waitress) as well as `python app.py`.
from blueprints.auth import auth_bp  # noqa: E402
from blueprints.journeys import journeys_bp  # noqa: E402
from blueprints.charges import charges_bp  # noqa: E402
from blueprints.trips import trips_bp  # noqa: E402
from blueprints.admin import admin_bp  # noqa: E402
from blueprints.profile import profile_bp  # noqa: E402
app.register_blueprint(auth_bp)
app.register_blueprint(journeys_bp)
app.register_blueprint(charges_bp)
app.register_blueprint(trips_bp)
app.register_blueprint(admin_bp)
app.register_blueprint(profile_bp)


def _print_startup_banner(host, port):
    """Clean startup banner, ASCII-only, single source of truth for runtime info."""
    bar = "=" * 64
    lines = [
        "",
        bar,
        f"  ID Mate  v{config.VERSION}",
        "  https://github.com/TheInGoF/IDMate-dev",
        bar,
        f"  Listening    : http://{host}:{port}",
        f"  SQLite       : {config.DB_PATH}",
        f"  InfluxDB     : {config.INFLUX_URL}  (bucket: {config.INFLUX_BUCKET})",
        f"  MQTT broker  : {config.MQTT_BROKER}:{config.MQTT_PORT}"
            + ("  [TLS]" if config.MQTT_TLS else ""),
        f"  Language     : {config.LANGUAGE}",
        f"  Debug pages  : {'on' if config.ENABLE_DEBUG else 'off'}",
        bar,
        "",
    ]
    for line in lines:
        log.info(line)


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

    # Force any orphaned 'running' import job into 'paused' state so it
    # doesn't silently resume after a restart.
    try:
        import_job.reset_on_boot()
    except Exception:
        log.exception("import_job.reset_on_boot failed")

    # Start background threads
    threading.Thread(target=background_detector, daemon=True).start()
    threading.Thread(target=background_geocoder, daemon=True).start()
    threading.Thread(target=_state_poller, daemon=True).start()
    threading.Thread(target=background_mqtt, daemon=True).start()

    host, port = "0.0.0.0", 5000
    _print_startup_banner(host, port)

    # Production: waitress (pure-Python WSGI, threaded — preserves the
    # background threads above, no fork). Dev: Flask's built-in server
    # via FLASK_DEV=1 for hot-reload during local development.
    if os.environ.get("FLASK_DEV", "").lower() in ("1", "true", "yes"):
        log.info("FLASK_DEV=1 -> using Flask development server")
        app.run(host=host, port=port)
    else:
        from waitress import serve
        # Quiet waitress' own 'Serving on …' line; banner above already says it.
        logging.getLogger("waitress").setLevel(logging.WARNING)
        # threads raised 8 -> 16: SSE streams are capped (_SSE_MAX_CLIENTS) but
        # still each park a worker for their lifetime; the extra headroom keeps
        # regular requests responsive alongside the allowed long-lived streams.
        serve(app, host=host, port=port, threads=16, _quiet=True)
