"""Authentication & first-run setup routes (FIXES 6.1).

Moved verbatim out of app.py. The handler bodies are unchanged except:
* ``@app.route`` → ``@auth_bp.route``;
* ``url_for("login")`` etc. now use the blueprint-qualified endpoint
  (``auth.login``) — the endpoint name changes when a view moves into a
  blueprint, but templates navigate via hardcoded paths so only Python
  ``url_for`` calls are affected (all updated here and in app.py);
* the ``_setup_required`` module global is read/cleared through
  ``app.is_setup_required()`` / ``app.clear_setup_required()`` so the flag's
  owner stays in app.py (a ``global`` here would target *this* module).

Shared helpers are imported from app at blueprint-import time (bottom of
app.py), by which point app's module namespace is fully populated.
"""

import base64
import io
import time

from flask import (Blueprint, abort, jsonify, redirect, render_template,
                   request, session, url_for)
from flask_login import current_user, login_required, login_user, logout_user

from app import (
    _LOGIN_COOLDOWN, _TOTP_AVAILABLE, _consume_recovery_code,
    _generate_recovery_codes, _is_rate_limited, _is_rate_limited_user,
    _login_attempts, _login_attempts_user, _needs_rehash, _record_attempt,
    _record_attempt_user, _safe_next, _store_recovery_codes, _translations,
    _user_from_row, _user_key, _validate_password, check_password_hash,
    clear_setup_required, generate_password_hash, get_db, get_language,
    is_setup_required, pyotp, qrcode,
)

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    error = None
    if request.method == "POST":
        ip = request.remote_addr
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # Beide Checks immer auswerten (kein Short-Circuit), damit auch die
        # Username-Einträge bei jedem POST von abgelaufenen Timestamps bereinigt
        # werden (kein Leak).
        ip_limited = _is_rate_limited(ip)
        user_limited = _is_rate_limited_user(username)
        # Blockieren, sobald EINE Schwelle reißt: das IP-Limit bleibt der
        # bestehende harte Schutz (auch gegen viele Usernames von einer IP), das
        # Username-Limit kommt zusätzlich gegen Brute-Force über rotierende IPs
        # hinweg dazu. Ein reines UND würde den IP-Schutz aushebeln, sobald der
        # Angreifer pro Username unter der Schwelle bleibt.
        if ip_limited or user_limited:
            # Restzeit aus dem jeweils aktiven Zähler (max), defensiv gegen leere
            # Listen — bei nur user_limited kann _login_attempts[ip] leer sein.
            waits = []
            if ip_limited and _login_attempts.get(ip):
                waits.append(_LOGIN_COOLDOWN - (time.time() - _login_attempts[ip][0]))
            ukey = _user_key(username)
            if user_limited and _login_attempts_user.get(ukey):
                waits.append(_LOGIN_COOLDOWN - (time.time() - _login_attempts_user[ukey][0]))
            remaining = int(max(waits)) if waits else _LOGIN_COOLDOWN
            error = f"Zu viele Versuche. Bitte {max(remaining, 1)}s warten."
            return render_template("login.html", error=error)

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
            _login_attempts_user.pop(_user_key(username), None)  # dito pro Username
            next_page = _safe_next(request.args.get("next", "/"))
            if row["totp_enabled"]:
                session["pending_user_id"] = row["id"]
                session["pending_user_next"] = next_page
                return redirect(url_for("auth.login_totp"))
            user = _user_from_row(row)
            login_user(user, remember=True)
            return redirect(next_page)
        _record_attempt(ip)
        _record_attempt_user(username)
        lang = get_language()
        error = _translations.get(lang, _translations["DE"])["login_error"]

    return render_template("login.html", error=error)


@auth_bp.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("auth.login"))


# ── TOTP Login ────────────────────────────────────────────────

@auth_bp.route("/login/totp", methods=["GET", "POST"])
def login_totp():
    if "pending_user_id" not in session:
        return redirect(url_for("auth.login"))
    error = None
    if request.method == "POST":
        uid = session.get("pending_user_id")
        totp_key = "totp:%s" % uid
        # Brute-Force-Schutz für den zweiten Faktor (anders als /login bisher
        # völlig ungeschützt — valid_window=1 akzeptiert 3 Zeitfenster). Zu viele
        # Versuche -> pending-Session verwerfen, Passwort-Login erzwingen.
        if _is_rate_limited_user(totp_key):
            session.pop("pending_user_id", None)
            session.pop("pending_user_next", None)
            _login_attempts_user.pop(_user_key(totp_key), None)
            return render_template("login_totp.html",
                                   error="Zu viele Versuche. Bitte erneut anmelden.")
        code = request.form.get("code", "").strip()
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
            _login_attempts_user.pop(_user_key(totp_key), None)  # Reset on success
            user = _user_from_row(row)
            login_user(user, remember=True)
            next_page = _safe_next(session.pop("pending_user_next", "/"))
            session.pop("pending_user_id", None)
            return redirect(next_page)
        _record_attempt_user(totp_key)
        error = "Ungültiger Code. Bitte erneut versuchen."
    return render_template("login_totp.html", error=error)


# ── First-run Setup ───────────────────────────────────────────

@auth_bp.route("/setup", methods=["GET", "POST"])
def setup():
    if request.method == "GET":
        if not is_setup_required():
            if not current_user.is_authenticated:
                return redirect(url_for("auth.login"))
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
    clear_setup_required()
    user = _user_from_row(row)
    login_user(user, remember=True)
    return redirect(url_for("auth.setup_2fa"))


@auth_bp.route("/setup/2fa", methods=["GET", "POST"])
def setup_2fa():
    if not current_user.is_authenticated:
        return redirect(url_for("auth.login"))
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
            return redirect(url_for("auth.show_recovery_codes"))
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


@auth_bp.route("/setup/recovery-codes")
@login_required
def show_recovery_codes():
    codes = session.pop("show_recovery_codes", None)
    if not codes:
        return redirect(url_for("dashboard"))
    return render_template("recovery_codes.html", codes=codes)


@auth_bp.route("/api/user/2fa/disable", methods=["POST"])
@login_required
def disable_2fa():
    data = request.get_json(silent=True, force=True) or {}
    uid = data.get("user_id", current_user.id)
    # Only admin can disable for others
    if uid != current_user.id and not current_user.is_admin:
        return jsonify({"error": "Keine Berechtigung"}), 403
    # Self-Deaktivierung erfordert Re-Authentifizierung (Passwort ODER gültiger
    # TOTP-Code) — sonst kann eine übernommene Session (oder XSS) den zweiten
    # Faktor still entfernen. Admin, der für andere abschaltet, ist ausgenommen.
    if uid == current_user.id:
        pw = data.get("password") or ""
        code = (data.get("code") or "").strip()
        db = get_db()
        row = db.execute("SELECT * FROM users WHERE id = ?", (current_user.id,)).fetchone()
        ok = bool(pw) and row is not None and check_password_hash(row["password_hash"], pw)
        if (not ok) and code and _TOTP_AVAILABLE and row is not None and row["totp_secret"]:
            ok = pyotp.TOTP(row["totp_secret"]).verify(code, valid_window=1)
        db.close()
        if not ok:
            return jsonify({"error": "Passwort oder 2FA-Code erforderlich", "reauth": True}), 403
    db = get_db()
    db.execute("UPDATE users SET totp_secret = NULL, totp_enabled = 0 WHERE id = ?", (uid,))
    db.commit()
    db.close()
    return jsonify({"ok": True})
