"""Profil-Routen: eigene Seite für Avatar, Darstellung (Kartenstil),
Passwort und 2FA-Status.

Avatar-Upload/-Delete und der eigene Passwortwechsel sind unverändert aus
app.py hierher gezogen (``@app.route`` → ``@profile_bp.route``, gleiche URLs).
Shared helpers werden wie bei den anderen Blueprints zur Importzeit aus app
geholt (Registrierung am Ende von app.py, Namespace dann vollständig).
"""

import io
import os

from flask import Blueprint, jsonify, render_template, request
from flask_login import current_user, login_required
from werkzeug.utils import secure_filename

from app import (MAP_STYLES, UI_THEMES, _MAX_ICON_BYTES, _USER_AVATAR_DIR,
                 _validate_password, check_password_hash,
                 generate_password_hash, get_db, get_language, log)

profile_bp = Blueprint("profile", __name__)

_AVATAR_EXTS = {".png", ".jpg", ".jpeg", ".webp"}  # kein GIF/SVG (XSS, siehe 2.2)


@profile_bp.route("/profile")
@login_required
def profile_page():
    db = get_db()
    row = db.execute("SELECT totp_enabled, map_style, theme, language FROM users WHERE id = ?",
                     (current_user.id,)).fetchone()
    db.close()
    # FIXES 15.5: Sprache ist per-User; Default DE wenn nichts gesetzt.
    user_lang = (row["language"] if row and "language" in row.keys() else None) or get_language()
    return render_template("profile.html",
                           totp_enabled=bool(row["totp_enabled"]) if row else False,
                           user_map_style=(row["map_style"] or "") if row else "",
                           user_theme=(row["theme"] or "") if row else "",
                           user_language=(user_lang or "DE").upper(),
                           map_styles=sorted(MAP_STYLES))


@profile_bp.route("/api/profile/preferences", methods=["POST"])
@login_required
def save_profile_preferences():
    """Eigene Darstellungs-Präferenzen (Kartenstil, UI-Theme)."""
    data = request.get_json(silent=True) or {}
    if "map_style" in data:
        style = (data.get("map_style") or "").strip()
        if style and style not in MAP_STYLES:
            return jsonify({"error": "Ungültiger Kartenstil"}), 400
        db = get_db()
        db.execute("UPDATE users SET map_style = ? WHERE id = ?",
                   (style or None, current_user.id))
        db.commit()
        db.close()
    if "theme" in data:
        theme = (data.get("theme") or "").strip()
        if theme not in UI_THEMES:
            return jsonify({"error": "Ungültiges Theme"}), 400
        db = get_db()
        db.execute("UPDATE users SET theme = ? WHERE id = ?",
                   (theme or None, current_user.id))
        db.commit()
        db.close()
    if "language" in data:  # FIXES 15.5: Sprache ist jetzt per-User
        lang = (data.get("language") or "").strip().upper()
        if lang not in ("DE", "EN"):
            return jsonify({"error": "Ungültige Sprache"}), 400
        db = get_db()
        db.execute("UPDATE users SET language = ? WHERE id = ?", (lang, current_user.id))
        db.commit()
        db.close()
    return jsonify({"ok": True})


# ── User-Avatar (5.11) ───────────────────────────────────────

def _delete_user_avatar_file(filename):
    try:
        path = os.path.join(_USER_AVATAR_DIR, filename)
        if os.path.isfile(path):
            os.remove(path)
    except OSError:
        log.warning("could not delete user avatar file %r", filename, exc_info=True)


@profile_bp.route("/api/user/avatar", methods=["POST"])
@login_required
def upload_user_avatar():
    """Eigenes Avatar hochladen: auf 128x128 PNG normiert (Pillow)."""
    from PIL import Image
    f = request.files.get("avatar")
    if not f or not f.filename:
        return jsonify({"error": "Keine Datei"}), 400
    ext = os.path.splitext(secure_filename(f.filename))[1].lower()
    if ext not in _AVATAR_EXTS:
        return jsonify({"error": "Ungültiges Format (PNG, JPG, WEBP)"}), 400
    data = f.read(_MAX_ICON_BYTES + 1)
    if len(data) > _MAX_ICON_BYTES:
        return jsonify({"error": "Datei zu groß (max. 200 KB)"}), 400
    # Auf 128x128 normieren, transparent zentriert, immer als PNG speichern.
    try:
        img = Image.open(io.BytesIO(data))
        img = img.convert("RGBA")
        img.thumbnail((128, 128), Image.Resampling.LANCZOS)
        thumb = Image.new("RGBA", (128, 128), (0, 0, 0, 0))
        thumb.paste(img, ((128 - img.size[0]) // 2, (128 - img.size[1]) // 2), img)
    except Exception:
        log.warning("avatar resize failed", exc_info=True)
        return jsonify({"error": "Bilddatei ungültig"}), 400
    os.makedirs(_USER_AVATAR_DIR, exist_ok=True)
    db = get_db()
    row = db.execute("SELECT avatar_filename FROM users WHERE id = ?", (current_user.id,)).fetchone()
    if row and row["avatar_filename"]:
        _delete_user_avatar_file(row["avatar_filename"])
    filename = f"user_{current_user.id}.png"
    thumb.save(os.path.join(_USER_AVATAR_DIR, filename), "PNG")
    db.execute("UPDATE users SET avatar_filename = ? WHERE id = ?", (filename, current_user.id))
    db.commit()
    db.close()
    return jsonify({"ok": True, "avatar_url": f"/media/user-avatars/{filename}"})


@profile_bp.route("/api/user/avatar", methods=["DELETE"])
@login_required
def delete_user_avatar():
    db = get_db()
    row = db.execute("SELECT avatar_filename FROM users WHERE id = ?", (current_user.id,)).fetchone()
    if row and row["avatar_filename"]:
        _delete_user_avatar_file(row["avatar_filename"])
        db.execute("UPDATE users SET avatar_filename = NULL WHERE id = ?", (current_user.id,))
        db.commit()
    db.close()
    return jsonify({"ok": True})


@profile_bp.route("/api/change-password", methods=["POST"])
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
