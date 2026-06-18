"""Profile routes: dedicated page for avatar, appearance (map style),
password and 2FA status.

Avatar upload/delete and the user's own password change were moved here
unchanged from app.py (``@app.route`` -> ``@profile_bp.route``, same URLs).
Shared helpers are pulled from app at import time, like the other blueprints
(registration happens at the end of app.py, so the namespace is then complete).
"""

import io
import os

from flask import Blueprint, jsonify, render_template, request
from flask_login import current_user, login_required
from werkzeug.utils import secure_filename

from app import (MAP_STYLES, UI_THEMES, _MAX_ICON_BYTES, _USER_AVATAR_DIR,
                 _translations, _validate_password, check_password_hash,
                 generate_password_hash, get_db, get_language, log)

profile_bp = Blueprint("profile", __name__)

_AVATAR_EXTS = {".png", ".jpg", ".jpeg", ".webp"}  # no GIF/SVG (XSS, see 2.2)


@profile_bp.route("/profile")
@login_required
def profile_page():
    db = get_db()
    row = db.execute("SELECT totp_enabled, map_style, theme, language FROM users WHERE id = ?",
                     (current_user.id,)).fetchone()
    db.close()
    # FIXES 15.5: language is per-user; default DE when nothing is set.
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
    """User's own appearance preferences (map style, UI theme)."""
    lang = get_language()
    _t = _translations.get(lang, _translations["DE"])
    data = request.get_json(silent=True) or {}
    if "map_style" in data:
        style = (data.get("map_style") or "").strip()
        if style and style not in MAP_STYLES:
            return jsonify({"error": _t["profile_err_invalid_map_style"]}), 400
        db = get_db()
        db.execute("UPDATE users SET map_style = ? WHERE id = ?",
                   (style or None, current_user.id))
        db.commit()
        db.close()
    if "theme" in data:
        theme = (data.get("theme") or "").strip()
        if theme not in UI_THEMES:
            return jsonify({"error": _t["profile_err_invalid_theme"]}), 400
        db = get_db()
        db.execute("UPDATE users SET theme = ? WHERE id = ?",
                   (theme or None, current_user.id))
        db.commit()
        db.close()
    if "language" in data:  # FIXES 15.5: language is now per-user
        new_lang = (data.get("language") or "").strip().upper()
        if new_lang not in ("DE", "EN"):
            return jsonify({"error": _t["profile_err_invalid_language"]}), 400
        db = get_db()
        db.execute("UPDATE users SET language = ? WHERE id = ?", (new_lang, current_user.id))
        db.commit()
        db.close()
    return jsonify({"ok": True})


# ── User avatar (5.11) ───────────────────────────────────────

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
    """Upload own avatar: normalized to a 128x128 PNG (Pillow)."""
    from PIL import Image
    lang = get_language()
    _t = _translations.get(lang, _translations["DE"])
    f = request.files.get("avatar")
    if not f or not f.filename:
        return jsonify({"error": _t["err_no_file"]}), 400
    ext = os.path.splitext(secure_filename(f.filename))[1].lower()
    if ext not in _AVATAR_EXTS:
        return jsonify({"error": _t["profile_err_invalid_format"]}), 400
    data = f.read(_MAX_ICON_BYTES + 1)
    if len(data) > _MAX_ICON_BYTES:
        return jsonify({"error": _t["profile_err_file_too_large"]}), 400
    # Normalize to 128x128, transparent-centered, always save as PNG.
    try:
        img = Image.open(io.BytesIO(data))
        img = img.convert("RGBA")
        img.thumbnail((128, 128), Image.Resampling.LANCZOS)
        thumb = Image.new("RGBA", (128, 128), (0, 0, 0, 0))
        thumb.paste(img, ((128 - img.size[0]) // 2, (128 - img.size[1]) // 2), img)
    except Exception:
        log.warning("avatar resize failed", exc_info=True)
        return jsonify({"error": _t["profile_err_invalid_image"]}), 400
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
    lang = get_language()
    _t = _translations.get(lang, _translations["DE"])
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
        return jsonify({"error": _t["profile_err_old_password_wrong"]}), 400

    db.execute("UPDATE users SET password_hash = ? WHERE id = ?",
               (generate_password_hash(new_pw), current_user.id))
    db.commit()
    db.close()
    return jsonify({"ok": True})
