"""Reverse geocoding for trips and charging sessions without an address."""

import sqlite3
import time
import logging
import threading
import urllib.request
import urllib.error
import json

import config
from detector import match_location, haversine_m

log = logging.getLogger("triplog.geocoder")

# Serialize geocoding runs: every caller spawns its own thread with its own
# interval. Two parallel runs double the request rate against Nominatim
# (policy: max 1 req/s → risk of 429/ban) and duplicate API calls for the same
# rows. A second concurrent run returns immediately.
_geocode_lock = threading.Lock()


class RateLimitError(Exception):
    """Nominatim returned 429 — stop immediately."""
    pass


# Cooldown: earliest re-geocode after 429
COOLDOWN_SECONDS = 3600  # 1 hour
_blocked_until = 0  # Unix-Timestamp


def get_db():
    db = sqlite3.connect(config.DB_PATH, timeout=10)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON")
    return db


# ── Backfill-Mode ──────────────────────────────────────────────
# A "backfill window" is a timestamp stored in settings.geocode_backfill_until.
# While now() < that timestamp, _safe_geocode uses the slower BACKFILL_INTERVAL.
# Import jobs and the "fill gaps" button extend the window.

_SETTING_KEY = "geocode_backfill_until"


def _read_backfill_until():
    try:
        db = get_db()
        row = db.execute("SELECT value FROM settings WHERE key = ?", (_SETTING_KEY,)).fetchone()
        db.close()
        return float(row["value"]) if row and row["value"] else 0.0
    except Exception:
        return 0.0


def _write_backfill_until(ts):
    db = get_db()
    db.execute(
        "INSERT INTO settings (key, value) VALUES (?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (_SETTING_KEY, str(ts)),
    )
    db.commit()
    db.close()


def is_backfill_active():
    return _read_backfill_until() > time.time()


def extend_backfill_window():
    """Set the backfill cooldown to now + GEOCODE_BACKFILL_COOLDOWN_HOURS.
    Call this when starting an import job, on every imported day, and from
    the manual 'fill gaps' button."""
    until = time.time() + config.GEOCODE_BACKFILL_COOLDOWN_HOURS * 3600
    _write_backfill_until(until)
    log.info("Backfill window extended until %s (interval=%.1fs)",
             time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(until)),
             config.GEOCODE_BACKFILL_INTERVAL)
    return until


def _current_rate_limit():
    return config.GEOCODE_BACKFILL_INTERVAL if is_backfill_active() else config.GEOCODE_RATE_LIMIT


def reverse_geocode(lat, lon):
    """Nominatim reverse geocoding → short address.
    Raises RateLimitError on 429 so the caller stops the run."""
    url = (
        f"{config.GEOCODE_URL}"
        f"?lat={lat}&lon={lon}&format=json&zoom=18&addressdetails=1"
    )
    req = urllib.request.Request(url, headers={"User-Agent": config.GEOCODE_USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        if e.code == 429:
            raise RateLimitError("429 Too Many Requests — geocoding paused")
        raise

    addr = data.get("address", {})

    # Country code
    cc = (addr.get("country_code") or "").upper()

    # Postal code + city
    postcode = addr.get("postcode", "")
    city = addr.get("city") or addr.get("town") or addr.get("village") or addr.get("municipality", "")

    # Street + house number
    road = addr.get("road", "")
    house = addr.get("house_number", "")
    street = f"{road} {house}".strip()

    # Format: DE - 23843 Bad Oldesloe - Lily-Braun-Strasse 1a
    parts = []
    if cc:
        parts.append(cc)
    if postcode and city:
        parts.append(f"{postcode} {city}")
    elif city:
        parts.append(city)
    if street:
        parts.append(street)

    return (" - ".join(parts) if parts else data.get("display_name", ""), cc)


def _safe_geocode(lat, lon):
    """Geocode with rate-limit pause. Returns (addr, country_code).
    On 429: raises RateLimitError → caller aborts.
    Uses GEOCODE_BACKFILL_INTERVAL while a backfill window is active."""
    addr, cc = reverse_geocode(lat, lon)
    time.sleep(_current_rate_limit())
    return addr, cc


# Re-geocode threshold: if a trip's start/end has moved more than this from
# the coordinates its stored address was geocoded for, fetch a fresh address.
# Catches trips that were closed before arrival and later extended to the
# real destination (the address would otherwise stay stuck on the old point).
GEO_REFRESH_M = 50.0


def _needs_geocode(addr, geo_lat, geo_lon, lat, lon):
    """Whether (lat, lon) needs (re)geocoding.

    - No coordinates                       → no
    - No address yet                       → yes (fresh)
    - Address but no anchor (legacy row)   → no (don't re-geocode the history)
    - Address + anchor, point moved >50 m  → yes (end shifted after geocode)
    """
    if lat is None or lon is None:
        return False
    if addr is None:
        return True
    if geo_lat is None or geo_lon is None:
        return False
    return haversine_m(geo_lat, geo_lon, lat, lon) > GEO_REFRESH_M


def geocode_trips(db):
    """Geocode trips that have no address yet, or whose start/end has shifted
    since it was last geocoded (coordinate-anchor delta). Geofenced locations
    are used directly as address (no API call). The anchor (start/end_geo_lat/lon)
    is written on every address update so future shifts can be detected.
    Stops immediately on 429 (rate limit) and saves results so far."""
    cursor = db.execute(
        """SELECT id, start_lat, start_lon, end_lat, end_lon,
                  start_address, end_address,
                  start_geo_lat, start_geo_lon, end_geo_lat, end_geo_lon
           FROM trips
           WHERE (start_lat IS NOT NULL AND (start_address IS NULL
                    OR (start_geo_lat IS NOT NULL
                        AND (start_geo_lat <> start_lat OR start_geo_lon <> start_lon))))
              OR (end_lat   IS NOT NULL AND (end_address IS NULL
                    OR (end_geo_lat IS NOT NULL
                        AND (end_geo_lat <> end_lat OR end_geo_lon <> end_lon))))
           ORDER BY id"""
    )
    count = 0
    for row in cursor.fetchall():
        trip_id = row["id"]
        slat, slon, elat, elon = row["start_lat"], row["start_lon"], row["end_lat"], row["end_lon"]

        if _needs_geocode(row["start_address"], row["start_geo_lat"], row["start_geo_lon"], slat, slon):
            loc = match_location(db, slat, slon)
            if loc:
                db.execute(
                    "UPDATE trips SET start_address = ?, start_geo_lat = ?, start_geo_lon = ? WHERE id = ?",
                    (loc["name"], slat, slon, trip_id))
                db.commit()
                log.info("Trip %d Start (Geofence): %s", trip_id, loc["name"])
                count += 1
            else:
                try:
                    addr, cc = _safe_geocode(slat, slon)
                    db.execute(
                        "UPDATE trips SET start_address = ?, country_code = ?, "
                        "start_geo_lat = ?, start_geo_lon = ? WHERE id = ?",
                        (addr, cc or None, slat, slon, trip_id))
                    db.commit()
                    log.info("Trip %d Start: %s", trip_id, addr)
                    count += 1
                except RateLimitError:
                    db.commit()
                    raise
                except Exception:
                    log.exception("Geocoding failed for trip %d start", trip_id)

        if _needs_geocode(row["end_address"], row["end_geo_lat"], row["end_geo_lon"], elat, elon):
            loc = match_location(db, elat, elon)
            if loc:
                db.execute(
                    "UPDATE trips SET end_address = ?, end_geo_lat = ?, end_geo_lon = ? WHERE id = ?",
                    (loc["name"], elat, elon, trip_id))
                db.commit()
                log.info("Trip %d destination (geofence): %s", trip_id, loc["name"])
                count += 1
            else:
                try:
                    addr, cc = _safe_geocode(elat, elon)
                    db.execute(
                        "UPDATE trips SET end_address = ?, end_geo_lat = ?, end_geo_lon = ? WHERE id = ?",
                        (addr, elat, elon, trip_id))
                    # Only set country_code if not yet set (start takes precedence)
                    if cc:
                        db.execute(
                            "UPDATE trips SET country_code = ? WHERE id = ? AND country_code IS NULL",
                            (cc, trip_id))
                    db.commit()
                    log.info("Trip %d destination: %s", trip_id, addr)
                    count += 1
                except RateLimitError:
                    db.commit()
                    raise
                except Exception:
                    log.exception("Geocoding failed for trip %d destination", trip_id)

    db.commit()
    return count


def geocode_charges(db):
    """Geocode all charging sessions without an address.
    Geofenced locations are used directly as address.
    Stops immediately on 429."""
    cursor = db.execute(
        """SELECT id, lat, lon FROM charges
           WHERE address IS NULL AND lat IS NOT NULL
           ORDER BY id"""
    )
    count = 0
    for row in cursor.fetchall():
        charge_id, lat, lon = row
        loc = match_location(db, lat, lon)
        if loc:
            db.execute("UPDATE charges SET address = ? WHERE id = ?", (loc["name"], charge_id))
            log.info("Charge %d (Geofence): %s", charge_id, loc["name"])
            count += 1
        else:
            try:
                addr, _cc = _safe_geocode(lat, lon)
                db.execute("UPDATE charges SET address = ? WHERE id = ?", (addr, charge_id))
                db.commit()
                log.info("Charge %d: %s", charge_id, addr)
                count += 1
            except RateLimitError:
                log.warning("Rate limit reached — geocoding will resume later")
                db.commit()
                return count
            except Exception:
                log.exception("Geocoding failed for charge %d", charge_id)

    db.commit()
    return count


def run_once():
    global _blocked_until
    # Non-blocking: a second concurrent run would breach Nominatim's 1 req/s
    # limit, so skip it instead of running in parallel.
    if not _geocode_lock.acquire(blocking=False):
        log.info("geocoding already running, skipping")
        return
    try:
        remaining = _blocked_until - time.time()
        if remaining > 0:
            log.info("Geocoding paused — cooldown %d min remaining", int(remaining / 60) + 1)
            return

        db = get_db()
        try:
            t = geocode_trips(db)
            c = geocode_charges(db)
            log.info("Geocoded: %d addresses", t + c)
        except RateLimitError:
            _blocked_until = time.time() + COOLDOWN_SECONDS
            log.warning("429 rate limit — geocoding paused for %d min", COOLDOWN_SECONDS // 60)
        finally:
            db.close()
    finally:
        _geocode_lock.release()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    run_once()
