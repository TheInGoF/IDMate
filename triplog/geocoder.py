"""Reverse geocoding for trips and charging sessions without an address."""

import sqlite3
import time
import logging
import urllib.request
import urllib.error
import json

import config
from detector import match_location

log = logging.getLogger("triplog.geocoder")


class RateLimitError(Exception):
    """Nominatim returned 429 — stop immediately."""
    pass


# Cooldown: earliest re-geocode after 429
COOLDOWN_SECONDS = 3600  # 1 hour
_blocked_until = 0  # Unix-Timestamp


def get_db():
    db = sqlite3.connect(config.DB_PATH, timeout=10)
    db.row_factory = sqlite3.Row
    return db


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
    On 429: raises RateLimitError → caller aborts."""
    addr, cc = reverse_geocode(lat, lon)
    time.sleep(config.GEOCODE_RATE_LIMIT)
    return addr, cc


def geocode_trips(db):
    """Geocode all trips without start/destination address.
    Geofenced locations are used directly as address (no API call).
    Stops immediately on 429 (rate limit) and saves results so far."""
    cursor = db.execute(
        """SELECT id, start_lat, start_lon, end_lat, end_lon
           FROM trips
           WHERE (start_address IS NULL AND start_lat IS NOT NULL)
              OR (end_address IS NULL AND end_lat IS NOT NULL)
           ORDER BY id"""
    )
    count = 0
    for row in cursor.fetchall():
        trip_id, slat, slon, elat, elon = row

        if slat and slon:
            loc = match_location(db, slat, slon)
            if loc:
                db.execute("UPDATE trips SET start_address = ? WHERE id = ?", (loc["name"], trip_id))
                log.info("Trip %d Start (Geofence): %s", trip_id, loc["name"])
                count += 1
            else:
                try:
                    addr, cc = _safe_geocode(slat, slon)
                    db.execute("UPDATE trips SET start_address = ?, country_code = ? WHERE id = ?",
                               (addr, cc or None, trip_id))
                    db.commit()
                    log.info("Trip %d Start: %s", trip_id, addr)
                    count += 1
                except RateLimitError:
                    db.commit()
                    raise
                except Exception:
                    log.exception("Geocoding failed for trip %d start", trip_id)

        if elat and elon:
            loc = match_location(db, elat, elon)
            if loc:
                db.execute("UPDATE trips SET end_address = ? WHERE id = ?", (loc["name"], trip_id))
                log.info("Trip %d destination (geofence): %s", trip_id, loc["name"])
                count += 1
            else:
                try:
                    addr, cc = _safe_geocode(elat, elon)
                    db.execute("UPDATE trips SET end_address = ? WHERE id = ?", (addr, trip_id))
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


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    run_once()
