import os

VERSION = "1.2.0"

# InfluxDB
INFLUX_URL = os.environ.get("INFLUX_URL", "http://influxdb:8086")
INFLUX_TOKEN = os.environ.get("INFLUX_TOKEN", "")
INFLUX_ORG = os.environ.get("INFLUX_ORG", "home")
INFLUX_BUCKET = os.environ.get("INFLUX_BUCKET", "can-scan")
INFLUX_DEVICE = os.environ.get("INFLUX_DEVICE", "id7")

# ── InfluxDB-Feldtypen (measurement "v") — EINE Wahrheit für alle Writer ──
# Feldtypen sind FIX, sobald ein Feld einmal geschrieben wurde: ein abweichender
# Typ liefert 422 field-type-conflict und der GANZE Batch/Tag wird verworfen
# (echte Vorfälle: Commits 9ebbbad, 73afef1, d951af9 = Datenverlust).
# Diese Tabelle muss von MQTT-Bridge, Replay (app.py) und Backfill-Import
# (import_job.py) identisch verwendet werden — niemand castet Influx-Felder
# noch von Hand. Ableitung aus dem Binär-Decoder (_BIN_FIELDS in app.py):
# Felder OHNE Divisor sind ganzzahlig (mit Divisor: la, lo, s, p, r, ca, kw,
# od = FLOAT).
#
# ACHTUNG 'v' (speed): der korrekte Typ ist INSTALLATIONS-ABHÄNGIG. Manche
# Buckets haben 'v' als float etabliert (Vorfall 73afef1 = genau diese
# Installation), andere als integer (Vorfall d951af9). Ein hartkodierter Wert
# pingpongt deshalb endlos zwischen beiden Welten und bricht jeweils die andere.
# Lösung: per ENV überschreibbar. Default = float für 'v' (Bucket dieser
# Installation, durch 73afef1 + erneutes 422 am 2025-12-31 belegt). Eine
# Installation, deren Bucket 'v' als integer führt, setzt:
#   INFLUX_INT_FIELDS=hd,u,i,c,dc,bt,et,pk,ls,bd,lp,v
# Format: kommaseparierte Feldnamen. Leerer String = ALLE Felder float.
_INFLUX_INT_FIELDS_DEFAULT = "hd,u,i,c,dc,bt,et,pk,ls,bd,lp"


def _parse_int_fields():
    raw = os.environ.get("INFLUX_INT_FIELDS")
    if raw is None:
        raw = _INFLUX_INT_FIELDS_DEFAULT
    return frozenset(f.strip() for f in raw.split(",") if f.strip())


INFLUX_INT_FIELDS = _parse_int_fields()


def influx_field_value(key, val):
    """Cast a numeric Influx field to the type fixed by this installation's
    schema. Use for EVERY write to measurement "v" so all writers agree."""
    if key in INFLUX_INT_FIELDS:
        return int(round(val))
    return float(val)


# Auth
SECRET_KEY = os.environ.get("SECRET_KEY", "")

# SQLite
DB_PATH = os.environ.get("DB_PATH", "/data/triplog.db")

# Geocoding
GEOCODE_URL = os.environ.get("GEOCODE_URL", "https://nominatim.openstreetmap.org/reverse")
GEOCODE_USER_AGENT = "IDMate/1.0"
GEOCODE_RATE_LIMIT = 2.0  # Seconds between requests (Nominatim: min 1/s)
# Backfill mode: slower interval used while bulk-imports/large catch-ups run,
# extended automatically by import jobs and the "Lücken füllen" button.
GEOCODE_BACKFILL_INTERVAL = float(os.environ.get("GEOCODE_BACKFILL_INTERVAL", "5.0"))
GEOCODE_BACKFILL_COOLDOWN_HOURS = float(os.environ.get("GEOCODE_BACKFILL_COOLDOWN_HOURS", "12"))

# Trip detection
TRIP_MIN_DISTANCE_KM = 0.5       # Minimum distance to count as a trip
TRIP_STOP_MINUTES = 5            # v==0 for >= X min = trip end
SCAN_INTERVAL_MINUTES = 10       # How often to scan for new trips
DATA_GAP_MINUTES = 5             # Data gap >= X min = trip end
SOC_JUMP_MIN = 5                 # SoC increase >= X% with standstill = charging → trip end
SOC_JUMP_STILL_KMH = 1.0         # avg speed below this since last SoC = "stood still" (not strict v==0)
GPS_MAX_KMH = 500                # GPS jumps > X km/h are filtered as invalid
MERGE_GAP_MIN = 10               # max minutes between split trips to count as one journey

# MQTT
MQTT_BROKER = os.environ.get("MQTT_BROKER", "mosquitto")
MQTT_PORT = int(os.environ.get("MQTT_BROKER_PORT", "1883"))
MQTT_USER = os.environ.get("MQTT_USER", "")
MQTT_PASS = os.environ.get("MQTT_PASS", "")
MQTT_TOPIC = os.environ.get("MQTT_TOPIC", "idmate/#")
MQTT_DATA_TOPIC = os.environ.get("MQTT_DATA_TOPIC", "tele/+/data")
MQTT_TLS = os.environ.get("MQTT_TLS", "0").lower() in ("1", "true", "yes")
MQTT_AES_KEY = os.environ.get("MQTT_AES_KEY", "")

# Debug pages (/debug, scan-debug, influx-delete) — opt-in for safety;
# enable via ENABLE_DEBUG=1 in .env when needed.
ENABLE_DEBUG = os.environ.get("ENABLE_DEBUG", "0").lower() in ("1", "true", "yes")

# Language (DE or EN, can be overridden in settings)
LANGUAGE = os.environ.get("LANGUAGE", "DE").upper()

# Charge tracker
CHARGE_WEBHOOK_TOKEN = os.environ.get("CHARGE_WEBHOOK_TOKEN", "")

# TeslaMate import (optional, opt-in via ENV)
# Format: postgresql://user:pass@host:5432/dbname
# When unset, the import tab + API routes are hidden.
TESLAMATE_PG_URL = os.environ.get("TESLAMATE_PG_URL", "")


# ── Startup validation ────────────────────────────────────────────
# Don't fail-fast on missing values (local dev would break) but log
# loud warnings to stderr so prod-misconfigs surface in the boot log.
def _warn(msg: str) -> None:
    import sys
    sys.stderr.write(f"[config] WARN: {msg}\n")

if not SECRET_KEY:
    _warn("SECRET_KEY empty — a random one will be generated and stored in the DB. "
          "Set SECRET_KEY=<hex> in env for stable sessions across restarts.")
if not INFLUX_TOKEN:
    _warn("INFLUX_TOKEN empty — telemetry queries and writes will fail silently.")
if MQTT_TOPIC and not MQTT_AES_KEY:
    _warn("MQTT_TOPIC subscribed but MQTT_AES_KEY empty — incoming AES-CBC payloads "
          "cannot be decrypted.")
if CHARGE_WEBHOOK_TOKEN == "":
    _warn("CHARGE_WEBHOOK_TOKEN empty — /api/charge/reading webhook will refuse "
          "all requests (returns 503).")
