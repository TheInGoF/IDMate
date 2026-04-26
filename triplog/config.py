import os

VERSION = "1.0.0"

# InfluxDB
INFLUX_URL = os.environ.get("INFLUX_URL", "http://influxdb:8086")
INFLUX_TOKEN = os.environ.get("INFLUX_TOKEN", "")
INFLUX_ORG = os.environ.get("INFLUX_ORG", "home")
INFLUX_BUCKET = os.environ.get("INFLUX_BUCKET", "can-scan")
INFLUX_DEVICE = os.environ.get("INFLUX_DEVICE", "id7")

# Auth
SECRET_KEY = os.environ.get("SECRET_KEY", "")

# SQLite
DB_PATH = os.environ.get("DB_PATH", "/data/triplog.db")

# Geocoding
GEOCODE_URL = os.environ.get("GEOCODE_URL", "https://nominatim.openstreetmap.org/reverse")
GEOCODE_USER_AGENT = "IDMate/1.0"
GEOCODE_RATE_LIMIT = 2.0  # Seconds between requests (Nominatim: min 1/s)

# Trip detection
TRIP_MIN_DISTANCE_KM = 0.5       # Minimum distance to count as a trip
TRIP_STOP_MINUTES = 5            # v==0 for X minutes = trip end
SCAN_INTERVAL_MINUTES = 10       # How often to scan for new trips

# MQTT
MQTT_BROKER = os.environ.get("MQTT_BROKER", "mosquitto")
MQTT_PORT = int(os.environ.get("MQTT_BROKER_PORT", "1883"))
MQTT_USER = os.environ.get("MQTT_USER", "")
MQTT_PASS = os.environ.get("MQTT_PASS", "")
MQTT_TOPIC = os.environ.get("MQTT_TOPIC", "idmate/#")
MQTT_DATA_TOPIC = os.environ.get("MQTT_DATA_TOPIC", "tele/+/data")
MQTT_TLS = os.environ.get("MQTT_TLS", "0").lower() in ("1", "true", "yes")
MQTT_AES_KEY = os.environ.get("MQTT_AES_KEY", "")

# Debug pages (/debug, scan-debug, influx-delete) — can be disabled via ENV
ENABLE_DEBUG = os.environ.get("ENABLE_DEBUG", "1").lower() in ("1", "true", "yes")

# Language (DE or EN, can be overridden in settings)
LANGUAGE = os.environ.get("LANGUAGE", "DE").upper()

# Charge tracker
CHARGE_WEBHOOK_TOKEN = os.environ.get("CHARGE_WEBHOOK_TOKEN", "")
