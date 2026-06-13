#!/bin/sh
set -e

CONF_FILE="/mosquitto/config/mosquitto.conf"

# ── Generate config ──────────────────────────────────────────
cat > "$CONF_FILE" <<EOF
log_dest stdout
log_type error
log_type warning
log_type notice

persistence true
persistence_location /mosquitto/data/

allow_anonymous true

listener 1883
protocol mqtt
EOF
echo ">>> mosquitto.conf generated (anonymous; authentication is handled by AES payload)"

# ── Fix permissions (volume may be owned by root; mosquitto runs as UID 1883)
chown -R mosquitto:mosquitto /mosquitto/data 2>/dev/null || true

exec mosquitto -c "$CONF_FILE"
