# Mosquitto MQTT Broker (TLS)

MQTT broker with TLS encryption for the IDMate project.

## Configure .env

Add the following variables to `.env`:

```env
# Multiple MQTT users (comma-separated, user:pass)
MQTT_USERS=car1:SecretPassword1!,car2:SecretPassword2!

# Or single user (backwards compatible)
# MQTT_USER=esp32
# MQTT_PASS=ASecurePassword123!

MQTT_DOMAIN=mqtt.example.com
MQTT_PORT=8883
```

- `MQTT_USERS` -- Comma-separated `user:pass` pairs (e.g. one user per vehicle)
- `MQTT_USER` / `MQTT_PASS` -- Fallback for a single user (backwards compatible)
- `MQTT_DOMAIN` -- Domain for the TLS certificate (e.g. `idmatemqtt.homecon.synology.me`)
- `MQTT_PORT` -- External port (default: 8883)

## First Start

```bash
docker compose up -d mosquitto
```

On first start the following happens automatically:

1. A **self-signed certificate** is generated (if no certificate exists)
2. The **password file** is created from `MQTT_USERS` (or `MQTT_USER`/`MQTT_PASS`)

The password file is regenerated from environment variables on every container start. To change users, update `.env` and restart:

```bash
docker compose restart mosquitto
```

## Port Forwarding (Synology / Router)

| External | Internal      | Protocol |
|----------|---------------|----------|
| 8883     | NAS-IP:8883   | TCP      |

In Synology DSM: **Control Panel > External Access > Router Configuration** or directly in your router.

## Let's Encrypt Certificates

### Option A: Certbot on the NAS (recommended)

```bash
# Install certbot (on the Synology host)
sudo certbot certonly --standalone -d mqtt.example.com --preferred-challenges http

# Copy certificates into the volume
CERT_VOL=$(docker volume inspect idmate_mosquitto-certs -f '{{.Mountpoint}}')
sudo cp /etc/letsencrypt/live/mqtt.example.com/fullchain.pem "$CERT_VOL/chain.pem"
sudo cp /etc/letsencrypt/live/mqtt.example.com/cert.pem "$CERT_VOL/cert.pem"
sudo cp /etc/letsencrypt/live/mqtt.example.com/privkey.pem "$CERT_VOL/key.pem"
sudo chown 1883:1883 "$CERT_VOL"/*.pem

docker compose restart mosquitto
```

### Option B: Use Synology Certificate

If a Synology DDNS certificate already exists, copy the files:

```bash
# Find the Synology certificate path
ls /usr/syno/etc/certificate/_archive/

CERT_VOL=$(docker volume inspect idmate_mosquitto-certs -f '{{.Mountpoint}}')
sudo cp /usr/syno/etc/certificate/_archive/XXXXXX/fullchain.pem "$CERT_VOL/chain.pem"
sudo cp /usr/syno/etc/certificate/_archive/XXXXXX/cert.pem "$CERT_VOL/cert.pem"
sudo cp /usr/syno/etc/certificate/_archive/XXXXXX/privkey.pem "$CERT_VOL/key.pem"

docker compose restart mosquitto
```

### Automatic Renewal

Cron job on the NAS (every 60 days):

```bash
0 3 1 */2 * certbot renew --quiet && cd /path/to/IDMate && ./mosquitto/renew-certs.sh
```

## Testing

### With mosquitto_sub/pub (local)

```bash
# Subscribe
mosquitto_sub -h mqtt.example.com -p 8883 \
  -u esp32 -P 'ASecurePassword123!' \
  --cafile /path/to/chain.pem \
  -t "idmate/#" -v

# Publish
mosquitto_pub -h mqtt.example.com -p 8883 \
  -u esp32 -P 'ASecurePassword123!' \
  --cafile /path/to/chain.pem \
  -t "idmate/test" -m '{"hello":"world"}'
```

Add `--insecure` when using a self-signed certificate.

### From the Docker Network

```bash
docker compose exec mosquitto mosquitto_sub \
  -h localhost -p 8883 \
  --cafile /mosquitto/certs/chain.pem \
  -u esp32 -P 'ASecurePassword123!' \
  -t "#" -v
```

## ESP32 Connection (Arduino / PlatformIO)

```cpp
#include <WiFiClientSecure.h>
#include <PubSubClient.h>

const char* mqtt_server = "mqtt.example.com";
const int   mqtt_port   = 8883;
const char* mqtt_user   = "esp32";
const char* mqtt_pass   = "ASecurePassword123!";

WiFiClientSecure espClient;
PubSubClient mqtt(espClient);

void setupMQTT() {
  // For self-signed certificates:
  espClient.setInsecure();

  // For Let's Encrypt (embed root CA):
  // espClient.setCACert(letsencrypt_root_ca);

  mqtt.setServer(mqtt_server, mqtt_port);
  mqtt.setCallback(mqttCallback);
}

void mqttCallback(char* topic, byte* payload, unsigned int length) {
  // Process message
}

void reconnect() {
  while (!mqtt.connected()) {
    if (mqtt.connect("ESP32-IDMate", mqtt_user, mqtt_pass)) {
      mqtt.subscribe("idmate/cmd/#");
    } else {
      delay(5000);
    }
  }
}

void loop() {
  if (!mqtt.connected()) reconnect();
  mqtt.loop();

  // Example: send data
  mqtt.publish("idmate/data/soc", "78");
}
```

## Files

```
mosquitto/
  mosquitto.conf    -- Broker configuration
  entrypoint.sh     -- Startup script (cert generation, password)
  passwd            -- Auto-generated (gitignored)
  README.md         -- This file
```
