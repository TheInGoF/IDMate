# How-To: Setup IDmate + IDTelemetry

Complete setup of **IDTelemetry** (the ESP32 stick in the vehicle) and **IDmate**
(server: Triplog + InfluxDB + Mosquitto) — from the MQTT connection through external
reachability (router / DuckDNS / Synology) to adding a vehicle and the Home Assistant
connection for charge data.

This guide covers four topics:

1. [MQTT connection: stick to server (incl. router port forwarding)](#1-mqtt-connection-stick-to-server)
2. [Remote access via DuckDNS or Synology (DDNS + reverse proxy)](#2-remote-access-via-duckdns-or-synology)
3. [Add a vehicle and map MQTT data](#3-add-a-vehicle-and-map-mqtt-data)
4. [Home Assistant integration: charge data + external vehicle data](#4-home-assistant-integration)

---

## Architecture & ports (overview)

```
┌─────────────────┐   MQTT (AES-256-CBC in payload)   ┌──────────────────────────┐
│  IDTelemetry    │  tele/<device>/data               │        IDmate            │
│  ESP32 stick    │ ────────────────────────────────► │  Mosquitto → Triplog     │
│  (in vehicle)   │                                    │           → InfluxDB     │
└─────────────────┘                                    └──────────────────────────┘
        ▲                                                          ▲
        │ Web UI config (WiFi AP)                                  │ REST webhook
                                                          ┌──────────────────┐
                                                          │  Home Assistant  │
                                                          │  (charge data)   │
                                                          └──────────────────┘
```

`docker-compose.yml` maps **host ports → container ports**. Configured in
[.env](../.env) (template: [.env.example](../.env.example)):

| Service      | Host port (`.env`)      | Container port | Purpose                                |
|--------------|-------------------------|----------------|----------------------------------------|
| Triplog Web  | `TRIPLOG_PORT=3004`     | `5000`         | Web UI + charge webhook                |
| InfluxDB     | `INFLUX_PORT=3001`      | `8086`         | Time-series database                   |
| Mosquitto    | `MQTT_PORT=3005`        | `1883`         | MQTT broker (telemetry from the stick) |

> **Important:** The stick connects to the **host port** (`3005`), not `1883`.
> Inside the Docker network the containers talk to the internal ports
> (`influxdb:8086`, `mosquitto:1883`).

---

## 1. MQTT connection: stick to server

### 1.1 Server side: Mosquitto + AES key

In [.env](../.env):

```env
MQTT_PORT=3005
MQTT_DATA_TOPIC=tele/+/data
# AES-256 key (32 bytes hex). Generate with: openssl rand -hex 32
# MUST match the key in the stick firmware.
MQTT_AES_KEY=<64-hex-chars>
MQTT_TLS=0
```

Generate the AES key **once** and use it for both the stick **and** the server:

```bash
openssl rand -hex 32
```

> **One global key:** IDmate decrypts with exactly **one** `MQTT_AES_KEY`
> ([triplog/app.py](../triplog/app.py), `_decrypt_payload`). There are **no** per-vehicle keys.
> With multiple sticks they must **all use the same AES key** — the vehicles are
> distinguished by their **topic** (see [section 3](#3-add-a-vehicle-and-map-mqtt-data)).

Start the stack and create a Mosquitto user (optional) — details in
[mosquitto/README.md](../mosquitto/README.md).

### 1.2 Stick side: configure via Web UI

On first boot the stick opens a **WiFi access point**. Open the config page there
([data/config.html](../../IDTelemetry/data/config.html)) and fill in the **MQTT** section:

| Field         | Value (example)         | Note                                                  |
|---------------|-------------------------|-------------------------------------------------------|
| Host          | `192.168.x.y`          | LAN IP of the IDmate server (or DDNS, see section 2)  |
| Port          | `3005`                  | = `MQTT_PORT` from `.env`                              |
| Username/Pass | (optional)              | only if Mosquitto auth is enabled                      |
| Topic prefix  | `tele/vw_id`           | determines the **device name** (see section 3)         |
| AES-256 key   | `<the same 64 hex>`     | = `MQTT_AES_KEY` from `.env`                            |

The stick then publishes to **`<topic-prefix>/data`**, e.g. `tele/vw_id/data`
([IDTelemetry/src/mod_mqtt.cpp](../../IDTelemetry/src/mod_mqtt.cpp)). The MQTT client ID is
derived automatically from the last topic segment (`tele/vw_id` → `vw_id`).

> **No TLS over LTE:** The SIM7080G firmware cannot do MQTT-TLS, so the LTE transfer
> runs as plain MQTT — confidentiality comes from the AES-256-CBC encryption **in the
> payload**, not from transport encryption. `MQTT_TLS` therefore stays `0`.

### 1.3 Router port forwarding (external access only)

**Inside the same LAN NO port forwarding is needed** — the stick talks to the LAN IP directly.

You only need port forwarding if the stick should reach the server **over LTE / on the road**
(SIM variant) or if an external service needs access. In that case forward in the router:

| External port | → Target (LAN IP : port) | Service             |
|---------------|--------------------------|---------------------|
| `3005`        | `192.168.x.y:3005`      | MQTT (telemetry)    |
| `3004`        | `192.168.x.y:3004`      | Triplog (webhook)   |

**Fritz!Box:** Internet → Permit Access → Port Sharing → "Add Device for Sharing"
→ pick the device → new sharing (TCP, port 3005 → 3005). Same for 3004.

**Synology router (SRM):** Network Center → Port Forwarding → Create → TCP, external/internal port.

**Generic:** In the router under "Port Forwarding / Virtual Server" add a TCP rule
*external 3005 → LAN-IP:3005*.

> **Security:** Before exposing MQTT externally, be sure to enable Mosquitto authentication
> (user/password) and ideally TLS on the broker (see [mosquitto/README.md](../mosquitto/README.md)).
> Telemetry payloads are AES-encrypted, but an open broker without auth is still attackable.

---

## 2. Remote access via DuckDNS or Synology

Home internet connections usually have a **changing public IP**. So that the stick (LTE)
or Home Assistant can reliably find the server from outside, you need a **DDNS name**
(fixed hostname → current IP).

### 2.1 Option A: DuckDNS (free)

1. Sign up at [duckdns.org](https://www.duckdns.org), create a subdomain,
   e.g. `myidmate` → `myidmate.duckdns.org`. Note the token.
2. **Update the IP automatically** (one option is enough):
   - **On the Synology** (Control Panel → External Access → DDNS → Add → Provider "Custom",
     URL with the DuckDNS update endpoint), **or**
   - via cron on any always-on host in the LAN:
     ```bash
     */5 * * * * curl -s "https://www.duckdns.org/update?domains=myidmate&token=<TOKEN>&ip="
     ```
3. **Router port forwarding** as in [section 1.3](#13-router-port-forwarding-external-access-only)
   (3005 for MQTT, 3004 for the webhook).
4. On the stick set the MQTT host to `myidmate.duckdns.org`, port `3005`.
   In Home Assistant set the webhook URL to `http://myidmate.duckdns.org:3004/api/charge/reading`.

### 2.2 Option B: Synology DDNS + reverse proxy

1. **DDNS:** Control Panel → External Access → DDNS → Add. Provider e.g. "Synology"
   (`xxx.synology.me`) or "Custom" (DuckDNS). Synology keeps the name up to date automatically.
2. **Reverse proxy (HTTP/HTTPS, for Triplog & webhook):**
   Control Panel → Login Portal → Advanced → Reverse Proxy → Create:
   - Source: `https` · `idmate.xxx.synology.me` · port `443`
   - Destination: `http` · `localhost` · port `3004`

   Triplog is then reachable at `https://idmate.xxx.synology.me` — including a valid
   Synology certificate. The charge webhook is then
   `https://idmate.xxx.synology.me/api/charge/reading`.
3. **MQTT (port 3005, TCP — not HTTP):** MQTT does **not** run through the HTTP reverse proxy.
   For external MQTT access either
   - router port forwarding `3005 → 3005` (see 1.3), **or**
   - enable TLS on the broker and mount the **Synology certificate** into the Mosquitto
     container (step by step in [mosquitto/README.md](../mosquitto/README.md), "Option B: Use Synology Certificate").

> **Rule of thumb:** A reverse proxy is ideal for **HTTP(S)** (Triplog/webhook). **MQTT** is
> its own TCP protocol → use either direct port forwarding or broker TLS, not the HTTP proxy.

---

## 3. Add a vehicle and map MQTT data

### 3.1 How the mapping works

The chain from stick to display:

```
Topic prefix on stick   →   MQTT topic            →   InfluxDB tag   →   vehicles.device
   tele/vw_id          →   tele/vw_id/data      →   d=vw_id       →   device = "vw_id"
```

- IDmate subscribes to `tele/+/data` and reads the **middle topic segment** as `device`
  ([triplog/app.py](../triplog/app.py), `on_message` → `parts[1]`).
- This `device` value is written as the InfluxDB tag **`d=<device>`** (measurement `v`).
- In the SQLite table `vehicles`, the column **`device`** links a vehicle to exactly
  that tag ([triplog/schema.sql](../triplog/schema.sql)).

**Data without a matching vehicle is not lost:** the telemetry is still written to
InfluxDB (tagged with the `device`). But **no** vehicle is created automatically — until
you add a `vehicles` row with a matching `device`, the data simply can't be cleanly mapped
to a plate in the UI.

### 3.2 Add a new vehicle (Web UI)

1. Log in to Triplog → **Admin → Vehicles**.
2. Click "Add vehicle" and fill in:

   | Field                 | Example         | Note                                                  |
   |-----------------------|-----------------|-------------------------------------------------------|
   | Plate                 | `B-MW 1234`     | **required**, unique                                  |
   | Name                  | `ID. Buzz`      | display name                                          |
   | Model                 | `VW ID. Buzz`   | optional                                              |
   | **Device**            | `vw_id`        | **must exactly match the topic-prefix suffix**        |
   | VIN                   | `WVW...`        | optional                                              |
   | Battery capacity (kWh)| `77`            | optional, for range/efficiency calculation           |

   The **device field is the key**: if the stick uses `tele/vw_id`, this must read `vw_id`.

3. Save. From now on, incoming `tele/vw_id/data` telegrams are mapped to this vehicle.

> **Alternatively via API:** `POST /api/vehicles` with JSON
> `{"plate","name","model","device","vin","battery_capacity_kwh"}`.

### 3.3 Multiple vehicles

- **Same AES key** for all sticks (there is only one global key).
- **Different topic prefix** per stick, e.g. `tele/vw_id` and `tele/vw_two`.
- One `vehicles` row per stick with the matching `device` (`vw_id`, `vw_two`).
- The wildcard topic `tele/+/data` catches them all automatically.

### 3.4 Test the connection

```bash
# Read raw telegrams at the broker (shows only THAT data arrives — payload is AES):
mosquitto_sub -h 192.168.x.y -p 3005 -t 'tele/+/data' -v
```

Then check in the Triplog UI whether current values (SoC, km, position) show up under the
vehicle. More test commands in [mosquitto/README.md](../mosquitto/README.md).

---

## 4. Home Assistant integration

IDmate receives **charge data** (and optionally SoC/odometer) via REST webhook from Home
Assistant. Ready-made templates live in the repo under [homeassistant/](../homeassistant/):

- [idmate_charge_tracker.yaml](../homeassistant/idmate_charge_tracker.yaml) — automation: send a charge reading every 15 min
- [configuration_example.yaml](../homeassistant/configuration_example.yaml) — REST command, input helpers, secrets
- [idmate_vehicle_telemetry.yaml](../homeassistant/idmate_vehicle_telemetry.yaml) — vehicle telemetry into InfluxDB

For a second vehicle, copy the templates above and adjust the sensor/entity names and the plate.

### 4.1 Server side: webhook token

In [.env](../.env):

```env
# Bearer token for the HA automation. Generate with: openssl rand -base64 32
CHARGE_WEBHOOK_TOKEN=<token>
```

> If the token is **empty**, the webhook rejects **all** requests with HTTP 503. So set it
> for normal operation.

**Endpoint:** `POST http://<host>:3004/api/charge/reading`
with header `Authorization: Bearer <token>` and `Content-Type: application/json`.

### 4.2 Payload schema

```json
{
  "vehicle": "B-MW 1234",
  "kwh": 1.234,
  "meter_start": 12345.67,
  "meter_end": 12346.90,
  "timestamp": "2026-03-22T14:30:00",
  "odometer": 45678.5,
  "tibber_price": 0.2845,
  "tibber_grundgebuehr": 0.0456,
  "soc": 85.5
}
```

| Field                  | Type   | Required | Note                                                            |
|------------------------|--------|----------|-----------------------------------------------------------------|
| `vehicle`              | string | **yes**  | plate (= `plate` in `vehicles`). `free`/`unknown`/`error` are handled specially |
| `kwh`                  | float  | **yes**  | energy charged since the last reading; `≤ 0` is ignored         |
| `meter_start`          | float  | no       | meter reading at start                                          |
| `meter_end`            | float  | no       | meter reading at end                                            |
| `timestamp`            | string | no       | ISO 8601; normalized to Europe/Berlin                          |
| `odometer`            | float  | no       | odometer (for efficiency)                                      |
| `tibber_price`         | float  | no       | energy price EUR/kWh                                            |
| `tibber_grundgebuehr`  | float  | no       | prorated base fee EUR/kWh                                       |
| `soc`                  | float  | no       | state of charge 0–100 %                                        |

Implementation: [triplog/blueprints/charges.py](../triplog/blueprints/charges.py), `charge_webhook()`.

### 4.3 Home Assistant configuration

In `configuration.yaml` (see [configuration_example.yaml](../homeassistant/configuration_example.yaml)):

```yaml
rest_command:
  idmate_charge_reading:
    url: "http://192.168.x.y:3004/api/charge/reading"   # or DDNS URL
    method: POST
    headers:
      Content-Type: application/json
      Authorization: !secret idmate_charge_token
    payload: >-
      {
        "timestamp": "{{ now().strftime('%Y-%m-%d %H:%M') }}",
        "vehicle": "{{ states('input_select.wallbox_vehicle') }}",
        "kwh": {{ states('sensor.wallbox_energy_15m') | float(0) }},
        "meter_start": {{ states('sensor.wallbox_meter_start') | float(0) }},
        "meter_end": {{ states('sensor.wallbox_meter_end') | float(0) }},
        "tibber_price": {{ states('sensor.tibber_price') | float(0) }},
        "tibber_grundgebuehr": {{ states('sensor.tibber_grundgebuehr_15m') | float(0) }},
        "odometer": {{ states('sensor.vehicle_odometer') | float(0) }}
      }
```

The matching automation (every 15 min, only when the wallbox is available) is in
[idmate_charge_tracker.yaml](../homeassistant/idmate_charge_tracker.yaml).

> **Vehicle selection:** The `vehicle` value must match a **plate from `vehicles`**.
> In the templates an `input_select.wallbox_vehicle` provides the plates; `free` = no
> vehicle at the wallbox right now (skipped).

### 4.4 External vehicle data (SoC / odometer without a stick)

Three ways to provide vehicle data without an IDTelemetry stick:

1. **Send it in the charge webhook:** the `soc` and `odometer` fields in the payload above — the simplest way.
2. **Auto-detect external charges:** if SoC rises by ≥ 3 % between two trips without a
   matching charge session, IDmate creates an external charge automatically
   (`detect_external_from_trips`, endpoint `POST /api/charge/detect-external` in
   [triplog/blueprints/charges.py](../triplog/blueprints/charges.py)).
3. **Write to InfluxDB directly:** Home Assistant can also write telemetry as line protocol
   into the InfluxDB bucket `can-scan` (tag `d=<device>`, measurement `v`) — example in
   [idmate_vehicle_telemetry.yaml](../homeassistant/idmate_vehicle_telemetry.yaml). That way a
   vehicle can be represented entirely without a stick, purely from HA sensors.

### 4.5 Test the webhook

```bash
curl -X POST "http://192.168.x.y:3004/api/charge/reading" \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"vehicle":"B-MW 1234","kwh":1.5,"soc":80,"odometer":45678}'
# Expected: {"ok": true}
```

---

## Checklist

- [ ] `.env` created from `.env.example`, ports set
- [ ] `MQTT_AES_KEY` generated with `openssl rand -hex 32` — identical in `.env` **and** the stick
- [ ] Stack started, Triplog reachable on `:3004`, `/setup` wizard completed
- [ ] Stick Web UI: MQTT host/port/topic-prefix/AES key set
- [ ] (External) router port forwarding 3005/3004 **or** DDNS + reverse proxy configured
- [ ] Vehicle added under **Admin → Vehicles**, `device` = topic-prefix suffix
- [ ] `mosquitto_sub` shows incoming telegrams, UI shows live values
- [ ] `CHARGE_WEBHOOK_TOKEN` set, HA `rest_command` + automation active, `curl` test = `{"ok": true}`
