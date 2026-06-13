# How-To: Setup IDMate + IDTelemetry

Komplette Einrichtung von **IDTelemetry** (ESP32-Stick im Fahrzeug) und **IDMate**
(Server: Triplog + InfluxDB + Mosquitto) — von der MQTT-Verbindung über externe
Erreichbarkeit (Router / DuckDNS / Synology) bis zum Anlegen eines Fahrzeugs und der
Home-Assistant-Anbindung für Ladedaten.

Diese Anleitung deckt vier Themen ab:

1. [MQTT-Verbindung Stick ↔ Server (inkl. Router-Portfreigabe)](#1-mqtt-verbindung-stick--server)
2. [Externe Erreichbarkeit: DuckDNS / Synology DDNS + Reverse-Proxy](#2-externe-erreichbarkeit-duckdns--synology)
3. [Fahrzeug anlegen & MQTT-Daten zuweisen](#3-fahrzeug-anlegen--mqtt-daten-zuweisen)
4. [Home-Assistant-Anbindung: Ladedaten + externe Fahrzeugdaten](#4-home-assistant-anbindung)

---

## Architektur & Ports (Überblick)

```
┌─────────────────┐   MQTT (AES-256-CBC im Payload)   ┌──────────────────────────┐
│  IDTelemetry    │  tele/<device>/data               │        IDMate            │
│  ESP32-Stick    │ ────────────────────────────────► │  Mosquitto → Triplog     │
│  (im Fahrzeug)  │                                    │           → InfluxDB     │
└─────────────────┘                                    └──────────────────────────┘
        ▲                                                          ▲
        │ Web-UI Config (WLAN-AP)                                  │ REST-Webhook
                                                          ┌──────────────────┐
                                                          │  Home Assistant  │
                                                          │  (Ladedaten)     │
                                                          └──────────────────┘
```

Die `docker-compose.yml` mappt **Host-Ports → Container-Ports**. Konfiguriert in der
[.env](../.env) (Vorlage: [.env.example](../.env.example)):

| Dienst       | Host-Port (`.env`)      | Container-Port | Zweck                                  |
|--------------|-------------------------|----------------|----------------------------------------|
| Triplog Web  | `TRIPLOG_PORT=3004`     | `5000`         | Web-UI + Charge-Webhook                |
| InfluxDB     | `INFLUX_PORT=3001`      | `8086`         | Zeitreihen-Datenbank                   |
| Mosquitto    | `MQTT_PORT=3005`        | `1883`         | MQTT-Broker (Telemetrie vom Stick)     |

> **Wichtig:** Der Stick verbindet sich mit dem **Host-Port** (`3005`), nicht mit `1883`.
> Innerhalb des Docker-Netzwerks sprechen die Container die internen Ports an
> (`influxdb:8086`, `mosquitto:1883`).

---

## 1. MQTT-Verbindung Stick ↔ Server

### 1.1 Server-Seite: Mosquitto + AES-Key

In der [.env](../.env):

```env
MQTT_PORT=3005
MQTT_DATA_TOPIC=tele/+/data
# AES-256-Key (32 Byte hex). Erzeugen mit: openssl rand -hex 32
# MUSS mit dem Key in der Stick-Firmware übereinstimmen.
MQTT_AES_KEY=<64-hex-zeichen>
MQTT_TLS=0
```

Den AES-Key **einmal** erzeugen und für Stick **und** Server verwenden:

```bash
openssl rand -hex 32
```

> **Ein globaler Key:** IDMate entschlüsselt mit genau **einem** `MQTT_AES_KEY`
> ([triplog/app.py](../triplog/app.py) `_decrypt_payload`). Es gibt **keine** Keys pro Fahrzeug.
> Bei mehreren Sticks müssen also **alle denselben AES-Key** nutzen — unterschieden
> werden die Fahrzeuge über das **Topic** (siehe [Abschnitt 3](#3-fahrzeug-anlegen--mqtt-daten-zuweisen)).

Stack starten und Mosquitto-Benutzer (optional) anlegen — Details in
[mosquitto/README.md](../mosquitto/README.md).

### 1.2 Stick-Seite: Web-UI konfigurieren

Der Stick spannt beim ersten Start einen **WLAN-Access-Point** auf. Dort die Config-Seite
öffnen ([data/config.html](../../IDTelemetry/data/config.html)) und unter **MQTT** eintragen:

| Feld          | Wert (Beispiel)         | Bemerkung                                              |
|---------------|-------------------------|-------------------------------------------------------|
| Host          | `192.168.x.y`          | LAN-IP des IDMate-Servers (oder DDNS, s. Abschnitt 2) |
| Port          | `3005`                  | = `MQTT_PORT` aus der `.env`                           |
| Username/Pass | (optional)              | nur falls Mosquitto-Auth aktiv                         |
| Topic-Prefix  | `tele/vw_nox`           | bestimmt den **Device-Namen** (s. Abschnitt 3)        |
| AES-256 Key   | `<dieselben 64 hex>`    | = `MQTT_AES_KEY` aus der `.env`                        |

Der Stick publiziert dann auf **`<Topic-Prefix>/data`**, also z. B. `tele/vw_nox/data`
([IDTelemetry/src/mod_mqtt.cpp](../../IDTelemetry/src/mod_mqtt.cpp)). Die MQTT-Client-ID wird
automatisch aus dem letzten Topic-Segment abgeleitet (`tele/vw_nox` → `vw_nox`).

> **Kein TLS über LTE:** Die SIM7080G-Firmware kann kein MQTT-TLS, daher läuft die
> LTE-Übertragung als Plain-MQTT — die Vertraulichkeit kommt aus der AES-256-CBC-Verschlüsselung
> **im Payload**, nicht aus der Transportverschlüsselung. `MQTT_TLS` bleibt entsprechend `0`.

### 1.3 Router: Portfreigabe (nur für Zugriff von außerhalb des Heimnetzes)

**Im selben LAN ist KEINE Portfreigabe nötig** — der Stick spricht direkt die LAN-IP an.

Eine Portfreigabe brauchst du nur, wenn der Stick **per LTE / von unterwegs** (SIM-Variante)
oder ein externer Dienst auf den Server zugreifen soll. Dann im Router weiterleiten:

| Externer Port | → Ziel (LAN-IP : Port) | Dienst              |
|---------------|------------------------|---------------------|
| `3005`        | `192.168.x.y:3005`    | MQTT (Telemetrie)   |
| `3004`        | `192.168.x.y:3004`    | Triplog (Webhook)   |

**Fritz!Box:** Internet → Freigaben → Portfreigaben → „Gerät für Freigaben hinzufügen"
→ Gerät wählen → neue Freigabe (TCP, Port 3005 → 3005). Analog für 3004.

**Synology-Router (SRM):** Network Center → Port Forwarding → Create → TCP, externer/interner Port.

**Generisch:** Im Router unter „Port-Forwarding / Virtual Server" eine TCP-Regel
*extern 3005 → LAN-IP:3005* anlegen.

> **Sicherheit:** Vor dem Öffnen von MQTT nach außen unbedingt Mosquitto-Authentifizierung
> (User/Passwort) aktivieren und idealerweise TLS am Broker (siehe [mosquitto/README.md](../mosquitto/README.md)).
> Telemetrie-Payloads sind zwar AES-verschlüsselt, ein offener Broker ohne Auth ist aber angreifbar.

---

## 2. Externe Erreichbarkeit: DuckDNS / Synology

Heim-Internetanschlüsse haben meist eine **wechselnde öffentliche IP**. Damit der Stick (LTE)
oder Home Assistant von extern den Server zuverlässig findet, brauchst du einen
**DDNS-Namen** (fester Hostname → aktuelle IP).

### 2.1 Variante A — DuckDNS (kostenlos)

1. Auf [duckdns.org](https://www.duckdns.org) mit einem Account anmelden, Subdomain anlegen,
   z. B. `meinidmate` → `meinidmate.duckdns.org`. Token notieren.
2. **IP automatisch aktualisieren** (eine Möglichkeit genügt):
   - **Auf der Synology** (Control Panel → External Access → DDNS → Add → Provider „Custom",
     URL mit DuckDNS-Update-Endpoint), **oder**
   - per Cron auf irgendeinem Dauerläufer im LAN:
     ```bash
     */5 * * * * curl -s "https://www.duckdns.org/update?domains=meinidmate&token=<TOKEN>&ip="
     ```
3. **Router-Portfreigabe** wie in [Abschnitt 1.3](#13-router-portfreigabe-nur-für-zugriff-von-außerhalb-des-heimnetzes)
   (3005 für MQTT, 3004 für Webhook).
4. Im Stick als MQTT-Host `meinidmate.duckdns.org`, Port `3005` eintragen.
   In Home Assistant als Webhook-URL `http://meinidmate.duckdns.org:3004/api/charge/reading`.

### 2.2 Variante B — Synology DDNS + Reverse-Proxy

1. **DDNS:** Control Panel → External Access → DDNS → Add. Provider z. B. „Synology"
   (`xxx.synology.me`) oder „Custom" (DuckDNS). Synology hält den Namen automatisch aktuell.
2. **Reverse-Proxy (HTTP/HTTPS, für Triplog & Webhook):**
   Control Panel → Login Portal → Advanced → Reverse Proxy → Create:
   - Source: `https` · `idmate.xxx.synology.me` · Port `443`
   - Destination: `http` · `localhost` · Port `3004`

   Damit ist Triplog unter `https://idmate.xxx.synology.me` erreichbar — inkl. gültigem
   Synology-Zertifikat. Der Charge-Webhook lautet dann
   `https://idmate.xxx.synology.me/api/charge/reading`.
3. **MQTT (Port 3005, TCP — kein HTTP):** MQTT läuft **nicht** über den HTTP-Reverse-Proxy.
   Für externen MQTT-Zugriff entweder
   - Router-Portfreigabe `3005 → 3005` (siehe 1.3), **oder**
   - TLS am Broker aktivieren und das **Synology-Zertifikat** in den Mosquitto-Container
     einbinden (Schritt-für-Schritt in [mosquitto/README.md](../mosquitto/README.md), „Option B: Use Synology Certificate").

> **Faustregel:** Reverse-Proxy ist für **HTTP(S)** (Triplog/Webhook) ideal. **MQTT** ist
> ein eigenes TCP-Protokoll → entweder direkte Portfreigabe oder Broker-TLS, nicht über den
> HTTP-Proxy.

---

## 3. Fahrzeug anlegen & MQTT-Daten zuweisen

### 3.1 Wie die Zuordnung funktioniert

Die Kette vom Stick bis zur Anzeige:

```
Topic-Prefix am Stick   →   MQTT-Topic            →   InfluxDB-Tag   →   vehicles.device
   tele/vw_nox          →   tele/vw_nox/data      →   d=vw_nox       →   device = "vw_nox"
```

- IDMate abonniert `tele/+/data` und liest das **mittlere Topic-Segment** als `device`
  ([triplog/app.py](../triplog/app.py), `on_message` → `parts[1]`).
- Dieser `device`-Wert wird als InfluxDB-Tag **`d=<device>`** geschrieben (Measurement `v`).
- In der SQLite-Tabelle `vehicles` verknüpft die Spalte **`device`** ein Fahrzeug mit genau
  diesem Tag ([triplog/schema.sql](../triplog/schema.sql)).

**Daten ohne passendes Fahrzeug gehen nicht verloren:** Die Telemetrie wird trotzdem nach
InfluxDB geschrieben (getaggt mit dem `device`). Es wird aber **kein** Fahrzeug automatisch
angelegt — bis du in `vehicles` einen Eintrag mit passendem `device` anlegst, lassen sich die
Daten in der UI nur nicht sauber einem Kennzeichen zuordnen.

### 3.2 Neues Fahrzeug anlegen (Web-UI)

1. In Triplog einloggen → **Admin → Fahrzeuge**.
2. „Fahrzeug hinzufügen" und ausfüllen:

   | Feld                  | Beispiel        | Bemerkung                                              |
   |-----------------------|-----------------|-------------------------------------------------------|
   | Kennzeichen (plate)   | `B-MW 1234`     | **Pflicht**, eindeutig                                |
   | Name                  | `ID. Buzz`      | Anzeigename                                           |
   | Modell                | `VW ID. Buzz`   | optional                                               |
   | **Device**            | `vw_nox`        | **muss exakt dem Topic-Prefix-Suffix entsprechen**    |
   | VIN                   | `WVW...`        | optional                                               |
   | Akku-Kapazität (kWh)  | `77`            | optional, für Reichweiten-/Effizienz-Rechnung         |

   Das **Device-Feld ist der Schlüssel**: Steht am Stick `tele/vw_nox`, muss hier `vw_nox` stehen.

3. Speichern. Ab jetzt werden eingehende `tele/vw_nox/data`-Telegramme diesem Fahrzeug zugeordnet.

> **Alternativ per API:** `POST /api/vehicles` mit JSON
> `{"plate","name","model","device","vin","battery_capacity_kwh"}`.

### 3.3 Mehrere Fahrzeuge

- **Gleicher AES-Key** für alle Sticks (es gibt nur einen globalen Key).
- **Unterschiedlicher Topic-Prefix** pro Stick, z. B. `tele/vw_nox` und `tele/vw_two`.
- Pro Stick ein `vehicles`-Eintrag mit passendem `device` (`vw_nox`, `vw_two`).
- Das Wildcard-Topic `tele/+/data` fängt automatisch alle ab.

### 3.4 Verbindung testen

```bash
# Roh-Telegramme am Broker mitlesen (zeigt nur, DASS Daten ankommen — Payload ist AES):
mosquitto_sub -h 192.168.x.y -p 3005 -t 'tele/+/data' -v
```

Danach in der Triplog-UI prüfen, ob unter dem Fahrzeug aktuelle Werte (SoC, km, Position)
erscheinen. Mehr Test-Befehle in [mosquitto/README.md](../mosquitto/README.md).

---

## 4. Home-Assistant-Anbindung

IDMate empfängt **Ladedaten** (und optional SoC/Odometer) per REST-Webhook von Home Assistant.
Fertige Vorlagen liegen im Repo unter [homeassistant/](../homeassistant/):

- [idmate_charge_tracker.yaml](../homeassistant/idmate_charge_tracker.yaml) — Automation: alle 15 min Lade-Messwert senden
- [configuration_example.yaml](../homeassistant/configuration_example.yaml) — REST-Command, Input-Helper, Secrets
- [idmate_vehicle_telemetry.yaml](../homeassistant/idmate_vehicle_telemetry.yaml) — Fahrzeugtelemetrie nach InfluxDB
Für ein zweites Fahrzeug die obigen Vorlagen kopieren und Sensor-/Entity-Namen
sowie das Kennzeichen anpassen.

### 4.1 Server-Seite: Webhook-Token

In der [.env](../.env):

```env
# Bearer-Token für die HA-Automation. Erzeugen mit: openssl rand -base64 32
CHARGE_WEBHOOK_TOKEN=<token>
```

> Ist der Token **leer**, weist der Webhook **alle** Requests mit HTTP 503 ab. Für den
> Betrieb also setzen.

**Endpoint:** `POST http://<host>:3004/api/charge/reading`
mit Header `Authorization: Bearer <token>` und `Content-Type: application/json`.

### 4.2 Payload-Schema

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

| Feld                   | Typ    | Pflicht | Bemerkung                                                        |
|------------------------|--------|---------|-----------------------------------------------------------------|
| `vehicle`              | String | **ja**  | Kennzeichen (= `plate` in `vehicles`). `free`/`unknown`/`error` werden gesondert behandelt |
| `kwh`                  | Float  | **ja**  | geladene Energie seit letztem Messwert; `≤ 0` wird ignoriert    |
| `meter_start`          | Float  | nein    | Zählerstand Beginn                                              |
| `meter_end`            | Float  | nein    | Zählerstand Ende                                                |
| `timestamp`            | String | nein    | ISO8601; wird nach Europe/Berlin normalisiert                  |
| `odometer`            | Float  | nein    | Kilometerstand (für Effizienz)                                  |
| `tibber_price`         | Float  | nein    | Arbeitspreis EUR/kWh                                            |
| `tibber_grundgebuehr`  | Float  | nein    | anteilige Grundgebühr EUR/kWh                                   |
| `soc`                  | Float  | nein    | Ladezustand 0–100 %                                            |

Implementierung: [triplog/blueprints/charges.py](../triplog/blueprints/charges.py), `charge_webhook()`.

### 4.3 Home-Assistant-Konfiguration

In `configuration.yaml` (siehe [configuration_example.yaml](../homeassistant/configuration_example.yaml)):

```yaml
rest_command:
  idmate_charge_reading:
    url: "http://192.168.x.y:3004/api/charge/reading"   # oder DDNS-URL
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

Die zugehörige Automation (alle 15 min, nur wenn Wallbox verfügbar) steht in
[idmate_charge_tracker.yaml](../homeassistant/idmate_charge_tracker.yaml).

> **Fahrzeug-Auswahl:** Der `vehicle`-Wert muss einem **Kennzeichen aus `vehicles`** entsprechen.
> In den Vorlagen liefert ein `input_select.wallbox_vehicle` die Kennzeichen; `free` = gerade
> kein Fahrzeug an der Wallbox (wird übersprungen).

### 4.4 Externe Fahrzeugdaten (SoC / Odometer ohne Stick)

Drei Wege, Fahrzeugdaten ohne IDTelemetry-Stick zu liefern:

1. **Im Charge-Webhook mitsenden:** Felder `soc` und `odometer` im obigen Payload — einfachster Weg.
2. **Auto-Erkennung externer Ladungen:** Steigt der SoC zwischen zwei Trips um ≥ 3 % ohne
   passende Ladesession, legt IDMate automatisch eine externe Ladung an
   (`detect_external_from_trips`, Endpoint `POST /api/charge/detect-external` in
   [triplog/blueprints/charges.py](../triplog/blueprints/charges.py)).
3. **Direkt nach InfluxDB schreiben:** Home Assistant kann Telemetrie auch per Line-Protocol
   in den InfluxDB-Bucket `can-scan` schreiben (Tag `d=<device>`, Measurement `v`) — Beispiel in
   [idmate_vehicle_telemetry.yaml](../homeassistant/idmate_vehicle_telemetry.yaml). So lässt sich
   ein Fahrzeug ganz ohne Stick rein über HA-Sensoren abbilden.

### 4.5 Webhook testen

```bash
curl -X POST "http://192.168.x.y:3004/api/charge/reading" \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"vehicle":"B-MW 1234","kwh":1.5,"soc":80,"odometer":45678}'
# Erwartet: {"ok": true}
```

---

## Checkliste

- [ ] `.env` aus `.env.example` erstellt, Ports gesetzt
- [ ] `MQTT_AES_KEY` per `openssl rand -hex 32` erzeugt — identisch in `.env` **und** Stick
- [ ] Stack gestartet, Triplog unter `:3004` erreichbar, `/setup`-Wizard durchlaufen
- [ ] Stick-Web-UI: MQTT-Host/Port/Topic-Prefix/AES-Key gesetzt
- [ ] (Extern) Router-Portfreigabe 3005/3004 **oder** DDNS + Reverse-Proxy eingerichtet
- [ ] Fahrzeug in **Admin → Fahrzeuge** angelegt, `device` = Topic-Prefix-Suffix
- [ ] `mosquitto_sub` zeigt eingehende Telegramme, UI zeigt Live-Werte
- [ ] `CHARGE_WEBHOOK_TOKEN` gesetzt, HA-`rest_command` + Automation aktiv, `curl`-Test = `{"ok": true}`
