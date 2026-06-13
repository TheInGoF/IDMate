"""European PLMN (MCC*100 + MNC) → mobile carrier name + brand color.

Used by the dashboard to label the active LTE carrier, the trip detail chart,
and the admin telemetry coverage map. Brand colors follow each operator's
public corporate identity so the map matches how users recognise providers.

Unknown PLMNs degrade gracefully via plmn_info():
  - name falls back to "PLMN <code>"
  - color falls back to a country-derived shade so foreign roaming pings
    still cluster visually on the map.
"""
from __future__ import annotations

# (name, brand color hex)
PLMN_INFO: dict[int, tuple[str, str]] = {
    # ── Germany (MCC 262) ─────────────────────────────────────
    26201: ("Telekom", "#e20074"),
    26206: ("Telekom", "#e20074"),
    26278: ("Telekom", "#e20074"),
    26202: ("Vodafone", "#e60000"),
    26204: ("Vodafone", "#e60000"),
    26209: ("Vodafone", "#e60000"),
    26242: ("Vodafone", "#e60000"),
    26203: ("O2", "#0050ad"),
    26207: ("O2", "#0050ad"),
    26208: ("O2", "#0050ad"),
    26211: ("O2", "#0050ad"),
    26220: ("O2", "#0050ad"),
    26212: ("Dolphin", "#7a3fb7"),
    26213: ("Mobilcom", "#cc0000"),
    26214: ("Quam", "#a02060"),
    26216: ("E-Plus", "#009a3d"),
    26217: ("E-Plus", "#009a3d"),
    26218: ("E-Plus", "#009a3d"),
    26219: ("E-Plus", "#009a3d"),
    26243: ("1&1", "#003d8f"),
    26277: ("Lyca", "#c8102e"),

    # ── Austria (MCC 232) ─────────────────────────────────────
    23201: ("A1", "#e2001a"),
    23209: ("A1", "#e2001a"),
    23202: ("Magenta", "#e20074"),
    23203: ("Magenta", "#e20074"),
    23210: ("Drei", "#00b5e2"),
    23205: ("Drei", "#00b5e2"),
    23207: ("tele.ring", "#d70021"),
    23211: ("bob", "#ff8800"),
    23212: ("Yesss", "#ffd400"),
    23214: ("Spusu", "#00a651"),

    # ── Switzerland (MCC 228) ─────────────────────────────────
    22801: ("Swisscom", "#002f87"),
    22802: ("Sunrise", "#dc0028"),
    22803: ("Salt", "#b30000"),
    22806: ("Lyca", "#c8102e"),
    22807: ("TalkTalk", "#0066b3"),
    22812: ("Sunrise", "#dc0028"),

    # ── France (MCC 208) ──────────────────────────────────────
    20801: ("Orange", "#ff7900"),
    20802: ("Orange", "#ff7900"),
    20805: ("Free Mobile", "#cd131c"),
    20806: ("SFR", "#e2231a"),
    20809: ("SFR", "#e2231a"),
    20810: ("SFR", "#e2231a"),
    20811: ("SFR", "#e2231a"),
    20813: ("SFR", "#e2231a"),
    20815: ("Free Mobile", "#cd131c"),
    20816: ("Free Mobile", "#cd131c"),
    20820: ("Bouygues Telecom", "#00529b"),
    20821: ("Bouygues Telecom", "#00529b"),
    20888: ("Bouygues Telecom", "#00529b"),
    20889: ("Bouygues Telecom", "#00529b"),

    # ── Italy (MCC 222) ───────────────────────────────────────
    22201: ("TIM", "#0033a0"),
    22210: ("Vodafone", "#e60000"),
    22288: ("WindTre", "#ff6900"),
    22299: ("WindTre", "#ff6900"),
    22298: ("WindTre", "#ff6900"),
    22250: ("Iliad", "#e6005e"),
    22230: ("Rete Ferroviaria", "#999999"),
    22277: ("PosteMobile", "#ffcc00"),
    22208: ("Fastweb", "#1fb6ff"),

    # ── Spain (MCC 214) ───────────────────────────────────────
    21401: ("Vodafone", "#e60000"),
    21406: ("Vodafone", "#e60000"),
    21403: ("Orange", "#ff7900"),
    21409: ("Orange", "#ff7900"),
    21411: ("Orange", "#ff7900"),
    21407: ("Movistar", "#019df4"),
    21405: ("Movistar", "#019df4"),
    21404: ("Yoigo", "#ed1c24"),
    21451: ("Yoigo", "#ed1c24"),
    21422: ("Digi", "#ee2a26"),
    21425: ("Lyca", "#c8102e"),

    # ── United Kingdom (MCC 234 / 235) ────────────────────────
    23410: ("O2", "#0019a5"),
    23411: ("O2", "#0019a5"),
    23415: ("Vodafone", "#e60000"),
    23491: ("Vodafone", "#e60000"),
    23420: ("Three", "#ee2d72"),
    23494: ("Three", "#ee2d72"),
    23430: ("EE", "#00a39a"),
    23431: ("EE", "#00a39a"),
    23432: ("EE", "#00a39a"),
    23433: ("EE", "#00a39a"),
    23434: ("EE", "#00a39a"),
    23450: ("Jersey Telecom", "#cc0000"),
    23455: ("Sure (Guernsey)", "#0066cc"),
    23458: ("Manx Telecom", "#a51d2d"),
    23478: ("Airtel-Vodafone", "#e60000"),
    23502: ("Vodafone", "#e60000"),
    23501: ("Vectone", "#0066b3"),

    # ── Ireland (MCC 272) ─────────────────────────────────────
    27201: ("Vodafone", "#e60000"),
    27202: ("3 Ireland", "#ee2d72"),
    27203: ("eir", "#00a651"),
    27205: ("3 Ireland", "#ee2d72"),
    27207: ("eir", "#00a651"),
    27211: ("Tesco Mobile", "#ed1c24"),

    # ── Netherlands (MCC 204) ─────────────────────────────────
    20401: ("KPN", "#009639"),
    20408: ("KPN", "#009639"),
    20410: ("KPN", "#009639"),
    20404: ("Vodafone", "#e60000"),
    20416: ("T-Mobile", "#e20074"),
    20420: ("T-Mobile", "#e20074"),
    20402: ("Tele2", "#001e62"),
    20406: ("VodafoneZiggo", "#e60000"),
    20407: ("VodafoneZiggo", "#e60000"),
    20412: ("Telfort", "#ff6600"),
    20415: ("Ziggo", "#e60000"),

    # ── Belgium (MCC 206) ─────────────────────────────────────
    20601: ("Proximus", "#6a1b9a"),
    20605: ("Telenet", "#ffc700"),
    20620: ("Telenet (BASE)", "#ffc700"),
    20610: ("Orange", "#ff7900"),
    20640: ("Lyca", "#c8102e"),
    20606: ("Telenet (Lycamobile)", "#c8102e"),

    # ── Luxembourg (MCC 270) ──────────────────────────────────
    27001: ("POST (LUXGSM)", "#ffcc00"),
    27077: ("Tango", "#c71585"),
    27099: ("Orange", "#ff7900"),

    # ── Denmark (MCC 238) ─────────────────────────────────────
    23801: ("TDC", "#0049a0"),
    23810: ("TDC", "#0049a0"),
    23802: ("Telenor", "#00adef"),
    23877: ("Telenor", "#00adef"),
    23820: ("Telia", "#990ae3"),
    23830: ("Telia", "#990ae3"),
    23806: ("3 (Hi3G)", "#dc0070"),
    23803: ("Mundio", "#0066b3"),

    # ── Sweden (MCC 240) ──────────────────────────────────────
    24001: ("Telia", "#990ae3"),
    24007: ("Tele2", "#009ed4"),
    24024: ("Tele2", "#009ed4"),
    24008: ("Telenor", "#00adef"),
    24006: ("Telenor", "#00adef"),
    24002: ("3 (Tre)", "#dc0070"),
    24004: ("3 (Tre)", "#dc0070"),
    24028: ("Lyca", "#c8102e"),

    # ── Norway (MCC 242) ──────────────────────────────────────
    24201: ("Telenor", "#00adef"),
    24202: ("Telia", "#990ae3"),
    24206: ("ice.net", "#005bbb"),
    24214: ("ice.net", "#005bbb"),
    24207: ("Ventelo", "#0066b3"),
    24212: ("Telenor (M2M)", "#00adef"),

    # ── Finland (MCC 244) ─────────────────────────────────────
    24405: ("Elisa", "#00a3e0"),
    24421: ("Elisa", "#00a3e0"),
    24412: ("DNA", "#ff5800"),
    24403: ("DNA", "#ff5800"),
    24491: ("Telia", "#990ae3"),
    24414: ("Alcom", "#0066b3"),

    # ── Iceland (MCC 274) ─────────────────────────────────────
    27401: ("Síminn", "#007ac8"),
    27402: ("Vodafone", "#e60000"),
    27403: ("Nova", "#872177"),
    27411: ("Nova", "#872177"),
    27408: ("On-Waves", "#0066b3"),

    # ── Liechtenstein (MCC 295) ───────────────────────────────
    29501: ("Swisscom FL", "#002f87"),
    29502: ("Salt FL", "#b30000"),
    29505: ("FL1", "#ed1c24"),
    29577: ("Telecom Liechtenstein", "#ed1c24"),

    # ── Czech Republic (MCC 230) ──────────────────────────────
    23001: ("T-Mobile", "#e20074"),
    23002: ("O2", "#0019a5"),
    23003: ("Vodafone", "#e60000"),
    23004: ("Nordic Telecom", "#1fb6ff"),
    23098: ("Sazka Mobil", "#fcd000"),

    # ── Slovakia (MCC 231) ────────────────────────────────────
    23101: ("Orange", "#ff7900"),
    23102: ("Telekom", "#e20074"),
    23106: ("O2", "#0019a5"),
    23103: ("4ka", "#ffe600"),
    23104: ("4ka", "#ffe600"),

    # ── Slovenia (MCC 293) ────────────────────────────────────
    29340: ("Telekom Slovenije", "#e20074"),
    29341: ("Mobitel", "#e20074"),
    29370: ("A1 Slovenija", "#e2001a"),
    29364: ("T-2", "#ff8e00"),
    29310: ("Telemach", "#00a0e2"),

    # ── Hungary (MCC 216) ─────────────────────────────────────
    21630: ("Magyar Telekom", "#e20074"),
    21601: ("Yettel", "#813396"),
    21670: ("Vodafone", "#e60000"),
    21671: ("DIGI", "#0066b3"),

    # ── Poland (MCC 260) ──────────────────────────────────────
    26001: ("Plus", "#00a85a"),
    26002: ("T-Mobile", "#e20074"),
    26003: ("Orange", "#ff7900"),
    26006: ("Play", "#62217f"),
    26007: ("NetWorkS!", "#999999"),
    26016: ("Aero2", "#1fb6ff"),
    26009: ("Lyca", "#c8102e"),

    # ── Romania (MCC 226) ─────────────────────────────────────
    22601: ("Vodafone", "#e60000"),
    22610: ("Orange", "#ff7900"),
    22603: ("Telekom", "#e20074"),
    22606: ("Telekom", "#e20074"),
    22605: ("Digi", "#ee2a26"),

    # ── Bulgaria (MCC 284) ────────────────────────────────────
    28401: ("A1", "#e2001a"),
    28403: ("Vivacom", "#663d8c"),
    28405: ("Yettel", "#813396"),

    # ── Greece (MCC 202) ──────────────────────────────────────
    20201: ("Cosmote", "#00b04f"),
    20205: ("Vodafone", "#e60000"),
    20210: ("Nova", "#dc0028"),
    20209: ("Nova", "#dc0028"),

    # ── Portugal (MCC 268) ────────────────────────────────────
    26801: ("Vodafone", "#e60000"),
    26803: ("NOS", "#ff0000"),
    26806: ("MEO", "#00a0dc"),
    26807: ("MEO", "#00a0dc"),
    26821: ("DIGI", "#ee2a26"),

    # ── Croatia (MCC 219) ─────────────────────────────────────
    21901: ("T-Mobile (HT)", "#e20074"),
    21910: ("A1", "#e2001a"),
    21902: ("Telemach", "#00a0e2"),

    # ── Serbia (MCC 220) ──────────────────────────────────────
    22001: ("Telekom Srbija", "#ff6900"),
    22003: ("mts", "#ff6900"),
    22002: ("Telenor / Yettel", "#813396"),
    22005: ("A1", "#e2001a"),

    # ── Bosnia (MCC 218) ──────────────────────────────────────
    21803: ("HT ERONET", "#e20074"),
    21805: ("m:tel", "#ff6900"),
    21890: ("BH Mobile", "#0066b3"),

    # ── Montenegro (MCC 297) ──────────────────────────────────
    29701: ("Telenor / Yettel", "#813396"),
    29702: ("T-Mobile", "#e20074"),
    29703: ("m:tel", "#ff6900"),

    # ── North Macedonia (MCC 294) ─────────────────────────────
    29401: ("T-Mobile", "#e20074"),
    29402: ("ONE", "#ff7900"),
    29403: ("Vip", "#e2001a"),

    # ── Albania (MCC 276) ─────────────────────────────────────
    27601: ("Vodafone", "#e60000"),
    27602: ("Telekom Albania", "#e20074"),
    27603: ("Eagle / ONE", "#ff7900"),

    # ── Estonia (MCC 248) ─────────────────────────────────────
    24801: ("Telia", "#990ae3"),
    24802: ("Elisa", "#00a3e0"),
    24803: ("Tele2", "#001e62"),
    24804: ("Top Connect", "#0066b3"),
    24806: ("Bravocom", "#0066b3"),

    # ── Latvia (MCC 247) ──────────────────────────────────────
    24701: ("LMT", "#ffce00"),
    24702: ("Tele2", "#001e62"),
    24705: ("Bité", "#fcd400"),

    # ── Lithuania (MCC 246) ───────────────────────────────────
    24601: ("Telia", "#990ae3"),
    24602: ("Bité", "#fcd400"),
    24603: ("Tele2", "#001e62"),

    # ── Malta (MCC 278) ───────────────────────────────────────
    27801: ("Vodafone", "#e60000"),
    27821: ("Epic", "#ffd500"),
    27877: ("GO Mobile", "#ed1c24"),

    # ── Cyprus (MCC 280) ──────────────────────────────────────
    28001: ("Cyta", "#009ca6"),
    28010: ("Epic", "#ffd500"),
    28020: ("PrimeTel", "#0066b3"),
}


# Country (MCC) → fallback brand color for unknown PLMNs inside that country.
# Picks the dominant national operator's color so foreign roaming pings still
# group sensibly on the map even if a specific MNC isn't catalogued yet.
_MCC_COLOR_FALLBACK: dict[int, str] = {
    202: "#00b04f",  # Greece — Cosmote
    204: "#009639",  # Netherlands — KPN
    206: "#6a1b9a",  # Belgium — Proximus
    208: "#ff7900",  # France — Orange
    214: "#019df4",  # Spain — Movistar
    216: "#e20074",  # Hungary — Magyar Telekom
    218: "#e20074",  # Bosnia
    219: "#e20074",  # Croatia — HT
    220: "#ff6900",  # Serbia — Telekom Srbija
    222: "#0033a0",  # Italy — TIM
    226: "#e60000",  # Romania — Vodafone
    228: "#002f87",  # Switzerland — Swisscom
    230: "#e20074",  # Czechia — T-Mobile
    231: "#ff7900",  # Slovakia — Orange
    232: "#e2001a",  # Austria — A1
    234: "#0019a5",  # UK — O2
    235: "#0019a5",  # UK — O2
    238: "#0049a0",  # Denmark — TDC
    240: "#990ae3",  # Sweden — Telia
    242: "#00adef",  # Norway — Telenor
    244: "#00a3e0",  # Finland — Elisa
    246: "#990ae3",  # Lithuania — Telia
    247: "#ffce00",  # Latvia — LMT
    248: "#990ae3",  # Estonia — Telia
    260: "#00a85a",  # Poland — Plus
    262: "#e20074",  # Germany — Telekom
    268: "#e60000",  # Portugal — Vodafone
    270: "#ffcc00",  # Luxembourg — POST
    272: "#e60000",  # Ireland — Vodafone
    274: "#007ac8",  # Iceland — Síminn
    276: "#e60000",  # Albania — Vodafone
    278: "#e60000",  # Malta — Vodafone
    280: "#009ca6",  # Cyprus — Cyta
    284: "#e2001a",  # Bulgaria — A1
    293: "#e20074",  # Slovenia — Telekom
    294: "#e20074",  # N. Macedonia — T-Mobile
    295: "#ed1c24",  # Liechtenstein — FL1
    297: "#813396",  # Montenegro — Yettel
}

# Generic fallback for any PLMN we don't know — neutral grey.
_UNKNOWN_COLOR = "#8b949e"


def plmn_info(plmn) -> tuple[str | None, str]:
    """Return (carrier_name, brand_color) for a PLMN code.

    name is None if `plmn` can't be parsed. For an unknown but parseable
    PLMN, name falls back to "PLMN <code>" and color falls back to the
    country's dominant brand (or neutral grey if even the MCC is unknown).
    """
    try:
        code = int(plmn)
    except (TypeError, ValueError):
        return None, _UNKNOWN_COLOR
    entry = PLMN_INFO.get(code)
    if entry:
        return entry
    mcc = code // 100
    return f"PLMN {code}", _MCC_COLOR_FALLBACK.get(mcc, _UNKNOWN_COLOR)


def plmn_name(plmn) -> str | None:
    """Carrier name for a PLMN code, or None if unparseable."""
    name, _ = plmn_info(plmn)
    return name


def plmn_color(plmn) -> str:
    """Brand color for a PLMN code (always returns a hex string)."""
    _, color = plmn_info(plmn)
    return color
