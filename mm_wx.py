#!/usr/bin/env python3
"""
WX (Weather Alerts) — MeshMonitor Auto Responder Script

Triggers (recommended):
  ^!wx$
  ^!wx\\s+detail\\s+([0-9]+)$
  ^!wx\\s+help$

Output:
  JSON to stdout with either:
    { "response": "..." }  or  { "responses": ["...", "..."] }

NWS Alerts API:
  https://api.weather.gov/alerts/active?point=LAT,LON

Notes:
- KISS: This is ON-DEMAND only (no background polling).
- NOAA "feel": includes UGC and SAME identifiers when present in alert.geocode.
"""

from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

try:
    import requests
except ImportError:
    print(json.dumps({"response": "WX error: missing dependency 'requests'. Install it in the MeshMonitor container."}))
    raise


# =========================
# KISS CONFIG (EDIT THESE)
# =========================

WX_LAT = 25.7617
WX_LON = -80.1918

# Keep it simple: allow the big ones by default
WX_SEVERITIES_ALLOW = {"Extreme", "Severe", "Moderate"}  # set() to allow all

# Optional noise suppression (example)
WX_EVENTS_BLOCK = {"Special Weather Statement"}  # set() to block nothing

# NWS prefers a real UA with contact info
WX_USER_AGENT = "WX-MeshMonitor-Script (contact: you@example.com)"

# LoRa-friendly splitting (roughly)
MAX_LINE_LEN = 180


# =========================
# Data model
# =========================

@dataclass
class Alert:
    event: str
    severity: str
    urgency: str
    certainty: str
    headline: str
    area_desc: str
    description: str
    instruction: str
    sent: str
    effective: str
    ends: str
    expires: str
    ugc: List[str]
    same: List[str]

    @staticmethod
    def from_feature(f: Dict[str, Any]) -> "Alert":
        p = (f.get("properties") or {})
        geo = (p.get("geocode") or {})

        ugc = geo.get("UGC") or []
        same = geo.get("SAME") or []

        return Alert(
            event=p.get("event") or "Unknown",
            severity=p.get("severity") or "Unknown",
            urgency=p.get("urgency") or "Unknown",
            certainty=p.get("certainty") or "Unknown",
            headline=p.get("headline") or "",
            area_desc=p.get("areaDesc") or "",
            description=p.get("description") or "",
            instruction=p.get("instruction") or "",
            sent=p.get("sent") or "",
            effective=p.get("effective") or "",
            ends=p.get("ends") or "",
            expires=p.get("expires") or "",
            ugc=[str(x) for x in ugc if x],
            same=[str(x) for x in same if x],
        )

    def ends_best(self) -> str:
        # Practical: ends if present; else expires; else sent
        return self.ends or self.expires or self.sent or ""

    def summary_line(self) -> str:
        end = self.ends_best()
        end_short = end.replace("T", " ").replace("Z", "Z")
        return f"{self.event} [{self.severity}] (ends {end_short})"


# =========================
# MeshMonitor IO helpers
# =========================

def _read_stdin_json() -> Optional[Dict[str, Any]]:
    try:
        raw = sys.stdin.read()
        if not raw.strip():
            return None
        return json.loads(raw)
    except Exception:
        return None

def _emit_response(text: str) -> None:
    print(json.dumps({"response": text}, ensure_ascii=False))

def _emit_responses(lines: List[str]) -> None:
    # MeshMonitor supports multi-response arrays
    print(json.dumps({"responses": lines}, ensure_ascii=False))

def _chunk_text(text: str, max_len: int = MAX_LINE_LEN) -> List[str]:
    lines: List[str] = []
    cur = ""
    for part in text.splitlines():
        part = part.rstrip()
        if not part:
            if cur and len(cur) + 1 > max_len:
                lines.append(cur.rstrip())
                cur = ""
            cur += "\n"
            continue

        if len(cur) + len(part) + 1 > max_len:
            if cur.strip():
                lines.append(cur.rstrip())
                cur = ""
            # If a single line is still too long, hard-split it.
            while len(part) > max_len:
                lines.append(part[:max_len])
                part = part[max_len:]
        cur += part + "\n"

    if cur.strip():
        lines.append(cur.rstrip())

    # Prevent empty responses
    return [x for x in lines if x.strip()]


# =========================
# NWS fetch + formatting
# =========================

def fetch_alerts(lat: float, lon: float) -> List[Alert]:
    url = f"https://api.weather.gov/alerts/active?point={lat},{lon}"
    headers = {
        "User-Agent": WX_USER_AGENT,
        "Accept": "application/ld+json",
    }
    r = requests.get(url, headers=headers, timeout=12)
    r.raise_for_status()
    j = r.json()
    feats = j.get("features") or []
    alerts = [Alert.from_feature(f) for f in feats]

    # Filters (KISS)
    out: List[Alert] = []
    for a in alerts:
        if WX_SEVERITIES_ALLOW and a.severity not in WX_SEVERITIES_ALLOW:
            continue
        if WX_EVENTS_BLOCK and a.event in WX_EVENTS_BLOCK:
            continue
        out.append(a)

    return out

def format_summary(alerts: List[Alert]) -> str:
    if not alerts:
        return "WX SUMMARY\nNo active alerts for this area."

    lines = ["WX SUMMARY"]
    for i, a in enumerate(alerts, start=1):
        lines.append(f"{i}) {a.summary_line()}")
    lines.append("")
    lines.append("Use: !wx detail <N>")
    return "\n".join(lines).strip()

def format_detail(alerts: List[Alert], n: int) -> str:
    if not alerts:
        return "WX\nNo active alerts for this area."

    if n < 1 or n > len(alerts):
        return f"WX\nOut of range. Choose 1..{len(alerts)}"

    a = alerts[n - 1]

    # NOAA-inspired “bulletin” layout, with UGC/SAME when present
    parts: List[str] = []
    parts.append(f"WX ALERT ({a.severity})")
    parts.append(a.event)

    if a.ugc:
        parts.append(f"UGC: {'-'.join(a.ugc)}")
    if a.same:
        parts.append(f"SAME: {','.join(a.same)}")

    ends = a.ends_best()
    if ends:
        parts.append(f"Ends: {ends}")

    if a.area_desc:
        parts.append("")
        parts.append(a.area_desc)

    # Use instruction first (actionable), then headline/description
    if a.instruction:
        parts.append(a.instruction.strip())
    elif a.headline:
        parts.append(a.headline.strip())
    elif a.description:
        parts.append(a.description.strip())

    return "\n".join(parts).strip()

def format_help() -> str:
    return "\n".join([
        "WX HELP",
        "!wx              -> summary of active alerts",
        "!wx detail <N>   -> detailed bulletin for alert N",
        "!wx help         -> this help",
    ]).strip()


# =========================
# Command parsing
# =========================

def parse_command(message: str) -> Tuple[str, Optional[int]]:
    msg = message.strip()

    if re.fullmatch(r"!wx", msg, flags=re.IGNORECASE):
        return ("summary", None)

    m = re.fullmatch(r"!wx\s+detail\s+([0-9]+)", msg, flags=re.IGNORECASE)
    if m:
        return ("detail", int(m.group(1)))

    if re.fullmatch(r"!wx\s+help", msg, flags=re.IGNORECASE):
        return ("help", None)

    return ("unknown", None)

def get_inbound_message() -> str:
    """
    Best-effort extraction:
    - If MeshMonitor provides stdin JSON, read it and look for message/text fields.
    - Otherwise, fallback to common env vars.
    """
    payload = _read_stdin_json()
    if payload:
        for key in ("message", "text", "input", "trigger", "content"):
            val = payload.get(key)
            if isinstance(val, str) and val.strip():
                return val.strip()

        # Nested patterns (best effort)
        pkt = payload.get("packet") if isinstance(payload.get("packet"), dict) else {}
        if isinstance(pkt, dict):
            decoded = pkt.get("decoded") if isinstance(pkt.get("decoded"), dict) else {}
            if isinstance(decoded, dict):
                t = decoded.get("text")
                if isinstance(t, str) and t.strip():
                    return t.strip()

    # Fallback envs (names vary by deployments)
    for k in ("MM_MESSAGE", "MESHMESSAGE", "AUTORESPONDER_MESSAGE", "MESSAGE", "TEXT"):
        v = os.environ.get(k)
        if v and v.strip():
            return v.strip()

    return ""


def main() -> int:
    msg = get_inbound_message()
    if not msg:
        _emit_response("WX error: no inbound message context provided.")
        return 0

    cmd, n = parse_command(msg)
    if cmd == "help":
        _emit_response(format_help())
        return 0

    if cmd == "unknown":
        _emit_response("WX: Unknown command. Try: !wx help")
        return 0

    try:
        alerts = fetch_alerts(WX_LAT, WX_LON)
    except Exception as e:
        _emit_response(f"WX error: failed to fetch alerts ({e})")
        return 0

    if cmd == "summary":
        _emit_response(format_summary(alerts))
        return 0

    if cmd == "detail" and n is not None:
        detail = format_detail(alerts, n)
        chunks = _chunk_text(detail, MAX_LINE_LEN)
        if len(chunks) == 1:
            _emit_response(chunks[0])
        else:
            _emit_responses(chunks)
        return 0

    _emit_response("WX: Unknown state. Try: !wx help")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
