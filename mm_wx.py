#!/usr/bin/env python3
"""
WX (Weather Alerts) — MeshMonitor Script

Modes:
A) Timer Trigger / Timed Event (automatic alerts)
   - If MESSAGE env var is not set, assume TIMER mode.
   - Fetch NWS alerts for WX_LAT/WX_LON
   - Dedupes using WX_STATE_PATH
   - Emits NEW / UPDATED / CLEARED bulletins only when something changes

B) Auto Responder (on-demand)
   - !wx
   - !wx detail N
   - !wx help

Deployment note:
- Uses Python standard library only (no pip deps). Works in locked-down containers (PEP 668 safe).

v1.0.2 changes:
- Retry/backoff on transient network/DNS errors (e.g., EAI_AGAIN / "Try again")
- Optional silent failure in TIMER mode on fetch error to avoid spamming the mesh
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError


# =========================
# VERSION
# =========================

WX_VERSION = "v1.0.2"


# =========================
# KISS CONFIG (EDIT THESE)
# =========================

WX_LAT = 25.7617
WX_LON = -80.1918

# Allow severities. Set to empty set() to allow all.
WX_SEVERITIES_ALLOW = {"Extreme", "Severe", "Moderate"}

# Optional noise suppression. Set to empty set() to block nothing.
WX_EVENTS_BLOCK = {"Special Weather Statement"}

# NWS prefers a real UA with contact info
WX_USER_AGENT = "WX-MeshMonitor-Script (contact: you@example.com)"

# Timer behavior
WX_STATE_PATH = "/data/wx_state.json"
WX_TIMER_SILENT_NOCHANGE = True  # recommended

# If True: timer runs will NOT emit error messages on fetch failure (prevents mesh noise on transient outages)
TIMER_SILENT_ON_FETCH_ERROR = True

# LoRa-friendly chunking
MAX_LINE_LEN = 180

# Documentation only (does not control scheduling)
WX_TIMER_SCHEDULE_NOTE = "*/5 * * * *"

# Network timeout seconds
HTTP_TIMEOUT = 12

# Retry/backoff for transient failures (DNS "Try again", timeouts, intermittent connectivity)
HTTP_RETRIES = 3
HTTP_RETRY_SLEEP_SECONDS = 2


# =========================
# Data model
# =========================

@dataclass
class Alert:
    nid: str  # NWS feature id (URL string)

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
        nid = str(f.get("id") or "")
        p = (f.get("properties") or {})
        geo = (p.get("geocode") or {})

        ugc = geo.get("UGC") or []
        same = geo.get("SAME") or []

        return Alert(
            nid=nid,
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
        return self.ends or self.expires or self.sent or ""

    def fingerprint(self) -> str:
        """
        Stable-ish fingerprint for dedupe:
        - feature id + timestamps that commonly change on updates
        """
        base = "|".join([self.nid, self.sent, self.effective, self.ends, self.expires])
        return hashlib.sha256(base.encode("utf-8")).hexdigest()[:24]

    def summary_line(self) -> str:
        end = self.ends_best().replace("T", " ").replace("Z", "Z")
        return f"{self.event} [{self.severity}] (ends {end})"


# =========================
# MeshMonitor output helpers
# =========================

def emit_response(text: str) -> None:
    print(json.dumps({"response": text}, ensure_ascii=False))

def emit_responses(lines: List[str]) -> None:
    print(json.dumps({"responses": lines}, ensure_ascii=False))

def chunk_text(text: str, max_len: int = MAX_LINE_LEN) -> List[str]:
    out: List[str] = []
    cur = ""

    def flush() -> None:
        nonlocal cur
        if cur.strip():
            out.append(cur.rstrip())
        cur = ""

    for line in text.splitlines():
        line = line.rstrip()
        if not line:
            if len(cur) + 1 > max_len:
                flush()
            cur += "\n"
            continue

        if len(cur) + len(line) + 1 > max_len:
            flush()

        while len(line) > max_len:
            out.append(line[:max_len])
            line = line[max_len:]

        cur += line + "\n"

    flush()
    return [x for x in out if x.strip()]


# =========================
# NWS fetch + filters (stdlib only)
# =========================

def http_get_json(url: str) -> Dict[str, Any]:
    last_err: Optional[Exception] = None

    for attempt in range(1, HTTP_RETRIES + 1):
        req = Request(
            url,
            headers={
                "User-Agent": WX_USER_AGENT,
                "Accept": "application/geo+json",
            },
            method="GET",
        )

        try:
            with urlopen(req, timeout=HTTP_TIMEOUT) as resp:
                data = resp.read().decode("utf-8", errors="replace")
                return json.loads(data)

        except HTTPError as e:
            # HTTP errors are typically not transient; surface immediately.
            raise RuntimeError(f"HTTP {e.code} {e.reason}") from e

        except URLError as e:
            last_err = e
            # Common transient: EAI_AGAIN -> "[Errno -3] Try again"
            if attempt < HTTP_RETRIES:
                time.sleep(HTTP_RETRY_SLEEP_SECONDS)
                continue
            raise RuntimeError(f"URL error: {e.reason}") from e

        except Exception as e:
            last_err = e
            if attempt < HTTP_RETRIES:
                time.sleep(HTTP_RETRY_SLEEP_SECONDS)
                continue
            raise RuntimeError(str(e)) from e

    raise RuntimeError(str(last_err) if last_err else "Unknown error")


def fetch_alerts(lat: float, lon: float) -> List[Alert]:
    url = f"https://api.weather.gov/alerts/active?point={lat},{lon}"
    j = http_get_json(url)

    feats = j.get("features") or []
    alerts = [Alert.from_feature(f) for f in feats]

    out: List[Alert] = []
    for a in alerts:
        if WX_SEVERITIES_ALLOW and a.severity not in WX_SEVERITIES_ALLOW:
            continue
        if WX_EVENTS_BLOCK and a.event in WX_EVENTS_BLOCK:
            continue
        out.append(a)

    out.sort(key=lambda x: (x.severity, x.event, x.ends_best(), x.nid))
    return out


# =========================
# State (dedupe) for TIMER mode
# =========================

def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")

def load_state(path: str) -> Dict[str, Any]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f) or {}
    except Exception:
        return {}

def save_state(path: str, state: Dict[str, Any]) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


# =========================
# Formatting
# =========================

def format_help() -> str:
    return "\n".join([
        f"WX HELP ({WX_VERSION})",
        "!wx              -> summary of active alerts",
        "!wx detail <N>   -> detailed bulletin for alert N",
        "!wx help         -> this help",
        "",
        f"Timer schedule note: {WX_TIMER_SCHEDULE_NOTE}",
    ]).strip()

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
    parts: List[str] = []

    parts.append(f"WX ALERT ({a.severity})")
    parts.append(a.event)

    if a.ugc:
        parts.append(f"UGC: {'-'.join(a.ugc)}")
    if a.same:
        parts.append(f"SAME: {','.join(a.same)}")

    end = a.ends_best()
    if end:
        parts.append(f"Ends: {end}")

    if a.area_desc:
        parts.append("")
        parts.append(a.area_desc)

    if a.instruction:
        parts.append(a.instruction.strip())
    elif a.headline:
        parts.append(a.headline.strip())
    elif a.description:
        parts.append(a.description.strip())

    return "\n".join(parts).strip()

def format_timer_bulletin(title: str, alerts: List[Alert]) -> str:
    lines: List[str] = [title]
    for a in alerts:
        lines.append(f"- {a.summary_line()}")
    return "\n".join(lines).strip()


# =========================
# Commands (Auto Responder mode)
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


# =========================
# TIMER mode
# =========================

def run_timer_mode(alerts: List[Alert]) -> None:
    state = load_state(WX_STATE_PATH)

    prev_by_id: Dict[str, str] = dict(state.get("active_by_id") or {})
    prev_ids = set(prev_by_id.keys())

    cur_by_id: Dict[str, str] = {a.nid: a.fingerprint() for a in alerts}
    cur_ids = set(cur_by_id.keys())

    new_ids = sorted(cur_ids - prev_ids)
    cleared_ids = sorted(prev_ids - cur_ids)

    updated_ids: List[str] = []
    for nid in sorted(cur_ids & prev_ids):
        if prev_by_id.get(nid) != cur_by_id.get(nid):
            updated_ids.append(nid)

    responses: List[str] = []

    if new_ids:
        new_alerts = [a for a in alerts if a.nid in set(new_ids)]
        responses.append(format_timer_bulletin("WX NEW ALERT(S)", new_alerts))

    if updated_ids:
        upd_alerts = [a for a in alerts if a.nid in set(updated_ids)]
        responses.append(format_timer_bulletin("WX UPDATED ALERT(S)", upd_alerts))

    if cleared_ids:
        cleared_lines = ["WX CLEARED ALERT(S)"]
        prev_meta: Dict[str, Any] = dict(state.get("meta_by_id") or {})
        for nid in cleared_ids:
            meta = prev_meta.get(nid) or {}
            ev = meta.get("event") or "Alert"
            sev = meta.get("severity") or ""
            cleared_lines.append(f"- {ev}{' [' + sev + ']' if sev else ''}")
        responses.append("\n".join(cleared_lines).strip())

    meta_by_id: Dict[str, Any] = {}
    for a in alerts:
        meta_by_id[a.nid] = {"event": a.event, "severity": a.severity}

    save_state(WX_STATE_PATH, {
        "last_run_utc": utc_now_iso(),
        "active_by_id": cur_by_id,
        "meta_by_id": meta_by_id,
    })

    if not responses:
        if WX_TIMER_SILENT_NOCHANGE:
            emit_response("")
            return
        emit_response("WX: no changes.")
        return

    final_msgs: List[str] = []
    for b in responses:
        final_msgs.extend(chunk_text(b, MAX_LINE_LEN))

    if len(final_msgs) == 1:
        emit_response(final_msgs[0])
    else:
        emit_responses(final_msgs)


# =========================
# Main
# =========================

def main() -> int:
    msg = (os.environ.get("MESSAGE") or "").strip()
    is_timer = not bool(msg)

    try:
        alerts = fetch_alerts(WX_LAT, WX_LON)
    except Exception as e:
        # Timer mode: optionally stay silent to avoid spamming the mesh on transient outages
        if is_timer and TIMER_SILENT_ON_FETCH_ERROR:
            emit_response("")
            return 0
        # On-demand: show error to requesting user
        emit_response(f"WX error: failed to fetch alerts ({e})")
        return 0

    # TIMER mode: no inbound message context
    if is_timer:
        run_timer_mode(alerts)
        return 0

    cmd, n = parse_command(msg)

    if cmd == "help":
        emit_response(format_help())
        return 0

    if cmd == "unknown":
        emit_response("WX: Unknown command. Try: !wx help")
        return 0

    if cmd == "summary":
        emit_response(format_summary(alerts))
        return 0

    if cmd == "detail" and n is not None:
        detail = format_detail(alerts, n)
        chunks = chunk_text(detail, MAX_LINE_LEN)
        if len(chunks) == 1:
            emit_response(chunks[0])
        else:
            emit_responses(chunks)
        return 0

    emit_response("WX: Unknown state. Try: !wx help")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

WX_LAT = 25.7617
WX_LON = -80.1918

# Allow severities. Set to empty set() to allow all.
WX_SEVERITIES_ALLOW = {"Extreme", "Severe", "Moderate"}

# Optional noise suppression. Set to empty set() to block nothing.
WX_EVENTS_BLOCK = {"Special Weather Statement"}

# NWS prefers a real UA with contact info
WX_USER_AGENT = "WX-MeshMonitor-Script (contact: you@example.com)"

# Timer behavior
WX_STATE_PATH = "/data/wx_state.json"
WX_TIMER_SILENT_NOCHANGE = True  # recommended

# LoRa-friendly chunking
MAX_LINE_LEN = 180

# Documentation only (does not control scheduling)
WX_TIMER_SCHEDULE_NOTE = "*/5 * * * *"

# Network timeout seconds
HTTP_TIMEOUT = 12


# =========================
# Data model
# =========================

@dataclass
class Alert:
    nid: str  # NWS feature id (URL string)

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
        nid = str(f.get("id") or "")
        p = (f.get("properties") or {})
        geo = (p.get("geocode") or {})

        ugc = geo.get("UGC") or []
        same = geo.get("SAME") or []

        return Alert(
            nid=nid,
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
        return self.ends or self.expires or self.sent or ""

    def fingerprint(self) -> str:
        """
        Stable-ish fingerprint for dedupe:
        - feature id + timestamps that commonly change on updates
        """
        base = "|".join([self.nid, self.sent, self.effective, self.ends, self.expires])
        return hashlib.sha256(base.encode("utf-8")).hexdigest()[:24]

    def summary_line(self) -> str:
        end = self.ends_best().replace("T", " ").replace("Z", "Z")
        return f"{self.event} [{self.severity}] (ends {end})"


# =========================
# MeshMonitor output helpers
# =========================

def emit_response(text: str) -> None:
    print(json.dumps({"response": text}, ensure_ascii=False))

def emit_responses(lines: List[str]) -> None:
    print(json.dumps({"responses": lines}, ensure_ascii=False))

def chunk_text(text: str, max_len: int = MAX_LINE_LEN) -> List[str]:
    out: List[str] = []
    cur = ""

    def flush() -> None:
        nonlocal cur
        if cur.strip():
            out.append(cur.rstrip())
        cur = ""

    for line in text.splitlines():
        line = line.rstrip()
        if not line:
            if len(cur) + 1 > max_len:
                flush()
            cur += "\n"
            continue

        if len(cur) + len(line) + 1 > max_len:
            flush()

        while len(line) > max_len:
            out.append(line[:max_len])
            line = line[max_len:]

        cur += line + "\n"

    flush()
    return [x for x in out if x.strip()]


# =========================
# NWS fetch + filters (stdlib only)
# =========================

def http_get_json(url: str) -> Dict[str, Any]:
    req = Request(
        url,
        headers={
            "User-Agent": WX_USER_AGENT,
            "Accept": "application/geo+json",
        },
        method="GET",
    )
    try:
        with urlopen(req, timeout=HTTP_TIMEOUT) as resp:
            data = resp.read().decode("utf-8", errors="replace")
            return json.loads(data)
    except HTTPError as e:
        raise RuntimeError(f"HTTP {e.code} {e.reason}") from e
    except URLError as e:
        raise RuntimeError(f"URL error: {e.reason}") from e
    except Exception as e:
        raise RuntimeError(str(e)) from e

def fetch_alerts(lat: float, lon: float) -> List[Alert]:
    url = f"https://api.weather.gov/alerts/active?point={lat},{lon}"
    j = http_get_json(url)

    feats = j.get("features") or []
    alerts = [Alert.from_feature(f) for f in feats]

    out: List[Alert] = []
    for a in alerts:
        if WX_SEVERITIES_ALLOW and a.severity not in WX_SEVERITIES_ALLOW:
            continue
        if WX_EVENTS_BLOCK and a.event in WX_EVENTS_BLOCK:
            continue
        out.append(a)

    out.sort(key=lambda x: (x.severity, x.event, x.ends_best(), x.nid))
    return out


# =========================
# State (dedupe) for TIMER mode
# =========================

def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")

def load_state(path: str) -> Dict[str, Any]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f) or {}
    except Exception:
        return {}

def save_state(path: str, state: Dict[str, Any]) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


# =========================
# Formatting
# =========================

def format_help() -> str:
    return "\n".join([
        "WX HELP",
        "!wx              -> summary of active alerts",
        "!wx detail <N>   -> detailed bulletin for alert N",
        "!wx help         -> this help",
        "",
        f"Timer schedule note: {WX_TIMER_SCHEDULE_NOTE}",
    ]).strip()

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
    parts: List[str] = []

    parts.append(f"WX ALERT ({a.severity})")
    parts.append(a.event)

    if a.ugc:
        parts.append(f"UGC: {'-'.join(a.ugc)}")
    if a.same:
        parts.append(f"SAME: {','.join(a.same)}")

    end = a.ends_best()
    if end:
        parts.append(f"Ends: {end}")

    if a.area_desc:
        parts.append("")
        parts.append(a.area_desc)

    if a.instruction:
        parts.append(a.instruction.strip())
    elif a.headline:
        parts.append(a.headline.strip())
    elif a.description:
        parts.append(a.description.strip())

    return "\n".join(parts).strip()

def format_timer_bulletin(title: str, alerts: List[Alert]) -> str:
    lines: List[str] = [title]
    for a in alerts:
        lines.append(f"- {a.summary_line()}")
    return "\n".join(lines).strip()


# =========================
# Commands (Auto Responder mode)
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


# =========================
# TIMER mode
# =========================

def run_timer_mode(alerts: List[Alert]) -> None:
    state = load_state(WX_STATE_PATH)

    prev_by_id: Dict[str, str] = dict(state.get("active_by_id") or {})
    prev_ids = set(prev_by_id.keys())

    cur_by_id: Dict[str, str] = {a.nid: a.fingerprint() for a in alerts}
    cur_ids = set(cur_by_id.keys())

    new_ids = sorted(cur_ids - prev_ids)
    cleared_ids = sorted(prev_ids - cur_ids)

    updated_ids: List[str] = []
    for nid in sorted(cur_ids & prev_ids):
        if prev_by_id.get(nid) != cur_by_id.get(nid):
            updated_ids.append(nid)

    responses: List[str] = []

    if new_ids:
        new_alerts = [a for a in alerts if a.nid in set(new_ids)]
        responses.append(format_timer_bulletin("WX NEW ALERT(S)", new_alerts))

    if updated_ids:
        upd_alerts = [a for a in alerts if a.nid in set(updated_ids)]
        responses.append(format_timer_bulletin("WX UPDATED ALERT(S)", upd_alerts))

    if cleared_ids:
        cleared_lines = ["WX CLEARED ALERT(S)"]
        prev_meta: Dict[str, Any] = dict(state.get("meta_by_id") or {})
        for nid in cleared_ids:
            meta = prev_meta.get(nid) or {}
            ev = meta.get("event") or "Alert"
            sev = meta.get("severity") or ""
            cleared_lines.append(f"- {ev}{' [' + sev + ']' if sev else ''}")
        responses.append("\n".join(cleared_lines).strip())

    meta_by_id: Dict[str, Any] = {}
    for a in alerts:
        meta_by_id[a.nid] = {"event": a.event, "severity": a.severity}

    save_state(WX_STATE_PATH, {
        "last_run_utc": utc_now_iso(),
        "active_by_id": cur_by_id,
        "meta_by_id": meta_by_id,
    })

    if not responses:
        if WX_TIMER_SILENT_NOCHANGE:
            emit_response("")
            return
        emit_response("WX: no changes.")
        return

    final_msgs: List[str] = []
    for b in responses:
        final_msgs.extend(chunk_text(b, MAX_LINE_LEN))

    if len(final_msgs) == 1:
        emit_response(final_msgs[0])
    else:
        emit_responses(final_msgs)


# =========================
# Main
# =========================

def main() -> int:
    msg = (os.environ.get("MESSAGE") or "").strip()

    try:
        alerts = fetch_alerts(WX_LAT, WX_LON)
    except Exception as e:
        emit_response(f"WX error: failed to fetch alerts ({e})")
        return 0

    # TIMER mode: no inbound message context
    if not msg:
        run_timer_mode(alerts)
        return 0

    cmd, n = parse_command(msg)

    if cmd == "help":
        emit_response(format_help())
        return 0

    if cmd == "unknown":
        emit_response("WX: Unknown command. Try: !wx help")
        return 0

    if cmd == "summary":
        emit_response(format_summary(alerts))
        return 0

    if cmd == "detail" and n is not None:
        detail = format_detail(alerts, n)
        chunks = chunk_text(detail, MAX_LINE_LEN)
        if len(chunks) == 1:
            emit_response(chunks[0])
        else:
            emit_responses(chunks)
        return 0

    emit_response("WX: Unknown state. Try: !wx help")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
