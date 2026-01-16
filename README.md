<p align="center">
  <a href="https://www.python.org/">
    <img src="https://img.shields.io/badge/Python-3.8%2B-blue" alt="Python Version">
  </a>
  <a href="https://opensource.org/licenses/MIT">
    <img src="https://img.shields.io/badge/License-MIT-green" alt="License">
  </a>
</p>

# ⛈️ WX (Weather Alerts)

WX (Weather Alerts) is a [**MeshMonitor**](https://github.com/Yeraze/MeshMonitor) Script Auto Responder that provides NOAA/NWS weather alert bulletins for a configured latitude/longitude.

This repository contains:

- `mm_wx.py` — the MeshMonitor script (runtime)
- `docs/` — GitHub Pages documentation (display only)

---

## What this does

WX supports TWO modes:

1) **Automatic alerts (recommended)**
   - Uses MeshMonitor **Timer Triggers (Timed Events)** to run the script on a schedule
   - Script dedupes alerts and only posts when something is NEW/UPDATED/CLEARED

2) **On-demand commands**
   - `!wx` summary
   - `!wx detail N`
   - `!wx help`

Design goals:

- KISS: location is configured as latitude/longitude
- Lightweight messages that work well over LoRa
- No “NOAA audio rebroadcast” — this is text-based alerting using official NWS data

---

## Repository layout

    .
    ├── mm_wx.py              # Runtime script used by MeshMonitor
    ├── docs/                 # GitHub Pages documentation
    │   ├── index.html
    │   └── index.js
    └── README.md

---

## IMPORTANT: Which file do I use?

### Use this file in MeshMonitor

    mm_wx.py

This is the only file MeshMonitor should execute.

### Do NOT run this file

    docs/index.js

`index.js` only displays the script on a web page.

---

## Installing mm_wx.py

MeshMonitor script requirements (high level):
- Script must be in `/data/scripts/`
- Script must output valid JSON to stdout with `response` or `responses`
- Must complete within the timeout window
- Must be executable :contentReference[oaicite:1]{index=1}

Copy the script into the MeshMonitor container:

    /data/scripts/mm_wx.py

Make it executable:

    chmod +x /data/scripts/mm_wx.py

---

## Configuration (inside mm_wx.py)

Edit these constants near the top of `mm_wx.py`:

- `WX_LAT`
- `WX_LON`

Optional:
- `WX_SEVERITIES_ALLOW`
- `WX_EVENTS_BLOCK`
- `WX_TIMER_SCHEDULE_NOTE` (documentation only)
- `WX_STATE_PATH` (where the dedupe file is stored)
- `WX_TIMER_SILENT_NOCHANGE` (recommended ON)

---

## Automatic Alerts (Timer Triggers / Timed Events) — RECOMMENDED

MeshMonitor can run scripts automatically using **Timer Triggers (Timed Events)**. When the timer fires, MeshMonitor executes the script and sends the script output to the configured channel. :contentReference[oaicite:2]{index=2}

### Step-by-step setup

1. Open MeshMonitor
2. Go to **Info → Automation**
3. Scroll to **Timer Triggers (Timed Events)**
4. Add a timer:
   - **Name:** `WX Alerts`
   - **Schedule:** `*/5 * * * *` (every 5 minutes)
   - **Script:** `mm_wx.py`
   - **Channel:** `0` (Primary) or whatever channel you want
   - **Enabled:** On
5. Click **Add Timer**
6. Click **Save**

MeshMonitor’s Timer Triggers execute scripts from `/data/scripts/` and send the output to the selected channel. :contentReference[oaicite:3]{index=3}

### How dedupe works (so you don’t spam the mesh)

- On each timer run, `mm_wx.py` fetches active alerts for your point (LAT/LON)
- It builds a “fingerprint set” of alerts (id + sent/effective/ends/expires)
- It compares to the last run, stored in:

    /data/wx_state.json

- It only posts messages if something changed:
  - NEW alerts
  - UPDATED alerts
  - CLEARED alerts (previously active but now gone)

If you want a “heartbeat” even when nothing changes, set:

- `WX_TIMER_SILENT_NOCHANGE = False`

(Otherwise it outputs an empty response and MeshMonitor should effectively send nothing.)

---

## MeshMonitor Auto Responder configuration (optional)

Create three Auto Responder rules if you want on-demand commands too.

### Rule 1 — WX summary

Trigger regex:

    ^!wx$

Response Type: Script  
Script path:

    /data/scripts/mm_wx.py

### Rule 2 — WX detail

Trigger regex:

    ^!wx\s+detail\s+([0-9]+)$

Response Type: Script  
Script path:

    /data/scripts/mm_wx.py

### Rule 3 — WX help (optional)

Trigger regex:

    ^!wx\s+help$

Response Type: Script  
Script path:

    /data/scripts/mm_wx.py

---

## Example Triggers

    !wx
    !wx detail 1
    !wx help

---

## Inspiration & references

- NOAA/NWS alerting concepts (SAME/UGC-style targeting)
- Inspired by [SkywarnPlus](https://github.com/Yeraze)  (CAP alert redistribution patterns)

WX (Weather Alerts) is not affiliated with NOAA and does not rebroadcast NOAA audio. It provides text-based alerting for Meshtastic meshes using official NWS alert data.

---

## License

MIT License

## Acknowledgments

* MeshMonitor built by [Yeraze](https://github.com/Yeraze) 
* Shout out to [SkywarnPlus](https://github.com/Mason10198/SkywarnPlus)

Discover other community-contributed Auto Responder scripts for MeshMonitor [here](https://meshmonitor.org/user-scripts.html).
