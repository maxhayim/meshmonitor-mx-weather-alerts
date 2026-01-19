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
   - Script dedupes alerts and only posts when something is NEW, UPDATED, or CLEARED

2) **On-demand commands**
   - `!wx` summary
   - `!wx detail N`
   - `!wx help`

Design goals:

- KISS: location is configured as latitude/longitude
- Lightweight messages that work well over LoRa
- No NOAA audio rebroadcast — this is text-based alerting using official NWS data

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
- Must complete within the MeshMonitor timeout window
- Must be executable

Copy the script into the MeshMonitor container:

    /data/scripts/mm_wx.py

Make it executable:

    chmod +x /data/scripts/mm_wx.py

---

## Configuration (inside mm_wx.py)

Edit these constants near the top of `mm_wx.py`:

Required:
- `WX_LAT`
- `WX_LON`

Optional:
- `WX_SEVERITIES_ALLOW`
- `WX_EVENTS_BLOCK`
- `WX_TIMER_SILENT_NOCHANGE`
- `WX_STATE_PATH`
- `WX_TIMER_SCHEDULE_NOTE` (documentation only)
- `WX_USER_AGENT` (recommended to include contact info)

---

## Automatic Alerts (Timer Triggers / Timed Events) — RECOMMENDED

MeshMonitor can run scripts automatically using **Timer Triggers (Timed Events)**. When the timer fires, MeshMonitor executes the script and sends the script output to the configured channel.

### Step-by-step setup

1. Open MeshMonitor
2. Go to **Info → Automation**
3. Scroll to **Timer Triggers (Timed Events)**
4. Add a timer:
   - **Name:** `WX (Weather Alerts)`
   - **Schedule:** `*/5 * * * *` (every 5 minutes)
   - **Script:** `mm_wx.py`
   - **Channel:** `0` (Primary) or any desired channel
   - **Enabled:** On
5. Click **Add Timer**
6. Click **Save**

---

## How deduplication works (no mesh spam)

- On each timer run, WX fetches active alerts for the configured latitude/longitude
- Each alert is fingerprinted (ID + timestamps)
- State is stored persistently in:

    /data/wx_state.json

- Messages are only sent when alerts are:
  - **NEW** (not previously active)
  - **UPDATED** (timing or content changed)
  - **CLEARED** (previously active but no longer present)

If you want a heartbeat message even when nothing changes, set:

    WX_TIMER_SILENT_NOCHANGE = False

(Default behavior is silent when there are no changes.)

---

## MeshMonitor Auto Responder configuration (optional)

If you want on-demand commands in addition to automatic alerts, create Auto Responder rules.

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

### Rule 3 — WX help

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

## Packaging / Dependencies (PEP 668 safe)

WX uses **Python standard library only**.

There are **no pip or third-party dependencies**, which avoids issues with PEP 668 / externally-managed Python environments inside containers.

If your MeshMonitor container has Python 3, the script will run without installing anything.

---

## DNS / Connectivity Troubleshooting (Docker)

If WX reports DNS failures, connection errors, or cannot reach `api.weather.gov`, the issue is almost always Docker or host DNS configuration.

### Verify DNS inside the container

    docker exec -it meshmonitor sh -lc "getent hosts api.weather.gov; echo '---'; cat /etc/resolv.conf"

If this fails, DNS is broken inside the container.

### Recommended docker-compose DNS override

Add the following to your MeshMonitor service in `docker-compose.yml`:

    services:
      meshmonitor:
        dns:
          - 1.1.1.1
          - 8.8.8.8

Redeploy:

    docker compose up -d

### Host-level Docker daemon DNS (if needed)

Create or edit `/etc/docker/daemon.json`:

    {
      "dns": ["1.1.1.1", "8.8.8.8"]
    }

Restart Docker:

    sudo systemctl restart docker

---

## NWS API notes

- WX queries active alerts by point:
  - `https://api.weather.gov/alerts/active?point=LAT,LON`
- The National Weather Service may rate-limit or block generic clients.
- Keep `WX_USER_AGENT` set to a real identifier with contact information.

---

## Maintenance / Reinstall (Advanced)

These steps are only needed if you are upgrading versions, changing core configuration
(e.g. latitude/longitude), or troubleshooting unexpected behavior.

This is **not required** for normal operation.

---

### Disable WX in MeshMonitor

1. Open **MeshMonitor**
2. Go to **Info → Automation**
3. Under **Timer Triggers (Timed Events)**:
   - Disable the `WX Alerts` timer
4. (Optional) Remove Auto Responder rules for:
   - `^!wx$`
   - `^!wx\s+detail\s+([0-9]+)$`
   - `^!wx\s+help$`
5. Click **Save**

---

### Remove script and state (inside container)

Enter the MeshMonitor container:

    docker exec -it meshmonitor sh

Remove the WX runtime script:

    rm -f /data/scripts/mm_wx.py

Remove the persistent deduplication state:

    rm -f /data/wx_state.json

Exit the container:

    exit

---

### Reinstall WX

1. Copy the updated `mm_wx.py` back into:

       /data/scripts/mm_wx.py

2. Make the script executable:

       chmod +x /data/scripts/mm_wx.py

3. Re-enable the **WX Alerts** Timer Trigger in MeshMonitor
4. Click **Save**

On the next timer run, WX will rebuild its state and resume normal operation.

---

## Inspiration & references

- NOAA / NWS Weather Radio alerting concepts (SAME / UGC-style targeting)
- Inspired by SkywarnPlus (CAP alert redistribution patterns)

WX (Weather Alerts) is **not affiliated with NOAA** and does **not** rebroadcast NOAA audio.  
It provides text-based alerting for Meshtastic meshes using official NWS alert data.

---

## License

MIT License

---

## Acknowledgments

* MeshMonitor built by [Yeraze](https://github.com/Yeraze) 
* Shout out to [SkywarnPlus](https://github.com/Mason10198/SkywarnPlus)

Discover other community-contributed Auto Responder scripts for MeshMonitor [here](https://meshmonitor.org/user-scripts.html).
