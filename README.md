<p align="center">
  <a href="https://www.python.org/">
    <img src="https://img.shields.io/badge/Python-3.8%2B-blue" alt="Python Version">
  </a>
  <a href="https://opensource.org/licenses/MIT">
    <img src="https://img.shields.io/badge/License-MIT-green" alt="License">
  </a>
</p>

# ⛈️ WX (Weather Alerts)

WX (Weather Alerts) is a MeshMonitor Script Auto Responder that provides NOAA/NWS weather alert bulletins for a configured latitude/longitude.

This repository contains:

- `mm_wx.py` — the actual MeshMonitor Auto Responder script (runtime)
- `docs/` — GitHub Pages documentation (display only)

---

## What this does

This MeshMonitor Auto Responder script allows users to:

- Request a summary of active NWS alerts for a configured latitude/longitude
- Request details for a specific alert item
- Receive “NOAA-inspired” bulletins that include SAME-style targeting identifiers when available (UGC, SAME)

Design goals:

- KISS: location is configured as latitude/longitude
- On-demand only (no beaconing / no background polling)
- Short messages that work well over LoRa

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

The script must exist inside the MeshMonitor environment at:

    /data/scripts/mm_wx.py

Make it executable:

    chmod +x mm_wx.py

---

## MeshMonitor Auto Responder configuration

Create three Auto Responder rules.

### Rule 1 — WX summary

Trigger regex:

    ^!wx$

Action: Script  
Script path:

    /data/scripts/mm_wx.py

### Rule 2 — WX detail

Trigger regex:

    ^!wx\s+detail\s+([0-9]+)$

Action: Script  
Script path:

    /data/scripts/mm_wx.py

### Rule 3 — WX help (optional)

Trigger regex:

    ^!wx\s+help$

Action: Script  
Script path:

    /data/scripts/mm_wx.py

---

## Example Triggers

    !wx
    !wx detail 1
    !wx help

---

## Configuration (inside mm_wx.py)

Edit these constants near the top of `mm_wx.py`:

- `WX_LAT`
- `WX_LON`
- `WX_SEVERITIES_ALLOW` (optional)
- `WX_EVENTS_BLOCK` (optional)

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
