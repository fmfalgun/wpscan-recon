#!/usr/bin/env python3
"""build_demo.py — generate wpscan.com demo data for the wpscan-recon web UI."""

import json
import subprocess
import sys
import datetime
from pathlib import Path

SITE         = "https://wpscan.com"
DOMAIN       = "wpscan.com"
SITE_FILE    = Path("web/data/sites") / f"{DOMAIN}.json"
INDEX_FILE   = Path("web/data/index.json")
DISPLAY_NAME = "fmfalgun"
DISPLAY_LOC  = "Chennai, India"


def run_tool():
    print(f"[*] Running wpscan-recon.py on {SITE}...")
    result = subprocess.run(
        ["python3", "wpscan-recon.py", "-u", SITE, "-o", str(SITE_FILE), "--no-cache"],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        print(f"[WARN] wpscan-recon.py exited {result.returncode}:\n{result.stderr[:300]}")
        # Don't exit — http_fallback may still have produced usable output
    if not SITE_FILE.exists():
        print(f"[ERROR] {SITE_FILE} not created — aborting")
        sys.exit(1)
    print(f"[OK] wrote {SITE_FILE}")


def update_site_file():
    with open(SITE_FILE) as f:
        data = json.load(f)
    now = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    data["display_name"]   = DISPLAY_NAME
    data["display_loc"]    = DISPLAY_LOC
    data["last_refreshed"] = now
    with open(SITE_FILE, "w") as f:
        json.dump(data, f, indent=2)
    return data


def update_index(data):
    now = data.get("last_refreshed", "")
    entry = {
        "d":                 DOMAIN,
        "url":               SITE,
        "display_name":      DISPLAY_NAME,
        "display_loc":       DISPLAY_LOC,
        "scanned_at":        data.get("scanned_at", now),
        "last_refreshed":    now,
        "wp_version":        data.get("wp_version", ""),
        "wp_version_status": data.get("wp_version_status", "unknown"),
        "vuln_count":        data.get("vuln_count", 0),
        "plugin_count":      data.get("plugin_count", 0),
        "user_count":        data.get("user_count", 0),
        "xmlrpc_active":     bool(data.get("xmlrpc_active")),
        "readme_exposed":    bool(data.get("readme_exposed")),
        "method":            data.get("method", "wpscan"),
    }

    try:
        with open(INDEX_FILE) as f:
            index = json.load(f)
    except Exception:
        index = {"total_sites": 0, "sites": []}

    existing = [s for s in index.get("sites", []) if s["d"] != DOMAIN]
    existing.append(entry)
    existing.sort(key=lambda s: -(s.get("vuln_count", 0)))
    index["sites"]       = existing
    index["total_sites"] = len(existing)

    with open(INDEX_FILE, "w") as f:
        json.dump(index, f, indent=2)
    print(f"[OK] updated {INDEX_FILE}")


if __name__ == "__main__":
    SITE_FILE.parent.mkdir(parents=True, exist_ok=True)
    run_tool()
    data = update_site_file()
    update_index(data)
    print("[DONE]")
