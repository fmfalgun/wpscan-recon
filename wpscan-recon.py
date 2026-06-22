#!/usr/bin/env python3
"""
wpscan-recon — WordPress enumeration with TTL cache and community submission.

Primary mode : wraps the wpscan Ruby CLI tool, parses JSON output.
Fallback mode : HTTP fingerprinting via urllib (stdlib only) when wpscan is absent.
Cache         : SQLite (cache.db), 24h TTL, keyed by normalised URL.
Submit        : posts full JSON result to GitHub Issues as [submission] entry.
"""

import argparse
import datetime
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.request
import urllib.error
from pathlib import Path

# ── constants ─────────────────────────────────────────────────────────────────

__version__       = "1.0.0"
CACHE_DB          = "./cache.db"
CONFIG_PATH       = Path.home() / ".config" / "wpscan-recon" / "config.json"
GITHUB_ISSUES_URL = "https://api.github.com/repos/fmfalgun/wpscan-recon/issues"
DEFAULT_ENUMERATE = "vp,vt,u,ap"

# ── url helpers ───────────────────────────────────────────────────────────────

def normalize_url(url: str) -> str:
    """Ensure https:// scheme; strip trailing slash."""
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip("/")


def normalize_filename(url: str) -> str:
    """
    Convert URL to a safe filename.
      https://wpscan.com        → wpscan.com.json
      https://shop.example.com  → shop.example.com.json
    """
    # strip scheme
    name = re.sub(r"^https?://", "", url)
    # strip trailing slash
    name = name.rstrip("/")
    # replace remaining slashes with dashes
    name = name.replace("/", "-")
    return name + ".json"

# ── cache ─────────────────────────────────────────────────────────────────────

def get_cache_db():
    import sqlite3 as _sqlite3
    conn = _sqlite3.connect(CACHE_DB)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS wpscan_cache (
            url       TEXT PRIMARY KEY,
            data      TEXT NOT NULL,
            cached_at TEXT NOT NULL
        )
    """)
    conn.commit()
    return conn


def cache_get(url: str, ttl_hours: int = 24):
    """Return parsed dict if cached and within TTL, else None."""
    import sqlite3 as _sqlite3
    try:
        conn = get_cache_db()
        row = conn.execute(
            "SELECT data, cached_at FROM wpscan_cache WHERE url = ?", (url,)
        ).fetchone()
        conn.close()
        if row is None:
            return None
        data_str, cached_at_str = row
        cached_at = datetime.datetime.strptime(cached_at_str, "%Y-%m-%dT%H:%M:%SZ")
        age = (datetime.datetime.utcnow() - cached_at).total_seconds() / 3600
        if age > ttl_hours:
            return None
        return json.loads(data_str)
    except Exception:
        return None


def cache_put(url: str, data: dict):
    """Upsert result into cache."""
    import sqlite3 as _sqlite3
    try:
        conn = get_cache_db()
        now = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        conn.execute(
            """INSERT INTO wpscan_cache (url, data, cached_at) VALUES (?, ?, ?)
               ON CONFLICT(url) DO UPDATE SET data=excluded.data, cached_at=excluded.cached_at""",
            (url, json.dumps(data), now),
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[WARN] cache write failed: {e}", file=sys.stderr)

# ── config / setup / submit ───────────────────────────────────────────────────

def load_config() -> dict:
    """Load config from CONFIG_PATH; return {} if absent/corrupt."""
    try:
        if CONFIG_PATH.exists():
            with open(CONFIG_PATH) as f:
                return json.load(f)
    except Exception:
        pass
    return {}


def save_config(cfg: dict):
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(CONFIG_PATH, "w") as f:
        json.dump(cfg, f, indent=2)
    print(f"[+] config saved → {CONFIG_PATH}")


def setup_wizard() -> dict:
    """Interactive first-run prompt; persists to CONFIG_PATH."""
    print("\n── wpscan-recon setup ──────────────────────────────────")
    print("  (press Enter to skip any field)")
    cfg = load_config()

    def ask(prompt, key, secret=False):
        current = cfg.get(key, "")
        display = ("*" * 8) if (secret and current) else (current or "not set")
        val = input(f"  {prompt} [{display}]: ").strip()
        if val:
            cfg[key] = val

    ask("GitHub PAT (Issues write scope)", "github_pat",    secret=True)
    ask("Display name (shown on submission)", "display_name")
    ask("Display location (optional)",        "display_loc")
    ask("WPScan API token (optional)",        "wpscan_api_token", secret=True)

    save_config(cfg)
    print("────────────────────────────────────────────────────────\n")
    return cfg


def submit_result(result: dict, config: dict):
    """POST result to GitHub Issues as a community submission."""
    pat = config.get("github_pat") or os.environ.get("GITHUB_PAT")
    if not pat:
        print("[ERROR] No GitHub PAT found. Run --reconfigure to add one.", file=sys.stderr)
        return

    domain = result.get("domain", result.get("url", "unknown"))
    consent = input(f"\n  Submit scan of {domain} to the community board? [y/N]: ").strip().lower()
    if consent != "y":
        print("  Submission cancelled.")
        return

    display_name = config.get("display_name", "anonymous")
    display_loc  = config.get("display_loc", "")
    credit_line  = f"{display_name}" + (f" ({display_loc})" if display_loc else "")

    body = (
        f"**Submitted by:** {credit_line}\n\n"
        f"**Scanned at:** {result.get('scanned_at', 'unknown')}\n\n"
        f"**Method:** {result.get('method', 'unknown')}\n\n"
        "```json\n"
        + json.dumps(result, indent=2)
        + "\n```"
    )

    payload = json.dumps({
        "title": f"[submission] {domain}",
        "body":  body,
        "labels": ["submission"],
    }).encode()

    req = urllib.request.Request(
        GITHUB_ISSUES_URL,
        data=payload,
        headers={
            "Authorization": f"token {pat}",
            "Accept":        "application/vnd.github+json",
            "Content-Type":  "application/json",
            "User-Agent":    f"wpscan-recon/{__version__}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            resp_data = json.loads(resp.read())
            print(f"[+] submitted → {resp_data.get('html_url', '(no URL)')}")
    except urllib.error.HTTPError as e:
        body_err = e.read().decode(errors="replace")
        print(f"[ERROR] GitHub API {e.code}: {body_err[:300]}", file=sys.stderr)
    except Exception as e:
        print(f"[ERROR] submission failed: {e}", file=sys.stderr)

# ── wpscan wrapper ────────────────────────────────────────────────────────────

def check_wpscan() -> bool:
    """Return True if wpscan binary is on PATH."""
    return shutil.which("wpscan") is not None


def parse_wpscan_json(raw: dict) -> dict:
    """
    Parse wpscan's native JSON output into a normalised dict.

    wpscan JSON schema:
      raw["version"]              — dict: "number", "status" (latest/outdated/unknown)
      raw["interesting_findings"] — list of dicts: "type", "url", "to_s", "references"
      raw["plugins"]              — dict keyed by slug; each: "version", "vulnerabilities", "location"
      raw["main_theme"]           — dict: "slug", "version", "vulnerabilities"
      raw["users"]                — dict keyed by login: "id", "display_name"
      raw["stop_user_enumeration"] — bool
    """
    wp_ver      = raw.get("version") or {}
    interesting = raw.get("interesting_findings") or []
    plugins_raw = raw.get("plugins") or {}
    theme_raw   = raw.get("main_theme") or {}
    users_raw   = raw.get("users") or {}

    # interesting findings
    findings        = []
    xmlrpc_active   = False
    readme_exposed  = False

    for f in interesting:
        ftype = (f.get("type") or "").lower()
        furl  = f.get("url") or ""
        msg   = f.get("to_s") or ""
        findings.append({"type": ftype, "url": furl, "message": msg})
        if "xmlrpc" in ftype or "xmlrpc" in furl.lower():
            xmlrpc_active = True
        if "readme" in ftype or "readme" in furl.lower():
            readme_exposed = True

    # plugins
    plugins = []
    for slug, pdata in plugins_raw.items():
        vulns = pdata.get("vulnerabilities") or []
        plugins.append({
            "slug":       slug,
            "version":    ((pdata.get("version") or {}).get("number") or ""),
            "vuln_count": len(vulns),
            "location":   pdata.get("location") or "",
        })

    # themes
    themes = []
    if theme_raw:
        t_vulns = theme_raw.get("vulnerabilities") or []
        themes.append({
            "slug":       theme_raw.get("slug") or "",
            "version":    ((theme_raw.get("version") or {}).get("number") or ""),
            "vuln_count": len(t_vulns),
        })

    # users
    users = []
    for login, udata in users_raw.items():
        users.append({
            "id":           udata.get("id"),
            "login":        login,
            "display_name": udata.get("display_name") or "",
        })

    total_vulns = (
        sum(p["vuln_count"] for p in plugins)
        + sum(t["vuln_count"] for t in themes)
    )

    return {
        "wp_version":           (wp_ver.get("number") or ""),
        "wp_version_status":    (wp_ver.get("status")  or "unknown"),
        "interesting_findings": findings,
        "plugins":              plugins,
        "themes":               themes,
        "users":                users,
        "vuln_count":           total_vulns,
        "plugin_count":         len(plugins),
        "user_count":           len(users),
        "xmlrpc_active":        xmlrpc_active,
        "readme_exposed":       readme_exposed,
        "api_token_used":       False,   # caller sets True when token passed
    }


def run_wpscan(url: str, api_token: str = None, enumerate: str = DEFAULT_ENUMERATE) -> dict:
    """Run wpscan subprocess and return parsed result dict."""
    cmd = [
        "wpscan",
        "--url", url,
        "--format", "json",
        "--no-banner",
        "--random-user-agent",
        "--enumerate", enumerate,
        "--disable-tls-checks",
    ]
    if api_token:
        cmd += ["--api-token", api_token]

    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    # wpscan exits non-zero when vulnerabilities are found — parse stdout regardless
    try:
        raw = json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        raise RuntimeError(
            f"wpscan JSON parse failed: {e}\nstdout: {proc.stdout[:500]}"
        )

    result = parse_wpscan_json(raw)
    if api_token:
        result["api_token_used"] = True
    return result

# ── HTTP fallback ─────────────────────────────────────────────────────────────

def _http_get(url: str, timeout: int = 10):
    """Fetch url; return (status_code, body_str) or (None, None) on error."""
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "Mozilla/5.0 (compatible; wpscan-recon)"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        # still useful: 405 on xmlrpc, 403 on login, etc.
        try:
            return e.code, e.read().decode(errors="replace")
        except Exception:
            return e.code, ""
    except Exception:
        return None, None


def http_fallback(url: str) -> dict:
    """
    Stdlib-only WordPress fingerprinting when wpscan is not installed.

    Checks:
      GET /               — meta generator for WP version
      GET /xmlrpc.php     — 200 or 405 → xmlrpc active
      GET /readme.html    — 200 → readme exposed (version disclosure)
      GET /readme.txt     — 200 → readme exposed (alternate path)
      GET /wp-login.php   — 200 → wp-login exposed
      GET /wp-json/wp/v2/users?per_page=3  — user enumeration
    """
    findings       = []
    wp_version     = ""
    xmlrpc_active  = False
    readme_exposed = False
    users          = []

    # 1. GET / — parse meta generator
    status, body = _http_get(url)
    if body:
        m = re.search(
            r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']WordPress\s+([\d.]+)',
            body, re.IGNORECASE
        )
        if m:
            wp_version = m.group(1)
            findings.append({
                "type":    "generator_tag",
                "url":     url,
                "message": f"WordPress {wp_version} detected via meta generator",
            })

    # 2. GET /xmlrpc.php
    xmlrpc_url = url + "/xmlrpc.php"
    status, body = _http_get(xmlrpc_url)
    if status in (200, 405):
        xmlrpc_active = True
        findings.append({
            "type":    "xmlrpc",
            "url":     xmlrpc_url,
            "message": f"XML-RPC enabled (HTTP {status}) — system.multicall brute-force risk",
        })

    # 3. GET /readme.html
    for readme_path in ("/readme.html", "/readme.txt"):
        status, body = _http_get(url + readme_path)
        if status == 200:
            readme_exposed = True
            findings.append({
                "type":    "readme",
                "url":     url + readme_path,
                "message": "readme file exposed — WordPress version disclosure",
            })
            break   # one hit is enough

    # 4. GET /wp-login.php
    status, body = _http_get(url + "/wp-login.php")
    if status == 200:
        findings.append({
            "type":    "wp_login",
            "url":     url + "/wp-login.php",
            "message": "wp-login.php accessible",
        })

    # 5. GET /wp-json/wp/v2/users — user enumeration
    users_url = url + "/wp-json/wp/v2/users?per_page=3"
    status, body = _http_get(users_url)
    if status == 200 and body:
        try:
            raw_users = json.loads(body)
            if isinstance(raw_users, list):
                for u in raw_users:
                    users.append({
                        "id":           u.get("id"),
                        "login":        u.get("slug", ""),
                        "display_name": u.get("name", ""),
                    })
                if users:
                    findings.append({
                        "type":    "user_enumeration",
                        "url":     users_url,
                        "message": f"REST API user enumeration: {len(users)} user(s) exposed",
                    })
        except Exception:
            pass

    return {
        "wp_version":           wp_version,
        "wp_version_status":    "unknown",
        "interesting_findings": findings,
        "plugins":              [],
        "themes":               [],
        "users":                users,
        "vuln_count":           0,
        "plugin_count":         0,
        "user_count":           len(users),
        "xmlrpc_active":        xmlrpc_active,
        "readme_exposed":       readme_exposed,
        "api_token_used":       False,
    }

# ── terminal output ───────────────────────────────────────────────────────────

def print_result(result: dict):
    """Pretty-print scan result to stdout."""
    sep = "─" * 48

    target     = result.get("url", "")
    method     = result.get("method", "unknown")
    wp_ver     = result.get("wp_version", "") or "unknown"
    wp_status  = result.get("wp_version_status", "unknown")
    plugins    = result.get("plugins") or []
    themes     = result.get("themes") or []
    users      = result.get("users") or []
    vuln_count = result.get("vuln_count", 0)
    api_used   = "YES" if result.get("api_token_used") else "NO"
    xmlrpc     = result.get("xmlrpc_active", False)
    readme     = result.get("readme_exposed", False)
    cached     = result.get("cached", False)

    xmlrpc_line = "EXPOSED ← system.multicall brute-force risk" if xmlrpc else "not detected"
    readme_line = "EXPOSED ← version disclosure" if readme else "not detected"

    print(sep)
    print(f"  target      : {target}" + (" [CACHED]" if cached else ""))
    print(f"  method      : {method}")
    print(f"  WP version  : {wp_ver}  ({wp_status})")
    print(f"  plugins     : {len(plugins)}   themes: {len(themes)}   users: {len(users)}")
    print(f"  vulns       : {vuln_count}   (api token: {api_used})")
    print(f"  xmlrpc      : {xmlrpc_line}")
    print(f"  readme      : {readme_line}")

    if users:
        print(sep)
        print("  users:")
        for u in users:
            uid   = u.get("id", "?")
            login = u.get("login", "?")
            dname = u.get("display_name", "")
            line  = f"    {login}  (id: {uid})"
            if dname and dname.lower() != login.lower():
                line += f"  — {dname}"
            print(line)

    if plugins:
        print(sep)
        print("  plugins:")
        for p in plugins:
            slug    = p.get("slug", "?")
            ver     = p.get("version", "") or "?"
            vulns   = p.get("vuln_count", 0)
            vuln_tag = f"[{vulns} vulns]" if vulns else "[0 vulns]"
            print(f"    {slug}  {ver}  {vuln_tag}")

    if themes:
        print(sep)
        print("  themes:")
        for t in themes:
            slug  = t.get("slug", "?")
            ver   = t.get("version", "") or "?"
            vulns = t.get("vuln_count", 0)
            vuln_tag = f"[{vulns} vulns]" if vulns else "[0 vulns]"
            print(f"    {slug}  {ver}  {vuln_tag}")

    findings = result.get("interesting_findings") or []
    if findings:
        print(sep)
        print("  interesting findings:")
        for f in findings:
            ftype = f.get("type", "")
            furl  = f.get("url", "")
            msg   = f.get("message", "")
            label = msg or furl or ftype
            print(f"    [{ftype}] {label}")

    print(sep)

# ── orchestration ─────────────────────────────────────────────────────────────

def run(url: str, api_token: str = None, enumerate: str = DEFAULT_ENUMERATE) -> dict:
    """Run the scan (wpscan or fallback), print result, return dict."""
    url    = normalize_url(url)
    domain = url.split("://", 1)[1].split("/")[0]
    now    = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

    if check_wpscan():
        # Show wpscan version as a startup note
        try:
            vproc = subprocess.run(
                ["wpscan", "--version"], capture_output=True, text=True, timeout=10
            )
            ver_line = vproc.stdout.strip().splitlines()[0] if vproc.stdout.strip() else "?"
            print(f"[*] wpscan found: {ver_line}")
        except Exception:
            print("[*] wpscan found")

        data = run_wpscan(url, api_token, enumerate)
        data["method"] = "wpscan"
    else:
        print("[WARN] wpscan not found — falling back to HTTP fingerprinting", file=sys.stderr)
        print("[WARN] Install: gem install wpscan", file=sys.stderr)
        data = http_fallback(url)
        data["method"] = "http_fallback"

    data["url"]        = url
    data["domain"]     = domain
    data["d"]          = domain   # routing key used by the web UI
    data["scanned_at"] = now
    data["cached"]     = False

    print_result(data)
    return data

# ── CLI entry point ───────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description=f"wpscan-recon {__version__} — WordPress enumeration with TTL cache",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  %(prog)s -u https://blog.startbitsolutions.com
  %(prog)s -u shop.startbitsolutions.com --api-token $WPSCAN_API_TOKEN
  %(prog)s -u https://blog.startbitsolutions.com --enumerate vp,vt,u,ap --output result.json
  %(prog)s -u https://blog.startbitsolutions.com --no-cache --submit
  %(prog)s --reconfigure
        """,
    )
    parser.add_argument("-u", "--url",        metavar="URL",   help="Target WordPress URL")
    parser.add_argument("-o", "--output",     metavar="FILE",  help="Write JSON result to file")
    parser.add_argument("--no-cache",         action="store_true", help="Skip cache lookup; always rescan")
    parser.add_argument("--ttl",              type=int, default=24, metavar="HOURS",
                        help="Cache TTL in hours (default: 24)")
    parser.add_argument("--api-token",        metavar="TOKEN",
                        help="WPScan API token (overrides config / WPSCAN_API_TOKEN env var)")
    parser.add_argument("--enumerate",        default=DEFAULT_ENUMERATE, metavar="OPTS",
                        help=f"wpscan --enumerate value (default: {DEFAULT_ENUMERATE})")
    parser.add_argument("--submit",           action="store_true",
                        help="Post result to community board via GitHub Issues")
    parser.add_argument("--reconfigure",      action="store_true",
                        help="Re-run setup wizard to update stored credentials")
    parser.add_argument("--version",          action="store_true", help="Print version and exit")
    args = parser.parse_args()

    if args.version:
        print(f"wpscan-recon {__version__}")
        sys.exit(0)

    if args.reconfigure:
        setup_wizard()
        sys.exit(0)

    if not args.url:
        parser.error("--url is required (or use --reconfigure / --version)")

    # resolve API token: flag > config > environment
    cfg       = load_config()
    api_token = args.api_token or cfg.get("wpscan_api_token") or os.environ.get("WPSCAN_API_TOKEN")

    url = normalize_url(args.url)

    # cache check
    result = None
    if not args.no_cache:
        result = cache_get(url, args.ttl)
        if result:
            result["cached"] = True
            print_result(result)

    if result is None:
        result = run(url, api_token=api_token, enumerate=args.enumerate)
        result["cached"] = False
        cache_put(url, result)

    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w") as f:
            json.dump(result, f, indent=2)
        print(f"[+] written → {out_path}")

    if args.submit:
        cfg = load_config()
        if not cfg:
            cfg = setup_wizard()
        submit_result(result, cfg)


if __name__ == "__main__":
    main()
