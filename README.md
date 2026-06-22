# wpscan-recon

WordPress enumeration wrapper — version fingerprinting, plugin/theme detection with CVE lookup (requires WPScan API token), user enumeration, XMLRPC + README exposure checks. Structured JSON output. Community WordPress Board.

**[→ WordPress Board](https://fmfalgun.github.io/wpscan-recon/wp-board.html)** — community WordPress scans, browsable without the tool.

## Requirements

- Python 3.8+ (stdlib only — no pip install needed)
- `wpscan` Ruby gem: `gem install wpscan` ← required for full enumeration
- Without wpscan: HTTP fallback mode runs automatically (partial results)

## Usage

```bash
# full WordPress scan
python3 wpscan-recon.py -u https://target.com

# save structured JSON
python3 wpscan-recon.py -u https://target.com -o results.json

# include CVE data (requires WPScan API token)
python3 wpscan-recon.py -u https://target.com --api-token $WPSCAN_API_TOKEN

# bypass 24h cache
python3 wpscan-recon.py -u https://target.com --no-cache

# submit to WordPress Board
python3 wpscan-recon.py -u https://target.com --submit
```

## Output schema

```json
{
  "url": "https://wpscan.com",
  "method": "wpscan",
  "wp_version": "6.5.3",
  "wp_version_status": "latest",
  "plugins": [
    {"slug": "yoast-seo", "version": "22.1", "vuln_count": 0}
  ],
  "users": [{"id": 1, "login": "admin", "display_name": "Admin"}],
  "interesting_findings": [
    {"type": "xmlrpc", "url": "https://target.com/xmlrpc.php", "message": "XML-RPC enabled"}
  ],
  "vuln_count": 0,
  "plugin_count": 3,
  "user_count": 1,
  "xmlrpc_active": true,
  "readme_exposed": true,
  "api_token_used": false
}
```

## Flags

| Flag | Description |
|------|-------------|
| `-u`, `--url` | Target WordPress URL |
| `-o`, `--output` | Write JSON to file |
| `--api-token` | WPScan API token for CVE lookup |
| `--enumerate` | Enumeration options (default: vp,vt,u,ap) |
| `--no-cache` | Bypass 24h SQLite cache |
| `--ttl` | Cache TTL hours (default: 24) |
| `--submit` | Submit result to WordPress Board |
| `--reconfigure` | Update stored credentials |

## XMLRPC risk

`xmlrpc.php` exposes `system.multicall` — allows 500+ password attempts in a single HTTP request, bypassing rate limiting. Standard attack path for credential stuffing. Disable via mu-plugin or `.htaccess`.

## Pairs with

- [dig-recon](https://github.com/fmfalgun/dig-recon) — DNS sweep + SPF/DMARC
- [whois-extracter](https://github.com/fmfalgun/whois-extracter) — registry WHOIS + risk scoring
- [subfinder-recon](https://github.com/fmfalgun/subfinder-recon) — passive subdomain enumeration

---

MIT License · Built by [Falgun Marothia](https://fmfalgun.github.io)
