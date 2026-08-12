# WebGuard Scanner

Local **DAST** (Dynamic Application Security Testing) tool with CLI and Flask dashboard.
Designed for **authorized** security testing in labs and owned environments.

> WebGuard is an automated scanner, not a full human pentest. It finds common
> web issues (headers, cookies, reflected XSS, error-based SQLi, open redirects,
> CORS, sensitive paths, CSRF heuristics). It does **not** replace manual testing,
> business-logic review, authenticated deep exploitation, or social engineering.

## Features

- Unified `ScanEngine` shared by CLI and dashboard
- Async scans in the dashboard (job queue + progress polling)
- Check plugins with severity + confidence
- Crawler with depth/page limits, rate limiting, same-origin allowlist
- Exports: JSON, CSV, SARIF
- Optional local auth via `WEBGUARD_TOKEN`

## Requirements

- Python 3.10+

## Install

```bash
pip install -r requirements.txt
```

## Authenticated scanning

Use only on systems you are authorized to test.

```bash
python main.py scan -u http://127.0.0.1:8765/ \
  --login-url http://127.0.0.1:8765/auth/login \
  --username admin --password admin123 \
  --success-marker LOGIN_OK \
  --seed-path /private
```

Or reuse a browser session cookie:

```bash
python main.py scan -u http://127.0.0.1:8765/ --cookie "session=..."
```

Env alternatives: `WEBGUARD_TARGET_USER`, `WEBGUARD_TARGET_PASS`, `WEBGUARD_TARGET_COOKIE`, `WEBGUARD_TARGET_AUTH_HEADER`.

## Executive reports

`scan` writes by default:
- `webguard_report.json`
- `webguard_executive.md`
- `webguard_executive.html`

Dashboard also exports Exec HTML / Exec MD per scan.

## Authorized use only

Only scan systems you own or have explicit written permission to test.
Misuse against third-party systems may be illegal.

## CLI

```bash
# Synchronous scan
python main.py scan -u http://127.0.0.1:5001/

# Legacy shorthand
python main.py -u http://127.0.0.1:5001/

# Dashboard
python main.py serve
# or
python web/app.py
```

Exit codes for `scan`:
- `0` — completed, no finding at high/critical
- `1` — completed with high/critical findings
- `2` — failed

Optional SARIF:

```bash
python main.py scan -u http://127.0.0.1:5001/ --sarif-out report.sarif
```

## Dashboard auth

```bash
set WEBGUARD_TOKEN=change-me
python main.py serve
```

Pass the token in the form field or `X-WebGuard-Token` header.

## Configuration

See [`webguard.yaml`](webguard.yaml):

- `max_pages`, `max_depth`, `timeout`, `rate_limit_rps`
- `checks.enabled`
- `allowlist_hosts` (empty = target host only)
- `server.host` / `server.port` / `server.debug` (default `false`)

Override path with `WEBGUARD_CONFIG` or `~/.webguard/config.yaml`.

## Architecture

1. Crawl HTML (requests + BeautifulSoup)
2. Run enabled checks from `core/checks/`
3. Persist scans + findings in SQLite
4. Report via CLI files or dashboard exports

## Limitations

- No JavaScript / SPA rendering
- No complex authenticated crawling
- XSS is reflection-based; SQLi is error-based
- Findings are signals for investigation, not guaranteed exploits

## Tests

```bash
pytest -q
```

## License

MIT
