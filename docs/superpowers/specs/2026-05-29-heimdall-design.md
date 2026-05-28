# Heimdall — OSINT Agent Design Spec
**Date:** 2026-05-29  
**Status:** Approved

---

## Overview

Heimdall is a web-based autonomous OSINT agent. The user enters a company name or domain; the app runs multiple recon steps sequentially and produces a professional threat intelligence report powered by Claude.

**Tech stack:** Python (Flask) backend · Vanilla JS/CSS single-page frontend · Anthropic Claude API · Free/no-auth public data sources only.

---

## File Structure

```
HEIMDALL/
├── app.py                        ← Flask app, all recon logic, SSE stream
├── templates/
│   └── index.html                ← Single-page frontend
├── requirements.txt
└── docs/superpowers/specs/
    └── 2026-05-29-heimdall-design.md
```

---

## Architecture

### Request Flow

1. User submits input via `POST /scan` → backend returns `{"scan_id": "<uuid>"}`
2. Frontend opens `GET /stream/<scan_id>` as an `EventSource`
3. Flask generator runs 9 recon steps sequentially, yielding SSE events:
   - `event: step` — `{"name": str, "status": "running"|"done"|"failed", "summary": str}`
   - `event: report` — `{"html": str}` (Claude's full report HTML)
   - `event: done` — stream closes
4. Frontend updates progress feed live; injects report HTML on `report` event

### State Management

Each scan's collected data lives in an in-memory dict keyed by `scan_id` (UUID). No persistence — data exists only for the duration of the scan stream.

---

## Recon Pipeline

Each step follows this contract:
```python
def step_N_name(domain: str, data: dict) -> dict:
    # mutates data in-place
    # returns {"status": "done"|"failed", "summary": str}
```

Every step is wrapped in `try/except`. On failure: emit `status: failed` with the error message and continue to the next step.

| Step | Name | Source | Data Collected |
|------|------|--------|----------------|
| 1 | Domain Resolution | Claude API (only if input is not a bare domain) | Canonical domain |
| 2 | WHOIS | `python-whois` | Registrar, created, expiry, registrant org |
| 3 | DNS Enumeration | `dnspython` | A, MX, TXT, NS records |
| 4 | Subdomain Discovery | `crt.sh` JSON API | Subdomains from cert transparency logs |
| 5 | Tech Stack Detection | `requests` (fetch homepage) | CMS, frameworks, analytics (headers + HTML) |
| 6 | Wayback Machine | CDX API | Historical URLs, exposed paths |
| 7 | Robots.txt + Sitemap | `requests` direct fetch | Disallowed paths, sitemap entries |
| 8 | Breach Check | `psbdmp.ws` (free) + HIBP (optional) | Paste mentions, known breaches |
| 9 | Claude Report | Anthropic SDK (`claude-sonnet-4-20250514`) | Structured HTML threat intel report |

### Step 1 — Input Normalisation

Before domain-vs-company-name detection, strip:
- `https://` or `http://`
- Leading `www.`
- Trailing slashes

Detection rule: if cleaned input contains a dot and no spaces → treat as bare domain, skip Claude. Otherwise → call Claude to resolve.

### Step 8 — Breach Check Details

- **psbdmp.ws:** `GET https://psbdmp.ws/api/v3/search/{domain}` — treat any non-200 response or timeout as a silent skip (service is unreliable).
- **HIBP:** Only attempt `GET https://haveibeenpwned.com/api/v3/breacheddomain/{domain}` if `HIBP_API_KEY` env var is set. If not set, record "HIBP check skipped (no API key configured)" in the report data.

### Step 9 — Claude Only Fires If

At least one of steps 2–7 returned `status: done` with non-empty data. If all prior steps failed, emit a meaningful error instead of sending an empty prompt to Claude.

---

## Claude Prompts

### Step 1 — Domain Resolution

**System:**
```
You are a domain research assistant. Reply with only the bare domain name, nothing else.
```

**User:**
```
What is the most likely primary domain for the company named '{input}'? Reply with only the domain, e.g. example.com
```

### Step 9 — Threat Intelligence Report

**System:**
```
You are a senior threat intelligence analyst. You write professional, structured OSINT reports for defensive security teams. Output ONLY valid HTML using <h2>, <p>, <ul>, <li>, <strong>, <span> tags. No markdown. No code blocks. No preamble.
```

**User:**
```
Based on this raw OSINT data about {domain}, write a professional threat intelligence report with these exact sections:
1. Executive Summary (3 sentences, non-technical)
2. Digital Footprint Overview
3. Exposed Attack Surface (subdomains, tech stack, open paths)
4. Breach & Leak History
5. Key Risk Findings — rank each High / Medium / Low, wrap badge in <span class='badge-high'>, <span class='badge-medium'>, or <span class='badge-low'>
6. Recommended Actions
Raw data: {all_collected_data}
```

**Model:** `claude-sonnet-4-20250514`

---

## Frontend UI

### Theme
- Background: `#0d1117`
- Accent / primary green: `#00ff88`
- Font: monospace terminal aesthetic
- Mobile responsive

### Layout (top → bottom)

1. **Header** — "HEIMDALL" wordmark + tagline
2. **Input bar** — text field with placeholder `"company name or domain (e.g. google.com)"` + "Run Scan" button
   - Submit button disabled while scan is active (EventSource open)
3. **Progress feed** — appears after scan starts; one row per step:
   - Spinner → green checkmark (done) → red ✕ (failed)
   - Step name + one-line summary on completion
4. **Report section** — hidden until Step 9 completes; Claude HTML injected via `innerHTML`
5. **Action bar** — "Copy Report" + "Download PDF" (`window.print()` with print CSS) + "New Scan"
6. **Footer** — disclaimer

### SSE Event Handling (JS)

| Event | Action |
|-------|--------|
| `step` | Update corresponding step row (status + summary) |
| `report` | Inject `data.html` into report section, reveal section |
| `done` | Close EventSource, re-enable submit, show action bar |
| `error` (on EventSource) | Show error banner, close source, re-enable submit |

### Badge CSS Classes

```css
.badge-high   { background: #ff4444; color: #fff; }
.badge-medium { background: #ffaa00; color: #000; }
.badge-low    { background: #00ff88; color: #000; }
```

---

## Requirements

```
flask
anthropic
requests
dnspython
python-whois
```

---

## Disclaimer (Footer Text)

> Heimdall uses only publicly available data. Use responsibly and only on domains you own or have permission to test.

---

## Out of Scope

- User authentication
- Scan history / persistence
- Rate limiting / concurrency controls
- Production deployment (gunicorn, nginx, etc.)
