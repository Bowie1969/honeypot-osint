# honeypot-osint

> **A self-hosted web lure and beacon platform that turns opportunistic internet noise into attributed threat intelligence.** Every request, credential attempt, and planted-beacon hit is logged and enriched into ranked indicators and a Flowsint/Neo4j entity graph — including an 18-day, 547k-event Cowrie capture reduced to five attacker campaigns.

![Python](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.0-000000?logo=flask&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-ready-2496ED?logo=docker&logoColor=white)
![Cowrie](https://img.shields.io/badge/Cowrie-18d%2F547k%20events-00adb5)
![Neo4j](https://img.shields.io/badge/Neo4j-Flowsint%20graph-4581C3?logo=neo4j&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-green)

## What it is

Two complementary tools for **passive** OSINT collection:

1. **A web lure** — a fake corporate operations portal (`honeypot/`) that looks like a neglected production app. It answers mass-scanner traffic with a believable login page, decoy secret files, and self-hosted beacon tokens. It observes and logs; it never scans, attacks, or calls back out to any client.
2. **An analysis pipeline** — a set of scripts that turn raw honeypot logs into ranked indicators (`osint/aggregate.py`) and a Flowsint (Neo4j-backed) entity graph (`build_graph.py`, `inject_flowsint.py`, `layout_flowsint.py`).

## Highlights

- **Per-request OSINT** — source IP, full `X-Forwarded-For` chain, user-agent, headers, cookies, locale, referer, and attempted credentials captured as structured JSONL.
- **Beacon-token unmasking** — decoy `.env` / AWS configs embed a self-hosted `/t/<token>` URL. When an attacker's tooling consumes a leaked config and later hits that URL, the beacon fires and reveals their **real egress IP** — often different from the scanning IP (unmasks proxy/C2 infra).
- **547,857 events → 5 campaigns** — an 18-day Cowrie capture (1,605 unique source IPs, 117 reaching a shell) classified into Mirai loaders, an IoT dropper, a self-propagating SSH worm, SOCKS-relay abuse, and Windows RDP tooling.
- **Attributed entity graph** — 47 nodes / 50 edges in Flowsint, with ASN, org, geo, and abuse-contact attribution per IP.
- **Zero dependencies beyond stdlib + Flask** — the pipeline scripts use only the Python standard library.

## Web lure + beacon design

The Flask app (`honeypot/app.py`) has no real functionality by design — its job is to look interesting and record who touches it:

- **`/login`** — a styled corporate portal (brand configurable via `HONEYPOT_BRAND`). Every `POST` logs the attempted `username`/`password` pair.
- **Sensitive paths** — `/.env`, `/.aws/credentials`, `/config.json`, `/.git/config`, `/wp-config.php`, and ~20 more are answered with planted canary content instead of a 404.
- **Canary files** contain a **beacon token**: each planted secret embeds a unique `http://<host>/t/<token>` URL. If an attacker's automation downloads the "leaked" config and later fetches the beacon (e.g. as a webhook or embedded image), the `/t/<token>` handler logs a `beacon_hit` with their live egress IP and cross-references the plant origin.

This is what makes the lure a *correlation* tool, not just a log collector: it connects the scanner that grabbed a config to the infrastructure that later acted on it.

## Cowrie-log → Flowsint graph pipeline

The `cowrie-logs/` directory (not committed — 673 MB of raw attacker events) fed a three-stage pipeline:

```
cowrie-logs/all.json
        │
        ▼
build_graph.py        parse + campaign classification → flowsint_graph.json
        │              + intel_summary.json (sanitized headline stats)
        ▼
inject_flowsint.py    POST nodes/edges into a local Flowsint (Neo4j) sketch
        │
        ▼
layout_flowsint.py    radial-by-category layout, push node positions
```

- **`build_graph.py`** — reads the Cowrie event log, classifies sessions into five campaigns by command signatures, pulls in OSINT attribution (ASN/org/geo/abuse), and emits a Flowsint-shaped graph plus `intel_summary.json`.
- **`inject_flowsint.py`** — registers/logs in to a Flowsint instance, creates an investigation + sketch, and adds every node/edge.
- **`layout_flowsint.py`** — computes a sector-based radial layout (honeypot at centre, campaigns in a ring, attackers/C2/ASNs/creds outward) and pushes positions.

**Sanitized summary** (`intel_summary.json`):

| Metric | Value |
|---|---|
| Window | 2026-09-27 → 2026-10-16 (18 days) |
| Events | 547,857 |
| Sessions | 99,353 |
| Unique source IPs | 1,605 |
| IPs reaching a shell | 117 |
| Campaigns | 5 |
| Top successful credential | `admin:admin` (5,434×) |
| Graph | 47 nodes / 50 edges |

## Quickstart

```bash
# 1. Clone and set up a honeypot VM (any fresh Ubuntu 22.04/24.04 box you own)
scp -r honeypot-osint root@YOUR_VM_IP:/opt/
ssh root@YOUR_VM_IP 'cd /opt/honeypot-osint && bash deploy/provision.sh'
```

Open port 80 inbound in the cloud firewall. A public IPv4 attracts mass scanners within minutes.

```bash
# 2. Pull the captured log back to your workstation
scp root@YOUR_VM_IP:/opt/honeypot-osint/logs/events.jsonl ./logs/

# 3. Rank indicators for OSINT enrichment
python3 osint/aggregate.py logs/events.jsonl   # → osint/indicators.json
```

Run locally without a VM (Docker):

```bash
docker compose up -d --build
# tail traffic:  docker compose logs -f   (or: tail -f logs/events.jsonl)
```

Enrich the ranked indicators (`osint/indicators.json`) with your OSINT tooling of choice — IP intel, Shodan exposure, abuse/breach lookups on captured usernames/emails.

## Rebuilding the graph (with raw logs present)

```bash
python3 build_graph.py        # → flowsint_graph.json + intel_summary.json
python3 inject_flowsint.py    # push into a local Flowsint API (127.0.0.1:5001)
python3 layout_flowsint.py    # apply the radial layout
```

`inject_flowsint.py` and `layout_flowsint.py` expect a running Flowsint instance and its local credentials file (`.flowsint-creds.json`, gitignored).

## Architecture

```
        Internet — opportunistic scanners, bots, attackers
                          │  probes / login attempts / config grabs
                          ▼
   ┌──────────────────────────────────────────────────────────────────┐
   │  Web lure — honeypot/app.py  (Flask, :80, Docker)                │
   │   · fake corporate portal + /login                               │
   │   · planted .env / .aws/credentials with beacon token /t/<tok>   │
   └────────────┬──────────────────────────────────┬──────────────────┘
                │ every request (JSONL)            │ attacker tooling later
                ▼                                  │ fetches the beacon URL
     logs/events.jsonl                             ▼
                │                          beacon_hit → real egress IP
                ▼
     osint/aggregate.py → osint/indicators.json → OSINT MCP enrichment
                                                     (ip_intel, Shodan, breach)


   Cowrie SSH honeypot (separate box)
                │  cowrie.json.*  (18 days, 547k events)
                ▼
     build_graph.py → flowsint_graph.json + intel_summary.json
                ▼
     inject_flowsint.py → Flowsint (Neo4j) sketch
                ▼
     layout_flowsint.py → radial node layout
```

## Passive OSINT / authorized use

This project **only observes traffic that comes to infrastructure you own and are authorized to run**. It performs no scanning, no exploitation, no outbound callbacks to third parties, and no interaction with live systems beyond answering the requests they send to your honeypot. Deploy it only on hosts you control, in jurisdictions where running a honeypot is lawful, and never point it at infrastructure you do not own.

## License

[MIT](./LICENSE) — Copyright (c) 2026 honeypot-osint contributors.
