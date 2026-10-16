# honeypot-osint

A web honeypot (fake corporate ops portal) built for OSINT yield, plus an enrichment
pipeline for the indicators it captures. **Defensive use only — deploy on infrastructure
you own and are authorized to run.** It observes and logs; it never scans or calls back
out to any client.

## What it captures
- Every request as a JSON line in `logs/events.jsonl`: source IP + full forwarded chain,
  user-agent, all headers, cookies, locale, referer.
- Credential attempts on the fake `/login`.
- Scanner probes for sensitive paths (`.env`, `.aws/credentials`, config/backup, etc.).
- **Beacon correlation:** fake "leaked" configs embed a self-hosted beacon URL
  (`/t/<token>`). When an attacker's tooling consumes the leaked config and later hits
  that URL, the beacon fires — revealing their real egress IP, often different from the
  scanning IP (unmasks proxy/C2 infra).

## Deploy (any fresh Ubuntu 22.04/24.04 cloud VM)
```bash
# from your workstation
scp -r honeypot-osint root@YOUR_VM_IP:/opt/
ssh root@YOUR_VM_IP 'cd /opt/honeypot-osint && bash deploy/provision.sh'
```
Open port 80 inbound in the cloud firewall/security group. Within minutes of being live
on a public IPv4, mass scanners will start hitting it.

## Collect + enrich
```bash
# pull logs back to your workstation
scp root@YOUR_VM_IP:/opt/honeypot-osint/logs/events.jsonl ./logs/
# rank indicators
python3 osint/aggregate.py logs/events.jsonl   # -> osint/indicators.json
```
Then run OSINT enrichment (IP intel, Shodan exposure, abuse history, breach checks on
any captured usernames/emails) against `osint/indicators.json`.

## Files
- `honeypot/app.py` — the honeypot (Flask).
- `Dockerfile`, `docker-compose.yml` — containerized run on port 80.
- `deploy/provision.sh` — one-shot VM setup.
- `osint/aggregate.py` — digests the log into a ranked indicator set.
