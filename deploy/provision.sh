#!/usr/bin/env bash
# One-shot provisioning for a fresh Ubuntu 22.04/24.04 cloud VM.
# Run as root (or with sudo) ON THE VM after copying this repo to it.
#   scp -r honeypot-osint root@YOUR_VM_IP:/opt/
#   ssh root@YOUR_VM_IP 'cd /opt/honeypot-osint && bash deploy/provision.sh'
set -euo pipefail

echo "[*] Installing Docker..."
if ! command -v docker >/dev/null 2>&1; then
  curl -fsSL https://get.docker.com | sh
fi

cd "$(dirname "$0")/.."

echo "[*] Building and starting honeypot on port 80..."
docker compose up -d --build

echo "[*] Done. Live at: http://$(curl -fsS ifconfig.me 2>/dev/null || echo YOUR_VM_IP)/"
echo "[*] Tail attacker traffic:  docker compose logs -f   (or: tail -f logs/events.jsonl)"
echo "[*] Pull logs to your workstation for OSINT:"
echo "    scp root@YOUR_VM_IP:/opt/honeypot-osint/logs/events.jsonl ./logs/"
