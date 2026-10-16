"""
Digest honeypot events.jsonl into a ranked indicator set for OSINT enrichment.

Usage: python3 osint/aggregate.py [logs/events.jsonl]
Emits osint/indicators.json and a console summary. The enrichment itself
(IP intel, Shodan, breach checks, etc.) is run separately against these indicators.
"""
import json
import sys
from collections import Counter, defaultdict

LOG = sys.argv[1] if len(sys.argv) > 1 else "logs/events.jsonl"


def load(path):
    out = []
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line:
                    out.append(json.loads(line))
    except FileNotFoundError:
        print(f"No log file at {path} yet — honeypot has no traffic.")
        sys.exit(0)
    return out


def main():
    events = load(LOG)
    ips = Counter()
    uas = Counter()
    creds = Counter()
    paths = Counter()
    tags = Counter()
    beacon_ips = set()
    ip_tags = defaultdict(set)
    ip_first = {}
    ip_last = {}

    for e in events:
        ip = e.get("source_ip")
        if ip:
            ips[ip] += 1
            ip_tags[ip].add(e.get("tag"))
            ts = e.get("ts")
            ip_first.setdefault(ip, ts)
            ip_last[ip] = ts
        if e.get("user_agent"):
            uas[e["user_agent"]] += 1
        if e.get("tag") == "login_attempt":
            u, p = e.get("cred_username"), e.get("cred_password")
            creds[f"{u} / {p}"] += 1
        if e.get("tag") == "beacon_hit":
            beacon_ips.add(ip)
        if e.get("probed"):
            paths[e["probed"]] += 1
        tags[e.get("tag")] += 1

    indicators = {
        "total_events": len(events),
        "unique_ips": len(ips),
        "top_ips": [
            {"ip": ip, "hits": n, "tags": sorted(ip_tags[ip]),
             "first_seen": ip_first[ip], "last_seen": ip_last[ip],
             "hit_beacon": ip in beacon_ips}
            for ip, n in ips.most_common(50)
        ],
        "beacon_ips": sorted(beacon_ips),
        "top_user_agents": uas.most_common(20),
        "attempted_credentials": creds.most_common(50),
        "probed_paths": paths.most_common(30),
        "event_tags": tags.most_common(),
    }

    with open("osint/indicators.json", "w") as f:
        json.dump(indicators, f, indent=2)

    print(f"Events: {len(events)}  |  Unique IPs: {len(ips)}  |  Beacon hits from: {len(beacon_ips)} IP(s)")
    print("\nTop source IPs:")
    for row in indicators["top_ips"][:15]:
        flag = "  <-- CONSUMED LEAKED CONFIG (beacon)" if row["hit_beacon"] else ""
        print(f"  {row['ip']:<16} {row['hits']:>4} hits  {','.join(row['tags'])}{flag}")
    if creds:
        print("\nTop credentials tried:")
        for c, n in creds.most_common(10):
            print(f"  {n:>3}x  {c}")
    print("\nWrote osint/indicators.json")


if __name__ == "__main__":
    main()
