#!/usr/bin/env python3
"""
Build the honeypot threat-intelligence graph from the Cowrie logs + OSINT
attribution, emitting:
  - flowsint_graph.json : nodes/edges in Flowsint GraphNode/GraphEdge shape
  - intel_summary.json  : headline stats for the portfolio write-up

Grounded in the real cowrie event log (all.json); OSINT attributions
(ASN/org/geo) were gathered via the osint MCP ip_intel tool and are recorded
in OSINT below so the graph is reproducible.
"""
import json, collections, os

import glob
# all.json is a DERIVED/partial export (547,857 lines) and is NOT a concat of the
# rotated set (674,912 lines) — read the rotated + live files instead. Note the
# rotated names have no trailing ".json", so glob on "cowrie.json*".
_LOGDIR = os.path.join(os.path.dirname(__file__), "cowrie-logs")
LOGS = [f for f in sorted(glob.glob(os.path.join(_LOGDIR, "cowrie.json*")))
        if os.path.isfile(f)]
OUT = os.path.dirname(__file__)
HONEYPOT_IP = "134.199.170.29"

# ---- OSINT attribution gathered via ip_intel (host -> asn/org/geo/abuse) ----
OSINT = {
    "213.232.114.14": ("AS3214", "xTom GmbH / VirMach-NL", "Amsterdam, NL", "report-abuse+xtom@virmach.com"),
    "144.202.28.52":  ("AS20473", "Vultr (The Constant Company)", "Atlanta, US", "abuse@vultr.com"),
    "45.32.215.222":  ("AS20473", "Vultr (The Constant Company)", "Atlanta, US", "abuse@vultr.com"),
    "217.60.102.5":   ("AS209373", "SWISSNET LLC", "Amsterdam, NL", "abuse@swissnetwork.co"),
    "179.43.133.154": ("AS51852", "Private Layer INC", "Bellinzona, CH", "support@privatelayer.com"),
    "179.43.139.58":  ("AS51852", "Private Layer INC", "Bellinzona, CH", "support@privatelayer.com"),
    "185.246.128.133":("AS42237", "w1n ltd", "Stockholm, SE", "abuse@w1n.nl"),
    "109.160.32.153": ("AS198364", "BANATSYNC SRL (GBTCloud)", "Dusseldorf, DE", "abuse@gcn.bg"),
    "109.160.32.141": ("AS198364", "BANATSYNC SRL (GBTCloud)", "Dusseldorf, DE", "abuse@gcn.bg"),
    "109.160.32.102": ("AS198364", "BANATSYNC SRL (GBTCloud)", "Dusseldorf, DE", "abuse@gcn.bg"),
    "109.160.32.144": ("AS198364", "BANATSYNC SRL (GBTCloud)", "Dusseldorf, DE", "abuse@gcn.bg"),
    "77.239.124.75":  ("AS198364", "BANATSYNC SRL (RocketCloud)", "Kerkrade, NL", "abuse@rocket-cloud.org"),
    "77.239.124.72":  ("AS198364", "BANATSYNC SRL (RocketCloud)", "Kerkrade, NL", "abuse@rocket-cloud.org"),
    "77.239.124.40":  ("AS198364", "BANATSYNC SRL (RocketCloud)", "Kerkrade, NL", "abuse@rocket-cloud.org"),
    "164.30.17.82":   ("AS6878", "Open Telekom Cloud (T-Systems)", "Berlin, DE", "abuse@telekom.de"),
}

# ---- Campaign classification (name -> matching signatures in command input) ----
def classify(cmds_blob):
    b = cmds_blob.lower()
    if "handshakebins" in b or "nokillbins" in b or "/telnetd" in b or "tftp" in b and "213.232.114.14" in b:
        return "C1_mirai_handshakebins"
    if "iran.x86" in b or "iran.aarch64" in b or "cat.sh" in b or "iran.m68k" in b:
        return "C2_iot_multiarch_iran"
    if "auth_ok" in b or "x61\\x75\\x74\\x68" in b or "217.60.102.5" in b or "key.ppk" in b:
        return "C3_ssh_worm_keyplant"
    if "rdpci" in b or "sqhost" in b or ".exe" in b or "7z" in b:
        return "C5_windows_rdp_tooling"
    return None

# ---- Parse the log ----
ip_hits = collections.Counter()
ip_shell = collections.Counter()          # commands run per ip
ip_campaigns = collections.defaultdict(set)
cred_ok = collections.Counter()
dl_by_ip = collections.defaultdict(set)    # ip -> set(payload urls/hosts)
relay = collections.Counter()
sess_cmds = collections.defaultdict(list)
sess_ip = {}
total_events = 0
sessions = set()

# real captured samples: sha256 -> drop count / dropping ips / payload urls / sessions
sample_hits = collections.Counter()
sample_ips = collections.defaultdict(set)
sample_urls = collections.defaultdict(set)
sample_sess = collections.defaultdict(set)
url_hits = collections.Counter()
ts_min = ts_max = None

for _lf in LOGS:
  for line in open(_lf, errors="replace"):
    try: e = json.loads(line)
    except: continue
    total_events += 1
    _ts = e.get("timestamp")
    if _ts:
        if ts_min is None or _ts < ts_min: ts_min = _ts
        if ts_max is None or _ts > ts_max: ts_max = _ts
    eid = e.get("eventid",""); s = e.get("session"); ip = e.get("src_ip")
    if s: sessions.add(s)
    if eid == "cowrie.session.connect" and ip: ip_hits[ip]+=1
    if eid == "cowrie.login.success":
        cred_ok[f"{e.get('username')}:{e.get('password')}"]+=1
    if eid == "cowrie.command.input" and s:
        sess_cmds[s].append(e.get("input","")); sess_ip[s]=ip; ip_shell[ip]+=1
    if eid in ("cowrie.session.file_download","cowrie.session.file_upload"):
        u = e.get("url") or ""
        if ip:
            for host in OSINT:
                if host in u: dl_by_ip[ip].add(host)
        _h = e.get("shasum")
        if _h:
            sample_hits[_h] += 1
            if ip: sample_ips[_h].add(ip)
            if u: sample_urls[_h].add(u); url_hits[u] += 1
            if e.get("session"): sample_sess[_h].add(e["session"])
    if eid == "cowrie.direct-tcpip.request":
        dst = e.get("dst_ip","")
        relay[dst]+=1

# assign campaigns from session command blobs
for s, cmds in sess_cmds.items():
    c = classify("\n".join(cmds))
    if c and sess_ip.get(s): ip_campaigns[sess_ip[s]].add(c)

# relay target grouping (Yahoo / Google / Cloudflare by known prefixes)
def relay_org(ip):
    if ip.startswith("74.6.") or ip.startswith("98.137.") or ip.startswith("2001:4998"): return "Yahoo"
    if ip.startswith("142.251.") or ip.startswith("2a00:1450"): return "Google"
    if ip.startswith("1.1.1.1"): return "Cloudflare"
    return None
relay_org_hits = collections.Counter()
for ip,n in relay.items():
    o = relay_org(ip)
    if o: relay_org_hits[o]+=n

# ---- Build graph ----
PALETTE = {
    "honeypot":"#e03131","campaign":"#f08c00","attacker":"#1971c2",
    "asn":"#2f9e44","c2":"#9c36b5","malware":"#c92a2a","credential":"#5c7cfa",
    "relay":"#868e96",
}
nodes=[]; edges=[]; seen=set()
# Each Flowsint type requires its primary field present in nodeProperties:
PRIMARY = {"ip":"address","asn":"asn_str","malware":"name",
           "credential":"username","organization":"name","riskprofile":"entity_id"}
def node(nid, ntype, label, props, color, icon, shape="circle", size=10, flag=None):
    if nid in seen: return nid
    seen.add(nid)
    props = dict(props)
    pkey = PRIMARY.get(ntype)
    if pkey and pkey not in props:
        # derive the primary value from the most sensible existing prop
        props[pkey] = (props.get("ip") or props.get("asn") or props.get("credential")
                       or props.get("org") or props.get("campaign") or label or nid)
    nodes.append({"id":nid,"nodeType":ntype,"nodeLabel":label,
        "nodeProperties":props,"nodeColor":color,"nodeIcon":icon,
        "nodeShape":shape,"nodeSize":size,"nodeFlag":flag,
        "nodeMetadata":{"source":"cowrie-honeypot"}})
    return nid
def edge(src,tgt,label,weight=1,conf="confirmed"):
    edges.append({"id":f"{src}->{tgt}:{label}","source":src,"target":tgt,
        "label":label,"weight":weight,"confidence_level":conf})

# honeypot (center)
node(HONEYPOT_IP,"ip","prod-db-01 (honeypot)",
     {"ip":HONEYPOT_IP,"role":"SSH honeypot (Cowrie)","disguise":"neglected Ubuntu 18.04 DB box"},
     PALETTE["honeypot"],"ServerCrash","hexagon",28,"red")

# campaigns
CAMP = {
 "C1_mirai_handshakebins":("Mirai 'handshakebins' loader","IoT DDoS botnet; multi-protocol fetch (wget/curl/tftp/ftp); /nokillbins variant"),
 "C2_iot_multiarch_iran":("Multi-arch IoT 'iran' dropper","cat.sh + iran.{x86_64,aarch64,m68k}; Vultr-hosted"),
 "C3_ssh_worm_keyplant":("Self-propagating SSH worm","plants hardcoded ed25519 key, scp 2nd-stage from C2, host-key checks disabled"),
 "C4_socks_relay_abuse":("Open-relay / SOCKS abuse","direct-tcpip tunnels validating the box as a proxy"),
 "C5_windows_rdp_tooling":("Windows RDP tooling drop","rdpcIip.exe, sqhost.exe, 7z self-extractors (proxyware/miner)"),
}
for cid,(name,desc) in CAMP.items():
    node(cid,"riskprofile",name,{"campaign":name,"description":desc},
         PALETTE["campaign"],"Crosshair","triangle",20,"orange")

# C2 / payload hosts
C2 = {
 "213.232.114.14":("C1_mirai_handshakebins","SERVES"),
 "144.202.28.52":("C2_iot_multiarch_iran","SERVES"),
 "45.32.215.222":("C2_iot_multiarch_iran","SERVES"),
 "217.60.102.5":("C3_ssh_worm_keyplant","SERVES"),
}
for host,(camp,_) in C2.items():
    asn,org,geo,abuse = OSINT[host]
    node(host,"ip",f"{host} (C2/payload)",
         {"ip":host,"role":"malware payload host","asn":asn,"org":org,"geo":geo,"abuse":abuse},
         PALETTE["c2"],"Bug","square",18,"red")
    edge(camp,host,"DOWNLOADS_FROM",weight=3)
    # asn node
    aid=f"asn:{asn}"
    node(aid,"asn",f"{asn} {org}",{"asn":asn,"org":org,"geo":geo,"abuse_contact":abuse},
         PALETTE["asn"],"Network","square",14)
    edge(host,aid,"HOSTED_BY")

def attacker_node(ip):
    """Ensure an attacker IP exists as a node (idempotent). Used by both the
    sample-linkage pass and the top-shell pass so no edge dangles."""
    if ip == HONEYPOT_IP: return None
    asn,org,geo,abuse = OSINT.get(ip,("?","unattributed","?","?"))
    node(ip,"ip",ip,{"ip":ip,"connects":ip_hits.get(ip,0),"commands":ip_shell.get(ip,0),
                     "asn":asn,"org":org,"geo":geo},
         PALETTE["attacker"],"Skull","circle",
         max(8,min(18,ip_shell.get(ip,0)//40 or 8)),"blue")
    if asn!="?":
        aid=f"asn:{asn}"
        node(aid,"asn",f"{asn} {org}",{"asn":asn,"org":org,"geo":geo,"abuse_contact":abuse},
             PALETTE["asn"],"Network","square",14)
        edge(ip,aid,"HOSTED_BY")
    return ip

# ---- REAL captured samples (actual SHA256 from the logs, not placeholders) ----
# Two distinct kinds, and conflating them would misrepresent the data:
#   payload  = fetched from a remote host (has a URL)  -> real dropped malware
#   authored = written on-box by the attacker (no URL) -> e.g. the `printf > filter`
#              capability probe, which is the single highest-volume artefact
PRIMARY["file"] = "filename"
# Real static-triage results produced ON the honeypot droplet (file type, size,
# embedded URLs/IPs). Results only — no sample binaries are moved off the droplet.
_TRIAGE = {}
_tp = os.path.join(OUT, "sample_triage.json")
if os.path.exists(_tp):
    try:
        _TRIAGE = {x["sha256"]: x for x in json.load(open(_tp)) if x.get("sha256")}
    except Exception: _TRIAGE = {}
SAMPLE_TOP = 24
for _h, _n in sample_hits.most_common(SAMPLE_TOP):
    _urls = sorted(sample_urls[_h])
    _authored = not _urls
    _label = ("authored " if _authored else "") + _h[:12] + "\u2026"
    _props = {
        "filename": _h,
        "hash_sha256": _h,
        "drop_events": _n,
        "dropping_ips": len(sample_ips[_h]),
        "sessions": len(sample_sess[_h]),
        "origin": "attacker-authored on-box" if _authored else "downloaded from remote host",
    }
    _t = _TRIAGE.get(_h)
    if _t:
        _props["file_type"] = _t.get("type") or "unknown"
        _props["size_bytes"] = _t.get("size")
        _props["hash_verified"] = bool(_t.get("name_matches"))
        _ft = (_t.get("type") or "").lower()
        _props["arch"] = ("ELF 32-bit" if "elf 32-bit" in _ft else
                          "ELF 64-bit" if "elf 64-bit" in _ft else
                          "Windows PE32" if "pe32" in _ft else
                          "shell script" if "shell script" in _ft else "other")
        if _t.get("urls"): _props["embedded_urls"] = ", ".join(_t["urls"][:4])
        if _t.get("ips"): _props["embedded_ips"] = ", ".join(_t["ips"][:6])
    if _urls:
        _props["payload_urls"] = ", ".join(_urls[:4])
        _props["malware_family"] = "Mirai/Gafgyt" if "handshakebins" in " ".join(_urls) or "telnetd" in " ".join(_urls) else "unclassified"
    node(f"file:{_h}", "file", _label, _props,
         PALETTE["malware"] if not _authored else "#868e96",
         "Bug" if not _authored else "FileCode", "circle",
         max(8, min(20, 8 + _n // 150)), "red" if not _authored else None)
    # link each sample to the hosts that served it, and the IPs that dropped it
    for _u in _urls:
        for _host in OSINT:
            if _host in _u:
                edge(_host, f"file:{_h}", "SERVES", weight=min(6, 1 + _n // 20))
    for _ip in sorted(sample_ips[_h])[:6]:
        if attacker_node(_ip):
            edge(_ip, HONEYPOT_IP, "ATTACKED", weight=1)
            edge(_ip, f"file:{_h}", "DROPPED", weight=min(5, 1 + _n // 300))

# top attacker IPs that actually reached a shell
top_shell = [ip for ip,_ in ip_shell.most_common(18)]
for ip in top_shell:
    if not attacker_node(ip): continue
    edge(ip,HONEYPOT_IP,"ATTACKED",weight=min(6,1+ip_shell[ip]//100))
    for c in ip_campaigns.get(ip,[]):
        edge(ip,c,"RAN_CAMPAIGN")

# credentials (top successful)
for cred,n in cred_ok.most_common(8):
    cid=f"cred:{cred}"
    node(cid,"credential",cred,{"credential":cred,"successful_logins":n},
         PALETTE["credential"],"KeyRound","circle",max(8,min(16,n//400)))
    edge(HONEYPOT_IP,cid,"ACCEPTED_LOGIN",weight=min(6,1+n//1000))

# relay / open-proxy abuse
node("C4_socks_relay_abuse_hub",HONEYPOT_IP,"",{},"","",) if False else None
for org,n in relay_org_hits.most_common():
    rid=f"relay:{org}"
    node(rid,"organization",f"{org} (relay target)",{"org":org,"tunnel_attempts":n},
         PALETTE["relay"],"Globe","circle",12,"yellow")
    edge("C4_socks_relay_abuse",rid,"TUNNELED_TO",weight=min(6,1+n//500))
edge(HONEYPOT_IP,"C4_socks_relay_abuse","ABUSED_AS_RELAY")

# connect honeypot -> campaigns
for cid in CAMP:
    if cid!="C4_socks_relay_abuse": edge(HONEYPOT_IP,cid,"TARGETED_BY")

# de-duplicate edges by (source,target,label) — both passes can emit ATTACKED
_seen_e=set(); _ded=[]
for _e in edges:
    _k=(_e["source"],_e["target"],_e["label"])
    if _k in _seen_e: continue
    _seen_e.add(_k); _ded.append(_e)
edges=_ded

# fail loudly if any edge references a node that was never created
_ids={n["id"] for n in nodes}
_dangling=[e["id"] for e in edges if e["source"] not in _ids or e["target"] not in _ids]
if _dangling:
    print(f"WARNING: {len(_dangling)} dangling edges (node missing): {_dangling[:5]}")
else:
    print("edge integrity: OK (no dangling references)")

graph={"nodes":nodes,"edges":edges}
json.dump(graph,open(os.path.join(OUT,"flowsint_graph.json"),"w"),indent=2)

summary={
 "window":f"{ts_min} to {ts_max}",
 "log_files_read":len(LOGS),
 "total_events":total_events,
 "total_sessions":len(sessions),
 "unique_source_ips":len(ip_hits),
 "ips_reaching_shell":len([i for i in ip_shell if i!=HONEYPOT_IP]),
 "campaigns":len(CAMP),
 "top_successful_cred":cred_ok.most_common(1)[0] if cred_ok else None,
 "distinct_sample_hashes":len(sample_hits),
 "samples_with_payload_url":sum(1 for h in sample_hits if sample_urls[h]),
 "samples_attacker_authored":sum(1 for h in sample_hits if not sample_urls[h]),
 "top_sample":(sample_hits.most_common(1)[0] if sample_hits else None),
 "top_payload_urls":url_hits.most_common(5),
 "samples_statically_triaged":len(_TRIAGE),
 "triage_hash_verified":sum(1 for v in _TRIAGE.values() if v.get("name_matches")),
 "triage_file_types":dict(collections.Counter((v.get("type") or "unknown").split(",")[0] for v in _TRIAGE.values()).most_common(8)),
 "c2_infrastructure":list(C2.keys()),
 "graph_nodes":len(nodes),"graph_edges":len(edges),
}
json.dump(summary,open(os.path.join(OUT,"intel_summary.json"),"w"),indent=2)
print(json.dumps(summary,indent=2))
print(f"\nGraph: {len(nodes)} nodes, {len(edges)} edges -> flowsint_graph.json")
