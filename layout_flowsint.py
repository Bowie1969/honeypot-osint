#!/usr/bin/env python3
"""Compute a readable radial-by-category layout and push node positions."""
import json, math, os, urllib.request, urllib.parse, urllib.error, collections

API="http://127.0.0.1:5001/api"; HERE=os.path.dirname(__file__)
cred=json.load(open(os.path.join(HERE,".flowsint-creds.json")))
sk=json.load(open(os.path.join(HERE,".flowsint-sketch.json")))["sketch_id"]

def call(method,path,token=None,json_body=None,form_body=None):
    data=None;h={}
    if json_body is not None: data=json.dumps(json_body).encode();h["Content-Type"]="application/json"
    elif form_body is not None: data=urllib.parse.urlencode(form_body).encode();h["Content-Type"]="application/x-www-form-urlencoded"
    if token:h["Authorization"]=f"Bearer {token}"
    req=urllib.request.Request(API+path,data=data,headers=h,method=method)
    try:
        with urllib.request.urlopen(req,timeout=30) as r:
            b=r.read().decode(); return r.status,(json.loads(b) if b else {})
    except urllib.error.HTTPError as e: return e.code,e.read().decode()

_,tok=call("POST","/auth/token",form_body={"username":cred["email"],"password":cred["password"],"grant_type":"password"})
token=tok["access_token"]
_,g=call("GET",f"/sketches/{sk}/graph",token=token)
nds=g["nds"]

# sector (angle center, radius) per category
SECTORS={  # nodeType or special -> (angle_deg_center, radius, spread_deg)
 "honeypot":(0,0,0),
 "riskprofile":(0,320,360),        # campaigns: full inner ring
 "ip_attacker":(200,760,150),      # attackers: left/lower arc
 "ip_c2":(40,560,70),              # C2 hosts: upper-right
 "asn":(90,980,180),               # ASNs: outer
 "malware":(10,760,60),            # malware: right
 "credential":(300,560,80),        # creds: lower-right
 "organization":(150,560,60),      # relay targets: upper-left
}
def cat(n):
    t=n["nodeType"]; lbl=(n.get("nodeLabel") or "")
    props=n.get("nodeProperties",{})
    if t=="ip":
        if "honeypot" in lbl: return "honeypot"
        if "C2" in lbl or props.get("role")=="malware payload host": return "ip_c2"
        return "ip_attacker"
    return t if t in SECTORS else "ip_attacker"

groups=collections.defaultdict(list)
for n in nds: groups[cat(n)].append(n)

positions=[]
for c,members in groups.items():
    ang0,rad,spread=SECTORS[c]
    k=len(members)
    for i,n in enumerate(members):
        if c=="honeypot":
            x,y=0,0
        else:
            if k==1: a=ang0
            else: a=ang0-spread/2 + spread*i/(k-1 if k>1 else 1)
            ar=math.radians(a)
            # slight radius jitter by index parity so labels don't collide
            rr=rad + (60 if i%2 else -60 if k>6 else 0)
            x=rr*math.cos(ar); y=rr*math.sin(ar)
        positions.append({"nodeId":n["id"],"x":round(x,1),"y":round(y,1)})

st,r=call("PUT",f"/sketches/{sk}/nodes/positions",token=token,json_body={"positions":positions})
print("positions update:",st,r if st!=200 else f"{len(positions)} nodes placed")
