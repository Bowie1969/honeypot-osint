#!/usr/bin/env python3
"""Push the honeypot intel graph into a Flowsint sketch via its local API."""
import json, os, sys, urllib.request, urllib.parse, urllib.error

API = "http://127.0.0.1:5001/api"
HERE = os.path.dirname(__file__)
CRED_FILE = os.path.join(HERE, ".flowsint-creds.json")

def call(method, path, token=None, json_body=None, form_body=None):
    url = API + path
    data = None; headers = {}
    if json_body is not None:
        data = json.dumps(json_body).encode(); headers["Content-Type"]="application/json"
    elif form_body is not None:
        data = urllib.parse.urlencode(form_body).encode()
        headers["Content-Type"]="application/x-www-form-urlencoded"
    if token: headers["Authorization"]=f"Bearer {token}"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            body = r.read().decode()
            return r.status, (json.loads(body) if body else {})
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()

# --- credentials (reuse if present so the script is idempotent) ---
if os.path.exists(CRED_FILE):
    cred = json.load(open(CRED_FILE))
else:
    import secrets
    cred = {"email":"analyst@honeypot.local","password":secrets.token_urlsafe(18)}
    json.dump(cred, open(CRED_FILE,"w"), indent=2); os.chmod(CRED_FILE,0o600)

# --- register (ignore 'already registered') ---
st,_ = call("POST","/auth/register",json_body={"email":cred["email"],"password":cred["password"]})
print(f"register -> {st}")

# --- login ---
st,tok = call("POST","/auth/token",form_body={"username":cred["email"],"password":cred["password"],"grant_type":"password"})
if st!=200: print("login failed",st,tok); sys.exit(1)
token = tok["access_token"]; print("login -> ok")

# --- investigation + sketch ---
st,inv = call("POST","/investigations/create",token=token,
    json_body={"name":"Cowrie Honeypot — prod-db-01","description":"18-day SSH honeypot capture, DigitalOcean syd1 (134.199.170.29)"})
print(f"investigation -> {st}"); inv_id = inv["id"]
st,sk = call("POST","/sketches/create",token=token,
    json_body={"title":"Attacker infrastructure map","description":"Campaigns, source IPs, ASNs, C2/payload hosts, malware, credentials","investigation_id":inv_id})
print(f"sketch -> {st}"); sketch_id = sk["id"]
print(f"SKETCH_ID={sketch_id}")

graph = json.load(open(os.path.join(HERE,"flowsint_graph.json")))

# --- nodes (capture Neo4j element_id returned for each logical id) ---
ok=0; elem={}   # logical id -> neo4j element_id
for n in graph["nodes"]:
    payload = {
        "id": n["id"], "nodeLabel": n["nodeLabel"], "nodeType": n["nodeType"],
        "nodeSize": n.get("nodeSize"), "nodeColor": n.get("nodeColor"),
        "nodeIcon": n.get("nodeIcon"), "nodeShape": n.get("nodeShape"),
        "nodeFlag": n.get("nodeFlag"),
        "nodeMetadata": n.get("nodeMetadata",{}) or {},
        "nodeProperties": n.get("nodeProperties",{}) or {},
    }
    st,r = call("POST",f"/sketches/{sketch_id}/nodes/add",token=token,json_body=payload)
    if st in (200,201):
        ok+=1
        try: elem[n["id"]] = r["node"]["id"]   # element_id assigned by Neo4j
        except Exception: pass
    else: print(f"  node {n['id']} -> {st} {str(r)[:120]}")
print(f"nodes added: {ok}/{len(graph['nodes'])}  (mapped {len(elem)} element ids)")

# --- edges (translate logical source/target -> element_id) ---
oke=0; skipped=0
for e in graph["edges"]:
    s = elem.get(e["source"]); t = elem.get(e["target"])
    if not s or not t: skipped+=1; continue
    payload = {"source":s,"target":t,"type":"one-way","label":e["label"]}
    st,r = call("POST",f"/sketches/{sketch_id}/relations/add",token=token,json_body=payload)
    if st in (200,201): oke+=1
    else: print(f"  edge {e['source']}->{e['target']} -> {st} {str(r)[:120]}")
print(f"edges added: {oke}/{len(graph['edges'])}  (skipped {skipped} unmapped)")

json.dump({"investigation_id":inv_id,"sketch_id":sketch_id},open(os.path.join(HERE,".flowsint-sketch.json"),"w"),indent=2)
print(f"\nOpen: http://localhost:5173/dashboard/sketches/{sketch_id}  (login: {cred['email']})")
