# A1 final analysis (AWS scripting sandbox). Prepend pyinflate helpers (b64d, inflate, gunzip, zdecomp).
B = "<BUCKET_01>"
ENI = {"<ENI_01>": "t3-Xt", "<ENI_02>": "t3-Xu", "<ENI_03>": "t3-X6",
       "<ENI_04>": "t3-Ps", "<ENI_05>": "t3-Po", "<ENI_06>": "g-Xt",
       "<ENI_07>": "g-Xu", "<ENI_08>": "g-X6", "<ENI_09>": "g-Ps", "<ENI_10>": "g-Po"}
ADDR = {}
for n in ENI.values():
    g, r = n.split("-"); o = 1 if g == "t3" else 2
    last = {"Xt": 1, "Xu": 2, "X6": 3, "Ps": 4, "Po": 4}[r]
    sub = 2 if r == "Po" else 1
    ADDR["10.20.%d.%d%d" % (sub, o, last)] = n
    ADDR["<IPV6PREFIX>:a90%d::%d%d" % (sub, o, last)] = n
async def lst(prefix):
    keys = []; tok = None
    while True:
        p = {"Bucket": B, "Prefix": prefix}
        if tok: p["ContinuationToken"] = tok
        r = await call_boto3(service_name="s3", operation_name="ListObjectsV2", params=p)
        keys += [(o["Key"], o["LastModified"]) for o in r.get("Contents", [])]
        tok = r.get("NextContinuationToken")
        if not tok: break
    return keys
async def get(k):
    return (await call_boto3(service_name="s3", operation_name="GetObject", params={"Bucket": B, "Key": k}))["Body"]
# phases
ph = []
for k, _ in await lst("a1/phases/"):
    d = json.loads(await get(k))
    if d.get("t_change1"): ph.append(d)
ph.sort(key=lambda d: d["t_change0"])
ph = [p for p in ph if p["t_change0"] >= 1794323220]          # current instance set only
win = []
for i, p in enumerate(ph):
    end = ph[i + 1]["t_change0"] if i + 1 < len(ph) else p["t_change1"] + 300
    win.append((p["t_change1"], end, p["rep"], p["act"]))
def phase_of(b0, b1, guard=10):
    for s, e, rep, act in win:
        if b0 >= s + guard and b1 <= e: return rep, act
    return None
# console data
seen = {}
for k, _ in await lst("a1/console/"):
    nm = k.split("/")[2]
    t = await get(k)
    for line in t.splitlines():
        if not line.startswith("D|"): continue
        p = line.strip().split("|")
        if len(p) < 5: continue
        key = (nm, int(p[3]))
        if key in seen: continue
        try: seen[key] = json.loads(zdecomp(b64d(p[4])).decode())
        except Exception: seen[key] = None
bad = [k for k, v in seen.items() if v is None]
unit = {}   # (act, cond, side, fam, typ, rep, arch) -> [ok, fail, none]
for (nm, seq), d in seen.items():
    if d is None: continue
    for b, v in d.items():
        pa = phase_of(int(b), int(b) + 10)
        if pa is None: continue
        rep, act = pa
        for k, c in v["c"].items():
            tgt, fam, typ = k.split(".")
            if typ == "Oe": x, peer = nm, tgt
            else: x, peer = tgt, nm
            arch, cond = x.split("-"); side = "same" if peer.endswith("Ps") else "other"
            a = unit.setdefault((act, cond, side, fam, typ, rep, arch), [0, 0, 0])
            for j in range(3): a[j] += c[j]
summary = {}
for (act, cond, side, fam, typ, rep, arch), c in unit.items():
    cls = "ok" if c[0] > 0 and c[1] == 0 and c[2] == 0 else "fail" if c[0] == 0 and (c[1] > 0 or c[2] > 0) else "none" if sum(c) == 0 else "mixed"
    s = summary.setdefault("%s|%s|%s|%s|%s" % (act, cond, side, fam, typ), {"units": {}, "ok": 0, "fail": 0, "noconn": 0})
    s["units"][cls] = s["units"].get(cls, 0) + 1
    s["ok"] += c[0]; s["fail"] += c[1]; s["noconn"] += c[2]
    if cls == "mixed": s.setdefault("mixed_at", []).append("r%d-%s:%d/%d/%d" % (rep, arch, c[0], c[1], c[2]))
# flow logs: where are REJECT/ACCEPT recorded for X<->peer traffic, per phase
fl = {}; fl_objects = 0; fl_records = 0
for k, lm in await lst("a1/AWSLogs/"):
    fl_objects += 1
    txt = gunzip(b64d(await get(k))).decode().splitlines()
    for line in txt[1:]:
        f = line.split()
        if len(f) < 20 or f[9] == "-": continue
        eni, src, dst, st, en, action = f[1], f[2], f[3], int(f[9]), int(f[10]), f[11]
        if eni not in ENI or src not in ADDR or dst not in ADDR: continue
        a, b2 = ADDR[src], ADDR[dst]
        x = a if "-X" in a else b2 if "-X" in b2 else None
        peer = b2 if x == a else a
        if x is None or "-P" not in peer: continue
        pa = phase_of(st, en, guard=0)
        if pa is None: continue
        fl_records += 1
        at = "at_X" if ENI[eni] == x else "at_peer"
        side = "same" if peer.endswith("Ps") else "other"
        cond = x.split("-")[1]
        kk = "%s|%s|%s|%s|%s" % (pa[1], cond, side, at, action)
        fl[kk] = fl.get(kk, 0) + 1
result = {"phases": [(w[2], w[3], round(w[1] - w[0])) for w in win], "console_dumps": len(seen), "bad_dumps": len(bad),
          "summary": summary, "flowlog_objects": fl_objects, "flowlog_records_classified": fl_records, "flowlog": fl}
result
