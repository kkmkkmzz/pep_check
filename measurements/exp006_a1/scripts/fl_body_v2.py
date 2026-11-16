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
PROTO = {"6": "tcp", "17": "udp", "1": "icmp", "58": "icmp"}
def ts(s):
    return datetime.datetime.fromisoformat(str(s).replace("Z", "+00:00")).timestamp()
async def lst(prefix):
    keys = []; tok = None
    while True:
        p = {"Bucket": B, "Prefix": prefix}
        if tok: p["ContinuationToken"] = tok
        r = await call_boto3(service_name="s3", operation_name="ListObjectsV2", params=p)
        keys += [(o["Key"], ts(o["LastModified"])) for o in r.get("Contents", [])]
        tok = r.get("NextContinuationToken")
        if not tok: break
    return keys
async def get(k):
    return (await call_boto3(service_name="s3", operation_name="GetObject", params={"Bucket": B, "Key": k}))["Body"]
ph = []
for k, _ in await lst("a1/phases/"):
    d = json.loads(await get(k))
    if d.get("t_change1"): ph.append(d)
ph.sort(key=lambda d: d["t_change0"])
ph = [p for p in ph if p["t_change0"] >= 1794323220]
win = []
for i, p in enumerate(ph):
    end = ph[i + 1]["t_change0"] if i + 1 < len(ph) else p["t_change1"] + 300
    win.append((p["t_change1"], end, p["rep"], p["act"]))
def phase_of(b0, b1):
    for s, e, rep, act in win:
        if b0 >= s and b1 <= e: return rep, act
    return None
fl = {}; nobj = 0; nrec = 0; ncls = 0; straddle = 0; delay = []; status = {}; skipph = {}; objd = []; lastlm = 0
for k, lm in await lst("a1/AWSLogs/"):
    if lm < 1794323220: continue
    nobj += 1
    lastlm = max(lastlm, lm)
    txt = gunzip(b64d(await get(k))).decode().splitlines()
    oends = []
    for line in txt[1:]:
        f = line.split()
        if len(f) < 20: continue
        status[f[12]] = status.get(f[12], 0) + 1
        if f[9] == "-": continue
        if f[12] != "OK":
            pz = phase_of(int(f[9]), int(f[10]))
            sk = "%s|%s" % (ENI.get(f[1], "other").split("-")[-1], pz[1] if pz else "straddle/outside")
            skipph[sk] = skipph.get(sk, 0) + 1
            continue
        oends.append(int(f[10]))
        nrec += 1
        eni, src, dst, proto, st, en, action = f[1], f[2], f[3], f[6], int(f[9]), int(f[10]), f[11]
        if eni not in ENI or src not in ADDR or dst not in ADDR: continue
        a, b2 = ADDR[src], ADDR[dst]
        x = a if "-X" in a else b2 if "-X" in b2 else None
        if x is None: continue
        peer = b2 if x == a else a
        if "-P" not in peer: continue
        pa = phase_of(st, en)
        if pa is None:
            straddle += 1; continue
        ncls += 1; delay.append(lm - en)
        at = "atX" if ENI[eni] == x else "atP"
        side = "same" if peer.endswith("Ps") else "other"
        dirn = ("toX" if ADDR[dst] == x else "fromX") + "/" + f[18]
        fl_s = "-" if proto != "6" or f[15] == "-" else ("syn" if int(f[15]) & 2 else "nosyn")
        kk = "%s|%s|%s|%s%s|%s|%s|%s" % (pa[1], x.split("-")[1], side, PROTO.get(proto, proto), "" if fl_s == "-" else "." + fl_s, at, dirn, action)
        e = fl.setdefault(kk, [0, 0, set()]); e[0] += 1; e[1] += int(f[7]) if f[7] != "-" else 0; e[2].add(pa[0])
        pass
    if oends: objd.append(int(lm - max(oends)))
delay.sort()
q = lambda p: delay[int((len(delay) - 1) * p)] if delay else None
result = {"last_object_lm": lastlm, "skip_by_role_phase": skipph, "obj_newest_delay": sorted(objd), "objects": nobj, "records": nrec, "classified": ncls, "straddling_phase_change": straddle, "log_status": status,
          "delay_s": {"n": len(delay), "min": delay[0] if delay else None, "p50": q(0.5), "p95": q(0.95), "max": delay[-1] if delay else None},
          "fl": {k: [v[0], v[1], sorted(v[2])] for k, v in sorted(fl.items())}}
result
