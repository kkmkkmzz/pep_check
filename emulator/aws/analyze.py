# Analysis of the live measurement. Runs inside the provider's scripting sandbox (no gzip/base64
# modules there, hence the small pure-Python decoders). Returns aggregates only; the raw flow-log
# objects stay in the bucket.
R = "ap-northeast-2"; B = "<BUCKET_01>"
T1, T2, T3 = 1794312930.39, 1794313755.25, 1794314262.86
ENI = {"<ENI_01>": "X", "<ENI_02>": "P1", "<ENI_03>": "P2"}
INST = {"X": "<INSTANCE_01>", "P1": "<INSTANCE_02>", "P2": "<INSTANCE_03>"}
ALPHA = string.ascii_uppercase + string.ascii_lowercase + string.digits + "+/"
A2I = {ch: i for i, ch in enumerate(ALPHA)}


def b64d(s):
    s = s.strip().rstrip("=")
    out = bytearray(); acc = 0; n = 0
    for ch in s:
        if ch not in A2I:
            continue
        acc = (acc << 6) | A2I[ch]; n += 6
        if n >= 8:
            n -= 8; out.append((acc >> n) & 255)
    return bytes(out)


LBASE = [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258]
LEXT = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0]
DBASE = [1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577]
DEXT = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13]


def build(lengths):
    maxl = max(lengths)
    cnt = [0] * (maxl + 1)
    for l in lengths:
        if l:
            cnt[l] += 1
    code = 0; nxt = [0] * (maxl + 2)
    for b in range(1, maxl + 1):
        code = (code + cnt[b - 1]) << 1; nxt[b] = code
    table = {}
    for sym, l in enumerate(lengths):
        if l:
            table[(l, nxt[l])] = sym; nxt[l] += 1
    return table


def inflate(data, pos):
    st = {"pos": pos, "buf": 0, "cnt": 0}
    out = bytearray()

    def bits(n):
        while st["cnt"] < n:
            st["buf"] |= data[st["pos"]] << st["cnt"]; st["pos"] += 1; st["cnt"] += 8
        v = st["buf"] & ((1 << n) - 1); st["buf"] >>= n; st["cnt"] -= n
        return v

    def dec(table):
        code = 0; l = 0
        while True:
            code = (code << 1) | bits(1); l += 1
            if (l, code) in table:
                return table[(l, code)]
            if l > 15:
                raise ValueError("bad code")

    while True:
        final = bits(1); typ = bits(2)
        if typ == 0:
            st["buf"] = 0; st["cnt"] = 0
            ln = data[st["pos"]] | (data[st["pos"] + 1] << 8); st["pos"] += 4
            out += data[st["pos"]:st["pos"] + ln]; st["pos"] += ln
        else:
            if typ == 1:
                lt = build([8] * 144 + [9] * 112 + [7] * 24 + [8] * 8); dt = build([5] * 30)
            else:
                hlit = bits(5) + 257; hdist = bits(5) + 1; hclen = bits(4) + 4
                cl = [0] * 19
                for i in range(hclen):
                    cl[[16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15][i]] = bits(3)
                ct = build(cl); ls = []
                while len(ls) < hlit + hdist:
                    s = dec(ct)
                    if s < 16:
                        ls.append(s)
                    elif s == 16:
                        ls += [ls[-1]] * (3 + bits(2))
                    elif s == 17:
                        ls += [0] * (3 + bits(3))
                    else:
                        ls += [0] * (11 + bits(7))
                lt = build(ls[:hlit]); dt = build(ls[hlit:hlit + hdist])
            while True:
                s = dec(lt)
                if s < 256:
                    out.append(s)
                elif s == 256:
                    break
                else:
                    s -= 257
                    ln = LBASE[s] + bits(LEXT[s])
                    d = dec(dt)
                    dist = DBASE[d] + bits(DEXT[d])
                    for _ in range(ln):
                        out.append(out[-dist])
        if final:
            break
    return bytes(out), st["pos"]


def gunzip(data):
    out = bytearray(); pos = 0
    while pos + 18 <= len(data) and data[pos] == 0x1F and data[pos + 1] == 0x8B:
        flg = data[pos + 3]; pos += 10
        if flg & 4:
            pos += 2 + (data[pos] | (data[pos + 1] << 8))
        if flg & 8:
            while data[pos]:
                pos += 1
            pos += 1
        if flg & 16:
            while data[pos]:
                pos += 1
            pos += 1
        if flg & 2:
            pos += 2
        chunk, pos = inflate(data, pos)
        out += chunk; pos += 8
    return bytes(out)


def label(sa, da, sp, dp):
    ports = {5001: "c1", 5002: "c2", 5003: "c3", 5004: "c4", 5005: "c5", 5010: "n1", 5011: "n2", 5012: "n3"}
    return ports.get(dp) or ports.get(sp) or "other"


def phase(t):
    if t < T1 - 60: return "0_baseline"
    if T1 + 60 <= t < T2 - 60: return "1_sg"
    if T2 + 60 <= t < T3 - 60: return "2_sg_nacl"
    if t >= T3 + 60: return "3_stopped"
    return "x_transition"


async def s3(op, **p):
    return await call_boto3(service_name="s3", operation_name=op, region_name=R, params=p)

lst = await s3("ListObjectsV2", Bucket=B)
objs = [o for o in lst.get("Contents", []) if o["Size"] > 0]
agg = collections.Counter(); delays = []; status = collections.Counter(); nrec = 0; errs = []
per_obj = []
for o in objs:
    try:
        g = await s3("GetObject", Bucket=B, Key=o["Key"])
        body = g["Body"]
        raw = b64d(body) if isinstance(body, str) else bytes(body)
        txt = gunzip(raw).decode()
    except Exception as e:
        errs.append((o["Key"][-40:], str(e)[:80])); continue
    lm = o["LastModified"]
    lm = datetime.datetime.fromisoformat(lm).timestamp() if isinstance(lm, str) else lm.timestamp()
    lines = txt.splitlines()
    hdr = lines[0].split()
    ix = {h: i for i, h in enumerate(hdr)}
    cnt = 0
    for ln in lines[1:]:
        f = ln.split()
        if len(f) != len(hdr):
            continue
        cnt += 1; nrec += 1
        status[f[ix["log-status"]]] += 1
        if f[ix["log-status"]] != "OK":
            continue
        st_, en = int(f[ix["start"]]), int(f[ix["end"]])
        delays.append(lm - en)
        eni = ENI.get(f[ix["interface-id"]], "other")
        lab = label(f[ix["srcaddr"]], f[ix["dstaddr"]], int(f[ix["srcport"]]), int(f[ix["dstport"]]))
        agg[(eni, lab, f[ix["flow-direction"]], f[ix["action"]], phase(st_))] += 1
    per_obj.append((o["Key"][-28:-7], round(lm), cnt))

delays.sort()
q = lambda p: delays[min(len(delays) - 1, int(p * len(delays)))] if delays else None
out = {
    "now": time.time(), "objects": len(objs), "records": nrec, "errors": errs[:5], "log_status": dict(status),
    "delay": {"n": len(delays), "min": q(0), "p05": q(0.05), "median": q(0.5), "p95": q(0.95), "max": delays[-1] if delays else None,
              "quantiles_5pct_steps": [round(q(i / 20)) for i in range(20)] + [round(delays[-1])] if delays else []},
    "obj_lastmod_sec_mod300": sorted(collections.Counter(int(lm % 300) // 10 * 10 for _, lm, _ in per_obj).items()),
    "agg": sorted([list(k) + [v] for k, v in agg.items() if k[1] != "other" and not k[4].startswith("x")]),
}
# console timelines, one character per 60 s bin from T1-10 min: 2 = all ok, 1 = partial, 0 = all failed, - = no line
tl = {}; sums = {}
for nm, iid in INST.items():
    co = await call_boto3(service_name="ec2", operation_name="GetConsoleOutput", region_name=R, params={"InstanceId": iid, "Latest": True})
    for l in (co.get("Output") or "").splitlines():
        if "PEPM" not in l:
            continue
        f = l[l.find("PEPM"):].split()
        try:
            t = int(f[2])
        except Exception:
            continue
        b = int((t - (T1 - 600)) // 60)
        for kv in f[3:]:
            if "=" not in kv or "/" not in kv:
                continue
            k, v = kv.split("=")
            ok, bad = [int(x) for x in v.split("/")]
            d = tl.setdefault(k, {})
            a = d.setdefault(b, [0, 0]); a[0] += ok; a[1] += bad
            ph = phase(t - 30)
            s_ = sums.setdefault((k, ph), [0, 0]); s_[0] += ok; s_[1] += bad
nb = int((time.time() - (T1 - 600)) // 60)
out["timeline"] = {k: "".join("-" if (b not in d or sum(d[b]) == 0) else ("2" if d[b][1] == 0 else ("0" if d[b][0] == 0 else "1")) for b in range(0, nb)) for k, d in sorted(tl.items())}
out["timeline_counts"] = {k: [v.count(ch) for ch in "210-"] for k, v in out["timeline"].items()}
out["T1"], out["T2"], out["T3"] = T1, T2, T3
out["console_sums"] = sorted([[k, ph, v[0], v[1]] for (k, ph), v in sums.items() if not ph.startswith("x")])
result = out
result
