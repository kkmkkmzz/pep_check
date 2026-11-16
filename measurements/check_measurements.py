"""Checks the live-measurement values quoted in Sect. 4 of the manuscript (v0.15) against the aggregate files
in this repository. Exits non-zero on any mismatch. Run from the repository root or from this directory."""
import collections, json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
J = lambda *p: json.load(open(os.path.join(*p)))
fails = []


def eq(name, got, want):
    ok = got == want
    print(("PASS  " if ok else "FAIL  ") + "%-64s got %s, manuscript %s" % (name, got, want))
    if not ok:
        fails.append(name)


# ---- Sect. 4.2 initial run (EXP-004/005), Table 3
m = J(ROOT, "emulator", "aws", "measure_summary.json")
dd = m["delivery_delay_s"]
eq("4.2 records / objects", (m["records"], m["objects"]), (1861, 18))
eq("4.2 delay n, min, median, p95, max (s)", (dd["n"], dd["min"], dd["median"], dd["p95"], dd["max"]), (1842, 27.0, 179.0, 306.0, 341.0))
eq("4.2 emulator calibration p05 (s)", dd["p05"], 40.0)
t = m["tracked"]
eq("4.2 established survive SG: 5 of 5, 573 ok / 0 failed", (t["n_survived"], t["n_total"], t["exchanges_ok_after_sg"], t["exchanges_failed_after_sg"]), (5, 5, 573, 0))
eq("4.2 new connections: 194/1 before, 0/163 after SG", (t["new_ok_before"], t["new_failed_before"], t["new_ok_after_sg"], t["new_failed_after_sg"]), (194, 1, 0, 163))
n = m["nacl"]
eq("4.2 ACL: other subnet 0/88, same subnet 156/0", (n["cross_ok"], n["cross_failed"], n["same_ok"], n["same_failed"]), (0, 88, 156, 0))
eq("4.2 phase lengths (min)", (m["phase_min"]["sg"], m["phase_min"]["sg_nacl"]), (13.7, 8.5))

# ---- Sect. 4.3 repeated run (EXP-006)
A = os.path.join(HERE, "exp006_a1", "results")
fr = J(A, "a1_flowlog_result_final.json"); cr = J(A, "a1_console_result.json")
eq("4.3 console dumps / bad", (cr["console_dumps"], cr["bad_dumps"]), (890, 0))
eq("4.3 objects, OK records, SKIPDATA", (fr["objects"], fr["log_status"]["OK"], fr["log_status"]["SKIPDATA"]), (43, 102826, 122))
d = fr["delay_s"]
eq("4.3 delay n, median, p95, max (s)", (d["n"], d["p50"], d["p95"], d["max"]), (37427, 175.0, 310.0, 327.0))
od = fr["obj_newest_delay"]
eq("4.3 objects 18-22 s / 173-176 s / 306 s", (sum(18 <= x <= 22 for x in od), sum(173 <= x <= 176 for x in od), od.count(306)), (21, 21, 1))
eq("4.3 SKIPDATA on four interfaces (roles Po, X6 x 2 architectures)", sorted({k.split("|")[0] for k in fr["skip_by_role_phase"] if k.split("|")[0] in ("Po", "X6")}), ["Po", "X6"])
S = cr["summary"]
units = lambda key: S[key]["units"]
cell = lambda act, cond, side, typ: sum(units("%s|%s|%s|%s|%s" % (act, cond, side, fam, typ)).get("ok", 0) for fam in ("4", "6"))
eq("Table 4 est. TCP 5 s, SG same/other", (cell("sg", "Xt", "same", "Te"), cell("sg", "Xt", "other", "Te")), (20, 20))
eq("Table 4 est. TCP 5 s, +ACL same/other", (cell("nacl", "Xt", "same", "Te"), cell("nacl", "Xt", "other", "Te")), (20, 0))
eq("Table 4 est. TCP 5 s, ACL removed other (ok, mixed)", (cell("rev", "Xt", "other", "Te"), sum(units("rev|Xt|other|%s|Te" % f).get("mixed", 0) for f in "46")), (11, 9))
eq("Table 4 idle TCP 90 s, SG same/other", (cell("sg", "Xt", "same", "Ti"), cell("sg", "Xt", "other", "Ti")), (20, 18))
eq("Table 4 idle TCP, ACL removed other (ok, mixed)", (cell("rev", "Xt", "other", "Ti"), sum(units("rev|Xt|other|%s|Ti" % f).get("mixed", 0) for f in "46")), (11, 5))
eq("Table 4 UDP / ICMP est., SG other", (cell("sg", "Xt", "other", "Ue"), cell("sg", "Xt", "other", "Ie")), (20, 20))
eq("Table 4 UDP / ICMP est., ACL removed other", (cell("rev", "Xt", "other", "Ue"), cell("rev", "Xt", "other", "Ie")), (0, 0))
eq("Table 4 new TCP/UDP/ICMP, SG same", sum(cell("sg", "Xt", "same", t_) for t_ in ("Tn", "Un", "In")), 0)
eq("Table 4 untracked: any established, SG same", sum(cell("sg", "Xu", "same", t_) for t_ in ("Te", "Ue", "Ie")), 0)
eq("Table 4 60 s timeout idle TCP, SG same/other", (cell("sg", "X6", "same", "Ti"), cell("sg", "X6", "other", "Ti")), (0, 0))
eq("Table 4 route, other subnet est. TCP", cell("route", "Xt", "other", "Te"), 0)

# ---- Sect. 4.4 attribution run (EXP-008), Table 5
E = os.path.join(HERE, "exp008_attribution")
f8 = J(E, "flowlog_result.json"); c8 = J(E, "console_by_phase.json")
eq("4.4 objects / records", (f8["objects"], f8["n_ok"]), (13, 2785))
eq("4.4 delay median / max (s)", (f8["delay"]["p50"], f8["delay"]["max"]), (160.0, 327.0))
a = f8["agg"]
eq("Table 5b REJECT at X: SG Po new, SG Ps new, ACL Po new, ACL Po est.", (a["SG|X|Po>X|new|REJECT"], a["SG|X|Ps>X|new|REJECT"], a["NACL|X|Po>X|new|REJECT"], a["NACL|X|Po>X|est|REJECT"]), (136, 133, 127, 135))
rd = f8["reject_detail"]
eq("4.4 ACL-phase rejections SYN / no flag", (rd["NACL|X|Po>X|dir=ingress|path=-|reason=-|flags=2"], rd["NACL|X|Po>X|dir=ingress|path=-|reason=-|flags=0"]), (256, 6))
eq("4.4 Po interface ACCEPT to X in ACL phase: new / est.", (a["NACL|Po|Po>X|new|ACCEPT"], a["NACL|Po|Po>X|est|ACCEPT"]), (110, 99))
T5 = {("Ps", "base"): (104, 0, 103, 0), ("Ps", "SG"): (0, 138, 140, 0), ("Ps", "NACL"): (130, 0, 131, 0),
      ("Po", "base"): (106, 0, 106, 0), ("Po", "SG"): (0, 138, 138, 0), ("Po", "NACL"): (0, 134, 0, 134)}
for (peer, ph), want in T5.items():
    v = c8["%s|%s" % (peer, ph)]
    eq("Table 5a %s %s new ok/fail, est. ok/fail" % (peer, ph), tuple(sum(v[r][i] for r in v) for i in range(4)), want)

# ---- Sect. 4.5 72-hour delivery (EXP-007), recomputed from the per-batch histograms
def hist(s):
    c = collections.Counter()
    for kv in (s.split(",") if s else []):
        x, y = kv.split(":"); c[int(x)] += int(y)
    return c


def q(c, p):
    xs = sorted(c.elements()); k = (len(xs) - 1) * p; f = int(k); g = min(f + 1, len(xs) - 1)
    return xs[f] + (xs[g] - xs[f]) * (k - f)


W = {"Seoul": ("seoul_batches.jsonl", 1703, 25575, 290, 336, 1211, 319, (2, 4), 2467, 2999),
     "N. Virginia": ("virginia_batches.jsonl", 1722, 29237, 303, 344, 1040, 319, (1, 2), 2663, 1777)}
late = []
for reg, (fn, nobj, nrec, p50o, p95o, mx, p95r, over600, over306, nodata) in W.items():
    B = [json.loads(l) for l in open(os.path.join(HERE, "exp007_a2", fn))]
    oo = sum((hist(b["oo"]) for b in B), collections.Counter()); rdh = sum((hist(b["rd"]) for b in B), collections.Counter())
    st = collections.Counter()
    for b in B:
        st.update(b["st_in"])
    eq("4.5 %s objects / records" % reg, (sum(oo.values()), sum(rdh.values())), (nobj, nrec))
    eq("4.5 %s object delay (oldest record) p50 / p95 / max" % reg, (q(oo, .5), q(oo, .95), max(oo)), (p50o, p95o, mx))
    eq("4.5 %s record p95 / max" % reg, (q(rdh, .95), max(rdh)), (p95r, mx))
    eq("4.5 %s objects / records over 600 s" % reg, (sum(v for k, v in oo.items() if k > 600), sum(v for k, v in rdh.items() if k > 600)), over600)
    eq("4.5 %s records over 306 s (Sect. 10.1)" % reg, sum(v for k, v in rdh.items() if k > 306), over306)
    eq("4.5 %s NODATA / SKIPDATA" % reg, (st.get("NODATA", 0), st.get("SKIPDATA", 0)), (nodata, 0))
    late += [k for k, v in rdh.items() for _ in range(v) if k > 369]
    eq("4.5 %s latest object apart from those over 600 s <= 369 s" % reg, max(k for k in oo if k <= 600) <= 369, True)
eq("4.5/10.1 records later than 369 s: six, 1,031-1,211 s", (len(late), min(late), max(late)), (6, 1031, 1211))

print("\n%d mismatch(es)" % len(fails) if fails else "\nall measurement values reproduced")
sys.exit(1 if fails else 0)
