"""Turns the aggregate returned by aws/analyze.py (saved as sandbox_output.json) into measure_summary.json."""
import json, os
H = os.path.dirname(os.path.abspath(__file__))
o = json.load(open(os.path.join(H, "sandbox_output.json")))
T1, T2, T3 = o["T1"], o["T2"], o["T3"]
LONG, NEW = ["c1", "c2", "c3", "c4", "c5"], ["n1", "n2", "n3"]
console = {}
for k, ph, ok, bad in o["console_sums"]:
    console.setdefault(k, {})[ph] = [ok, bad]
g = lambda k, ph: console.get(k, {}).get(ph, [0, 0])
flow = o["agg"]
cnt = lambda pred: sum(r[5] for r in flow if pred(*r[:5]))
tl = o["timeline"]
for k, s in tl.items():                                   # transcription guard: character counts must match
    assert [s.count(ch) for ch in "210-"] == o["timeline_counts"][k], k
rows = {}
DESC = {"c1": "c1 est. P1→X (other subnet)", "c2": "c2 est. X→P1 (other subnet)", "c5": "c5 est. P1→X, idle 4 min",
        "c3": "c3 est. P2→X (same subnet)", "c4": "c4 est. X→P2 (same subnet)",
        "n1": "n1 new P1→X", "n3": "n3 new X→P1", "n2": "n2 new P2→X"}
for k in ["c1", "c2", "c5", "c3", "c4", "n1", "n3", "n2"]:
    rows[DESC[k]] = [[b - 10, {"2": 1.0, "1": 0.5, "0": 0.0, "-": None}[ch]] for b, ch in enumerate(tl[k])]
d = o["delay"]
out = {
    "date_utc": "2026-11-10", "region": "ap-northeast-2", "instance_type": "t3.micro", "T1": T1, "T2": T2, "T3": T3,
    "phase_min": {"sg": round((T2 - T1) / 60, 1), "sg_nacl": round((T3 - T2) / 60, 1)},
    "console": console,
    "tracked": {
        "n_total": len(LONG),
        "n_survived": sum(1 for k in LONG if g(k, "1_sg")[0] > 0 and g(k, "1_sg")[1] == 0),
        "exchanges_ok_after_sg": sum(g(k, "1_sg")[0] for k in LONG), "exchanges_failed_after_sg": sum(g(k, "1_sg")[1] for k in LONG),
        "new_ok_before": sum(g(k, "0_baseline")[0] for k in NEW), "new_failed_before": sum(g(k, "0_baseline")[1] for k in NEW),
        "new_ok_after_sg": sum(g(k, "1_sg")[0] for k in NEW), "new_failed_after_sg": sum(g(k, "1_sg")[1] for k in NEW),
    },
    "nacl": {
        "cross_ok": sum(g(k, "2_sg_nacl")[0] for k in ("c1", "c2", "c5")), "cross_failed": sum(g(k, "2_sg_nacl")[1] for k in ("c1", "c2", "c5")),
        "same_ok": sum(g(k, "2_sg_nacl")[0] for k in ("c3", "c4")), "same_failed": sum(g(k, "2_sg_nacl")[1] for k in ("c3", "c4")),
    },
    "stop": {"ok": sum(g(k, "3_stopped")[0] for k in LONG + NEW), "failed": sum(g(k, "3_stopped")[1] for k in LONG + NEW)},
    "flow": {
        "rows": flow,
        "X_accept_established_sg": cnt(lambda e, l, dr, a, p: e == "X" and l in LONG and a == "ACCEPT" and p == "1_sg"),
        "X_reject_established_sg": cnt(lambda e, l, dr, a, p: e == "X" and l in LONG and a == "REJECT" and p == "1_sg"),
        "X_accept_new_sg": cnt(lambda e, l, dr, a, p: e == "X" and l in NEW and a == "ACCEPT" and p == "1_sg"),
        "X_reject_new_sg": cnt(lambda e, l, dr, a, p: e == "X" and l in NEW and a == "REJECT" and p == "1_sg"),
        "P1_reject_to_X_nacl": cnt(lambda e, l, dr, a, p: e == "P1" and l in ("c1", "c2", "c5", "n1", "n3") and a == "REJECT" and p == "2_sg_nacl"),
        "P1_accept_to_X_nacl": cnt(lambda e, l, dr, a, p: e == "P1" and l in ("c1", "c2", "c5", "n1", "n3") and a == "ACCEPT" and p == "2_sg_nacl"),
        "X_ingress_from_P1_nacl": cnt(lambda e, l, dr, a, p: e == "X" and l in ("c1", "c5", "n1") and dr == "ingress" and p == "2_sg_nacl"),
        "X_accept_same_subnet_nacl": cnt(lambda e, l, dr, a, p: e == "X" and l in ("c3", "c4") and a == "ACCEPT" and p == "2_sg_nacl"),
        "X_records_after_stop": cnt(lambda e, l, dr, a, p: e == "X" and p == "3_stopped"),
    },
    "delivery_delay_s": {k: d[k] for k in ("n", "min", "p05", "median", "p95", "max")},
    "delivery_delay_samples_s": d["quantiles_5pct_steps"],
    "log_status": o["log_status"], "objects": o["objects"], "records": o["records"],
    "timeline": {"rows": rows, "bin_min": 1, "t_min": -10, "t_max": max(len(s) for s in tl.values()) - 10,
                 "phases": {"SG swap": 0.0, "ACL deny": round((T2 - T1) / 60, 2), "stop": round((T3 - T1) / 60, 2)}},
}
json.dump(out, open(os.path.join(H, "measure_summary.json"), "w"), indent=1)
print(json.dumps({k: out[k] for k in ("tracked", "nacl", "stop", "delivery_delay_s", "log_status", "objects", "records")}, indent=1))
print({k: v for k, v in out["flow"].items() if k != "rows"})
