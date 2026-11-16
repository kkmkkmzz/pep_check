"""Checks every quantitative value of the manuscript (v0.15) that comes from the emulator or from the
closed-form expressions against the result files in this directory. Exits non-zero on any mismatch.

Run after `python3 run_experiments.py` (E1, E3) and `python3 run_experiments2.py` (E2, E4, E5), or on the
shipped results. Live-measurement values are checked separately by ../measurements/check_measurements.py.
"""
import json, math, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import closed_form as cf
import paired_stats as ps

J = lambda *p: json.load(open(os.path.join(HERE, *p)))
e1 = J("results", "e1_trigger.json"); e3 = J("results", "e3_scalability.json")
e2 = J("results_v2", "e2_containment_v2.json"); e4 = J("results_v2", "e4_sensitivity_v2.json"); e5 = J("results_v2", "e5_integrated.json")
P = e2["S0_pooled"]; S = e2["scenarios"]
fails = []


def eq(name, got, want, tol=0.0):
    if tol and isinstance(want, tuple):
        ok = len(got) == len(want) and all(abs(a - b) <= tol for a, b in zip(got, want))
    else:
        ok = (abs(got - want) <= tol) if isinstance(want, (int, float)) and not isinstance(want, bool) else got == want
    print(("PASS  " if ok else "FAIL  ") + "%-70s got %s, manuscript %s" % (name, got, want))
    if not ok:
        fails.append(name)


TIE = 0.05 + 1e-9  # values exactly at a .x5 boundary (9,755/10,000; 0.2225) are rounded either way in the text
pc = lambda k, n: 100.0 * k / n
r1 = lambda x: float("%.1f" % x)  # same formatting as tools_numbers.py (Python float formatting)
CFG = {"B1": "B1_agent_selfreport", "B2": "B2_SG_apiack", "B3": "B3_SG_naiveprobe", "B4": "B4_SG_NACLv4_apiack",
       "B5": "B5_SG_NACLdual_apiack", "A1": "A1_nosel_verify", "A2": "A2_sel_apiack", "Full": "FULL"}

# ---- Table 10 (S0 pooled, 10,000 incidents)
T10 = {  # k, set range, residual %, declared Π/scope/UNRES %, exposed min, t50/t95 min, approvals, stops, avoidable
    "B1": (6997, (1382, 1411), 70.0, (100.0, 0.0, 0.0), 84.1, (0.1, 0.1), 0.00, 0.00, 0.000),
    "B2": (7561, (1484, 1531), 75.6, (100.0, 0.0, 0.0), 87.5, (0.0, 0.0), 0.00, 0.00, 0.000),
    "B3": (7540, (1478, 1527), 75.6, (99.8, 0.0, 0.2), 87.5, (2.0, 2.0), 0.00, 0.00, 0.000),
    "B4": (4621, (893, 956), 46.2, (100.0, 0.0, 0.0), 53.2, (0.0, 0.0), 0.00, 0.00, 0.000),
    "B5": (3397, (648, 695), 34.0, (100.0, 0.0, 0.0), 38.9, (0.0, 0.0), 0.00, 0.00, 0.000),
    "A1": (575, (108, 126), 9.8, (95.0, 3.6, 1.3), 16.6, (11.1, 41.1), 0.33, 0.28, 0.021),
    "A2": (3085, (602, 638), 33.3, (97.5, 0.0, 2.5), 40.6, (0.0, 0.0), 0.02, 0.02, 0.000),
    "Full": (12, (1, 5), 7.1, (92.5, 5.1, 2.5), 14.9, (11.1, 41.1), 0.35, 0.30, 0.028),
}
for c, (k, rng, res, dec, exp, t, apr, stp, av) in T10.items():
    v = P[CFG[c]]; n = v["n"]; d = v["declared_k"]
    seeds = [e2["S0_by_seed"][str(s)][CFG[c]]["false_effective_k"] for s in range(5)]
    eq("T10 %s false-effective k" % c, v["false_effective_k"], k)
    eq("T10 %s range per set" % c, (min(seeds), max(seeds)), rng)
    eq("T10 %s residual %%" % c, r1(pc(v["residual_k"], n)), res)
    eq("T10 %s declared" % c, tuple(pc(d.get(x, 0), n) for x in ("EFFECTIVE", "EFFECTIVE_PARTIAL", "UNRESOLVED")), dec, TIE)
    eq("T10 %s exposed min" % c, r1(v["mean_exposure_min"]), exp)
    eq("T10 %s time to EFFECTIVE" % c, (r1(v["median_t_effective_s"] / 60), r1(v["p95_t_effective_s"] / 60)), t)
    eq("T10 %s approvals/stops/avoidable" % c, (round(v["approvals_k"] / n, 2), round(v["stops_k"] / n, 2), round(v["avoidable_stops_k"] / n, 3)), (apr, stp, av))
lo, hi = P["FULL"]["false_effective_ci"]; eq("T10 Full Wilson CI %", (round(100 * lo, 2), round(100 * hi, 2)), (0.07, 0.21))
lo, hi = P["A1_nosel_verify"]["false_effective_ci"]; eq("T10 A1 Wilson CI %", (round(100 * lo, 2), round(100 * hi, 2)), (5.31, 6.22))

# ---- closed forms (Table 10 last column and Sect. 10.5)
base = cf.table(); no_est = cf.table(est_on=False); rev = cf.table(revoke=True)
eq("closed form B1/B2/B4/B5 %", tuple(round(100 * base[k], 2) for k in ("B1", "B2", "B4", "B5")), (70.00, 75.30, 46.06, 33.52))
z = max(abs((P[CFG[k]]["false_effective_k"] / 1e4 - base[k]) / math.sqrt(base[k] * (1 - base[k]) / 1e4)) for k in ("B1", "B2", "B4", "B5"))
eq("closed form max |z| <= 0.95", round(z, 2) <= 0.95, True)
eq("two-step bound B2/B5 %", (round(100 * no_est["B2"], 2), round(100 * no_est["B5"], 2)), (38.26, 17.59))
eq("linear in f: B2/B4/B5 slopes %", tuple(round(100 * (base[k] - no_est[k]), 2) for k in ("B2", "B4", "B5")), (37.04, 22.26, 15.93))
eq("linear in f: B4 intercept %", round(100 * no_est["B4"], 2), 23.79)
eq("revocation bound B2/B4/B5 %", tuple(round(100 * rev[k], 2) for k in ("B2", "B4", "B5")), (64.00, 37.12, 25.60))

# ---- Sect. 10.5 text
F = P["FULL"]; rb = F["residual_by_declared_k"]
eq("Full residual 707 = UNRESOLVED 246 + scope 451 + EFFECTIVE 10", (F["residual_k"], rb.get("UNRESOLVED"), rb.get("EFFECTIVE_PARTIAL"), rb.get("EFFECTIVE")), (707, 246, 451, 10))
mc = e2["mcnemar_S0_pooled"]
eq("McNemar Full vs A1 discordant", tuple(mc["FULL vs A1_nosel_verify"][:2]), (0, 563))
eq("McNemar Full vs B5 discordant", tuple(mc["FULL vs B5_SG_NACLdual_apiack"][:2]), (0, 3385))
eq("Full vs earlier rules discordant", tuple(mc["FULL vs FULL_v1rules"][:2]), (0, 0))
d, l, h = ps.newcombe_paired(12, 0, 563, 10000 - 575)
eq("Newcombe Full vs A1 (pp)", (round(100 * d, 2), round(100 * l, 2), round(100 * h, 2)), (5.63, 5.19, 6.10))
d, l, h = ps.newcombe_paired(12, 0, 3385, 10000 - 3397)
eq("Newcombe Full vs B5 (pp)", (round(100 * d, 2), round(100 * l, 2), round(100 * h, 2)), (33.85, 32.93, 34.78))
eq("FE | EFFECTIVE declared: Full %, A1 %", (round(100 * F["false_effective_given_declared"], 2), round(100 * P["A1_nosel_verify"]["false_effective_given_declared"], 1)), (0.12, 5.8))
eq("A1 with earlier rules k", P["A1_v1rules"]["false_effective_k"], 604)
eq("Full stops 3,005 of 10,000; A1 stop rate %", (F["stops_k"], round(pc(P["A1_nosel_verify"]["stops_k"], 1e4), 1)), (3005, 27.6))
eq("Full avoidable stop rate %", r1(pc(F["avoidable_stops_k"], 1e4)), 2.8)

# ---- Table 11
T11 = {  # B2 B5 A1 Full Full-earlier (%), declared Π/scope/UNRES (%), stops, residual %
    "S1": (100, 0, 0, 0, 0, (100, 0, 0), 0.00, 0), "S2": (100, 100, 0, 0, 0, (84, 16, 0), 0.84, 16),
    "S3": (100, 0, 0, 0, 0, (100, 0, 0), 0.00, 0), "S4": (100, 100, 0, 0, 0, (85, 15, 0), 0.85, 15),
    "S4L": (100, 100, 100, 0, 0, (85, 15, 0), 0.85, 15), "S5": (100, 100, 0, 0, 0, (85, 15, 0), 0.85, 15),
    "S5L": (100, 100, 100, 0, 0, (85, 15, 0), 0.85, 15), "S6": (0, 0, 0, 0, 0, (86, 14, 0), 0.86, 0),
    "S7": (100, 100, 4, 0, 0, (85, 15, 0), 0.85, 15), "S8": (0, 0, 0, 0, 0, (100, 0, 0), 0.02, 0),
    "S9": (100, 100, 0, 0, 0, (85, 0, 15), 0.85, 15), "S9L": (100, 100, 100, 100, 100, (100, 0, 0), 0.00, 100),
    "S10": (100, 100, 84, 0, 0, (0, 0, 100), 0.00, 100), "S11": (0, 0, 0, 0, 0, (85, 15, 0), 0.85, 0),
    "S12": (100, 100, 0, 0, 100, (83, 17, 0), 0.83, 17), "S13": (100, 100, 100, 0, 100, (86, 0, 14), 0.86, 14),
    "S14": (100, 100, 0, 0, 0, (85, 0, 15), 0.85, 15),
}
byid = {k.split("_")[0]: v for k, v in S.items()}
for s, (b2, b5, a1, fu, fv1, dec, stp, res) in T11.items():
    d = byid[s]; n = d["FULL"]["n"]; g = lambda c: round(pc(d[c]["false_effective_k"], n))
    eq("T11 %s false-effective B2/B5/A1/Full/Full-earlier" % s, (g("B2_SG_apiack"), g("B5_SG_NACLdual_apiack"), g("A1_nosel_verify"), g("FULL"), g("FULL_v1rules")), (b2, b5, a1, fu, fv1))
    dk = d["FULL"]["declared_k"]
    eq("T11 %s Full declared/stops/residual" % s, (tuple(round(pc(dk.get(x, 0), n)) for x in ("EFFECTIVE", "EFFECTIVE_PARTIAL", "UNRESOLVED")), round(d["FULL"]["stops_k"] / n, 2), round(pc(d["FULL"]["residual_k"], n))), (dec, stp, res))
eq("S7 A1 with Δt = 60 s %", round(pc(byid["S7"]["A1_v1rules"]["false_effective_k"], 2000)), 34)
eq("S8 Full EFFECTIVE Π / scope, median min", (byid["S8"]["FULL"]["declared_k"].get("EFFECTIVE"), byid["S8"]["FULL"]["declared_k"].get("EFFECTIVE_PARTIAL"), r1(byid["S8"]["FULL"]["median_t_effective_s"] / 60)), (1994, 6, 20.2))
eq("S10 A1 stops per incident", round(byid["S10"]["A1_nosel_verify"]["stops_k"] / 2000, 2), 0.84)

# ---- Table 12 (integrated run)
T12 = {"B2_SG_apiack": ((1696, 0, 0), 1256, 1560, 90.8), "B5_SG_NACLdual_apiack": ((1696, 0, 0), 553, 857, 49.8),
       "A1_nosel_verify": ((1615, 66, 15), 103, 465, 31.6), "FULL": ((1572, 85, 39), 1, 411, 29.9)}
for c, (dec, fe, res, exp) in T12.items():
    v = e5[c]; t = v["table_k"]
    eq("T12 %s held" % c, t.get("HOLD/not contained"), 304)
    eq("T12 %s contained Π/scope/UNRES" % c, (t.get("CONTAIN/EFFECTIVE", 0), t.get("CONTAIN/EFFECTIVE_PARTIAL", 0), t.get("CONTAIN/UNRESOLVED", 0)), dec)
    eq("T12 %s false-effective, residual, exposed" % c, (v["false_effective_k"], v["residual_k"], r1(v["mean_exposure_min"])), (fe, res, exp))

# ---- Table 13
T13 = {"B2_SG_apiack": (0.00, 1.0, 0.0, 0.0, 0.0), "B5_SG_NACLdual_apiack": (0.00, 8.8, 0.0, 0.0, 0.0), "A2_sel_apiack": (0.00, 14.2, 0.0, 0.0, 0.0),
       "A1_nosel_verify": (1.12, 16.6, 7.2, 23.2, 2.2), "FULL": (0.99, 15.2, 5.9, 21.7, 2.0)}
for c, want in T13.items():
    v = P[c]
    eq("T13 %s" % c, (round(v["mean_rounds"], 2), r1(v["mean_api_calls"]), r1(v["mean_probes"]), r1(v["mean_log_queries"]), r1(v["mean_snapshot_reads"])), want)

# ---- Sect. 10.6 documented delay and Sect. 10.7 sensitivity
doc = e4["documented_log_delay"]
eq("10.6 documented delay: Full median/p95 min", (r1(doc["FULL"]["median_t_effective_s"] / 60), r1(doc["FULL"]["p95_t_effective_s"] / 60)), (17.0, 47.0))
eq("10.6 documented delay: Full / A1 false reports", (doc["FULL"]["false_effective_k"], doc["A1_nosel_verify"]["false_effective_k"]), (1, 116))
rows = lambda key, c, f: [f(r[c]) for r in e4[key]]
fe = lambda s: s["false_effective_k"] / s["n"]
b2 = rows("tracked", "B2_SG_apiack", fe); b5 = rows("tracked", "B5_SG_NACLdual_apiack", fe); a1 = rows("late", "A1_nosel_verify", fe)
eq("10.7 B2 range over tracked share %", (r1(100 * min(b2)), r1(100 * max(b2))), (36.4, 93.4))
eq("10.7 B5 range over tracked share %", (r1(100 * min(b5)), r1(100 * max(b5))), (16.6, 40.6))
eq("10.7 A1 range over strategic share %", (r1(100 * min(a1)), r1(100 * max(a1))), (1.5, 9.8))
mx = max(fe(r["FULL"]) for k, rr in e4.items() if k != "documented_log_delay" for r in rr)
eq("10.7 Full max false-effective %", r1(100 * mx), 0.8)
viol = sum(1 for k, rr in e4.items() if k != "documented_log_delay" for r in rr
           if not (r["FULL"]["false_effective_k"] <= r["A1_nosel_verify"]["false_effective_k"] <= r["B5_SG_NACLdual_apiack"]["false_effective_k"] <= r["B2_SG_apiack"]["false_effective_k"]))
eq("10.7 ordering Full <= A1 <= B5 <= B2 at every point (violations)", viol, 0)
st = rows("v_same", "FULL", lambda s: s["stops_k"] / s["n"]); st2 = rows("tracked", "FULL", lambda s: s["stops_k"] / s["n"])
eq("10.7 stops over verifier coverage", (round(max(st), 2), round(min(st), 2)), (0.33, 0.27))
eq("10.7 stops over tracked share", (round(min(st2), 2), round(max(st2), 2)), (0.21, 0.34))
ra = rows("p_approve", "FULL", lambda s: s["residual_k"] / s["n"])
eq("10.7 residual at approval 0.5 / 1.0 %", (r1(100 * ra[0]), r1(100 * ra[-1])), (17.1, 2.2))

# ---- Table 9 and Sect. 10.4 (trigger, E1)
fab = e1["fabrication"]; abl = e1["ablation"]
T9 = {"a_one_node": (67, 0, 0, 0, 0), "b_two_nodes_target_plane": (100, 77, 0, 0, 0), "c_one_credential_two_planes": (100, 100, 0, 0, 100),
      "d_one_other_plane": (100, 100, 0, 100, 0), "e_two_other_planes": (100, 76, 72, 72, 76), "f_target_plane_plus_one_node": (100, 100, 100, 100, 100)}
for case, want in T9.items():
    f_ = fab[case]; a_ = abl[case]
    eq("T9 %s" % case, tuple(round(100 * x) for x in (f_["count"], f_["node_dedup"], f_["ours"], a_["no_plane_cap"], a_["no_control_quorum"])), want)
bp = e1["bypass"]
eq("10.4 detection intact: count / ours %", (r1(100 * bp["plane_intact"]["count"]), r1(100 * bp["plane_intact"]["ours"])), (98.6, 95.1))
eq("10.4 detection compromised: count / ours %", (r1(100 * bp["plane_compromised"]["count"]), r1(100 * bp["plane_compromised"]["ours"])), (80.3, 73.0))
eq("10.4 node-quorum holds with compromised plane %", 100 * bp["plane_compromised"]["hold_reason"]["L2"], 22.3, TIE)
eq("10.4 record loss with gate %", r1(100 * e1["record_loss"]["ours_gate"]), 4.3)
th = {round(r["theta"], 1): r for r in e1["sweep_theta"]}; cp = {round(r["cap"], 1): r for r in e1["sweep_cap"]}
eq("Fig4b theta 0.9 one-plane / 1.5 two-plane / 2.1 two-plane %", (round(100 * th[0.9]["fab_one_plane"]), round(100 * th[1.5]["fab_two_planes"]), round(100 * th[2.1]["fab_two_planes"])), (100, 70, 0))
eq("Fig4b detection at theta 1.5 / 2.1 %", (r1(100 * th[1.5]["detect"]), r1(100 * th[2.1]["detect"])), (94.7, 66.3))
eq("Fig4c cap 1.6 one-plane / cap 0.6 detection %", (round(100 * cp[1.6]["fab_one_plane"]), r1(100 * cp[0.6]["detect"])), (100, 66.7))
kl = {r["k_L3"]: r for r in e1["k_L3"]}
eq("10.4 k_L3 = 2: two-plane / detection %", (round(100 * kl[2]["fab_two_planes"]), r1(100 * kl[2]["detect"])), (70, 77.1))

# ---- Sect. 10.8 (wall-clock; reported, not asserted)
print("INFO  10.8 timings (wall clock, vary between runs):",
      {"share 1k/100k ms": [r["ms_median"] for r in e3["share_trigger"] if r["sources"] in (1000, 100000)],
       "closure 10k/100k ms": [r["ms_median"] for r in e3["iam_closure"] if r["roles"] in (10000, 100000)],
       "selection 10k ms": [r["ms_median"] for r in e3["selection"] if r["candidates"] == 10000]})

print("\n%d mismatch(es)" % len(fails) if fails else "\nall manuscript values reproduced")
sys.exit(1 if fails else 0)
