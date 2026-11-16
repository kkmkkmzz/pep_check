"""Experiments for manuscript v0.6 with emulator version 2 (containment_emu2.py).

E2v2  containment: S0 random mix with five independent incident sets (seeds 0-4, 2,000 each) and
      the targeted scenarios S1-S14 (2,000 incidents each, seed set 0); integer counts; paired
      McNemar tests on the same incidents.
E4v2  sensitivity: one-at-a-time variation of the random mix, 1,000 incidents per point.
E5    integrated trigger-to-declaration run on the S0 incidents of seed set 0: the trigger of
      Sect. 6 decides on a true bypass first; held incidents are not contained.
E1 (trigger) and E3 (scalability) are unchanged and taken from run_experiments.py.
Writes results_v2/*.json.
"""
from __future__ import annotations
import json, math, os, random, statistics, sys, time

import containment_emu2 as emu
import run_experiments as v1                     # helpers for E1-style trigger cases; calibrates version 1 only
from core import trigger

H = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(H, "results_v2")
os.makedirs(OUT, exist_ok=True)
m = json.load(open(os.path.join(H, "aws", "measure_summary.json")))
emu.calibrate(m["delivery_delay_s"]["p05"], m["delivery_delay_s"]["p95"])

SEED_SETS = 5
N = 2000
SCENARIOS = dict(v1.SCENARIOS)
SCENARIOS.update({
    "S12_second_subnet_other_acl": dict(tracked=True, same_hosts=False, two_subnets=True),
    "S13_inactive_sg_forged_reject": dict(reach_net=True, sg_inactive=True, adv_acl=True, late=True, same_hosts=False),
    "S14_inactive_sg": dict(sg_inactive=True),
})
BASE = dict(v1.BASE)


def dump(name, obj):
    with open(os.path.join(OUT, name), "w") as f:
        json.dump(obj, f, indent=1, sort_keys=True)


def incident(scn, i, s=0, mix=None):
    if SCENARIOS.get(scn) is None:
        return emu.random_incident(1_000_000 + 100_000 * s + i, mix or emu.MIX)
    return emu.Incident(seed=v1.hash_int(scn, i), **(BASE | SCENARIOS[scn]))


def pct(xs, q):
    if not xs:
        return None
    xs = sorted(xs)
    return round(xs[min(len(xs) - 1, int(q * (len(xs) - 1) + 0.5))], 1)


def summarize(outs):
    n = len(outs)
    dec = {}
    for o in outs:
        dec[o.declared] = dec.get(o.declared, 0) + 1
    fe = sum(o.false_effective for o in outs)
    n_eff = sum(o.declared != "UNRESOLVED" for o in outs)
    res_by = {}
    for o in outs:
        res_by[o.declared] = res_by.get(o.declared, 0) + o.residual
    te = [o.t_decl for o in outs if o.declared != "UNRESOLVED"]
    return {
        "n": n, "false_effective_k": fe, "false_effective": fe / n, "false_effective_ci": v1.wilson(fe, n),
        "declared_effective_any_k": n_eff,
        "false_effective_given_declared": (fe / n_eff) if n_eff else None,
        "declared_k": dec, "residual_k": sum(o.residual for o in outs), "residual_by_declared_k": res_by,
        "median_t_effective_s": pct(te, 0.5), "p95_t_effective_s": pct(te, 0.95),
        "mean_exposure_min": statistics.fmean(o.exposure_min for o in outs),
        "approvals_k": sum(o.approvals for o in outs), "stops_k": sum(o.stopped for o in outs),
        "avoidable_stops_k": sum(o.avoidable_stop for o in outs),
        "failed_rounds_k": sum(o.failed_rounds for o in outs),
        "mean_rounds": statistics.fmean(o.rounds for o in outs),
        "mean_api_calls": statistics.fmean(o.api_calls for o in outs),
        "mean_probes": statistics.fmean(o.probes for o in outs),
        "mean_log_queries": statistics.fmean(o.log_queries for o in outs),
        "mean_snapshot_reads": statistics.fmean(o.snapshot_reads for o in outs),
    }


def mcnemar(a, b):
    """Exact two-sided McNemar test on paired booleans. Returns (a_only, b_only, p)."""
    a_only = sum(1 for x, y in zip(a, b) if x and not y)
    b_only = sum(1 for x, y in zip(a, b) if y and not x)
    k, n = min(a_only, b_only), a_only + b_only
    if n == 0:
        return a_only, b_only, 1.0
    p = sum(math.comb(n, i) for i in range(k + 1)) / 2 ** n
    return a_only, b_only, min(1.0, 2 * p)


PAIRS = [("FULL", "A1_nosel_verify"), ("FULL", "B5_SG_NACLdual_apiack"), ("FULL", "FULL_v1rules"),
         ("A1_nosel_verify", "B5_SG_NACLdual_apiack")]


def e2():
    res = {"S0_by_seed": {}, "S0_pooled": {}, "scenarios": {}, "mcnemar_S0_pooled": {}}
    pooled = {c: [] for c in emu.CONFIGS}
    for s in range(SEED_SETS):
        incs = [incident("S0_random_mix", i, s) for i in range(N)]
        res["S0_by_seed"][s] = {}
        for c in emu.CONFIGS:
            outs = [emu.run(inc, c) for inc in incs]
            pooled[c] += outs
            res["S0_by_seed"][s][c] = summarize(outs)
    res["S0_pooled"] = {c: summarize(o) for c, o in pooled.items()}
    for a, b in PAIRS:
        res["mcnemar_S0_pooled"][f"{a} vs {b}"] = mcnemar([o.false_effective for o in pooled[a]],
                                                          [o.false_effective for o in pooled[b]])
    for scn in SCENARIOS:
        if SCENARIOS[scn] is None:
            continue
        incs = [incident(scn, i) for i in range(N)]
        res["scenarios"][scn] = {c: summarize([emu.run(inc, c) for inc in incs]) for c in emu.CONFIGS}
    dump("e2_containment_v2.json", res)
    return res


def e4(n=1000):
    sweeps = {
        "late": [0.0, 0.25, 0.5, 0.75, 1.0],
        "iam_miss": [0.0, 0.05, 0.1, 0.2, 0.4],
        "p_approve": [0.5, 0.7, 0.85, 1.0],
        "v_same": [0.3, 0.5, 0.7, 0.9, 1.0],
        "tracked": [0.0, 0.3, 0.6, 0.9],
        "reach_sg": [0.0, 0.15, 0.3, 0.6],
    }
    res = {}
    for key, vals in sweeps.items():
        res[key] = []
        for v in vals:
            mix = dict(emu.MIX); mix[key] = v
            incs = [emu.random_incident(2_000_000 + i, mix) for i in range(n)]
            row = {"value": v}
            for c in ("B2_SG_apiack", "B5_SG_NACLdual_apiack", "A1_nosel_verify", "A2_sel_apiack", "FULL"):
                row[c] = summarize([emu.run(inc, c) for inc in incs])
            res[key].append(row)
    saved = dict(emu.LOG_DELAY)
    emu.calibrate(540.0, 660.0)
    incs = [emu.random_incident(1_000_000 + i) for i in range(N)]
    res["documented_log_delay"] = {c: summarize([emu.run(inc, c) for inc in incs]) for c in ("A1_nosel_verify", "FULL")}
    emu.LOG_DELAY.update(saved)
    dump("e4_sensitivity_v2.json", res)
    return res


def e5():
    """Integrated run: trigger on a true bypass, then containment for the triggered incidents."""
    incs = [incident("S0_random_mix", i, 0) for i in range(N)]
    rows = {}
    for c in ("B2_SG_apiack", "B5_SG_NACLdual_apiack", "A1_nosel_verify", "FULL"):
        tab = {}
        fe = res_ = 0
        expo = []
        for i, inc in enumerate(incs):
            r = random.Random(f"e5|bypass|{i}")
            X, ev = v1.bypass_case(r, v1.topology(r), plane_compromised=inc.mp_comp)
            trig = trigger(X, ev).verdict
            if trig == "HOLD":
                key = "HOLD/not contained"
                res_ += 1
                expo.append(emu.EXPOSURE_WINDOW / 60.0)
            else:
                o = emu.run(inc, c)
                key = "CONTAIN/" + o.declared
                fe += o.false_effective
                res_ += o.residual
                expo.append(o.exposure_min)
            tab[key] = tab.get(key, 0) + 1
        rows[c] = {"n": N, "table_k": tab, "false_effective_k": fe, "residual_k": res_,
                   "mean_exposure_min": statistics.fmean(expo)}
    dump("e5_integrated.json", rows)
    return rows


if __name__ == "__main__":
    t0 = time.time()
    e2(); print("E2v2", round(time.time() - t0, 1), "s")
    e4(); print("E4v2", round(time.time() - t0, 1), "s")
    e5(); print("E5", round(time.time() - t0, 1), "s")
    dump("meta_v2.json", {"log_delay": emu.LOG_DELAY, "apply_max_s": emu.APPLY_MAX, "grace_s": emu.GRACE,
                          "rules": emu.RULES, "seed_sets": SEED_SETS, "n": N, "mix": emu.MIX,
                          "python": sys.version.split()[0]})
