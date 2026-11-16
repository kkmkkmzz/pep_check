"""Experiments E1-E4. Fixed seeds; writes results/*.json. Runtime about one minute on one core."""
from __future__ import annotations
import json, os, random, statistics, sys, time
from dataclasses import replace

import containment_emu as emu
from core import (Point, Evidence, TriggerParams, trigger, trigger_count, trigger_node_dedup,
                  iam_closure, select_enforcers, share)

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results")
os.makedirs(OUT, exist_ok=True)
CAL = os.path.join(os.path.dirname(os.path.abspath(__file__)), "aws", "measure_summary.json")
if os.path.exists(CAL):                       # calibrate log delay with the live measurement
    m = json.load(open(CAL))
    emu.calibrate(m["delivery_delay_s"]["p05"], m["delivery_delay_s"]["p95"])


def dump(name, obj):
    with open(os.path.join(OUT, name), "w") as f:
        json.dump(obj, f, indent=1, sort_keys=True)


def wilson(k, n, z=1.96):
    if n == 0:
        return [0.0, 0.0]
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * ((p * (1 - p) / n + z * z / (4 * n * n)) ** 0.5) / d
    return [round(max(0.0, c - h), 4), round(min(1.0, c + h), 4)]


# =============================================================================== E1 trigger
PLANES = ["M1", "M2", "M3"]


def topology(r: random.Random, n_nodes=60, group=4):
    """Nodes with an agent plane and an instance role shared per node group; 1-3 workloads per node."""
    nodes = []
    for i in range(n_nodes):
        plane = "M1" if r.random() < 0.5 else r.choice(["M2", "M3"])
        nodes.append(dict(name=f"n{i}", plane=plane, role=f"role-g{i // group}", pods=r.randint(1, 3)))
    return nodes


def sources(node):
    c = frozenset({node["role"]})
    return [Point(f"{node['name']}/p{j}", f"{node['name']}/p{j}", node["name"], node["plane"], c)
            for j in range(node["pods"])]


FLOWLOG = Point("flowlog", "csp-flowlog", "csp-flowlog", "CSP", frozenset())


def target_on(node):
    return Point("X", f"{node['name']}/x", node["name"], node["plane"], frozenset({node["role"]}))


RULES = {
    "count": lambda X, ev, prm: trigger_count(X, ev),
    "node_dedup": lambda X, ev, prm: trigger_node_dedup(X, ev, prm.theta),
    "ours": lambda X, ev, prm: trigger(X, ev, prm).verdict,
}
ABLATIONS = {
    "ours": TriggerParams(),
    "no_plane_cap": TriggerParams(c_L3=1e9),
    "no_plane_quorum": TriggerParams(k_L3=0),
    "no_control_quorum": TriggerParams(k_C=0),
    "no_cap_no_quorums": TriggerParams(c_L3=1e9, k_L3=0, k_C=0),
}


def fabricate(kind: str, r: random.Random, nodes):
    """Fabricated mismatches against a healthy target Y (first M1 node). Returns (Y, evidence)."""
    y_node = next(n for n in nodes if n["plane"] == "M1")
    Y = target_on(y_node)
    others = [n for n in nodes if n is not y_node and n["role"] != y_node["role"]]

    def pick(pred, k, distinct_roles=True):
        pool = [n for n in others if pred(n)]
        r.shuffle(pool)
        chosen, roles = [], set()
        for n in pool:
            if distinct_roles and n["role"] in roles:
                continue
            chosen.append(n); roles.add(n["role"])
            if len(chosen) == k:
                break
        return chosen

    if kind == "a_one_node":
        ns = pick(lambda n: True, 1)
    elif kind == "b_two_nodes_target_plane":
        ns = pick(lambda n: n["plane"] == "M1", 2)
    elif kind == "c_one_credential_two_planes":
        ns = []
        roles = sorted({n["role"] for n in others})
        r.shuffle(roles)
        for role in roles:                      # one node group whose nodes sit in two planes other than... any two planes
            g = [n for n in others if n["role"] == role]
            if len({n["plane"] for n in g}) >= 2 and any(n["plane"] != "M1" for n in g):
                ns = g
                break
    elif kind == "d_one_other_plane":
        ns = pick(lambda n: n["plane"] == "M2", 4)
    elif kind == "e_two_other_planes":
        ns = pick(lambda n: n["plane"] == "M2", 1) + pick(lambda n: n["plane"] == "M3", 1)
    elif kind == "f_target_plane_plus_one_node":
        ns = pick(lambda n: n["plane"] == "M1", 3) + pick(lambda n: n["plane"] != "M1", 1)
    else:
        raise KeyError(kind)
    ev = [Evidence(s, v=1.0, t=r.uniform(0.5, 1.0)) for n in ns for s in sources(n)]
    return Y, ev


def bypass_case(r: random.Random, nodes, plane_compromised: bool):
    """True bypass of X. Honest witnesses report; sources inside the compromise stay silent."""
    x_node = next(n for n in nodes if n["plane"] == "M1")
    X = target_on(x_node)
    peers = r.sample([n for n in nodes if n is not x_node], r.randint(1, 6))
    ev = []
    for n in peers:
        if plane_compromised and n["plane"] == "M1":
            continue                                   # the plane makes its agents conceal
        for s in sources(n)[:1]:
            ev.append(Evidence(s, v=r.choice([1.0, 1.0, 0.8]), t=r.uniform(0.6, 1.0)))
    if r.random() < 0.9:                               # flow-log interval not skipped
        ev.append(Evidence(FLOWLOG, v=1.0, t=0.95))
    return X, ev


def benign_record_loss(r: random.Random, nodes, gap_visible_p=0.95):
    """Healthy Y loses its own records; honest witnesses report unmatched flows (type I)."""
    y_node = next(n for n in nodes if n["plane"] == "M1")
    Y = target_on(y_node)
    peers = r.sample([n for n in nodes if n is not y_node], r.randint(2, 6))
    gap_seen = r.random() < gap_visible_p              # sequence/heartbeat gap on Y's record path
    ev_gated = [Evidence(s, 1.0, r.uniform(0.6, 1.0), attributed=not gap_seen) for n in peers for s in sources(n)[:1]]
    ev_gated.append(Evidence(FLOWLOG, 1.0, 0.95, attributed=not gap_seen))
    ev_raw = [Evidence(e.source, e.v, e.t, True) for e in ev_gated]
    return Y, ev_gated, ev_raw


def e1(n=4000):
    res = {"n": n, "fabrication": {}, "ablation": {}, "bypass": {}, "sweep_theta": [], "sweep_cap": []}
    kinds = ["a_one_node", "b_two_nodes_target_plane", "c_one_credential_two_planes",
             "d_one_other_plane", "e_two_other_planes", "f_target_plane_plus_one_node"]
    for kind in kinds:
        cnt = {k: 0 for k in RULES}
        abl = {k: 0 for k in ABLATIONS}
        m = 0
        for i in range(n):
            r = random.Random(f"e1|{kind}|{i}")
            Y, ev = fabricate(kind, r, topology(r))
            if not ev:
                continue
            m += 1
            for k, f in RULES.items():
                cnt[k] += f(Y, ev, TriggerParams()) == "CONTAIN"
            for k, prm in ABLATIONS.items():
                abl[k] += trigger(Y, ev, prm).verdict == "CONTAIN"
        res["fabrication"][kind] = {k: round(v / m, 4) for k, v in cnt.items()} | {"n": m}
        res["ablation"][kind] = {k: round(v / m, 4) for k, v in abl.items()}
    # benign record loss, with and without the attribution gate
    g = {"count_no_gate": 0, "ours_no_gate": 0, "ours_gate": 0}
    for i in range(n):
        r = random.Random(f"e1|loss|{i}")
        Y, ev_g, ev_raw = benign_record_loss(r, topology(r))
        g["count_no_gate"] += trigger_count(Y, ev_raw) == "CONTAIN"
        g["ours_no_gate"] += trigger(Y, ev_raw).verdict == "CONTAIN"
        g["ours_gate"] += trigger(Y, ev_g).verdict == "CONTAIN"
    res["record_loss"] = {k: round(v / n, 4) for k, v in g.items()}
    # true bypass: detection rate
    for label, pc in (("plane_intact", False), ("plane_compromised", True)):
        cnt = {k: 0 for k in RULES}
        hold_reason = {"L2": 0, "L3": 0, "C": 0, "score": 0}
        for i in range(n):
            r = random.Random(f"e1|bypass|{label}|{i}")
            X, ev = bypass_case(r, topology(r), pc)
            for k, f in RULES.items():
                cnt[k] += f(X, ev, TriggerParams()) == "CONTAIN"
            tr = trigger(X, ev)
            if tr.verdict == "HOLD":
                p = TriggerParams()
                if tr.n_L2 < p.k_L2: hold_reason["L2"] += 1
                elif tr.n_L3 < p.k_L3: hold_reason["L3"] += 1
                elif tr.n_C < p.k_C: hold_reason["C"] += 1
                else: hold_reason["score"] += 1
        res["bypass"][label] = {k: round(v / n, 4) for k, v in cnt.items()} | {
            "hold_reason": {k: round(v / n, 4) for k, v in hold_reason.items()}}
    # sensitivity: threshold and plane cap
    def rates(prm, m=1500):
        det = fab_d = fab_e = 0
        for i in range(m):
            r = random.Random(f"e1|bypass|plane_intact|{i}")
            X, ev = bypass_case(r, topology(r), False)
            det += trigger(X, ev, prm).verdict == "CONTAIN"
            r = random.Random(f"e1|d_one_other_plane|{i}")
            Y, ev = fabricate("d_one_other_plane", r, topology(r))
            fab_d += trigger(Y, ev, prm).verdict == "CONTAIN"
            r = random.Random(f"e1|e_two_other_planes|{i}")
            Y, ev = fabricate("e_two_other_planes", r, topology(r))
            fab_e += trigger(Y, ev, prm).verdict == "CONTAIN"
        return round(det / m, 4), round(fab_d / m, 4), round(fab_e / m, 4)
    for th in [0.9, 1.1, 1.3, 1.5, 1.7, 1.9, 2.1, 2.3]:
        d, a, b = rates(TriggerParams(theta=th))
        res["sweep_theta"].append({"theta": th, "detect": d, "fab_one_plane": a, "fab_two_planes": b})
    for cap in [0.6, 0.8, 1.0, 1.2, 1.4, 1.6, 2.0, 3.0]:
        d, a, b = rates(TriggerParams(c_L3=cap))
        res["sweep_cap"].append({"cap": cap, "detect": d, "fab_one_plane": a, "fab_two_planes": b})
    for k3 in (1, 2):
        d, a, b = rates(TriggerParams(k_L3=k3))
        res.setdefault("k_L3", []).append({"k_L3": k3, "detect": d, "fab_one_plane": a, "fab_two_planes": b})
    # the five worked cases of the specification
    res["worked_cases"] = worked_cases()
    dump("e1_trigger.json", res)
    return res


def worked_cases():
    def P(pid, node, plane, role):
        return Point(pid, pid, node, plane, frozenset({role}) if role else frozenset())
    out = {}
    X = P("X", "N1", "M1", "rN1")
    ev = [Evidence(P("W1", "N1", "M1", "rN1"), 1, 0.9), Evidence(P("W2", "N1", "M1", "rN1"), 1, 0.9),
          Evidence(P("W3", "N2", "M1", "rN2"), 1, 0.9), Evidence(P("W4", "N3", "M1", "rN3"), 1, 0.8),
          Evidence(P("W5", "N3", "M1", "rN3"), 1, 0.8), Evidence(P("F", "csp-fl", "CSP", None), 1, 0.95)]
    out["1_true_bypass"] = trigger(X, ev).__dict__
    Y = P("Y", "N9", "M1", "rN9")
    ev = [Evidence(P(f"P{i}", "N5", "M1", "rN5"), 1, 1.0) for i in range(5)]
    out["2_one_node"] = trigger(Y, ev).__dict__
    ev = [Evidence(P("A", "N5", "M1", "rN5"), 1, 1.0), Evidence(P("B", "N6", "M1", "rN6"), 1, 1.0)]
    out["3_two_nodes_same_plane"] = trigger(Y, ev).__dict__
    ev = [Evidence(P("F", "csp-fl", "CSP", None), 1, 0.95)]
    out["4_plane_conceals"] = trigger(X, ev).__dict__
    ev = [Evidence(P("A", "N7", "M2", "rN7"), 1, 0.8), Evidence(P("B", "N8", "M2", "rN8"), 1, 0.8)]
    out["5_other_plane"] = trigger(Y, ev).__dict__
    return out


# =============================================================================== E2 containment
BASE = dict(privileged=True, reach_sg=False, iam_miss=False, mp_sg=False, mp_comp=False, reach_net=False,
            reach_all=False, tracked=False, same_hosts=True, v_same=True, ipv6=False, outage=False,
            p_tail=0.05, p_skip=0.02, late=False, p_approve=0.85, n_peers=5)
SCENARIOS = {
    "S0_random_mix": None,
    "S1_tracked_cross_subnet": dict(tracked=True, same_hosts=False),
    "S2_tracked_same_subnet": dict(tracked=True),
    "S3_ipv6_tracked": dict(tracked=True, ipv6=True, same_hosts=False),
    "S4_target_role_modifies_SG": dict(reach_sg=True),
    "S4L_target_role_modifies_SG_late": dict(reach_sg=True, late=True),
    "S5_plane_modifies_SG": dict(mp_sg=True, mp_comp=True),
    "S5L_plane_modifies_SG_late": dict(mp_sg=True, mp_comp=True, late=True),
    "S6_plane_could_modify_SG_but_intact": dict(mp_sg=True, mp_comp=False),
    "S7_outage_plus_revert": dict(reach_sg=True, outage=True),
    "S8_log_delay_skipdata": dict(p_tail=0.5, p_skip=0.2),
    "S9_iam_miss": dict(reach_sg=True, iam_miss=True),
    "S9L_iam_miss_late_LIMITATION": dict(reach_sg=True, iam_miss=True, late=True),
    "S10_no_independent_enforcer": dict(reach_all=True),
    "S11_no_verifier_in_target_subnet": dict(v_same=False),
}


def pct(xs, q):
    xs = sorted(xs)
    if not xs:
        return None
    return xs[min(len(xs) - 1, int(q * len(xs)))]


def summarize(outs):
    n = len(outs)
    dec = {}
    for o in outs:
        dec[o.declared] = dec.get(o.declared, 0) + 1
    fe = sum(o.false_effective for o in outs)
    te = [o.t_decl for o in outs if o.declared == "EFFECTIVE"]
    stops = sum(o.stopped for o in outs)
    return {
        "n": n,
        "false_effective": round(fe / n, 4), "false_effective_ci": wilson(fe, n),
        "residual_exposure": round(sum(o.residual for o in outs) / n, 4),
        "declared": {k: round(v / n, 4) for k, v in sorted(dec.items())},
        "median_t_effective_s": pct(te, 0.5), "p95_t_effective_s": pct(te, 0.95),
        "mean_exposure_min": round(statistics.fmean(o.exposure_min for o in outs), 2),
        "approvals_per_incident": round(sum(o.approvals for o in outs) / n, 4),
        "stops_per_incident": round(stops / n, 4),
        "avoidable_stops_per_incident": round(sum(o.avoidable_stop for o in outs) / n, 4),
        "mean_rounds": round(statistics.fmean(o.rounds for o in outs), 3),
        "mean_api_calls": round(statistics.fmean(o.api_calls for o in outs), 2),
        "mean_probes": round(statistics.fmean(o.probes for o in outs), 2),
        "mean_log_queries": round(statistics.fmean(o.log_queries for o in outs), 2),
    }


def incident(scn, i, mix=None):
    if SCENARIOS.get(scn) is None:
        return emu.random_incident(1_000_000 + i, mix or emu.MIX)
    return emu.Incident(seed=hash_int(scn, i), **(BASE | SCENARIOS[scn]))


def hash_int(*parts):
    return random.Random("|".join(map(str, parts))).getrandbits(48)


def e2(n=2000):
    res = {}
    for scn in SCENARIOS:
        res[scn] = {}
        incs = [incident(scn, i) for i in range(n)]
        for cfg in emu.CONFIGS:
            res[scn][cfg] = summarize([emu.run(inc, cfg) for inc in incs])
    dump("e2_containment.json", res)
    return res


# =============================================================================== E3 scalability
def e3():
    res = {"share_trigger": [], "iam_closure": [], "selection": []}
    for n in [100, 1000, 10000, 100000]:
        r = random.Random(f"e3|{n}")
        nodes = topology(r, n_nodes=max(4, n // 2), group=4)
        srcs = [s for nd in nodes for s in sources(nd)][:n]
        X = target_on(nodes[0])
        ev = [Evidence(s, 1.0, 0.8) for s in srcs]
        ts = []
        for _ in range(5):
            t0 = time.perf_counter(); trigger(X, ev); ts.append(time.perf_counter() - t0)
        res["share_trigger"].append({"sources": len(ev), "ms_median": round(1000 * statistics.median(ts), 3)})
    for roles in [100, 1000, 10000, 100000]:
        r = random.Random(f"e3|iam|{roles}")
        assume = {f"r{i}": [f"r{r.randrange(roles)}" for _ in range(3)] for i in range(roles)}
        ts = []
        for _ in range(5):
            t0 = time.perf_counter(); c = iam_closure(["r0"], assume); ts.append(time.perf_counter() - t0)
        res["iam_closure"].append({"roles": roles, "edges": 3 * roles, "reached": len(c),
                                   "ms_median": round(1000 * statistics.median(ts), 3)})
    for m in [10, 100, 1000, 10000]:
        r = random.Random(f"e3|sel|{m}")
        X = Point("X", "ex", "nx", "M1", frozenset({"role-x", "role-a"}))
        cand = [Point(f"e{i}", f"e{i}", f"e{i}", "CSP", frozenset({f"role-{r.choice('abcdefgh')}"})) for i in range(m)]
        ts = []
        for _ in range(5):
            t0 = time.perf_counter(); select_enforcers(X, cand, "cred-M1"); ts.append(time.perf_counter() - t0)
        res["selection"].append({"candidates": m, "ms_median": round(1000 * statistics.median(ts), 3)})
    res["platform"] = {"python": sys.version.split()[0], "cores_used": 1}
    dump("e3_scalability.json", res)
    return res


# =============================================================================== E4 sensitivity
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
            for cfg in ("B2_SG_apiack", "A1_nosel_verify", "A2_sel_apiack", "FULL"):
                s = summarize([emu.run(inc, cfg) for inc in incs])
                row[cfg] = {k: s[k] for k in ("false_effective", "residual_exposure", "approvals_per_incident",
                                              "stops_per_incident")} | {"unresolved": s["declared"].get("UNRESOLVED", 0.0)}
            res[key].append(row)
    # record delay as documented by the provider (about ten minutes) instead of the measured one
    saved = dict(emu.LOG_DELAY)
    emu.calibrate(540.0, 660.0)
    incs = [emu.random_incident(1_000_000 + i) for i in range(2000)]
    doc = {cfg: summarize([emu.run(inc, cfg) for inc in incs]) for cfg in ("A1_nosel_verify", "FULL")}
    emu.LOG_DELAY.update(saved)
    dump("e4_sensitivity.json", res | {"documented_log_delay": doc})
    res["documented_log_delay"] = doc
    return res


if __name__ == "__main__":
    t0 = time.time()
    r1 = e1(); print("E1 done", round(time.time() - t0, 1), "s")
    r2 = e2(); print("E2 done", round(time.time() - t0, 1), "s")
    if not os.environ.get("PEP_SKIP_E3"):          # wall-clock timings; skipped in the reproducibility check
        r3 = e3(); print("E3 done", round(time.time() - t0, 1), "s")
    r4 = e4(); print("E4 done", round(time.time() - t0, 1), "s")
    dump("meta.json", {"log_delay": emu.LOG_DELAY, "calibrated": os.path.exists(CAL), "mix": emu.MIX})
