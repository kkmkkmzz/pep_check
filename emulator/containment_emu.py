"""Discrete-event emulation of the containment loop under AWS enforcement semantics.

Semantics encoded (see manuscript Table 5; items marked [M] were checked on a live VPC, Sect. 9):
  * security group (SG): stateful; blocks new connections on the target interface, does not
    interrupt connections that are already tracked [M]
  * network ACL (NACL): stateless; deny entries for the target address in other subnets block new
    and existing cross-subnet traffic, but never traffic inside the target's subnet [M]
  * instance stop: blocks everything; requires operator approval
  * flow logs: one-minute aggregation, delivery delay after the interval end, SKIPDATA intervals,
    records carry ACCEPT/REJECT and the interface, so the rejecting layer can be told apart [M]
Time is in seconds from detection (t = 0).
"""
from __future__ import annotations
import random
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from core import Point, select_enforcers, decide, FAILED, EFFECTIVE, INCONCLUSIVE

HORIZON = 3600.0          # ground-truth window after a declaration
EXPOSURE_WINDOW = 7200.0  # window for exposure-minutes
DT = 60.0                 # tolerance after T_iso before records are evaluated
PROBE_SPAN = 120.0        # probes are spread over this span after T_iso + DT
PROBES_PER_CLASS = 3
MAX_FAIL, MAX_INCONC = 2, 3
APPROVAL_TIMEOUT = 1800.0

# Flow-log delivery delay after the end of the aggregation interval (seconds).
# Defaults follow the provider documentation; calibrate() overrides them with measured values.
LOG_DELAY = {"lo": 540.0, "hi": 660.0, "tail_lo": 300.0, "tail_hi": 1800.0}


def _rng(*parts) -> random.Random:
    """Deterministic stream per (incident, purpose); string seeds do not depend on PYTHONHASHSEED."""
    return random.Random("|".join(str(p) for p in parts))


def calibrate(lo: float, hi: float) -> None:
    LOG_DELAY["lo"], LOG_DELAY["hi"] = float(lo), float(hi)


CONFIGS = ["B1_agent_selfreport", "B2_SG_apiack", "B3_SG_naiveprobe", "B4_SG_NACLv4_apiack",
           "A1_nosel_verify", "A2_sel_apiack", "FULL"]

# Random-mix probabilities (manuscript Table 6). They are assumptions, varied in experiment E4.
MIX = dict(privileged=0.70, reach_sg=0.30, iam_miss=0.05, mp_sg=0.20, mp_comp=0.50, reach_net=0.05,
           reach_all=0.02, tracked=0.60, same_hosts=0.40, v_same=0.70, ipv6=0.30, outage=0.10,
           p_tail=0.05, p_skip=0.02, late=0.50, p_approve=0.85)


@dataclass
class Incident:
    seed: int
    privileged: bool = True
    reach_sg: bool = False     # target's role can (truly) reach a role that modifies security groups
    iam_miss: bool = False     # the IAM analysis misses that edge
    mp_sg: bool = False        # management-plane credential can modify security groups
    mp_comp: bool = False      # adversary controls the target's management plane
    reach_net: bool = False    # target can reach the role that modifies network ACLs
    reach_all: bool = False    # target can reach every role, including instance start/stop
    tracked: bool = False      # long-lived tracked connections exist
    same_hosts: bool = False   # other hosts exist in the target's subnet
    v_same: bool = True        # verifier has an interface in the target's subnet
    ipv6: bool = False
    outage: bool = False       # target answers nothing (hung service)
    p_tail: float = 0.05
    p_skip: float = 0.02
    late: bool = False         # strategic adversary: silent during verification, reverts late
    p_approve: float = 0.85
    n_peers: int = 5

    # ---- derived
    def paths(self) -> Set[Tuple[str, int, str]]:
        fams = [4, 6] if self.ipv6 else [4]
        kinds = ["new", "tracked"] if self.tracked else ["new"]
        sides = ["other", "same"] if self.same_hosts else ["other"]
        return {(s, f, k) for s in sides for f in fams for k in kinds}

    def can_modify(self, enf: str) -> bool:
        if enf == "AGENT":
            return self.privileged
        if enf == "SG":
            return self.reach_sg or (self.mp_sg and self.mp_comp) or self.reach_all
        if enf in ("NACL4", "NACL6"):
            return self.reach_net or self.reach_all
        if enf == "STOP":
            return self.reach_all
        raise KeyError(enf)

    def revert_delay(self, enf: str, nth: int) -> float:
        r = _rng(self.seed, "rev", enf, nth)
        if enf == "AGENT":
            return r.uniform(0.0, 5.0)
        return r.uniform(2000.0, 3000.0) if self.late else r.uniform(60.0, 180.0)

    def log_delay(self, interval: int, eni: str) -> Optional[float]:
        """Delivery delay of the record of `interval` on `eni`; None if the interval is SKIPDATA."""
        r = _rng(self.seed, "log", interval, eni)
        if r.random() < self.p_skip:
            return None
        d = r.uniform(LOG_DELAY["lo"], LOG_DELAY["hi"])
        if r.random() < self.p_tail:
            d += r.uniform(LOG_DELAY["tail_lo"], LOG_DELAY["tail_hi"])
        return d

    def operator(self, nth: int) -> Tuple[bool, float]:
        r = _rng(self.seed, "op", nth)
        if r.random() < self.p_approve:
            return True, r.uniform(120.0, APPROVAL_TIMEOUT)
        return False, APPROVAL_TIMEOUT


def random_incident(seed: int, mix: Dict[str, float] = MIX) -> Incident:
    r = _rng(seed, "inc")
    b = lambda k: r.random() < mix[k]
    inc = Incident(seed=seed, privileged=b("privileged"), reach_sg=b("reach_sg"), mp_sg=b("mp_sg"),
                   mp_comp=b("mp_comp"), reach_net=b("reach_net"), reach_all=b("reach_all"),
                   tracked=b("tracked"), same_hosts=b("same_hosts"), v_same=b("v_same"), ipv6=b("ipv6"),
                   outage=b("outage"), p_tail=mix["p_tail"], p_skip=mix["p_skip"], late=b("late"),
                   p_approve=mix["p_approve"], n_peers=r.randint(3, 8))
    inc.iam_miss = inc.reach_sg and r.random() < mix["iam_miss"]
    return inc


# ------------------------------------------------------------------------------- world state
class World:
    """Ground truth: which enforcers are active when, given deployments and adversary reversions."""

    def __init__(self, inc: Incident):
        self.inc = inc
        self.active: Dict[str, List[Tuple[float, float]]] = {}
        self.ndeploy: Dict[str, int] = {}
        self.api_calls = 0

    def deploy(self, enf: str, t: float) -> float:
        """Deploy enforcer at t; returns the time the API acknowledged. The adversary reverts if it can."""
        n = self.ndeploy.get(enf, 0)
        self.ndeploy[enf] = n + 1
        t_on = t + 2.0
        t_off = t_on + self.inc.revert_delay(enf, n) if self.inc.can_modify(enf) else float("inf")
        self.active.setdefault(enf, []).append((t_on, t_off))
        self.api_calls += {"SG": 1, "STOP": 2, "AGENT": 1}.get(enf, 2 * min(self.inc.n_peers, 3))
        return t_on

    def is_on(self, enf: str, t: float) -> bool:
        return any(a <= t < b for a, b in self.active.get(enf, ()))

    def blocked(self, path: Tuple[str, int, str], t: float) -> bool:
        side, fam, kind = path
        if self.is_on("STOP", t) or self.is_on("AGENT", t):
            return True
        if kind == "new" and self.is_on("SG", t):
            return True
        if side == "other" and self.is_on("NACL%d" % fam, t):
            return True
        return False

    def events(self) -> List[float]:
        return sorted({x for iv in self.active.values() for ab in iv for x in ab if x != float("inf")})

    def any_open(self, paths, t0: float, t1: float) -> bool:
        ts = [t0] + [e for e in self.events() if t0 < e <= t1]
        return any(not self.blocked(p, t) for t in ts for p in paths)

    def exposure_minutes(self, paths, t1: float) -> float:
        ts = [0.0] + [e for e in self.events() if 0.0 < e < t1] + [t1]
        tot = 0.0
        for a, b in zip(ts, ts[1:]):
            if any(not self.blocked(p, a) for p in paths):
                tot += b - a
        return tot / 60.0


@dataclass
class Outcome:
    declared: str                 # EFFECTIVE | EFFECTIVE_PARTIAL | UNRESOLVED
    t_decl: float
    scope: Set[Tuple[str, int, str]]
    approvals: int = 0
    stopped: bool = False
    rounds: int = 0
    probes: int = 0
    log_queries: int = 0
    api_calls: int = 0
    false_effective: bool = False
    residual: bool = False
    exposure_min: float = 0.0
    avoidable_stop: bool = False


# ------------------------------------------------------------------------------- selection view
def _points(inc: Incident):
    """Attribute vectors as the controller sees them (IAM analysis may miss one edge)."""
    cx = {"role-x"}
    if inc.reach_sg and not inc.iam_miss:
        cx.add("role-sg-admin")
    if inc.reach_net:
        cx.add("role-net-admin")
    if inc.reach_all:
        cx |= {"role-sg-admin", "role-net-admin", "role-instance-admin"}
    X = Point("X", "env-x", "node-x", "M1", frozenset(cx))
    sg_c = {"role-sg-admin"} | ({"cred-M1"} if inc.mp_sg else set())
    cand = {
        "SG": Point("SG", "csp-sg", "csp-sg", "CSP", frozenset(sg_c)),
        "NACL": Point("NACL", "csp-nacl", "csp-nacl", "CSP", frozenset({"role-net-admin"})),
        "STOP": Point("STOP", "csp-ec2", "csp-ec2", "CSP", frozenset({"role-instance-admin"})),
    }
    return X, cand


def _nacls(inc: Incident) -> List[str]:
    return ["NACL4", "NACL6"] if inc.ipv6 else ["NACL4"]


# ------------------------------------------------------------------------------- verification
def _covered(enfs, path) -> bool:
    """Does the selected enforcer set block this path class by construction?"""
    side, fam, kind = path
    return (kind == "new" and "SG" in enfs) or (side == "other" and ("NACL%d" % fam) in enfs)


def _probe_classes(inc: Incident, enfs) -> List[Tuple[str, int]]:
    """Probe where the verifier has an interface, hosts exist, and the selection claims coverage."""
    fams = [4, 6] if inc.ipv6 else [4]
    sides = ["other"] + (["same"] if (inc.v_same and inc.same_hosts) else [])
    return [(s, f) for s in sides for f in fams if _covered(enfs, (s, f, "new"))]


def _verify_round(inc: Incident, w: World, enfs, t_iso: float, rnd: int, out: Outcome, recs: list):
    """One verification round. `recs` accumulates (t_delivered, kind, class, layer) since the last deployment.
    Returns (t_decision, per-class state, per-class rejecting layer)."""
    r = _rng(inc.seed, "probe", rnd)
    classes = _probe_classes(inc, enfs)
    response = False
    t_need = t_iso + DT + PROBE_SPAN
    for c in classes:
        side, fam = c
        for _ in range(PROBES_PER_CLASS):
            tau = t_iso + DT + r.uniform(0.0, PROBE_SPAN)
            out.probes += 1
            if w.is_on("STOP", tau):
                continue                                   # no interface traffic, no record
            if side == "other" and w.is_on("NACL%d" % fam, tau):
                layer = "NACL"
            elif w.is_on("SG", tau):
                layer = "SG"
            else:
                layer = None
            iv = int(tau // 60)
            d = inc.log_delay(iv, ("eni-v-%s" % side) if layer == "NACL" else "eni-x")
            if layer is None and not inc.outage:
                response = True                           # immediate, independent of logs
            if d is not None:
                enf = None if layer is None else ("SG" if layer == "SG" else "NACL%d" % fam)
                kind = "ACCEPT" if layer is None else ("REJECT" if enf in enfs else "REJECT_UNTRUSTED")
                recs.append(((iv + 1) * 60 + d, kind, c, layer))
    # passive observation: the target's own traffic on paths the selection claims to block
    if not inc.late:
        for iv in range(int((t_iso + DT) // 60) + 1, int(t_need // 60) + 1):
            t_mid = iv * 60 + 30.0
            if w.is_on("STOP", t_mid):
                continue
            if any(_covered(enfs, p) and not w.blocked(p, t_mid) for p in inc.paths()) and r.random() < 0.8:
                d = inc.log_delay(iv, "eni-x")
                if d is not None:
                    recs.append(((iv + 1) * 60 + d, "ACCEPT", None, None))
    t_dec = t_need if response else t_need + 60 + LOG_DELAY["hi"] + 60
    if not response and not inc.outage:
        # closing probes: one new connection per class at decision time; an answer means failure
        for side, fam in classes:
            out.probes += 1
            if not w.is_on("STOP", t_dec) and not w.blocked((side, fam, "new"), t_dec):
                response = True
    out.log_queries += 2 * (int(t_dec // 60) - int(t_iso // 60))      # list + get per interval since T_iso
    seen = [x for x in recs if x[0] <= t_dec]
    accept_rec = any(k == "ACCEPT" for _, k, _, _ in seen)
    reject: Dict[Tuple[str, int], Optional[str]] = {c: None for c in classes}
    for _, k, c, layer in seen:
        if k == "REJECT" and c in reject and reject[c] != "NACL":
            reject[c] = layer
    state = {c: decide(response, accept_rec, reject[c] is not None) for c in classes}
    return t_dec, state, reject


def _verified_scope(inc: Incident, reject) -> Set[Tuple[str, int, str]]:
    ok = set()
    for p in inc.paths():
        side, fam, kind = p
        layer = reject.get((side, fam))
        if layer is None:
            continue
        if kind == "new":
            ok.add(p)
        elif side == "other" and layer == "NACL":
            ok.add(p)                                     # stateless deny also cuts tracked flows
    return ok


def _stop_with_approval(inc: Incident, w: World, t: float, out: Outcome, check_state: bool) -> Optional[float]:
    """Ask for approval and stop the instance. Returns the time the stop was confirmed, or None."""
    ok, delay = inc.operator(out.approvals)
    out.approvals += 1
    if not ok:
        return None
    t_on = w.deploy("STOP", t + delay)
    out.stopped = True
    if not check_state:
        return t_on
    t_chk = t_on + 2 * 60 + LOG_DELAY["hi"]             # instance state plus two silent intervals
    out.log_queries += 4
    return t_chk if w.is_on("STOP", t_chk) else -t_chk    # negative: stop was undone before the check


def _loop(inc: Incident, w: World, select: bool) -> Outcome:
    """FULL (select=True) and A1 (select=False): deploy, verify, redeploy, escalate."""
    out = Outcome("UNRESOLVED", 0.0, set())
    P = inc.paths()
    X, cand = _points(inc)
    w.api_calls += 5 + len(X.C)                            # snapshot + one policy evaluation per principal
    if select:
        sel = select_enforcers(X, cand.values(), "cred-M1")
        chosen = {e.pid for e in sel.enforcers}
    else:
        chosen = set(cand)
    enfs = (["SG"] if "SG" in chosen else []) + (_nacls(inc) if "NACL" in chosen else [])   # trusted set
    # an excluded security group is still applied as a best-effort layer; it is never counted as evidence
    deploy = enfs + ([] if "SG" in chosen else ["SG"])
    stop_ok = "STOP" in chosen

    def escalate(t_now: float, partial_scope) -> Outcome:
        if not stop_ok:
            out.declared, out.t_decl = ("EFFECTIVE_PARTIAL", t_now) if partial_scope else ("UNRESOLVED", t_now)
            out.scope = set(partial_scope or ())
            return out
        tc = _stop_with_approval(inc, w, t_now, out, check_state=True)
        if tc is None:
            out.declared = "EFFECTIVE_PARTIAL" if partial_scope else "UNRESOLVED"
            out.t_decl, out.scope = t_now + APPROVAL_TIMEOUT, set(partial_scope or ())
        elif tc < 0:
            out.declared, out.t_decl, out.scope = "UNRESOLVED", -tc, set()
        else:
            out.declared, out.t_decl, out.scope = "EFFECTIVE", tc, set(P)
        return out

    t_iso = max(w.deploy(e, 0.0) for e in deploy)
    if not enfs:
        return escalate(t_iso, None)
    fails = inconc = 0
    recs: list = []
    while True:
        t_dec, state, reject = _verify_round(inc, w, enfs, t_iso, out.rounds, out, recs)
        out.rounds += 1
        if FAILED in state.values():
            fails += 1
            if fails >= MAX_FAIL:
                return escalate(t_dec, None)
            recs.clear()                                   # evidence about the old deployment is void
            t_iso = max(w.deploy(e, t_dec) for e in deploy)
            continue
        if INCONCLUSIVE in state.values():
            inconc += 1
            if inconc >= MAX_INCONC:
                return escalate(t_dec, _verified_scope(inc, reject))
            t_iso = t_dec - DT                             # re-probe at once; late records still count
            continue
        ver = _verified_scope(inc, reject)
        if ver >= P:
            out.declared, out.t_decl, out.scope = "EFFECTIVE", t_dec, set(P)
            return out
        return escalate(t_dec, ver)                        # paths outside the verified scope remain


def run(inc: Incident, cfg: str) -> Outcome:
    w = World(inc)
    P = inc.paths()
    if cfg == "B1_agent_selfreport":
        t = w.deploy("AGENT", 0.0)
        out = Outcome("EFFECTIVE", t + 5.0, set(P))
    elif cfg == "B2_SG_apiack":
        out = Outcome("EFFECTIVE", w.deploy("SG", 0.0), set(P))
    elif cfg == "B4_SG_NACLv4_apiack":
        t = max(w.deploy("SG", 0.0), w.deploy("NACL4", 0.0))
        out = Outcome("EFFECTIVE", t, set(P))
    elif cfg == "B3_SG_naiveprobe":
        out = Outcome("UNRESOLVED", 0.0, set())
        t = w.deploy("SG", 0.0)
        for _ in range(3):
            tp = t + 120.0
            out.probes += 1
            if w.blocked(("other", 4, "new"), tp) or inc.outage:   # silence is read as success
                out.declared, out.t_decl, out.scope = "EFFECTIVE", tp, set(P)
                break
            t = w.deploy("SG", tp)
        else:
            out.t_decl = t
    elif cfg == "A2_sel_apiack":
        out = Outcome("UNRESOLVED", 0.0, set())
        X, cand = _points(inc)
        w.api_calls += 5 + len(X.C)
        sel = select_enforcers(X, cand.values(), "cred-M1")
        chosen = {e.pid for e in sel.enforcers}
        enfs = (["SG"] if "SG" in chosen else []) + (_nacls(inc) if "NACL" in chosen else [])
        if enfs:
            out.declared, out.t_decl, out.scope = "EFFECTIVE", max(w.deploy(e, 0.0) for e in enfs), set(P)
        elif "STOP" in chosen:
            tc = _stop_with_approval(inc, w, 0.0, out, check_state=False)
            if tc is None:
                out.t_decl = APPROVAL_TIMEOUT
            else:
                out.declared, out.t_decl, out.scope = "EFFECTIVE", tc, set(P)
    elif cfg == "A1_nosel_verify":
        out = _loop(inc, w, select=False)
    elif cfg == "FULL":
        out = _loop(inc, w, select=True)
    else:
        raise KeyError(cfg)
    out.api_calls = w.api_calls
    if out.declared != "UNRESOLVED":
        out.false_effective = w.any_open(out.scope, out.t_decl, out.t_decl + HORIZON)
    out.residual = any(not w.blocked(p, out.t_decl + HORIZON) for p in P)
    out.exposure_min = w.exposure_minutes(P, EXPOSURE_WINDOW)
    if out.stopped:
        # in hindsight: would SG + NACL (all families), never reverted, have closed every path?
        revertible = inc.can_modify("SG") or inc.can_modify("NACL4")
        gap = any(s == "same" and k == "tracked" for s, f, k in P)
        out.avoidable_stop = not (revertible or gap)
    return out
