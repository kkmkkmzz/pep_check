"""Discrete-event emulation of the containment loop, version 2 (manuscript v0.6).

Differences from containment_emu.py (version 1, manuscript v0.1-v0.5), each tied to a live
measurement or a review finding:

  * Apply delay. An enforcement change is acknowledged after 2 s but takes effect after a further
    U(0, APPLY_MAX) s (Sect. 4.3: accepted records ended up to about 82 s after a change).
    Delta t is 120 s instead of 60 s. False-effective reports are counted from GRACE s after the
    declaration for every configuration, so that propagation does not count against anyone.
  * Observable attribution. The controller no longer knows which layer rejected a probe. It sees
    the interface of the REJECT record and the configuration snapshot (Sect. 4.4, Sect. 8):
      - "snapshot" rule (current): a record counts for a selected enforcer only if the snapshot
        shows no other layer that can reject the probe at that interface;
      - "location" rule (version 1): a record at the target interface counts for the security group,
        a record at a peer interface for the access control list.
  * Class splitting (Sect. 3.3). With two other subnets whose access control lists differ, the
    current rule treats each as its own class; version 1 extended the result for "other" to both.
  * Approval boundary and missing verifier (Algorithm 1). Unchanged in effect: stop is only ever
    deployed after approval; the emulated verifier and observer always exist.
  * Generator. reach_all now explicitly implies reach_sg and reach_net (the semantics were already
    implied through can_modify; the flags are now consistent in the incident record).
  * New baseline B5: security group plus access control list entries for both address families,
    acknowledged (strongest acknowledgement-based configuration).
  * New fault and adversary options for S12-S14 (see Incident).
Time is in seconds from detection (t = 0).
"""
from __future__ import annotations
import random
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple

from core import Point, select_enforcers, decide, FAILED, EFFECTIVE, INCONCLUSIVE

HORIZON = 3600.0
EXPOSURE_WINDOW = 7200.0
GRACE = 60.0              # seconds after a declaration not counted in the false-effective test
APPLY_MAX = 60.0          # maximum extra delay before an acknowledged change takes effect
PROBE_SPAN = 120.0
PROBES_PER_CLASS = 3
MAX_FAIL, MAX_INCONC = 2, 3
APPROVAL_TIMEOUT = 1800.0
LOG_DELAY = {"lo": 540.0, "hi": 660.0, "tail_lo": 300.0, "tail_hi": 1800.0}


def _rng(*parts) -> random.Random:
    return random.Random("|".join(str(p) for p in parts))


def calibrate(lo: float, hi: float) -> None:
    LOG_DELAY["lo"], LOG_DELAY["hi"] = float(lo), float(hi)


CONFIGS = ["B1_agent_selfreport", "B2_SG_apiack", "B3_SG_naiveprobe", "B4_SG_NACLv4_apiack",
           "B5_SG_NACLdual_apiack", "A1_nosel_verify", "A2_sel_apiack", "FULL",
           "A1_v1rules", "FULL_v1rules"]
RULES = {  # (attribution rule, class splitting, delta t)
    "A1_nosel_verify": ("snapshot", True, 120.0), "FULL": ("snapshot", True, 120.0),
    "A1_v1rules": ("location", False, 60.0), "FULL_v1rules": ("location", False, 60.0),
}

MIX = dict(privileged=0.70, reach_sg=0.30, iam_miss=0.05, mp_sg=0.20, mp_comp=0.50, reach_net=0.05,
           reach_all=0.02, tracked=0.60, same_hosts=0.40, v_same=0.70, ipv6=0.30, outage=0.10,
           p_tail=0.05, p_skip=0.02, late=0.50, p_approve=0.85)


@dataclass
class Incident:
    seed: int
    privileged: bool = True
    reach_sg: bool = False
    iam_miss: bool = False
    mp_sg: bool = False
    mp_comp: bool = False
    reach_net: bool = False
    reach_all: bool = False
    tracked: bool = False
    same_hosts: bool = False
    v_same: bool = True
    ipv6: bool = False
    outage: bool = False
    p_tail: float = 0.05
    p_skip: float = 0.02
    late: bool = False
    p_approve: float = 0.85
    n_peers: int = 5
    # ---- version 2 options (all False in the random mix)
    two_subnets: bool = False   # a second other subnet B whose ACL the containment role cannot modify,
                                # and in which the verifier has no interface (S12)
    sg_inactive: bool = False   # security-group change acknowledged but never applied (S13, S14)
    adv_acl: bool = False       # adversary adds a deny entry for the verifier's addresses to the ACL of
                                # the target's subnet, so probes are rejected at X's interface (S13)

    def paths(self) -> Set[Tuple[str, int, str]]:
        fams = [4, 6] if self.ipv6 else [4]
        kinds = ["new", "tracked"] if self.tracked else ["new"]
        sides = ["other"] + (["otherB"] if self.two_subnets else []) + (["same"] if self.same_hosts else [])
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

    def apply_delay(self, enf: str, nth: int) -> float:
        return _rng(self.seed, "apply", enf, nth).uniform(0.0, APPLY_MAX)

    def log_delay(self, interval: int, eni: str) -> Optional[float]:
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
    """Same draws, in the same order, as version 1, so that incidents are identical across versions."""
    r = _rng(seed, "inc")
    b = lambda k: r.random() < mix[k]
    inc = Incident(seed=seed, privileged=b("privileged"), reach_sg=b("reach_sg"), mp_sg=b("mp_sg"),
                   mp_comp=b("mp_comp"), reach_net=b("reach_net"), reach_all=b("reach_all"),
                   tracked=b("tracked"), same_hosts=b("same_hosts"), v_same=b("v_same"), ipv6=b("ipv6"),
                   outage=b("outage"), p_tail=mix["p_tail"], p_skip=mix["p_skip"], late=b("late"),
                   p_approve=mix["p_approve"], n_peers=r.randint(3, 8))
    inc.iam_miss = inc.reach_sg and r.random() < mix["iam_miss"]
    if inc.reach_all:                                   # explicit implication (version 2)
        inc.reach_sg, inc.reach_net = True, True
    return inc


class World:
    def __init__(self, inc: Incident):
        self.inc = inc
        self.active: Dict[str, List[Tuple[float, float]]] = {}
        self.ndeploy: Dict[str, int] = {}
        self.api_calls = 0

    def deploy(self, enf: str, t: float) -> float:
        """Returns the acknowledgement time. The change takes effect after the apply delay."""
        n = self.ndeploy.get(enf, 0)
        self.ndeploy[enf] = n + 1
        t_ack = t + 2.0
        t_on = t_ack + (0.0 if enf == "STOP" else self.inc.apply_delay(enf, n))
        if enf == "SG" and self.inc.sg_inactive:
            t_on = float("inf")                         # acknowledged, never applied
        t_off = t_on + self.inc.revert_delay(enf, n) if self.inc.can_modify(enf) and t_on != float("inf") else float("inf")
        self.active.setdefault(enf, []).append((t_on, t_off))
        self.api_calls += {"SG": 1, "STOP": 2, "AGENT": 1}.get(enf, 2 * min(self.inc.n_peers, 3))
        return t_ack

    def is_on(self, enf: str, t: float) -> bool:
        return any(a <= t < b for a, b in self.active.get(enf, ()))

    def nacl_covers(self, side: str, fam: int, t: float) -> bool:
        if side == "other":
            return self.is_on("NACL%d" % fam, t)
        if side == "otherB":
            return False                                # the containment role cannot modify B's ACL
        return False

    def blocked(self, path, t: float) -> bool:
        side, fam, kind = path
        if self.is_on("STOP", t) or self.is_on("AGENT", t):
            return True
        if kind == "new" and self.is_on("SG", t):
            return True
        return self.nacl_covers(side, fam, t)

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
    declared: str
    t_decl: float
    scope: Set[Tuple[str, int, str]]
    approvals: int = 0
    stopped: bool = False
    rounds: int = 0
    failed_rounds: int = 0
    probes: int = 0
    log_queries: int = 0
    api_calls: int = 0
    snapshot_reads: int = 0
    false_effective: bool = False
    residual: bool = False
    exposure_min: float = 0.0
    avoidable_stop: bool = False
    stop_before_approval: bool = False


def _points(inc: Incident):
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
    side, fam, kind = path
    return (kind == "new" and "SG" in enfs) or (side == "other" and ("NACL%d" % fam) in enfs)


def _probe_classes(inc: Incident, enfs, split: bool) -> List[Tuple[str, int]]:
    """Probe classes: (side, family) where the verifier has an interface, hosts exist and coverage is claimed.
    The verifier has an interface in subnet A ("other") and, if v_same, in the target's subnet; never in B."""
    fams = [4, 6] if inc.ipv6 else [4]
    sides = ["other"] + (["same"] if (inc.v_same and inc.same_hosts) else [])
    return [(s, f) for s in sides for f in fams if _covered(enfs, (s, f, "new"))]


def _actual_reject(inc: Incident, w: World, side: str, fam: int, t: float):
    """What really happens to a probe of class (side, fam) at time t: (rejecting layer, recording interface)."""
    if side == "other" and w.nacl_covers(side, fam, t):
        return "NACL", "eni-v-other"                    # deny entry in the verifier's subnet, recorded at its interface
    if side == "other" and inc.adv_acl:
        return "ADV_ACL", "eni-x"                       # adversary's entry in the target subnet's ACL
    if w.is_on("SG", t):
        return "SG", "eni-x"
    return None, None


def _attribute(rule: str, inc: Incident, enfs, iface: str, fam: int) -> bool:
    """Can a REJECT record at `iface` be counted for a selected enforcer?"""
    if iface == "eni-v-other":
        return ("NACL%d" % fam) in enfs                 # only our entries filter at the verifier's interface
    if iface == "eni-x":
        if "SG" not in enfs:
            return False
        if rule == "location":
            return True
        return not inc.adv_acl                          # snapshot shows another deny entry for the probe source
    return False


def _verify_round(inc, w, enfs, t_iso, rnd, out, recs, rule, split, dt):
    r = _rng(inc.seed, "probe", rnd)
    classes = _probe_classes(inc, enfs, split)
    response = False
    t_need = t_iso + dt + PROBE_SPAN
    out.snapshot_reads += 1
    for c in classes:
        side, fam = c
        for _ in range(PROBES_PER_CLASS):
            tau = t_iso + dt + r.uniform(0.0, PROBE_SPAN)
            out.probes += 1
            if w.is_on("STOP", tau):
                continue
            layer, iface = _actual_reject(inc, w, side, fam, tau)
            iv = int(tau // 60)
            if layer is None:
                if not inc.outage:
                    response = True
                d = inc.log_delay(iv, "eni-x")
                if d is not None:
                    recs.append(((iv + 1) * 60 + d, "ACCEPT", c, None))
                continue
            d = inc.log_delay(iv, iface)
            if d is not None:
                ok = _attribute(rule, inc, enfs, iface, fam)
                recs.append(((iv + 1) * 60 + d, "REJECT" if ok else "REJECT_UNATTRIBUTED", c, iface))
    if not inc.late:
        for iv in range(int((t_iso + dt) // 60) + 1, int(t_need // 60) + 1):
            t_mid = iv * 60 + 30.0
            if w.is_on("STOP", t_mid):
                continue
            if any(_covered(enfs, p) and not w.blocked(p, t_mid) for p in inc.paths()) and r.random() < 0.8:
                d = inc.log_delay(iv, "eni-x")
                if d is not None:
                    recs.append(((iv + 1) * 60 + d, "ACCEPT", None, None))
    t_dec = t_need if response else t_need + 60 + LOG_DELAY["hi"] + 60
    if not response and not inc.outage:
        for side, fam in classes:
            out.probes += 1
            if not w.is_on("STOP", t_dec) and _actual_reject(inc, w, side, fam, t_dec)[0] is None:
                response = True
    out.snapshot_reads += 1
    out.log_queries += 2 * (int(t_dec // 60) - int(t_iso // 60))
    seen = [x for x in recs if x[0] <= t_dec]
    accept_rec = any(k == "ACCEPT" for _, k, _, _ in seen)
    reject: Dict[Tuple[str, int], Optional[str]] = {c: None for c in classes}
    for _, k, c, iface in seen:
        if k == "REJECT" and c in reject and reject[c] != "eni-v-other":
            reject[c] = iface
    state = {c: decide(response, accept_rec, reject[c] is not None) for c in classes}
    return t_dec, state, reject


def _verified_scope(inc: Incident, reject, split: bool) -> Set[Tuple[str, int, str]]:
    ok = set()
    for p in inc.paths():
        side, fam, kind = p
        key = side if side != "otherB" else ("other" if not split else None)
        if key is None:
            continue                                    # own class, no verifier interface: unverified
        iface = reject.get((key, fam))
        if iface is None:
            continue
        if kind == "new":
            ok.add(p)
        elif side in ("other", "otherB") and iface == "eni-v-other":
            ok.add(p)                                   # stateless deny also cuts tracked flows
    return ok


def _stop_with_approval(inc, w, t, out, check_state=True):
    ok, delay = inc.operator(out.approvals)
    out.approvals += 1
    if not ok:
        return None
    t_on = w.deploy("STOP", t + delay)
    out.stopped = True
    if not check_state:
        return t_on
    t_chk = t_on + 30.0                                 # provider interface reports the stopped state
    return t_chk if w.is_on("STOP", t_chk) else -t_chk


def _loop(inc: Incident, w: World, select: bool, rule: str, split: bool, dt: float) -> Outcome:
    out = Outcome("UNRESOLVED", 0.0, set())
    P = inc.paths()
    X, cand = _points(inc)
    w.api_calls += 5 + len(X.C)
    if select:
        sel = select_enforcers(X, cand.values(), "cred-M1")
        chosen = {e.pid for e in sel.enforcers}
    else:
        chosen = set(cand)
    enfs = (["SG"] if "SG" in chosen else []) + (_nacls(inc) if "NACL" in chosen else [])
    deploy = enfs + ([] if "SG" in chosen else ["SG"])
    stop_ok = "STOP" in chosen

    def escalate(t_now, partial_scope):
        if not stop_ok:
            out.declared, out.t_decl = ("EFFECTIVE_PARTIAL", t_now) if partial_scope else ("UNRESOLVED", t_now)
            out.scope = set(partial_scope or ())
            return out
        tc = _stop_with_approval(inc, w, t_now, out)
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
        t_dec, state, reject = _verify_round(inc, w, enfs, t_iso, out.rounds, out, recs, rule, split, dt)
        out.rounds += 1
        if FAILED in state.values():
            fails += 1
            out.failed_rounds += 1
            if fails >= MAX_FAIL:
                return escalate(t_dec, None)
            recs.clear()
            t_iso = max(w.deploy(e, t_dec) for e in deploy)
            continue
        if INCONCLUSIVE in state.values():
            inconc += 1
            if inconc >= MAX_INCONC:
                return escalate(t_dec, _verified_scope(inc, reject, split))
            t_iso = t_dec - dt
            continue
        ver = _verified_scope(inc, reject, split)
        if ver >= P:
            out.declared, out.t_decl, out.scope = "EFFECTIVE", t_dec, set(P)
            return out
        return escalate(t_dec, ver)


def run(inc: Incident, cfg: str) -> Outcome:
    w = World(inc)
    P = inc.paths()
    if cfg == "B1_agent_selfreport":
        t = w.deploy("AGENT", 0.0)
        out = Outcome("EFFECTIVE", t + 5.0, set(P))
    elif cfg == "B2_SG_apiack":
        out = Outcome("EFFECTIVE", w.deploy("SG", 0.0), set(P))
    elif cfg == "B4_SG_NACLv4_apiack":
        out = Outcome("EFFECTIVE", max(w.deploy("SG", 0.0), w.deploy("NACL4", 0.0)), set(P))
    elif cfg == "B5_SG_NACLdual_apiack":
        out = Outcome("EFFECTIVE", max(w.deploy(e, 0.0) for e in ["SG"] + _nacls(inc)), set(P))
    elif cfg == "B3_SG_naiveprobe":
        out = Outcome("UNRESOLVED", 0.0, set())
        t = w.deploy("SG", 0.0)
        for _ in range(3):
            tp = t + 120.0
            out.probes += 1
            if w.blocked(("other", 4, "new"), tp) or inc.adv_acl or inc.outage:
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
    elif cfg in RULES:
        rule, split, dt = RULES[cfg]
        out = _loop(inc, w, select=cfg.startswith("FULL"), rule=rule, split=split, dt=dt)
    else:
        raise KeyError(cfg)
    out.api_calls = w.api_calls
    if out.declared != "UNRESOLVED":
        out.false_effective = w.any_open(out.scope, out.t_decl + GRACE, out.t_decl + HORIZON)
    out.residual = any(not w.blocked(p, out.t_decl + HORIZON) for p in P)
    out.exposure_min = w.exposure_minutes(P, EXPOSURE_WINDOW)
    if out.stopped:
        revertible = inc.can_modify("SG") or inc.can_modify("NACL4") or inc.sg_inactive
        gap = any(s == "same" and k == "tracked" for s, f, k in P) or inc.two_subnets
        out.avoidable_stop = not (revertible or gap)
    return out
