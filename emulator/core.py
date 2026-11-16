"""Reference implementation of the compromise-domain model.

Contains: attribute vectors, share(), IAM reachability closure, the independence-aware
containment trigger, control-path-independent enforcer selection, and the ordered
three-state verification decision. Pure Python, no dependencies.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, Iterable, List, Optional, Set, Tuple

UNKNOWN = None  # attribute could not be obtained ('?')


@dataclass(frozen=True)
class Point:
    """Enforcement or observation point with its compromise-domain attribute vector."""
    pid: str
    L1: Optional[str]            # execution environment
    L2: Optional[str]            # node (kernel-sharing unit)
    L3: Optional[str]            # management plane
    C: Optional[FrozenSet[str]]  # control principals (reachable from p or able to modify p)
    L4: Optional[str] = "acctA"  # cloud account


def share(p: Point, q: Point) -> bool:
    """Definition 1: can p and q be manipulated by one compromise event at L1/L2/C level?"""
    for x in (p, q):
        if x.L1 is UNKNOWN or x.L2 is UNKNOWN or x.C is UNKNOWN:
            return True
    return p.L1 == q.L1 or p.L2 == q.L2 or bool(p.C & q.C)


# ----------------------------------------------------------------------------- IAM closure
def iam_closure(start: Iterable[str], assume: Dict[str, Iterable[str]],
                unevaluable: Optional[Dict[str, Iterable[str]]] = None) -> FrozenSet[str]:
    """Principals reachable from `start` by recursive role assumption.

    `assume[r]` lists roles r may assume; `unevaluable[r]` lists edges guarded by policy
    conditions that could not be evaluated. Those are treated as satisfied (included),
    so the closure over-approximates reachability.
    """
    seen: Set[str] = set()
    stack = list(start)
    while stack:
        r = stack.pop()
        if r in seen:
            continue
        seen.add(r)
        stack.extend(assume.get(r, ()))
        if unevaluable:
            stack.extend(unevaluable.get(r, ()))
    return frozenset(seen)


# ----------------------------------------------------------------------------- trigger
@dataclass(frozen=True)
class Evidence:
    source: Point
    v: float = 1.0      # mismatch-type weight
    t: float = 0.8      # trust of the source, 0.5..1.0
    attributed: bool = True  # attribution condition met (otherwise indeterminate)


@dataclass
class TriggerParams:
    k_L2: int = 2
    k_L3: int = 1
    k_C: int = 2
    theta: float = 1.5
    c_L3: float = 1.0


@dataclass
class TriggerResult:
    verdict: str                 # 'CONTAIN' or 'HOLD'
    score: float
    n_L2: int
    n_L3: int
    n_C: int
    used: int
    excluded: int


def _components(sources: List[Point]) -> int:
    """Number of connected components of the C-intersection graph (union-find over principals)."""
    parent: Dict[str, str] = {}

    def find(a):
        while parent.setdefault(a, a) != a:
            parent[a] = parent[parent[a]]
            a = parent[a]
        return a

    comp_keys = set()
    anchors = []
    for s in sources:
        cs = sorted(s.C) if s.C else []
        if not cs:
            anchors.append(("#solo", s.pid))
            continue
        for c in cs[1:]:
            parent[find(c)] = find(cs[0])
        anchors.append(("#c", cs[0]))
    for kind, a in anchors:
        comp_keys.add((kind, a) if kind == "#solo" else ("#c", find(a)))
    return len(comp_keys)


def trigger(X: Point, evidence: Iterable[Evidence], prm: TriggerParams = TriggerParams()) -> TriggerResult:
    """Independence-aware trigger: quorums over independent groups plus capped score."""
    ev = [e for e in evidence if e.attributed]
    kept = [e for e in ev if not share(e.source, X)]
    excluded = len(ev) - len(kept)
    # one record per source: keep the strongest
    best: Dict[str, Evidence] = {}
    for e in kept:
        b = best.get(e.source.pid)
        if b is None or e.v * e.t > b.v * b.t:
            best[e.source.pid] = e
    kept = list(best.values())
    # node groups: maximum per node; remember the plane of the maximising source
    node_best: Dict[str, Evidence] = {}
    for e in kept:
        b = node_best.get(e.source.L2)
        if b is None or e.v * e.t > b.v * b.t:
            node_best[e.source.L2] = e
    planes = {e.source.L3 for e in kept if e.source.L3 is not UNKNOWN and e.source.L3 != X.L3}
    per_plane: Dict[Optional[str], float] = {}
    for e in node_best.values():
        per_plane[e.source.L3] = per_plane.get(e.source.L3, 0.0) + e.v * e.t
    score = sum(min(prm.c_L3, s) for s in per_plane.values())
    n_L2, n_L3, n_C = len(node_best), len(planes), _components([e.source for e in kept])
    ok = n_L2 >= prm.k_L2 and n_L3 >= prm.k_L3 and n_C >= prm.k_C and score >= prm.theta - 1e-12
    return TriggerResult("CONTAIN" if ok else "HOLD", round(score, 6), n_L2, n_L3, n_C, len(kept), excluded)


def trigger_count(X: Point, evidence: Iterable[Evidence], k: int = 2) -> str:
    """Baseline: k or more attributed witnesses."""
    return "CONTAIN" if sum(1 for e in evidence if e.attributed) >= k else "HOLD"


def trigger_node_dedup(X: Point, evidence: Iterable[Evidence], theta: float = 1.5) -> str:
    """Baseline: one vote per node (max), summed score against the same threshold; no share, planes or C."""
    nb: Dict[str, float] = {}
    for e in evidence:
        if e.attributed:
            nb[e.source.L2] = max(nb.get(e.source.L2, 0.0), e.v * e.t)
    return "CONTAIN" if len(nb) >= 2 and sum(nb.values()) >= theta - 1e-12 else "HOLD"


# ----------------------------------------------------------------------------- selection
@dataclass
class Selection:
    enforcers: List[Point]
    excluded: List[Tuple[str, str]]   # (pid, reason)
    resolved: bool                    # at least one enforcer independent in plane and control


def shares_control_path(e: Point, X: Point, mp_cred: Optional[str]) -> Optional[str]:
    """Reason why e shares a control path with X, or None."""
    if share(e, X):
        return "share"
    if mp_cred is not None and e.C is not UNKNOWN and mp_cred in e.C:
        return "mgmt-plane credential can modify"
    return None


def select_enforcers(X: Point, candidates: Iterable[Point], mp_cred: Optional[str]) -> Selection:
    """Algorithm 1: keep only enforcers the target cannot undo."""
    keep, excl = [], []
    for e in candidates:
        why = shares_control_path(e, X, mp_cred)
        if why:
            excl.append((e.pid, why))
        else:
            keep.append(e)
    resolved = any(e.L3 is not UNKNOWN and e.L3 != X.L3 and not (e.C & X.C) for e in keep)
    return Selection(keep, excl, resolved)


# ----------------------------------------------------------------------------- verification
FAILED, EFFECTIVE, INCONCLUSIVE = "FAILED", "EFFECTIVE", "INCONCLUSIVE"


def decide(probe_response: bool, accept_after_tiso: bool, reject_attributed: bool) -> str:
    """Ordered three-state decision for one probe class (Sect. 7). Silence is never success."""
    if probe_response or accept_after_tiso:
        return FAILED
    if reject_attributed:
        return EFFECTIVE
    return INCONCLUSIVE
