"""Closed-form false-effective expectations for the acknowledgement-based configurations (Sect. 10.5, Table 10).

Conditions of Table 7 are treated as independent events, except that a role reaching every role
also reaches the roles that modify security groups and network ACLs. The failure conditions are
  B1: agent impaired
  B2: est or sg
  B4: (est or sg) and (hosts or acl or v6)
  B5: (est or sg) and (hosts or acl)
with sg = reach_sg or reach_all or (mp_sg and mp_comp), acl = reach_net or reach_all.
Prints the expectations, the |z| against the emulated counts in results_v2/e2_containment_v2.json
(if present), the variant without established connections (two-step replacement bound), the
linear dependence on the tracked fraction f, and the optimistic credential-revocation bound.
"""
import itertools, json, math, os

P = dict(privileged=0.7, reach_sg=0.3, mp_sg=0.2, mp_comp=0.5, reach_net=0.05, reach_all=0.02,
         tracked=0.6, same_hosts=0.4, ipv6=0.3)
VARS = ["reach_sg", "mp_sg", "mp_comp", "reach_net", "reach_all", "tracked", "same_hosts", "ipv6"]


def expect(fail, p=P):
    tot = 0.0
    for bits in itertools.product([0, 1], repeat=len(VARS)):
        w = 1.0
        for v, b in zip(VARS, bits):
            w *= p[v] if b else 1 - p[v]
        if fail(dict(zip(VARS, bits))):
            tot += w
    return tot


def conds(c, revoke=False, est_on=True):
    sg = (c["mp_sg"] and c["mp_comp"]) if revoke else (c["reach_sg"] or c["reach_all"] or (c["mp_sg"] and c["mp_comp"]))
    acl = False if revoke else (c["reach_net"] or c["reach_all"])
    est = c["tracked"] if est_on else 0
    return est, sg, acl, c["same_hosts"], c["ipv6"]


def table(revoke=False, est_on=True, p=P):
    def b2(c):
        est, sg, acl, h, v6 = conds(c, revoke, est_on); return est or sg
    def b4(c):
        est, sg, acl, h, v6 = conds(c, revoke, est_on); return (est or sg) and (h or acl or v6)
    def b5(c):
        est, sg, acl, h, v6 = conds(c, revoke, est_on); return (est or sg) and (h or acl)
    return {"B1": p["privileged"], "B2": expect(b2, p), "B4": expect(b4, p), "B5": expect(b5, p)}


def main():
    base = table()
    print("Table 10 closed form (%):", {k: round(100 * v, 2) for k, v in base.items()})
    f = "results_v2/e2_containment_v2.json"
    if os.path.exists(f):
        d = json.load(open(f))
        names = {"B1": "B1_agent_selfreport", "B2": "B2_SG_apiack", "B4": "B4_SG_NACLv4_apiack", "B5": "B5_SG_NACLdual_apiack"}
        s0 = d.get("S0_pooled") or d.get("S0") or {}
        for k, name in names.items():
            r = s0.get(name) if isinstance(s0, dict) else None
            if isinstance(r, dict) and "false_effective_k" in r:
                n = r.get("n", 10000); k_ = r["false_effective_k"]; p = base[k]
                z = (k_ / n - p) / math.sqrt(p * (1 - p) / n)
                print("  %s emulated %d/%d  z = %+.2f" % (k, k_, n, z))
    no_est = table(est_on=False)
    print("Without tracked established connections (two-step bound, %):", {k: round(100 * v, 2) for k, v in no_est.items() if k != "B1"})
    print("Linear in tracked fraction f (%):", {k: "%.2f + %.2f f" % (100 * no_est[k], 100 * (base[k] - no_est[k])) for k in ("B2", "B4", "B5")})
    rev = table(revoke=True)
    print("Optimistic credential revocation (%):", {k: round(100 * v, 2) for k, v in rev.items() if k != "B1"})


if __name__ == "__main__":
    main()
