import json, math
r=json.load(open('results_v2/e2_containment_v2.json')); P=r['S0_pooled']
def pc(x): return 100*x
order=["B1_agent_selfreport","B2_SG_apiack","B3_SG_naiveprobe","B4_SG_NACLv4_apiack","B5_SG_NACLdual_apiack","A1_nosel_verify","A2_sel_apiack","FULL"]
print("TABLE10")
for c in order:
    v=P[c]; n=v['n']; d=v['declared_k']; lo,hi=v['false_effective_ci']
    seeds=[r['S0_by_seed'][str(s)][c]['false_effective_k'] for s in range(5)]
    t50=v['median_t_effective_s']; t95=v['p95_t_effective_s']
    print(f"| {c} | {v['false_effective_k']:,} ({pc(v['false_effective']):.2f}%) [{pc(lo):.2f}–{pc(hi):.2f}] | {min(seeds)}–{max(seeds)} | {pc(v['residual_k']/n):.1f}% | {pc(d.get('EFFECTIVE',0)/n):.1f} / {pc(d.get('EFFECTIVE_PARTIAL',0)/n):.1f} / {pc(d.get('UNRESOLVED',0)/n):.1f} | {v['mean_exposure_min']:.1f} | {t50/60:.1f} / {t95/60:.1f} | {v['approvals_k']/n:.2f} | {v['stops_k']/n:.2f} | {v['avoidable_stops_k']/n:.3f} |")
print("resid by declared FULL", P['FULL']['residual_by_declared_k'], "A1", P['A1_nosel_verify']['residual_by_declared_k'])
print("FE|decl FULL", P['FULL']['false_effective_given_declared'], 'A1', P['A1_nosel_verify']['false_effective_given_declared'], 'B5', P['B5_SG_NACLdual_apiack']['false_effective_given_declared'])
print("v1rules", {c:(P[c]['false_effective_k'],P[c]['median_t_effective_s'],P[c]['p95_t_effective_s'],P[c]['stops_k'],P[c]['failed_rounds_k']) for c in ('A1_v1rules','FULL_v1rules','A1_nosel_verify','FULL')})
print("MCNEMAR", r['mcnemar_S0_pooled'])
print("TABLE12")
for c in ("B2_SG_apiack","B5_SG_NACLdual_apiack","A2_sel_apiack","A1_nosel_verify","FULL"):
    v=P[c]; print(f"| {c} | {v['mean_rounds']:.2f} | {v['mean_api_calls']:.1f} | {v['mean_probes']:.1f} | {v['mean_log_queries']:.1f} | {v['mean_snapshot_reads']:.1f} |")
print("TABLE11")
S=r['scenarios']
def key(s):
    x=s.split('_')[0][1:]; return (int(x.rstrip('L')), x.endswith('L'))
for s in sorted(S,key=key):
    d=S[s]; f=d['FULL']; n=f['n']; dk=f['declared_k']
    g=lambda c: f"{pc(d[c]['false_effective_k']/n):.0f}%"
    print(f"| {s.split('_')[0]} | {g('B2_SG_apiack')} | {g('B5_SG_NACLdual_apiack')} | {g('A1_nosel_verify')} | {g('FULL')} | {g('FULL_v1rules')} | {pc(dk.get('EFFECTIVE',0)/n):.0f} / {pc(dk.get('EFFECTIVE_PARTIAL',0)/n):.0f} / {pc(dk.get('UNRESOLVED',0)/n):.0f} | {f['stops_k']/n:.2f} | {pc(f['residual_k']/n):.0f}% | A1v1 {g('A1_v1rules')} | t50 {f['median_t_effective_s']} | avoid {f['avoidable_stops_k']/n:.2f}")
print("S8 full declared", S['S8_log_delay_skipdata']['FULL']['declared_k'], S['S8_log_delay_skipdata']['FULL']['median_t_effective_s'])
print("S10 A1 stops", S['S10_no_independent_enforcer']['A1_nosel_verify']['stops_k'])
print("S7 B3",S['S7_outage_plus_revert']['B3_SG_naiveprobe']['false_effective_k'], 'A1', S['S7_outage_plus_revert']['A1_nosel_verify']['false_effective_k'], 'A1v1', S['S7_outage_plus_revert']['A1_v1rules']['false_effective_k'])
e5=json.load(open('results_v2/e5_integrated.json'))
print("E5"); [print(c, v) for c,v in e5.items()]
e4=json.load(open('results_v2/e4_sensitivity_v2.json'))
def rng(key,c,f):
    vals=[f(row[c]) for row in e4[key]]; return vals
print('B2 tracked', rng('tracked','B2_SG_apiack',lambda s:s['false_effective_k']/s['n']))
print('B5 tracked', rng('tracked','B5_SG_NACLdual_apiack',lambda s:s['false_effective_k']/s['n']))
print('A1 late', rng('late','A1_nosel_verify',lambda s:s['false_effective_k']/s['n']))
mx=max(row['FULL']['false_effective_k']/row['FULL']['n'] for k,rows in e4.items() if k!='documented_log_delay' for row in rows); print('FULL max', mx)
print('FULL iam', rng('iam_miss','FULL',lambda s:s['false_effective_k']/s['n']))
print('stops v_same', rng('v_same','FULL',lambda s:s['stops_k']/s['n']))
print('stops tracked', rng('tracked','FULL',lambda s:s['stops_k']/s['n']))
print('resid p_approve', rng('p_approve','FULL',lambda s:s['residual_k']/s['n']))
# ordering check
viol=0
for k,rows in e4.items():
    if k=='documented_log_delay': continue
    for row in rows:
        fe=lambda c: row[c]['false_effective_k']
        if not (fe('FULL')<=fe('A1_nosel_verify')<=fe('B5_SG_NACLdual_apiack')<=fe('B2_SG_apiack')): viol+=1; print('order viol',k,row['value'])
print('order violations',viol)
doc=e4['documented_log_delay']; print('doc', {c:(v['false_effective_k'],v['median_t_effective_s'],v['p95_t_effective_s']) for c,v in doc.items()})
