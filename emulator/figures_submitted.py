"""Figures of the submitted manuscript: values, checks and a redraw.

The figures in the submitted manuscript (../figures_submitted/Fig1-Fig7.png, extracted unchanged from the
submitted .docx) were drawn as editable charts from the values reported in the tables and text, not by this
repository's earlier plotting script (figs_v2/, an earlier draft layout). This script

  1. computes every value that the submitted Figures 2 and 4-7 display from the result files of this repository
     (emulator results, live-measurement aggregates),
  2. checks each value against the number printed in the submitted figure (exit code 1 on any mismatch),
  3. writes the values to figure_values.json, and
  4. redraws Figures 2 and 4-7 in the submitted layout to out/figs_submitted/ (same content; fonts and spacing
     are not pixel-identical to the submitted artwork). Figures 1 and 3 are diagrams without data.

Run:  python3 figures_submitted.py        (add --no-draw to skip the redraw)
"""
import collections, json, os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
J = lambda *p: json.load(open(os.path.join(*p)))
fails = []
V = {}  # figure values written to figure_values.json


def eq(key, got, shown, tol=0.0):
    V[key] = got
    if isinstance(shown, (list, tuple)):
        ok = len(got) == len(shown) and all(abs(a - b) <= tol for a, b in zip(got, shown))
    else:
        ok = abs(got - shown) <= tol
    print(("PASS  " if ok else "FAIL  ") + "%-58s computed %s, figure %s" % (key, got, shown))
    if not ok:
        fails.append(key)


r1 = lambda x: float("%.1f" % x)
# ------------------------------------------------------------------ data
m = J(HERE, "aws", "measure_summary.json")
a1 = J(ROOT, "measurements", "exp006_a1", "results", "a1_flowlog_result_final.json")
e1 = J(HERE, "results", "e1_trigger.json")
e2 = J(HERE, "results_v2", "e2_containment_v2.json"); e4 = J(HERE, "results_v2", "e4_sensitivity_v2.json")
P = e2["S0_pooled"]; S = {k.split("_")[0]: v for k, v in e2["scenarios"].items()}
SCEN = ["S0", "S1", "S2", "S3", "S4", "S4L", "S5", "S5L", "S6", "S7", "S8", "S9", "S9L", "S10", "S11", "S12", "S13", "S14"]
cell = lambda s: P if s == "S0" else S[s]

# ------------------------------------------------------------------ Fig. 2a  (Table 3, initial run)
C = m["console"]
def share(keys, ph):
    ok = sum(C[k].get(ph, [0, 0])[0] for k in keys); bad = sum(C[k].get(ph, [0, 0])[1] for k in keys)
    return 100.0 * ok / (ok + bad)
PH = ["0_baseline", "1_sg", "2_sg_nacl", "3_stopped"]
f2a = {"other": [r1(share(["c1", "c2", "c5"], p)) for p in PH], "same": [r1(share(["c3", "c4"], p)) for p in PH],
       "new": [r1(share(["n1", "n2", "n3"], p)) for p in PH]}
eq("Fig2a established, other subnet (%)", f2a["other"], [100, 100, 0, 0])
eq("Fig2a established, same subnet (%)", f2a["same"], [100, 100, 100, 0])
# The submitted figure labels the baseline bar of new connections "100"; the value is 194 of 195 = 99.5 %
# (Table 3: 194 / 1), drawn at that height. The label is a rounding of 99.5, so a tolerance of 0.5 is applied here.
eq("Fig2a new connections (%)", f2a["new"], [100, 0, 0, 0], tol=0.51)

# ------------------------------------------------------------------ Fig. 2b  (delivery delay)
def hist(s):
    c = collections.Counter()
    for kv in (s.split(",") if s else []):
        x, y = kv.split(":"); c[int(x)] += int(y)
    return c
def q(c, p):
    xs = sorted(c.elements()); k = (len(xs) - 1) * p; f = int(k); g = min(f + 1, len(xs) - 1)
    return xs[f] + (xs[g] - xs[f]) * (k - f)
dd = m["delivery_delay_s"]
rows2b = {"Initial run, records": [dd["median"], dd["p95"], dd["max"]],
          "Repeated run, records": [a1["delay_s"]["p50"], a1["delay_s"]["p95"], a1["delay_s"]["max"]]}
for reg, fn in (("Seoul", "seoul_batches.jsonl"), ("N. Virginia", "virginia_batches.jsonl")):
    B = [json.loads(l) for l in open(os.path.join(ROOT, "measurements", "exp007_a2", fn))]
    rd = sum((hist(b["rd"]) for b in B), collections.Counter()); oo = sum((hist(b["oo"]) for b in B), collections.Counter())
    rows2b["72 h %s, records" % reg] = [q(rd, .5), q(rd, .95), max(rd)]
    rows2b["72 h %s, objects" % reg] = [q(oo, .5), q(oo, .95), max(oo)]
SHOWN2b = {"Initial run, records": [179, 306, 341], "Repeated run, records": [175, 310, 327],
           "72 h Seoul, records": [185, 319, 1211], "72 h N. Virginia, records": [184, 319, 1040],
           "72 h Seoul, objects": [290, 336, 1211], "72 h N. Virginia, objects": [303, 344, 1040]}
order2b = ["Initial run, records", "Repeated run, records", "72 h Seoul, records", "72 h N. Virginia, records", "72 h Seoul, objects", "72 h N. Virginia, objects"]
for k in order2b:
    eq("Fig2b %s median/p95/max (s)" % k, [float(x) for x in rows2b[k]], SHOWN2b[k])

# ------------------------------------------------------------------ Fig. 4  (trigger, E1)
CASES = ["a_one_node", "b_two_nodes_target_plane", "c_one_credential_two_planes", "d_one_other_plane", "e_two_other_planes", "f_target_plane_plus_one_node"]
SHOWN4a = {"Witness count": [67, 100, 100, 100, 100, 100], "One vote per node": [0, 77, 100, 100, 76, 100], "Ours": [0, 0, 0, 0, 72, 100],
           "Ours, no plane cap": [0, 0, 0, 100, 72, 100], "Ours, no control quorum": [0, 0, 100, 0, 76, 100]}
src4a = {"Witness count": lambda c: e1["fabrication"][c]["count"], "One vote per node": lambda c: e1["fabrication"][c]["node_dedup"],
         "Ours": lambda c: e1["fabrication"][c]["ours"], "Ours, no plane cap": lambda c: e1["ablation"][c]["no_plane_cap"],
         "Ours, no control quorum": lambda c: e1["ablation"][c]["no_control_quorum"]}
f4a = {}
for lab, f in src4a.items():
    f4a[lab] = [round(100 * f(c)) for c in CASES]
    eq("Fig4a %s (%%)" % lab, f4a[lab], SHOWN4a[lab])
th = {round(r["theta"], 1): r for r in e1["sweep_theta"]}; cp = {round(r["cap"], 1): r for r in e1["sweep_cap"]}; kl = {r["k_L3"]: r for r in e1["k_L3"]}
f4b = [("chosen setting", th[1.5]["detect"]), ("θ = 2.1", th[2.1]["detect"]), ("c_L3 = 0.6", cp[0.6]["detect"]), ("k_L3 = 2", kl[2]["detect"])]
eq("Fig4b detection (%)", [r1(100 * v) for _, v in f4b], [94.7, 66.3, 66.7, 77.1])
f4c = [("chosen, case d", th[1.5]["fab_one_plane"]), ("chosen, case e", th[1.5]["fab_two_planes"]), ("θ = 0.9, case d", th[0.9]["fab_one_plane"]),
       ("θ = 2.1, case e", th[2.1]["fab_two_planes"]), ("c_L3 = 1.6, case d", cp[1.6]["fab_one_plane"]), ("k_L3 = 2, case e", kl[2]["fab_two_planes"])]
eq("Fig4c false containment (%)", [round(100 * v) for _, v in f4c], [0, 70, 100, 0, 100, 70])

# ------------------------------------------------------------------ Fig. 5  (false-effective heat map)
ROWS5 = [("B2", "B2_SG_apiack"), ("B5", "B5_SG_NACLdual_apiack"), ("A1", "A1_nosel_verify"), ("Full loop", "FULL"), ("Full, earlier rules", "FULL_v1rules")]
SHOWN5 = {"B2": [75.6] + [100] * 7 + [0, 100, 0, 100, 100, 100, 0, 100, 100, 100],
          "B5": [34.0, 0, 100, 0, 100, 100, 100, 100, 0, 100, 0, 100, 100, 100, 0, 100, 100, 100],
          "A1": [5.75, 0, 0, 0, 0, 100, 0, 100, 0, 4, 0, 0, 100, 84, 0, 0, 100, 0],
          "Full loop": [0.12] + [0] * 11 + [100] + [0] * 5,
          "Full, earlier rules": [0.12] + [0] * 11 + [100, 0, 0, 100, 100, 0]}
f5 = {}
for lab, cfg in ROWS5:
    vals = []
    for s in SCEN:
        v = cell(s)[cfg]; x = 100.0 * v["false_effective_k"] / v["n"]
        vals.append((float("%.2f" % x) if lab in ("A1", "Full loop", "Full, earlier rules") else r1(x)) if s == "S0" else round(x))
    f5[lab] = vals
    eq("Fig5 %s (%%)" % lab, vals, SHOWN5[lab])

# ------------------------------------------------------------------ Fig. 6  (outcomes, stops, exposure)
f6a = {}
for s in SCEN:
    v = cell(s)["FULL"]; n = v["n"]; d = v["declared_k"]
    f6a[s] = [100.0 * d.get(x, 0) / n for x in ("EFFECTIVE", "EFFECTIVE_PARTIAL", "UNRESOLVED")]
V["Fig6a declared EFFECTIVE Π / scope / UNRESOLVED (%)"] = f6a
f6b = [round(cell(s)["FULL"]["stops_k"] / cell(s)["FULL"]["n"], 2) for s in SCEN]
eq("Fig6b stops per incident", f6b, [0.30, 0.00, 0.84, 0.00, 0.85, 0.85, 0.85, 0.85, 0.86, 0.85, 0.02, 0.85, 0.00, 0.00, 0.85, 0.83, 0.86, 0.85])
CFG6 = [("B1", "B1_agent_selfreport"), ("B2", "B2_SG_apiack"), ("B3", "B3_SG_naiveprobe"), ("B4", "B4_SG_NACLv4_apiack"),
        ("B5", "B5_SG_NACLdual_apiack"), ("A1", "A1_nosel_verify"), ("A2", "A2_sel_apiack"), ("Full loop", "FULL")]
f6c = [r1(P[c]["mean_exposure_min"]) for _, c in CFG6]
eq("Fig6c exposed minutes in 2 h", f6c, [84.1, 87.5, 87.5, 53.2, 38.9, 16.6, 40.6, 14.9])

# ------------------------------------------------------------------ Fig. 7  (sensitivity end points)
fe = lambda s: s["false_effective_k"] / s["n"]
def ends(key, cfg, f):
    vals = [f(r[cfg]) for r in e4[key]]; return [vals[0], vals[-1]]
f7 = {"B2 · share with established connections (%)": [r1(100 * x) for x in ends("tracked", "B2_SG_apiack", fe)],
      "B5 · share with established connections (%)": [r1(100 * x) for x in ends("tracked", "B5_SG_NACLdual_apiack", fe)],
      "A1 · share of strategic adversaries (%)": [r1(100 * x) for x in ends("late", "A1_nosel_verify", fe)],
      "Stops · verifier coverage 0.3 → 1": [round(x, 2) for x in ends("v_same", "FULL", lambda s: s["stops_k"] / s["n"])],
      "Stops · share with established connections": [round(x, 2) for x in ends("tracked", "FULL", lambda s: s["stops_k"] / s["n"])],
      "Residual · operator approval 0.5 → 1 (%)": [r1(100 * x) for x in ends("p_approve", "FULL", lambda s: s["residual_k"] / s["n"])]}
SHOWN7 = [[36.4, 93.4], [16.6, 40.6], [1.5, 9.8], [0.33, 0.27], [0.21, 0.34], [17.1, 2.2]]
for (k, v), s in zip(f7.items(), SHOWN7):
    eq("Fig7 " + k, v, s)
mx = max(fe(r["FULL"]) for k, rr in e4.items() if k != "documented_log_delay" for r in rr)
eq("Fig7 Full loop max false-effective (%)", r1(100 * mx), 0.8)

json.dump(V, open(os.path.join(HERE, "figure_values.json"), "w"), indent=1, ensure_ascii=False)
print("\n%d mismatch(es)" % len(fails) if fails else "\nall values shown in the submitted figures reproduced; written to figure_values.json")

# ------------------------------------------------------------------ redraw (submitted layout)
if "--no-draw" not in sys.argv:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import numpy as np
    OUT = os.path.join(HERE, "out", "figs_submitted"); os.makedirs(OUT, exist_ok=True)
    plt.rcParams.update({"font.family": "sans-serif", "font.size": 8, "axes.spines.top": False, "axes.spines.right": False, "legend.frameon": False})
    NAVY, TEAL, CORAL, GREY, SAND = "#1f3a5f", "#2a9d8f", "#e76f51", "#8d99ae", "#e9c46a"
    def save(fig, name):
        fig.savefig(os.path.join(OUT, name + ".png"), dpi=300, bbox_inches="tight"); plt.close(fig)
    # Fig 2
    fig, (a, b) = plt.subplots(1, 2, figsize=(10, 4.2), gridspec_kw=dict(width_ratios=[1, 1.3]))
    x = np.arange(4); w = 0.27
    for i, (k, lab, col) in enumerate((("other", "Established, other subnet", NAVY), ("same", "Established, same subnet", TEAL), ("new", "New connections", CORAL))):
        a.bar(x + (i - 1) * w, f2a[k], w, color=col, label=lab)
    a.set_xticks(x); a.set_xticklabels(["Baseline", "Isolation\nsecurity group", "plus ACL deny\nentries", "Instance\nstopped"])
    a.set_ylabel("Exchanges that succeeded (%)"); a.legend(loc="upper center", bbox_to_anchor=(0.5, -0.18), ncol=2); a.text(-0.15, 1.02, "a", transform=a.transAxes, weight="bold")
    for i, k in enumerate(order2b):
        md, p95, mx_ = rows2b[k]; yy = len(order2b) - 1 - i
        b.barh(yy, md, color="#c9d6e8", height=0.35); b.barh(yy, p95 - md, left=md, color=NAVY, height=0.35)
        b.plot([p95, mx_], [yy, yy], color=NAVY, lw=1); b.plot(mx_, yy, "o", color=CORAL)
        b.text(md, yy + 0.3, "%g / %g / %s" % (md, p95, format(int(mx_), ",")), fontsize=7, color="#555")
    b.axvline(600, color="#c0392b", ls="--", lw=1); b.text(600, len(order2b) - 0.4, "documented ≈ 600 s", color="#c0392b", fontsize=7)
    b.set_yticks(range(len(order2b))); b.set_yticklabels(order2b[::-1]); b.set_xlabel("Delivery delay (s)"); b.text(-0.35, 1.02, "b", transform=b.transAxes, weight="bold")
    save(fig, "Fig2")
    # Fig 4
    fig = plt.figure(figsize=(10, 5.5)); gs = fig.add_gridspec(2, 2, height_ratios=[1, 1.1])
    a = fig.add_subplot(gs[0, :]); x = np.arange(6); cols = [GREY, SAND, NAVY, TEAL, CORAL]; w = 0.16
    for i, (lab, vals) in enumerate(f4a.items()):
        a.bar(x + (i - 2) * w, vals, w, color=cols[i], label=lab)
    a.set_xticks(x); a.set_xticklabels(["a One node", "b Two nodes,\ntarget's plane", "c One credential,\ntwo planes", "d Four nodes,\none other plane", "e Two other\nplanes", "f Target's plane +\none node"])
    a.set_ylabel("False containment (%)"); a.legend(loc="center left", bbox_to_anchor=(1, 0.5)); a.text(-0.06, 1.02, "a", transform=a.transAxes, weight="bold")
    b = fig.add_subplot(gs[1, 0]); c = fig.add_subplot(gs[1, 1])
    labs = ["chosen\nsetting", "θ = 2.1", "$c_{L3}$ = 0.6", "$k_{L3}$ = 2"]; vals = [100 * v for _, v in f4b]
    b.barh(range(4)[::-1], vals, color=NAVY); b.set_yticks(range(4)[::-1]); b.set_yticklabels(labs); b.set_xlim(0, 100); b.set_xlabel("Detection of real bypasses (%)")
    for yy, v in zip(range(4)[::-1], vals): b.text(v + 1, yy, "%.1f" % v, va="center", fontsize=7)
    b.text(-0.25, 1.02, "b", transform=b.transAxes, weight="bold")
    labs = ["chosen, case d", "chosen, case e", "θ = 0.9, case d", "θ = 2.1, case e", "$c_{L3}$ = 1.6, case d", "$k_{L3}$ = 2, case e"]; vals = [100 * v for _, v in f4c]
    c.barh(range(6)[::-1], vals, color=CORAL); c.set_yticks(range(6)[::-1]); c.set_yticklabels(labs); c.set_xlim(0, 100); c.set_xlabel("False containment (%)")
    for yy, v in zip(range(6)[::-1], vals): c.text(v + 1, yy, "%.0f" % v, va="center", fontsize=7)
    c.text(-0.35, 1.02, "c", transform=c.transAxes, weight="bold")
    fig.tight_layout(); save(fig, "Fig4")
    # Fig 5
    fig, a = plt.subplots(figsize=(10, 3.2)); M = np.array([[v for v in f5[l]] for l, _ in ROWS5], dtype=float)
    a.imshow(np.log10(1 + M), cmap="Reds", aspect="auto", vmin=0, vmax=2.3)
    for i in range(M.shape[0]):
        for j in range(M.shape[1]):
            lab_ = ROWS5[i][0]; txt = ("%.1f" if lab_ in ("B2", "B5") else "%.2f") % M[i, j] if j == 0 else "%g" % M[i, j]
            a.text(j, i, txt, ha="center", va="center", fontsize=7, color="white" if M[i, j] >= 50 else "black")
    a.set_xticks(range(len(SCEN))); a.set_xticklabels(SCEN); a.xaxis.tick_top(); a.set_yticks(range(len(ROWS5))); a.set_yticklabels([l for l, _ in ROWS5])
    a.axhline(3.5, color="#555", ls="--", lw=1); save(fig, "Fig5")
    # Fig 6
    fig = plt.figure(figsize=(10, 5.5)); gs = fig.add_gridspec(2, 2, width_ratios=[1.6, 1])
    a = fig.add_subplot(gs[0, :]); bot = np.zeros(len(SCEN))
    for i, (lab, col) in enumerate((("EFFECTIVE for Π", NAVY), ("EFFECTIVE for a scope", TEAL), ("UNRESOLVED", CORAL))):
        vals = np.array([f6a[s][i] for s in SCEN]); a.bar(SCEN, vals, bottom=bot, color=col, label=lab); bot += vals
    a.set_ylabel("Incidents (%)"); a.legend(loc="center left", bbox_to_anchor=(1, 0.5)); a.text(-0.06, 1.02, "a", transform=a.transAxes, weight="bold")
    b = fig.add_subplot(gs[1, 0]); b.bar(SCEN, f6b, color=GREY); b.set_ylabel("Instance stops per incident"); b.set_ylim(0, 1)
    for i, v in enumerate(f6b): b.text(i, v + 0.02, "%.2f" % v, ha="center", fontsize=6)
    b.tick_params(axis="x", labelsize=7); b.text(-0.1, 1.02, "b", transform=b.transAxes, weight="bold")
    c = fig.add_subplot(gs[1, 1]); labs = [l for l, _ in CFG6]
    c.barh(range(8)[::-1], f6c, color=NAVY); c.set_yticks(range(8)[::-1]); c.set_yticklabels(labs); c.set_xlim(0, 100); c.set_xlabel("Exposed min in 2 h")
    for yy, v in zip(range(8)[::-1], f6c): c.text(v + 1, yy, "%.1f" % v, va="center", fontsize=7)
    c.text(-0.2, 1.02, "c", transform=c.transAxes, weight="bold"); fig.tight_layout(); save(fig, "Fig6")
    # Fig 7
    fig, axs = plt.subplots(3, 1, figsize=(8, 5), gridspec_kw=dict(height_ratios=[4, 2, 1.3]))
    groups = [(axs[0], ["B2 · share with established connections (%)", "B5 · share with established connections (%)", "A1 · share of strategic adversaries (%)"], (0, 100), "a"),
              (axs[1], ["Stops · verifier coverage 0.3 → 1", "Stops · share with established connections"], (0, 0.5), "b"),
              (axs[2], ["Residual · operator approval 0.5 → 1 (%)"], (0, 20), "c")]
    for ax, keys, lim, letter in groups:
        for i, k in enumerate(keys):
            lo, hi = f7[k]; yy = len(keys) - 1 - i
            ax.plot([lo, hi], [yy, yy], color=GREY, lw=2); ax.plot(lo, yy, "o", mfc="white", mec=NAVY); ax.plot(hi, yy, "o", color=NAVY)
            ax.text(lo, yy + 0.25, "%g" % lo, ha="center", fontsize=7); ax.text(hi, yy + 0.25, "%g" % hi, ha="center", fontsize=7)
        if letter == "a":
            ax.plot(r1(100 * mx), -1, "o", color=CORAL); ax.text(r1(100 * mx) + 2, -1, "Full loop: ≤ %.1f at every point" % r1(100 * mx), va="center", fontsize=7)
            keys = keys + ["Full loop · all variations"]
        ax.set_yticks(range(len(keys))[::-1] if letter != "a" else [2, 1, 0, -1]); ax.set_yticklabels(keys); ax.set_xlim(*lim)
        ax.set_ylim((-1.6 if letter == "a" else -0.6), len(keys) - (1.4 if letter == "a" else 0.3))
        ax.text(-0.45, 1.02, letter, transform=ax.transAxes, weight="bold")
    fig.tight_layout(); save(fig, "Fig7")
    print("redrawn figures written to", OUT)

sys.exit(1 if fails else 0)
