"""Figures for manuscript v0.6. Numbering follows the manuscript (v0.4 order):
Fig1 loop, Fig2 initial live run, Fig3 verification timeline, Fig4 trigger (E1, unchanged),
Fig5 false-effective heat map, Fig6 outcomes and exposure, Fig7 sensitivity (all from results_v2).
Output: figs_v2/*.eps and *.png."""
import json, os
import numpy as np
import figures as F
from figures import plt, FancyBboxPatch, box, arrow, W2

HERE = os.path.dirname(os.path.abspath(__file__))
OUTDIR = os.path.join(HERE, "figs_v2")
os.makedirs(OUTDIR, exist_ok=True)


def save(fig, name):
    fig.savefig(os.path.join(OUTDIR, name + ".png"), dpi=600)
    fig.savefig(os.path.join(OUTDIR, name + ".eps"))
    plt.close(fig)


F.save = save
R2 = lambda n: json.load(open(os.path.join(HERE, "results_v2", n)))


def _compat(s):
    n = s["n"]
    return {"false_effective": s["false_effective_k"] / n,
            "declared": {k: v / n for k, v in s["declared_k"].items()},
            "stops_per_incident": s["stops_k"] / n, "mean_exposure_min": s["mean_exposure_min"],
            "residual_exposure": s["residual_k"] / n,
            "unresolved": s["declared_k"].get("UNRESOLVED", 0) / n}


e2 = R2("e2_containment_v2.json")
E2C = {"S0_random_mix": {c: _compat(v) for c, v in e2["S0_pooled"].items()}}
E2C.update({scn: {c: _compat(v) for c, v in d.items()} for scn, d in e2["scenarios"].items()})
e4 = R2("e4_sensitivity_v2.json")
E4C = {k: [{"value": r["value"], **{c: _compat(r[c]) for c in r if c != "value"}} for r in rows]
       for k, rows in e4.items() if k != "documented_log_delay"}


def R(name):
    if name == "e2_containment.json":
        return E2C
    if name == "e4_sensitivity.json":
        return E4C
    return json.load(open(os.path.join(HERE, "results", name)))   # E1 and the live measurement are unchanged


F.R = R
F.LABEL = {"B1_agent_selfreport": "B1 Agent + self-report", "B2_SG_apiack": "B2 SG + ack",
           "B3_SG_naiveprobe": "B3 SG + fixed probe", "B4_SG_NACLv4_apiack": "B4 SG + ACL (IPv4) + ack",
           "B5_SG_NACLdual_apiack": "B5 SG + ACL (both) + ack",
           "A1_nosel_verify": "A1 Verification, no selection", "A2_sel_apiack": "A2 Selection, ack",
           "FULL": "Full loop", "A1_v1rules": "A1, earlier rules", "FULL_v1rules": "Full loop, earlier rules"}


def fig1():
    fig = plt.figure(figsize=(W2, 3.5)); ax = fig.add_axes([0, 0, 1, 1]); ax.axis("off")
    ax.set_xlim(0, 1); ax.set_ylim(0, 1)
    ax.add_patch(FancyBboxPatch((0.02, 0.03), 0.96, 0.25, boxstyle="round,pad=0.004,rounding_size=0.01", fc="#f2f2f2", ec="black", lw=0.6, ls="--"))
    ax.text(0.03, 0.255, "Protected account A", fontsize=7, style="italic", va="center")
    ax.add_patch(FancyBboxPatch((0.02, 0.35), 0.96, 0.62, boxstyle="round,pad=0.004,rounding_size=0.01", fc="white", ec="black", lw=0.6, ls="--"))
    ax.text(0.03, 0.945, "Assurance account B (trusted base)", fontsize=7, style="italic", va="center")
    xs = [0.04, 0.232, 0.424, 0.616, 0.808]
    labels = ["1 Monitor\nrecords, attribute and\nconfiguration snapshots",
              "2 Trigger\nindependent groups;\nHOLD or contain",
              "3 Select\nenforcers S, best effort B,\nverifier V, observer O",
              "4 Enforce\ndeploy non-disruptive S, B;\nrecord $T_{iso}$ (ack is no proof)",
              "5 Verify\nattributed REJECTs;\nFAILED / EFFECTIVE /\nINCONCLUSIVE"]
    for x, l in zip(xs, labels):
        box(ax, (x, 0.62), 0.16, 0.2, l, fs=6.6)
    for a, b in zip(xs, xs[1:]):
        arrow(ax, (a + 0.162, 0.72), (b - 0.002, 0.72))
    arrow(ax, (0.886, 0.82), (0.70, 0.82), "first FAILED: redeploy once;  INCONCLUSIVE: re-probe", off=(-0.07, 0.07), rad=0.35)
    box(ax, (0.232, 0.40), 0.32, 0.12, "One compromise model (share, planes, C)\nused in steps 2, 3 and 5;\nno independent S, V or O: UNRESOLVED", fs=6.6, fc="#e6e6e6")
    arrow(ax, (0.31, 0.52), (0.31, 0.62)); arrow(ax, (0.50, 0.52), (0.50, 0.62))
    box(ax, (0.62, 0.40), 0.17, 0.12, "Operator approval:\nstop; route affecting\nother workloads", fs=6.6, fc="#e6e6e6")
    box(ax, (0.81, 0.40), 0.16, 0.12, "Declare: EFFECTIVE for\nscope, or UNRESOLVED;\nstop confirmed: all", fs=6.6)
    arrow(ax, (0.86, 0.62), (0.86, 0.52))
    arrow(ax, (0.83, 0.62), (0.76, 0.52), "escalate", off=(-0.005, 0.0), fs=6.0)
    # protected account
    box(ax, (0.04, 0.06), 0.26, 0.15, "Peer enforcers, flow logs,\ninventory, network config, IAM")
    box(ax, (0.47, 0.06), 0.25, 0.15, "Security groups, ACL entries;\nroute, instance stop (approved)")
    box(ax, (0.80, 0.06), 0.15, 0.15, "Target X", fc="#d9d9d9")
    arrow(ax, (0.12, 0.21), (0.12, 0.62), "records,\nsnapshots", off=(0.05, -0.05))
    arrow(ax, (0.62, 0.62), (0.62, 0.21), "isolation\nrole", off=(-0.04, -0.12))
    arrow(ax, (0.68, 0.40), (0.68, 0.21), "approved\naction", off=(0.04, -0.03), ls=":")
    arrow(ax, (0.72, 0.14), (0.80, 0.14))
    arrow(ax, (0.935, 0.62), (0.935, 0.52), None, ls=":")
    arrow(ax, (0.47, 0.11), (0.30, 0.11), "ACCEPT / REJECT", off=(0, 0.03))
    save(fig, "Fig1")


def fig3():
    fig = plt.figure(figsize=(W2, 2.3)); ax = fig.add_axes([0.01, 0.03, 0.98, 0.94]); ax.axis("off")
    ax.set_xlim(-3.2, 18.2); ax.set_ylim(0, 4.9)
    ax.annotate("", xy=(18.0, 1.5), xytext=(-3.0, 1.5), arrowprops=dict(arrowstyle="-|>", lw=0.8, color="black"))
    ax.text(18.0, 1.15, "min", fontsize=7, ha="right")
    for t, l, y in [(-2.2, "baseline probes;\nsnapshot", 1.1), (0, "deploy,\n$T_{iso}$", 1.1), (2, "$T_{iso}+\\Delta t$\n($\\Delta t$ = 2 min)", 0.6), (4, "probes\nend", 1.1)]:
        ax.plot([t, t], [1.35, 1.65], color="black", lw=0.8)
        ax.text(t, y, l, fontsize=6.5, ha="center", va="top")
    ax.add_patch(plt.Rectangle((0, 1.9), 2, 0.5, fc="#bdbdbd", ec="black", lw=0.5, hatch="////"))
    ax.text(1.0, 2.6, "records not\nevaluated", fontsize=6.5, ha="center", va="bottom")
    ax.add_patch(plt.Rectangle((2, 1.9), 2, 0.5, fc="#e6e6e6", ec="black", lw=0.5))
    ax.text(3.0, 2.6, "random\nprobes", fontsize=6.5, ha="center", va="bottom")
    ax.add_patch(plt.Rectangle((5, 1.9), 10.5, 0.5, fc="white", ec="black", lw=0.5, ls="--"))
    ax.text(10.25, 2.15, "wait for interval end and record delivery (Sect. 4)", fontsize=6.5, ha="center", va="center")
    ax.plot([15.5, 15.5], [1.35, 2.4], color="black", lw=0.8)
    ax.text(15.5, 1.1, "closing probes,\nsnapshot again,\ndecision", fontsize=6.5, ha="center", va="top")
    ax.text(5.0, 4.05, "FAILED (round): a probe is answered, or ACCEPT of X beyond the last trusted layer\n"
            "EFFECTIVE (class): otherwise, a REJECT of the verifier's own SYN probe that the snapshot\n"
            "    attributes to a selected enforcer, its window after $T_{iso}+\\Delta t$, no configuration change\n"
            "INCONCLUSIVE (class): otherwise; re-probe, late records of the same deployment still count",
            fontsize=6.4, va="center", ha="left", linespacing=1.4,
            bbox=dict(fc="white", ec="black", lw=0.5, boxstyle="round,pad=0.4"))
    save(fig, "Fig3")


def fig2_live():
    F.fig7()                    # live measurement, initial run; saved by F.fig7 under the name Fig3


def fig5_heat():
    e = F.R("e2_containment.json")
    scn = F.scn_keys(e); short = [s.split("_")[0] for s in scn]
    cfgs = ["B1_agent_selfreport", "B2_SG_apiack", "B3_SG_naiveprobe", "B4_SG_NACLv4_apiack", "B5_SG_NACLdual_apiack",
            "A2_sel_apiack", "A1_nosel_verify", "FULL", "A1_v1rules", "FULL_v1rules"]
    M = np.array([[e[s][c]["false_effective"] for s in scn] for c in cfgs])
    fig = plt.figure(figsize=(W2, 3.0)); ax = fig.add_axes([0.25, 0.12, 0.66, 0.85])
    im = ax.imshow(M, cmap="Greys", vmin=0, vmax=1, aspect="auto")
    ax.set_xticks(range(len(short))); ax.set_xticklabels(short, fontsize=6.5)
    ax.set_yticks(range(len(cfgs))); ax.set_yticklabels([F.LABEL[c] for c in cfgs], fontsize=6.5)
    for sp in ax.spines.values():
        sp.set_visible(True)
    for i in range(M.shape[0]):
        for j in range(M.shape[1]):
            v = M[i, j]
            t = "0" if v == 0 else ("1" if v == 1 else (f"{v:.2f}"[1:] if v >= 0.005 else f"{v:.3f}"[1:]))
            ax.text(j, i, t, ha="center", va="center", fontsize=6, color="white" if v > 0.5 else "black")
    ax.axhline(5.5, color="black", lw=0.8); ax.axhline(7.5, color="black", lw=0.8, ls="--"); ax.axvline(0.5, color="black", lw=0.8)
    cax = fig.add_axes([0.925, 0.12, 0.015, 0.85]); cb = fig.colorbar(im, cax=cax); cb.ax.tick_params(labelsize=6.5)
    cb.set_label("False-effective rate", fontsize=7)
    save(fig, "Fig5")


if __name__ == "__main__":
    fig1()
    F.fig7()     # live run (file name "Fig3" inside F); renamed below
    os.replace(os.path.join(OUTDIR, "Fig3.png"), os.path.join(OUTDIR, "Fig2.png"))
    os.replace(os.path.join(OUTDIR, "Fig3.eps"), os.path.join(OUTDIR, "Fig2.eps"))
    fig3()
    F.fig3()     # trigger, unchanged E1 (file name Fig4)
    fig5_heat()
    full = F.LABEL
    F.LABEL = {k: v for k, v in full.items() if not k.endswith("v1rules")}
    F.fig5()     # outcomes and exposure (file name Fig6)
    F.LABEL = full
    F.fig6()     # sensitivity (file name Fig7)
    print(sorted(os.listdir(OUTDIR)))
