"""Figures 1-7. Vector .eps for submission and 600-dpi .png for the Word manuscript.
No titles inside figures, sans-serif 7-9 pt, distinguishable in greyscale (journal artwork rules)."""
import json, os
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib import font_manager
from matplotlib.patches import FancyBboxPatch

HERE = os.path.dirname(os.path.abspath(__file__))
R = lambda n: json.load(open(os.path.join(HERE, "results", n)))
have = {f.name for f in font_manager.fontManager.ttflist}
FONT = next((f for f in ("Arial", "Helvetica", "Liberation Sans", "DejaVu Sans") if f in have), "sans-serif")
plt.rcParams.update({"font.family": FONT, "font.size": 8, "axes.linewidth": 0.6, "pdf.fonttype": 42,
                     "ps.fonttype": 42, "axes.spines.top": False, "axes.spines.right": False,
                     "xtick.major.width": 0.6, "ytick.major.width": 0.6, "legend.frameon": False})
W1, W2 = 3.31, 6.85   # 84 mm and 174 mm


def save(fig, name):
    os.makedirs(os.path.join(HERE, "figs"), exist_ok=True)
    fig.savefig(os.path.join(HERE, "figs", name + ".png"), dpi=600)
    fig.savefig(os.path.join(HERE, "figs", name + ".eps"))
    plt.close(fig)


def box(ax, xy, w, h, text, fc="white", ls="-", fs=7.5, lw=0.8):
    ax.add_patch(FancyBboxPatch(xy, w, h, boxstyle="round,pad=0.006,rounding_size=0.012", fc=fc, ec="black", lw=lw, ls=ls))
    ax.text(xy[0] + w / 2, xy[1] + h / 2, text, ha="center", va="center", fontsize=fs, linespacing=1.25)


def arrow(ax, a, b, text=None, ls="-", off=(0, 0), fs=6.5, rad=0.0):
    ax.annotate("", xy=b, xytext=a, arrowprops=dict(arrowstyle="-|>", lw=0.8, ls=ls, color="black",
                                                    shrinkA=1, shrinkB=1, connectionstyle=f"arc3,rad={rad}"))
    if text:
        ax.text((a[0] + b[0]) / 2 + off[0], (a[1] + b[1]) / 2 + off[1], text, ha="center", va="center", fontsize=fs,
                bbox=dict(fc="white", ec="none", pad=0.6))


# ------------------------------------------------------------------ Fig 1 architecture / loop
def fig1():
    fig = plt.figure(figsize=(W2, 3.3)); ax = fig.add_axes([0, 0, 1, 1]); ax.axis("off")
    ax.set_xlim(0, 1); ax.set_ylim(0, 1)
    ax.add_patch(FancyBboxPatch((0.02, 0.04), 0.96, 0.27, boxstyle="round,pad=0.004,rounding_size=0.01", fc="#f2f2f2", ec="black", lw=0.6, ls="--"))
    ax.text(0.03, 0.285, "Protected account A", fontsize=7, style="italic", va="center")
    ax.add_patch(FancyBboxPatch((0.02, 0.40), 0.96, 0.57, boxstyle="round,pad=0.004,rounding_size=0.01", fc="white", ec="black", lw=0.6, ls="--"))
    ax.text(0.03, 0.945, "Assurance account B (trusted base)", fontsize=7, style="italic", va="center")
    xs = [0.04, 0.232, 0.424, 0.616, 0.808]
    labels = ["1 Monitor\nrecords and attribute\nsnapshots",
              "2 Analyse\ngroups, independence-\naware trigger",
              "3 Decide\nselect enforcers,\nverifier, observer",
              "4 Enforce\ndeploy, record $T_{iso}$\n(API ack is not proof)",
              "5 Verify\nEFFECTIVE / FAILED /\nINCONCLUSIVE"]
    for x, l in zip(xs, labels):
        box(ax, (x, 0.60), 0.155, 0.2, l, fs=7)
    for a, b in zip(xs, xs[1:]):
        arrow(ax, (a + 0.157, 0.70), (b - 0.002, 0.70))
    # feedback above the row
    arrow(ax, (0.886, 0.80), (0.502, 0.80), "FAILED: redeploy; INCONCLUSIVE: re-probe", off=(0, 0.085), rad=0.3)
    # shared relation and operator below the row
    box(ax, (0.232, 0.44), 0.347, 0.08, "share(p, q): one compromise relation\nused in steps 2, 3 and 5", fs=7, fc="#e6e6e6")
    arrow(ax, (0.31, 0.52), (0.31, 0.60)); arrow(ax, (0.50, 0.52), (0.50, 0.60))
    box(ax, (0.67, 0.44), 0.19, 0.08, "Operator approval\n(disruptive actions)", fs=7, fc="#e6e6e6")
    arrow(ax, (0.84, 0.60), (0.84, 0.52), "escalate", off=(0.045, 0.0))
    arrow(ax, (0.72, 0.52), (0.72, 0.60), "approve", off=(0.045, 0.0))
    # protected account
    box(ax, (0.04, 0.08), 0.27, 0.16, "Peer enforcers, flow logs,\ninventory and IAM interfaces")
    box(ax, (0.50, 0.08), 0.23, 0.16, "Security groups, network\nACLs, instance stop")
    box(ax, (0.80, 0.08), 0.15, 0.16, "Target X", fc="#d9d9d9")
    arrow(ax, (0.12, 0.24), (0.12, 0.60), "records,\nattributes", off=(0.05, -0.02))
    arrow(ax, (0.64, 0.60), (0.64, 0.24), "isolation\nrole", off=(-0.045, -0.13))
    arrow(ax, (0.73, 0.16), (0.80, 0.16))
    arrow(ax, (0.93, 0.60), (0.93, 0.24), "test\nflows", ls=":", off=(-0.035, -0.13))
    arrow(ax, (0.50, 0.13), (0.31, 0.13), "ACCEPT / REJECT", off=(0, 0.035))
    save(fig, "Fig1")


# ------------------------------------------------------------------ Fig 2 verification timeline
def fig2():
    fig = plt.figure(figsize=(W2, 2.1)); ax = fig.add_axes([0.01, 0.03, 0.98, 0.94]); ax.axis("off")
    ax.set_xlim(-3.2, 18.2); ax.set_ylim(0, 4.6)
    ax.annotate("", xy=(18.0, 1.5), xytext=(-3.0, 1.5), arrowprops=dict(arrowstyle="-|>", lw=0.8, color="black"))
    ax.text(18.0, 1.15, "min", fontsize=7, ha="right")
    for t, l, y in [(-2.2, "baseline\nprobes", 1.1), (0, "deploy,\n$T_{iso}$", 1.1), (1, "$T_{iso}+\\Delta t$", 0.45), (3, "probes\nend", 1.1)]:
        ax.plot([t, t], [1.35, 1.65], color="black", lw=0.8)
        ax.text(t, y, l, fontsize=6.5, ha="center", va="top")
    ax.plot([1, 1], [0.5, 1.35], color="black", lw=0.4, ls=":")
    ax.add_patch(plt.Rectangle((0, 1.9), 1, 0.5, fc="#bdbdbd", ec="black", lw=0.5, hatch="////"))
    ax.text(0.5, 2.6, "not\nevaluated", fontsize=6.5, ha="center", va="bottom")
    ax.add_patch(plt.Rectangle((1, 1.9), 2, 0.5, fc="#e6e6e6", ec="black", lw=0.5))
    ax.text(2, 2.6, "random\nprobes", fontsize=6.5, ha="center", va="bottom")
    ax.add_patch(plt.Rectangle((4, 1.9), 11, 0.5, fc="white", ec="black", lw=0.5, ls="--"))
    ax.text(9.5, 2.15, "wait for interval end and record delivery (measured in Sect. 9)", fontsize=6.5, ha="center", va="center")
    ax.plot([15, 15], [1.35, 2.4], color="black", lw=0.8)
    ax.text(15, 1.1, "closing probes,\ndecision", fontsize=6.5, ha="center", va="top")
    ax.text(5.2, 3.75, "FAILED: any answer to a probe, or any ACCEPT record on a covered path\n"
            "EFFECTIVE: otherwise, a REJECT record of the verifier's own probe, per class\n"
            "INCONCLUSIVE: otherwise; re-probe, records that arrive late still count",
            fontsize=6.5, va="center", ha="left", linespacing=1.45,
            bbox=dict(fc="white", ec="black", lw=0.5, boxstyle="round,pad=0.4"))
    ax.annotate("", xy=(13.2, 3.1), xytext=(15, 2.45), arrowprops=dict(arrowstyle="-", lw=0.5, color="black"))
    save(fig, "Fig2")


# ------------------------------------------------------------------ Fig 3 trigger
ATT = ["a_one_node", "b_two_nodes_target_plane", "c_one_credential_two_planes", "d_one_other_plane",
       "e_two_other_planes", "f_target_plane_plus_one_node"]
ATT_L = ["a", "b", "c", "d", "e", "f"]


def fig3():
    e1 = R("e1_trigger.json")
    fig, axs = plt.subplots(1, 3, figsize=(W2, 2.8), gridspec_kw=dict(width_ratios=[1.5, 1, 1], wspace=0.42, left=0.07, right=0.985, bottom=0.17, top=0.76))
    ax = axs[0]
    rules = [("count", "Witness count", "white", "////"), ("node_dedup", "One vote per node", "#bdbdbd", ""), ("ours", "Independence-aware", "black", "")]
    x = np.arange(len(ATT))
    for i, (k, lab, fc, h) in enumerate(rules):
        ax.bar(x + (i - 1) * 0.27, [e1["fabrication"][a][k] for a in ATT], 0.26, fc=fc, ec="black", lw=0.5, hatch=h, label=lab)
    ax.set_xticks(x); ax.set_xticklabels(ATT_L); ax.set_ylim(0, 1.05); ax.set_ylabel("False-containment rate")
    ax.set_xlabel("Fabrication case (Table 7)")
    ax.legend(fontsize=6, loc="lower center", bbox_to_anchor=(0.5, 1.02), ncol=2, columnspacing=0.8, handlelength=1.2)
    ax.text(-0.16, 1.2, "a", transform=ax.transAxes, fontweight="bold", fontsize=9)
    for ax, key, xk, xl, tag in ((axs[1], "sweep_theta", "theta", "Threshold $\\theta$ ($c_{L3}=1.0$)", "b"),
                                 (axs[2], "sweep_cap", "cap", "Plane cap $c_{L3}$ ($\\theta=1.5$)", "c")):
        rows = e1[key]; xs = [r[xk] for r in rows]
        ax.plot(xs, [r["detect"] for r in rows], "-o", color="black", ms=3, lw=1, label="Real bypass detected")
        ax.plot(xs, [r["fab_one_plane"] for r in rows], "--s", color="black", ms=3, lw=1, mfc="white", label="False containment, case d")
        ax.plot(xs, [r["fab_two_planes"] for r in rows], ":^", color="#666666", ms=3, lw=1, label="False containment, case e")
        ax.set_ylim(-0.03, 1.05); ax.set_xlabel(xl)
        ax.text(-0.22, 1.2, tag, transform=ax.transAxes, fontweight="bold", fontsize=9)
    axs[1].set_ylabel("Rate")
    axs[2].legend(fontsize=6, loc="lower center", bbox_to_anchor=(-0.3, 1.02), ncol=2, columnspacing=0.8, handlelength=1.8)

    save(fig, "Fig4")


# ------------------------------------------------------------------ Fig 4 false-effective heat map
LABEL = {"B1_agent_selfreport": "B1 Agent + self-report", "B2_SG_apiack": "B2 SG + API ack",
         "B3_SG_naiveprobe": "B3 SG + naive probe", "B4_SG_NACLv4_apiack": "B4 SG + NACL(v4) + API ack",
         "A1_nosel_verify": "A1 Verify, no selection", "A2_sel_apiack": "A2 Selection, API ack",
         "FULL": "Full loop"}


def scn_keys(e2):
    def num(k):
        s = k.split("_")[0][1:]
        return (int(s.rstrip("L")), s.endswith("L"))
    return sorted(e2, key=num)


def fig4():
    e2 = R("e2_containment.json")
    scn = scn_keys(e2); short = [s.split("_")[0] for s in scn]
    cfgs = list(LABEL)
    M = np.array([[e2[s][c]["false_effective"] for s in scn] for c in cfgs])
    fig = plt.figure(figsize=(W2, 2.5)); ax = fig.add_axes([0.235, 0.14, 0.68, 0.82])
    im = ax.imshow(M, cmap="Greys", vmin=0, vmax=1, aspect="auto")
    ax.set_xticks(range(len(short))); ax.set_xticklabels(short, fontsize=7)
    ax.set_yticks(range(len(cfgs))); ax.set_yticklabels([LABEL[c] for c in cfgs], fontsize=7)
    for sp in ax.spines.values():
        sp.set_visible(True)
    for i in range(M.shape[0]):
        for j in range(M.shape[1]):
            v = M[i, j]
            t = "0" if v == 0 else ("1" if v == 1 else (f"{v:.2f}"[1:] if v >= 0.005 else f"{v:.3f}"[1:]))
            ax.text(j, i, t, ha="center", va="center", fontsize=6.5, color="white" if v > 0.5 else "black")
    ax.axhline(3.5, color="black", lw=0.8); ax.axvline(0.5, color="black", lw=0.8)
    cax = fig.add_axes([0.93, 0.14, 0.015, 0.82]); cb = fig.colorbar(im, cax=cax); cb.ax.tick_params(labelsize=6.5)
    cb.set_label("False-effective rate", fontsize=7)
    save(fig, "Fig5")


# ------------------------------------------------------------------ Fig 5 outcomes and exposure
def fig5():
    e2 = R("e2_containment.json")
    scn = scn_keys(e2); short = [s.split("_")[0] for s in scn]
    fig, axs = plt.subplots(1, 2, figsize=(W2, 2.3), gridspec_kw=dict(width_ratios=[1.7, 1], wspace=0.3, left=0.07, right=0.99, bottom=0.2, top=0.84))
    ax = axs[0]
    parts = [("EFFECTIVE", "white", "", "EFFECTIVE"), ("EFFECTIVE_PARTIAL", "#bdbdbd", "", "EFFECTIVE (scoped)"), ("UNRESOLVED", "black", "", "UNRESOLVED")]
    bottom = np.zeros(len(scn))
    for k, fc, h, lab in parts:
        v = np.array([e2[s]["FULL"]["declared"].get(k, 0.0) for s in scn])
        ax.bar(range(len(scn)), v, 0.7, bottom=bottom, fc=fc, ec="black", lw=0.5, hatch=h, label=lab); bottom += v
    st = [e2[s]["FULL"]["stops_per_incident"] for s in scn]
    ax.plot(range(len(scn)), st, "D", color="black", mfc="white", ms=4, mew=0.8, label="Instance stopped", zorder=5)
    ax.set_xticks(range(len(scn))); ax.set_xticklabels(short, fontsize=6.5, rotation=45)
    ax.set_ylabel("Fraction of incidents (full loop)"); ax.set_ylim(0, 1.02)
    ax.legend(fontsize=6.5, loc="lower center", bbox_to_anchor=(0.5, 1.01), ncol=4, columnspacing=0.8, handlelength=1.2)
    ax.text(-0.09, 1.08, "a", transform=ax.transAxes, fontweight="bold", fontsize=9)
    ax = axs[1]
    cfgs = list(LABEL)
    v = [e2["S0_random_mix"][c]["mean_exposure_min"] for c in cfgs]
    ax.barh(range(len(cfgs)), v, 0.65, fc="#bdbdbd", ec="black", lw=0.5)
    ax.set_yticks(range(len(cfgs))); ax.set_yticklabels([LABEL[c].split(" ")[0] if c != "FULL" else "Full" for c in cfgs], fontsize=7)
    ax.invert_yaxis(); ax.set_xlabel("Mean exposed minutes in 2 h (S0)")
    for i, x in enumerate(v):
        ax.text(x + 1.5, i, f"{x:.1f}", va="center", fontsize=6.5)
    ax.set_xlim(0, max(v) * 1.18)
    ax.text(-0.2, 1.08, "b", transform=ax.transAxes, fontweight="bold", fontsize=9)
    save(fig, "Fig6")


# ------------------------------------------------------------------ Fig 6 sensitivity
def fig6():
    e4 = R("e4_sensitivity.json")
    keys = [("late", "P(strategic reversion)"), ("iam_miss", "P(IAM analysis misses edge)"), ("reach_sg", "P(target role reaches SG admin)"),
            ("tracked", "P(tracked connections)"), ("v_same", "P(verifier in target subnet)"), ("p_approve", "P(operator approves)")]
    fig, axs = plt.subplots(2, 3, figsize=(W2, 3.9), gridspec_kw=dict(wspace=0.35, hspace=0.8, left=0.075, right=0.99, bottom=0.11, top=0.9))
    sty = {"B2_SG_apiack": ("--s", "#666666", "B2"), "A2_sel_apiack": (":^", "#666666", "A2"),
           "A1_nosel_verify": ("-.o", "black", "A1"), "FULL": ("-o", "black", "Full loop")}
    for i, (ax, (k, xl)) in enumerate(zip(axs.flat, keys)):
        rows = e4[k]; xs = [r["value"] for r in rows]
        if i < 4:
            for c, (ls, col, lab) in sty.items():
                ax.plot(xs, [r[c]["false_effective"] for r in rows], ls, color=col, ms=3, lw=1, mfc="white" if c != "FULL" else "black", label=lab)
            ax.set_ylabel("False-effective rate" if i in (0, 3) else ""); ax.set_ylim(-0.03, 1.0)
        else:
            ax.plot(xs, [r["FULL"]["stops_per_incident"] for r in rows], "-o", color="black", ms=3, lw=1, label="Stops per incident")
            ax.plot(xs, [r["FULL"]["residual_exposure"] for r in rows], "--s", color="black", ms=3, lw=1, mfc="white", label="Residual exposure")
            ax.plot(xs, [r["FULL"]["unresolved"] for r in rows], ":^", color="#666666", ms=3, lw=1, label="UNRESOLVED")
            ax.set_ylabel("Full loop: rate" if i == 4 else ""); ax.set_ylim(-0.02, 0.6)
        ax.set_xlabel(xl, fontsize=7.5)
        ax.text(-0.2, 1.08, "abcdef"[i], transform=ax.transAxes, fontweight="bold", fontsize=9)
    axs[0, 1].legend(fontsize=6.5, loc="lower center", bbox_to_anchor=(0.5, 1.03), ncol=4, columnspacing=1.0)
    axs[1, 1].legend(fontsize=6.5, loc="lower center", bbox_to_anchor=(1.1, 1.03), ncol=3, columnspacing=1.0)
    save(fig, "Fig7")


# ------------------------------------------------------------------ Fig 7 live measurement
def fig7():
    p = os.path.join(HERE, "aws", "measure_summary.json")
    if not os.path.exists(p):
        return
    m = json.load(open(p))
    fig, axs = plt.subplots(1, 2, figsize=(W2, 2.5), gridspec_kw=dict(width_ratios=[2.1, 1], wspace=0.28, left=0.2, right=0.99, bottom=0.2, top=0.9))
    ax = axs[0]
    rows = m["timeline"]["rows"]            # label -> list of (t_min, ok_fraction)
    labels = list(rows)
    for i, lab in enumerate(labels):
        for t, ok in rows[lab]:
            if ok is None:
                continue
            ax.add_patch(plt.Rectangle((t, i - 0.36), m["timeline"]["bin_min"], 0.72, fc=str(1 - ok * 0.75) if ok > 0 else "white",
                                       ec="black" if ok > 0 else "#999999", lw=0.25))
    for name, t in m["timeline"]["phases"].items():
        ax.axvline(t, color="black", lw=0.9, ls="--")
        ax.text(t, len(labels) - 0.35, " " + name, fontsize=6.5, va="bottom", ha="left")
    ax.set_yticks(range(len(labels))); ax.set_yticklabels(labels, fontsize=6.5)
    ax.set_ylim(-0.6, len(labels) + 0.25); ax.invert_yaxis()
    ax.set_xlim(m["timeline"]["t_min"], m["timeline"]["t_max"]); ax.set_xlabel("Minutes from security-group swap")
    ax.text(-0.3, 1.04, "a", transform=ax.transAxes, fontweight="bold", fontsize=9)
    ax = axs[1]
    d = np.sort(np.array(m["delivery_delay_samples_s"])) / 60.0
    ax.step(d, np.arange(1, len(d) + 1) / len(d), where="post", color="black", lw=1)
    ax.set_xlabel("Delivery delay (min)"); ax.set_ylabel("Cumulative fraction of records")
    ax.set_ylim(0, 1.02)
    ax.text(-0.3, 1.04, "b", transform=ax.transAxes, fontweight="bold", fontsize=9)
    save(fig, "Fig3")


if __name__ == "__main__":
    fig1(); fig2(); fig3(); fig4(); fig5(); fig6(); fig7()
    print("figures written with font", FONT)
