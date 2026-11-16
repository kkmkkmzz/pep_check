"""Self-verification. Exits non-zero if any check fails.
  1 reproducibility of E1/E2/E4 across interpreter hash seeds
  2 property tests of Lemma 1 and Propositions 1-3 on random inputs
  3 worked cases of the specification
  4 claims made in the text that are not table look-ups
  5 manuscript hygiene of the generated .docx (skipped when absent; see check_manuscript.py)
"""
import hashlib, json, os, random, re, subprocess, sys, zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import containment_emu as emu
from core import Point, Evidence, TriggerParams, trigger, share, select_enforcers
import run_experiments as rx

CAL = os.path.join(HERE, "aws", "measure_summary.json")
if os.path.exists(CAL):
    m = json.load(open(CAL)); emu.calibrate(m["delivery_delay_s"]["p05"], m["delivery_delay_s"]["p95"])

fails = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + (("  -- " + str(detail)) if detail else ""))
    if not ok:
        fails.append(name)


# ---------------------------------------------------------------- 1 reproducibility
def digest():
    h = hashlib.sha256()
    for f in ("e1_trigger.json", "e2_containment.json", "e4_sensitivity.json"):
        h.update(open(os.path.join(HERE, "results", f), "rb").read())
    return h.hexdigest()


if "--quick" not in sys.argv:
    d0 = digest()
    env = dict(os.environ, PYTHONHASHSEED="12345", PEP_SKIP_E3="1")
    subprocess.run([sys.executable, os.path.join(HERE, "run_experiments.py")], check=True, env=env, stdout=subprocess.DEVNULL)
    d1 = digest()
    check("1 results identical after re-run with a different hash seed", d0 == d1, d1[:16])

# ---------------------------------------------------------------- 2 property tests
r = random.Random(20261110)


def rnd_point(i):
    c = None if r.random() < 0.05 else frozenset(r.sample(["a", "b", "c", "d", "e", "f"], r.randint(0, 2)))
    return Point(f"p{i}", None if r.random() < 0.05 else f"e{r.randint(0, 30)}", None if r.random() < 0.05 else f"n{r.randint(0, 8)}",
                 r.choice(["M1", "M2", "M3", None]), c)


ok_sym = ok_mono = True
for i in range(20000):
    p, q = rnd_point(1), rnd_point(2)
    ok_sym &= share(p, q) == share(q, p)
    if not share(p, q):
        continue
    for attr in ("L1", "L2", "C"):
        p2 = Point(p.pid, **{a: (None if a == attr else getattr(p, a)) for a in ("L1", "L2", "L3", "C")})
        ok_mono &= share(p2, q)
check("2a Lemma 1: share is symmetric (20,000 random pairs)", ok_sym)
check("2b Lemma 1: unknown attributes never turn share from 1 to 0", ok_mono)

prm = TriggerParams()
viol = {"node": 0, "component": 0, "plane": 0}
for i in range(20000):
    Y = Point("Y", "ey", "ny", "M1", frozenset({"ry"}))
    n = r.randint(1, 12)
    # (i) one node, arbitrary planes/credentials
    ev = [Evidence(Point(f"s{j}", f"e{j}", "nA", r.choice(["M1", "M2", "M3"]), frozenset({f"r{r.randint(0, 5)}"})), 1.0, r.uniform(0.5, 1.0)) for j in range(n)]
    viol["node"] += trigger(Y, ev, prm).verdict == "CONTAIN"
    # (ii) one connected component of the C graph (chain a-b, b-c, ...), arbitrary nodes/planes
    ev = [Evidence(Point(f"s{j}", f"e{j}", f"n{j}", r.choice(["M2", "M3"]), frozenset({f"k{j}", f"k{j + 1}"})), 1.0, r.uniform(0.5, 1.0)) for j in range(n)]
    viol["component"] += trigger(Y, ev, prm).verdict == "CONTAIN"
    # (iii) one management plane, arbitrary nodes/credentials
    pl = r.choice(["M1", "M2", "M3"])
    ev = [Evidence(Point(f"s{j}", f"e{j}", f"n{j}", pl, frozenset({f"r{j}"})), 1.0, r.uniform(0.5, 1.0)) for j in range(n)]
    viol["plane"] += trigger(Y, ev, prm).verdict == "CONTAIN"
check("2c Proposition 1: no containment from one node / one control component / one plane (3 x 20,000 trials)", sum(viol.values()) == 0, viol)

# Proposition 2: when the IAM analysis is sound, no trusted enforcer is ever modifiable by the adversary
bad = n_sel = 0
fe_sound = fe_total = fe_not_miss_late = 0
N = 20000
for i in range(N):
    inc = emu.random_incident(5_000_000 + i)
    X, cand = emu._points(inc)
    sel = {e.pid for e in select_enforcers(X, cand.values(), "cred-M1").enforcers}
    trusted = (["SG"] if "SG" in sel else []) + (emu._nacls(inc) if "NACL" in sel else []) + (["STOP"] if "STOP" in sel else [])
    if not inc.iam_miss:
        n_sel += len(trusted)
        bad += sum(inc.can_modify(e) for e in trusted)
    o = emu.run(inc, "FULL")
    if o.false_effective:
        fe_total += 1
        if not (inc.iam_miss and inc.late):
            fe_not_miss_late += 1
        if not inc.iam_miss:
            fe_sound += 1
check(f"2d Proposition 2: with sound analysis no selected enforcer is adversary-modifiable ({n_sel} selections)", bad == 0, bad)
check(f"2e Propositions 2+3: full loop never false-effective when the analysis is sound ({N} random incidents)", fe_sound == 0, fe_sound)
check("2f every false-effective incident of the full loop has a missed IAM edge and late reversion", fe_not_miss_late == 0, f"{fe_total} false-effective in {N}")

# Proposition 3 on the decision function
from core import decide
ok = all(decide(a, b, c) == ("FAILED" if (a or b) else ("EFFECTIVE" if c else "INCONCLUSIVE")) for a in (0, 1) for b in (0, 1) for c in (0, 1))
check("2g Proposition 3: decision order, silence is INCONCLUSIVE", ok and decide(False, False, False) == "INCONCLUSIVE")

# ---------------------------------------------------------------- 3 worked cases
wc = rx.worked_cases()
exp = {"1_true_bypass": ("CONTAIN", 1.95), "2_one_node": ("HOLD", 1.0), "3_two_nodes_same_plane": ("HOLD", 1.0),
       "4_plane_conceals": ("HOLD", 0.95), "5_other_plane": ("HOLD", 1.0)}
check("3 five worked cases of the specification give the specified verdicts and scores",
      all(wc[k]["verdict"] == v and abs(wc[k]["score"] - s) < 1e-9 for k, (v, s) in exp.items()))

# ---------------------------------------------------------------- 4 textual claims
e1 = json.load(open(os.path.join(HERE, "results", "e1_trigger.json")))
e2 = json.load(open(os.path.join(HERE, "results", "e2_containment.json")))
e4 = json.load(open(os.path.join(HERE, "results", "e4_sensitivity.json")))
S0 = e2["S0_random_mix"]
check("4a trigger stops fabrication cases a-d completely", all(e1["fabrication"][k]["ours"] == 0 for k in e1["fabrication"] if k[0] in "abcd"))
check("4b threshold above the cap stops the one-plane case; cap above the threshold readmits it",
      all((row["fab_one_plane"] == 0) == (row["theta"] > 1.0) for row in e1["sweep_theta"]) and
      all((row["fab_one_plane"] == 0) == (row["cap"] < 1.5) for row in e1["sweep_cap"]))
order_ok = True
for k, rows in e4.items():
    if k == "documented_log_delay":
        continue
    for row in rows:
        v = [row[c]["false_effective"] for c in ("FULL", "A1_nosel_verify", "A2_sel_apiack", "B2_SG_apiack")]
        order_ok &= v == sorted(v)
check("4c ordering Full <= A1 <= A2 <= B2 of false-effective rates holds at every sensitivity point", order_ok)
check("4d baselines never stop instances; B3 differs little from B2",
      all(S0[c]["stops_per_incident"] == 0 for c in S0 if c.startswith("B")) and abs(S0["B2_SG_apiack"]["false_effective"] - S0["B3_SG_naiveprobe"]["false_effective"]) < 0.05)
check("4e S10: full loop declares UNRESOLVED in every incident without stopping", e2["S10_no_independent_enforcer"]["FULL"]["declared"] == {"UNRESOLVED": 1.0}
      and e2["S10_no_independent_enforcer"]["FULL"]["stops_per_incident"] == 0)
check("4f S6: no exposure beyond the seconds before deployment (best-effort layer holds)", e2["S6_plane_could_modify_SG_but_intact"]["FULL"]["mean_exposure_min"] < 0.1
      and e2["S6_plane_could_modify_SG_but_intact"]["FULL"]["residual_exposure"] == 0)
check("4g S7: B3 false-effective in every incident", e2["S7_outage_plus_revert"]["B3_SG_naiveprobe"]["false_effective"] == 1.0)

# ---------------------------------------------------------------- 5 manuscript hygiene
doc = os.path.join(HERE, "out", "Manuscript_JNSM_Containment_Assurance.docx")
if os.path.exists(doc):
    xml = zipfile.ZipFile(doc).read("word/document.xml").decode()
    paras = ["".join(re.findall(r"<w:t[^>]*>([^<]*)</w:t>", p)) for p in re.findall(r"<w:p[ >].*?</w:p>", xml, flags=re.S)]
    text = "\n".join(paras).replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">")
    ab = open(os.path.join(HERE, "out", "abstract.txt")).read()
    nw = len(ab.split())
    check("5a abstract has 150-250 words", 150 <= nw <= 250, nw)
    check("5b abstract has no citation and no undefined abbreviation", not re.search(r"\[\d", ab) and not re.search(r"\b(PEP|ACL|NACL|SG|IAM|VPC|AWS|SOAR|SDN)\b", ab))
    kw = [p for p in paras if p.startswith("Keywords")][0]
    check("5c four to six keywords", 4 <= len(kw.replace("Keywords", "").split("·")) <= 6, kw)
    check("5d no template leftovers (undefined, NaN, TBD, verify)", not re.search(r"undefined|NaN|\[TBD|\[verify|null%", text))
    body, refs = text.split("\nReferences\n")
    nref = len([l for l in refs.split("\n") if re.match(r"\d+\. ", l)])
    cited = set()
    for grp in re.findall(r"\[([\d,–\s]+)\]", body):
        for part in grp.split(","):
            part = part.strip()
            if "–" in part:
                a, b = part.split("–"); cited.update(range(int(a), int(b) + 1))
            elif part:
                cited.add(int(part))
    check("5e every reference is cited and every citation resolves", cited == set(range(1, nref + 1)), f"{nref} references")
    first = []
    for grp in re.findall(r"\[([\d,–\s]+)\]", body):
        for part in grp.split(","):
            ab_ = [int(x) for x in part.strip().split("–")]
            for n in range(ab_[0], ab_[-1] + 1):
                if n not in first:
                    first.append(n)
    check("5f references are numbered in order of first citation", all(first[i] <= max(first[:i + 1]) and (i == 0 or first[i] <= max(first[:i]) + 1) for i in range(len(first))))
    for kind, capre in (("Table", r"^Table (\d+) "), ("Fig.", r"^Fig\. (\d+) ")):
        caps = sorted({int(mm.group(1)) for p in paras for mm in [re.match(capre, p)] if mm})
        refd = {int(x) for x in re.findall(re.escape(kind) + r"\s(\d+)", body)}
        check(f"5g {kind} captions are consecutive and each is referenced in the text", caps == list(range(1, len(caps) + 1)) and refd == set(caps), f"{caps}")
    secs = [int(mm.group(1)) for p in paras for mm in [re.match(r"^(\d+) [A-Z]", p)] if mm and len(p) < 80]
    refsec = {int(x) for x in re.findall(r"Sects?\. (\d+)", body)} | {int(x) for a in re.findall(r"Sects\. \d+(?:\.\d+)?[–, and]+(\d+)", body) for x in [a]}
    check("5h section references point to existing sections", refsec <= set(secs), sorted(refsec - set(secs)))
    check("5i required declarations present", all(k in text for k in ("Competing interests", "Data availability", "Funding", "Use of generative artificial intelligence")))
else:
    # The manuscript is no longer generated from this directory (the v0.1 generator is not distributed).
    # Numbers in the current manuscript are checked by check_manuscript.py.
    print("SKIP  5 manuscript hygiene (no generated .docx; run check_manuscript.py for the manuscript values)")

print("\n%d check(s) failed" % len(fails) if fails else "\nall checks passed")
sys.exit(1 if fails else 0)
