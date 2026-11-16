# pep_check

Code and data for the manuscript

> Kwangmo Kim. *Closed-Loop Containment Assurance in Public Clouds: Compromise-Domain-Aware Enforcer Selection and Scoped Isolation Verification.* Submitted to the Journal of Network and Systems Management.

The repository contains the reference implementation of the compromise-domain model, the trigger, enforcer selection and the ordered decision rules; the discrete-event emulator used in Sect. 10; the scripts that ran the live measurements of Sect. 4 on Amazon Web Services; and the aggregated outputs from which every table and figure was produced. The manuscript version these files correspond to is **v0.15 (16 November 2026)**.

## Reproduce

Python 3.10 or later with `numpy` and `matplotlib` (`pip install -r requirements.txt`). The published results were produced with Python 3.13.18; a rerun with that version reproduces every result file byte for byte except `results/e3_scalability.json`, which holds wall-clock timings.

```
cd emulator
python3 run_experiments.py      # E1 trigger, E3 scalability (and the earlier-rule E2/E4 runs) -> results/        ~40 s
python3 run_experiments2.py     # E2 containment, E4 sensitivity, E5 integrated run (current rules) -> results_v2/ ~60 s
python3 figures_submitted.py    # checks every value shown in the submitted Figures 2, 4-7 and redraws them -> out/figs_submitted/
python3 figures_v2.py           # earlier draft layout of Figures 1-7 -> figs_v2/ (same data, see "Figures" below)
python3 verify.py               # reproducibility across hash seeds, property tests of Lemma 1 and Propositions 1-3, worked cases
python3 check_manuscript.py     # every emulator-derived number of the manuscript (Tables 9-13, Sects. 10.4-10.7, closed forms)
cd ..
python3 measurements/check_measurements.py   # every live-measurement number of Sect. 4 (Tables 3-5, Sect. 4.5)
```

`check_manuscript.py`, `check_measurements.py` and `figures_submitted.py` exit non-zero if any value differs from the manuscript. At the time of release none reports a mismatch (152, 49 and 29 checks).

## Figures

`figures_submitted/Fig1.png`-`Fig7.png` are the figures exactly as they appear in the submitted manuscript (extracted unchanged from the submitted .docx). They were drawn as editable charts from the values reported in the tables and the text. `emulator/figures_submitted.py` recomputes every value these figures display from the result files of this repository, checks it against the figure, writes the values to `emulator/figure_values.json`, and redraws the data figures (2, 4-7) in the same layout; the redraw has the same content but is not pixel-identical. Figures 1 and 3 are diagrams without data.

`emulator/figs_v2/` and `figures_v2.py` are an earlier draft layout produced directly from the same result files; they show the same quantities (Fig. 4b, 4c and 7 there also show the intermediate sweep points, which the submitted figures summarise by the end points reported in Sects. 10.4 and 10.7).

Rounding notes. In Fig. 2a the baseline bar for new connections is drawn at 194 of 195 exchanges (99.5 %) and labelled 100. Two values that lie exactly on a rounding boundary are rounded in different directions in the text: 9,755 of 10,000 (97.55 %, Table 10, A2, shown as 97.5) and 0.2225 (Sect. 10.4, shown as 22.3 %). The underlying counts are in the result files.

## Layout

| Path | Content | Manuscript |
|---|---|---|
| `emulator/core.py` | Attribute vectors, `share()`, role-assumption closure, independence-aware trigger and baselines, enforcer selection, ordered three-state decision | Sects. 5-8 |
| `emulator/containment_emu2.py` | Emulator with the current rules: snapshot attribution, class splitting, Δt = 120 s, application delay, configurations B1-B5, A1, A2, Full loop, scenarios S1-S14; earlier rules kept as `A1_v1rules` / `FULL_v1rules` | Sect. 10 |
| `emulator/run_experiments2.py` | E2 (S0: 5 seed sets × 2,000, S1-S14: 2,000 each, exact McNemar), E4 sensitivity, E5 integrated run | Tables 10-13, Figs. 5-7 |
| `emulator/run_experiments.py`, `containment_emu.py`, `figures.py` | E1 trigger and E3 scalability, used unchanged by the manuscript; also the earlier-rule containment runs, kept for comparison | Table 9, Fig. 4, Sect. 10.8 |
| `emulator/closed_form.py` | Closed-form false-effective expectations of B1, B2, B4, B5, the two-step bound, the tracked-fraction dependence and the credential-revocation bound | Table 10, Sect. 10.5 |
| `emulator/paired_stats.py` | Exact McNemar p-values and Newcombe intervals for the paired comparisons | Sect. 10.5 |
| `emulator/tools_numbers.py` | Prints the rows of Tables 10-13 and the numbers of Sects. 10.5-10.7 | |
| `emulator/check_manuscript.py` | Asserts the manuscript values against the result files | |
| `emulator/results/`, `results_v2/` | Result files used in the manuscript (`results_v2/` for Sect. 10.5-10.7, `results/` for E1 and E3) | |
| `figures_submitted/` | Figures 1-7 exactly as in the submitted manuscript | Figs. 1-7 |
| `emulator/figures_submitted.py`, `figure_values.json` | Values shown in the submitted figures, recomputed and checked; redraw in the submitted layout | Figs. 2, 4-7 |
| `emulator/figs_v2/` | Earlier draft layout of Figures 1-7 from `figures_v2.py` (same data) | |
| `emulator/aws/` | Initial live run (EXP-004/005): traffic generator `m.py`, sandbox analysis `analyze.py`, `build_summary.py`, aggregates `sandbox_output.json`, `measure_summary.json` (also the emulator's delay calibration, p05 = 40 s, p95 = 306 s), phase timestamps `state.json` | Sect. 4.2, Table 3, Fig. 2 |
| `measurements/exp006_a1/` | Repeated run: instance agent `agent.py`, phase controller `ctl_template.py`, sandbox analyses `a1_final_body.py`, `fl_body_v2.py` (with the pure-Python inflate helpers `pyinflate.py`), phase log `phases.jsonl`, console and flow-log aggregates in `results/` | Sect. 4.3, Table 4 |
| `measurements/exp008_attribution/` | Attribution run: phase timestamps, console counts per 10 s and per phase, flow-log aggregates with reject reason, traffic path and TCP flags | Sect. 4.4, Table 5 |
| `measurements/exp007_a2/` | 72-hour delivery measurement in two regions: analysis script, batch template (the sandbox allows 100 API calls per run, so objects were read in batches of 98), per-batch integer-second histograms, merge script, merged result | Sect. 4.5, Sect. 10.1 |
| `measurements/exp009_planned/` | Traffic agent for a planned measurement of the provider's two-step group replacement. Not run; no result is reported in the manuscript | Sect. 11 |
| `measurements/check_measurements.py` | Asserts the Sect. 4 values against the aggregates | |

The live-measurement scripts ran in the provider's scripting sandbox, which exposes AWS API calls through `call_boto3` and blocks `zlib`, `base64` and `hashlib`; this is why the analyses carry their own base64 and inflate implementations. They are included to document what was computed and are not runnable outside that sandbox without adaptation.

## Redaction

Account number, bucket names, and instance, interface, security-group, network-ACL, route-table, subnet, VPC, flow-log and Reachability Analyzer identifiers were replaced by placeholders such as `<ACCOUNT>`, `<BUCKET_01>`, `<ENI_03>` (the same identifier always maps to the same placeholder within an experiment), and the provider-assigned IPv6 prefix by `<IPV6PREFIX>`. Private IPv4 addresses of the deleted test networks and all timestamps are unchanged. All measurement resources were deleted after each run. Raw flow-log objects and console outputs are retained by the author and are available on request; the aggregates here are what the manuscript uses.

Two A1 aggregate files (`exp006_a1/results/*.json`) were restored from the author's working copies by two independent transcriptions that agree byte for byte and pass the consistency checks of `check_measurements.py`; the A1 scripts and the EXP-008 aggregates match the SHA-256 values recorded at the time of the runs before redaction.

## Use of generative AI

The emulator, the reference implementation and the measurement scripts were written with a generative AI assistant (Claude, Anthropic), which also ran the live measurements through the provider's scripting interface, as stated in the manuscript (Sects. 4.1 and 10.1).

## License

Code: MIT License (see `LICENSE`). Data and figures: CC BY 4.0.

## Citation

If you use this material, please cite the article (details will be added on publication) and this repository.
