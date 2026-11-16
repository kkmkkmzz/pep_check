# pep_check

Supplementary material for the manuscript *Closed-Loop Containment Assurance in Public Clouds: Compromise-Domain-Aware Enforcer Selection and Scoped Isolation Verification* (submitted to the Journal of Network and Systems Management).

## Status: incomplete

This repository does **not yet** reproduce the tables and figures of the manuscript. The following components are referenced by the manuscript but are not included here yet:

- reference implementation of the compromise-domain model, trigger, enforcer selection and decision rules (`core.py`)
- discrete-event emulator of the provider semantics (`containment_emu.py`)
- experiment runner for E1–E4 (`run_experiments.py`) and the figure and self-verification scripts (`figures.py`, `verify.py`)
- aggregated result files used for Tables 9–13 (`results/`) and the measurement summary (`aws/measure_summary.json`)

Until these are added, the code-availability statement of the manuscript is not satisfied.

## Contents

| Path | Content |
|---|---|
| `aws/exp9_agent.py` | Traffic agent for the second-stage security-group replacement experiment (EXP-009) |
| `aws/a2_batch_template.py` | Lambda-style batch reader for delivered flow-log objects, 72-hour delivery-delay measurement (EXP-007) |
| `aws/a2_analyze_sandbox.py` | Analysis of delivered flow-log objects inside the provider's scripting sandbox (EXP-007) |
| `aws/a2_merge.py` | Merges per-batch outputs into the 72-hour summary |
| `data/a2_result_72h.json` | 72-hour delivery-delay aggregates, Seoul and Northern Virginia (EXP-007) |
| `data/exp8_phases.jsonl` | Phase timestamps of the repeated attribution run (EXP-008) |

Not yet included: the traffic agent, control template and analysis scripts of the first live run (EXP-006), and its flow-record and console-output aggregates. These contain resource identifiers in their code and need a separate redaction pass before they are added.

## Redaction

Account identifiers, flow-log identifiers and storage bucket names of the measurement account were replaced by placeholders such as `<ACCOUNT_ID>`, `<FLOW_LOG_ID>` and `<BUCKET_SEOUL>`. Raw flow-log objects and raw console dumps are not included. Scripts that reference buckets must be given the real names at run time. Each published file was checked with a pattern search for account numbers, resource identifiers and bucket names before the commit.

## Live measurements

The measurements were run in a single account on an almost idle network in the Seoul (ap-northeast-2) and Northern Virginia (us-east-1) regions. Results are for the provider semantics as observed in these runs and do not establish behaviour in other regions, accounts or under load.

## License

To be decided before publication.
