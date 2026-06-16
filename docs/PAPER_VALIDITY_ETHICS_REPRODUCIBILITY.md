# Paper Validity, Ethics, Reproducibility, and Artifact Statement

This supplement is designed to strengthen the paper without changing existing
results. It gives reviewers a transparent account of what AdverSim does, what it
does not claim, what can be reproduced offline, and what remains limited by
synthetic data, reviewer composition, and available defensive logs.

## Reviewer-Ready Contribution Framing

AdverSim should be framed as a controllable scenario-generation and evaluation
pipeline for cyber-range research, not as a replacement for real incident
datasets. The strongest defensible claim is:

> AdverSim generates structured ATT&CK-aligned cyber-range scenarios and pairs
> them with validation layers that measure structural consistency, temporal
> ATT&CK robustness, detection-rule replay, real-baseline comparison, and
> blinded human realism judgments.

Avoid overclaiming that synthetic scenarios are real incidents, that the SOC
simulation is an empirical SOC study, or that `R(S)` alone proves realism.

## Threats to Validity

### Construct Validity

`R(S)` measures structural and ATT&CK consistency, not complete incident
realism. It captures active ATT&CK ID validity, scenario structure, and
transition coherence against ATT&CK group co-occurrence pairs. The Phase 7
human validation shows that human overall-realism ratings do not strongly
positively align with `R(S)`, so `R(S)` should be reported as a structural
quality metric rather than a substitute for expert judgment.

The SOC simulation uses a parameterized detection model. It is useful for
sensitivity analysis and for identifying model artifacts, but it is not an
empirical measurement of a production SOC. Claims based on this simulation
should be phrased as simulation behavior unless they survive sensitivity tests.

Sigma replay measures generated rule skeletons against available labelled
events. Coverage depends on the event corpus, label quality, logsource mapping,
and intentionally simple keyword matching. Replay results should therefore be
used as grounding evidence, not as a universal detection-performance claim.

### Internal Validity

Generation quality depends on prompt design, JSON parsing, ATT&CK validation,
and the validate-and-requery loop. The pipeline reduces invalid technique IDs
but does not guarantee full tactical realism. The re-query loop can also bias
accepted outputs toward scenarios that satisfy schema and ATT&CK constraints.

Human ratings were collected from five independent reviewers with technical
backgrounds: two software test engineers, one IT specialist, one master's
student in cybersecurity, and one master's student in computer science. The
reviewer pool is useful for independent human realism checking, but it should
not be described as a panel composed entirely of SOC, DFIR, or threat-intel
experts.

### External Validity

The corpus covers selected environments, attack types, difficulties, and ATT&CK
Enterprise techniques. Results may not transfer directly to operational
incidents, non-Enterprise ATT&CK matrices, highly specialized ICS environments,
or organizations with different logging and detection maturity.

Real-baseline comparisons use public metadata from CALDERA Stockpile and Atomic
Red Team. These baselines are strong because they are not author-constructed,
but they are not complete representations of all real adversary behavior.

### Statistical Conclusion Validity

Confidence intervals, permutation tests, held-out refits, and human agreement
statistics reduce the risk of unsupported numerical claims. Remaining risks
include aggregate-only mutation outputs, limited human reviewer count, and
correlation estimates that are sensitive to the selected sample and metric
definition.

## Ethics and Safety Statement

AdverSim is intended for defensive cyber-range research, evaluation, teaching,
and detection-engineering workflows. The repository does not require or execute
malware, exploit payloads, adversary emulation agents, Atomic Red Team tests, or
CALDERA operations. Public baseline scripts parse metadata only.

Generated Sigma rules are detection skeletons intended for review and defensive
experimentation. They are not exploit code and should be validated by security
teams before operational deployment.

Raw logs, raw human rating sheets, reviewer identities, API keys, and local
environment secrets are excluded from version control. `.env` files are ignored,
raw annotation files are ignored, and tracked outputs contain only aggregate or
anonymized results.

The intended users are researchers, instructors, cyber-range builders, and
defensive security teams. Out-of-scope uses include operational intrusion,
malware deployment, credential theft, evasion testing against third-party
systems without authorization, or automated attack execution.

## Artifact Availability and Reproducibility Statement

The repository separates API-dependent generation from offline reproducibility.

Offline, no-API-key path:

```powershell
.\.venv\Scripts\python.exe tests\smoke_pipeline.py
.\.venv\Scripts\python.exe scripts\reproducibility_ci.py
.\.venv\Scripts\python.exe analysis\regenerate_figures.py
bash scripts/pre_push_check.sh
```

Equivalent Make targets where `make` is available:

```bash
make smoke
make reproducibility-ci
make figures
make pre-push-check
```

Tracked reproducible artifacts include:

- `results/registry.json`
- `results/stats_table.json`
- `results/soc_invariance.json`
- `results/sigma_measured.json`
- `results/multimodel.json`
- `results/real_baselines.json`
- `results/human_validation.json`
- `results/human_ratings_summary.csv`
- `results/figure_manifest.json`
- `paper/generated_macros.tex`
- `paper_assets/figures/*.png`

API-dependent or external-data-dependent paths include fresh LLM scenario
generation, multi-model replication reruns, and fetching public baseline
metadata. Raw defensive logs and raw human rating files are intentionally not
committed.

## Methodological Component Contribution Table

| Component | What it adds | Paper claim it supports | Main limitation |
|---|---|---|---|
| Validate-and-requery generation | Rejects malformed JSON and invalid ATT&CK IDs before corpus acceptance | Generation is schema-constrained and ATT&CK-aware | Does not guarantee full real-world plausibility |
| Single ATT&CK source of truth | Prevents mixed-version technique accounting | Reported technique counts are traceable | Depends on selected ATT&CK matrix snapshot |
| Cross-version robustness | Tests v13/v14/v15 behavior under matrix drift | Validation loop generalizes across ATT&CK updates | Still limited to Enterprise ATT&CK |
| Statistical rigor | Adds CIs, null models, effect-size framing, and corrected p-values | Numeric claims are evidence-bounded | Some old outputs remain aggregate-only |
| SOC sensitivity analysis | Distinguishes invariant findings from model artifacts | SOC claims are not overstated | Simulation is not an empirical SOC deployment |
| Sigma replay grounding | Replays generated rules on labelled events | Detection claims have log-side evidence | Dependent on available labels and simple matching |
| Multi-LLM generalization | Tests whether validation survives model changes | Method is not tied to one model sample | Small replication compared with full corpus |
| Real baselines | Compares against CALDERA and Atomic Red Team metadata | Baseline is not author-constructed only | Public metadata is incomplete and heterogeneous |
| Human validation | Adds blinded human realism judgment and agreement statistics | `R(S)` is de-biased against human ratings | Reviewer pool is technical but not all SOC/DFIR experts |
| Reproducibility CI | Regenerates figures and checks offline pipeline | Artifacts can be verified without secrets | Full corpus generation still requires API access |

## Data and Model Card

| Field | Value |
|---|---|
| Dataset name | AdverSim synthetic cyber-range scenario corpus |
| Primary format | JSONL scenarios with narrative, stages, ATT&CK techniques, and attack graph |
| Scenario count used in main analyses | 1,000-scenario v14-clean corpus where available |
| Generation model | OpenAI model family via API; multi-model replication includes `gpt-4o-mini` and `gpt-4.1-mini` outputs |
| ATT&CK matrix | MITRE ATT&CK Enterprise v14.1 compact active-technique index for main validation |
| Additional ATT&CK robustness | v13/v14/v15 robustness audit |
| Human validation sample | 150 blinded scenarios |
| Human reviewers | 5 anonymous independent reviewers |
| Reviewer composition | 2 software test engineers, 1 IT specialist, 1 MSc cybersecurity student, 1 MSc computer science student |
| Reviewer author status | No reviewer was an author |
| Raw human ratings | Stored locally under ignored `annotation/raw/phase7/`; not committed |
| Raw logs | Excluded from git; only aggregate replay results are tracked |
| Secrets | `.env`, keys, and credential-like files ignored and checked by pre-push scan |
| Intended uses | Cyber-range scenario generation, defensive evaluation, teaching, reproducible research |
| Out-of-scope uses | Unauthorized intrusion, exploit execution, malware deployment, credential theft |
| Main limitations | Synthetic-data realism, reviewer expertise mix, log availability, ATT&CK version scope |

## Suggested Paper Text

### Limitations Paragraph

AdverSim scenarios are synthetic and should not be interpreted as substitutes
for real incident reports or telemetry. The validation pipeline reduces
malformed outputs and invalid ATT&CK IDs, but tactical realism remains partly a
human judgment. Accordingly, `R(S)` is reported as a structural consistency
metric, while blinded human ratings provide an independent realism check. SOC
detection results are presented as simulation and sensitivity-analysis outputs,
not as measurements of analyst performance in a production SOC.

### Ethics Paragraph

This work is intended for defensive cyber-range research and detection
engineering. The repository generates structured scenario descriptions and
Sigma-compatible detection skeletons; it does not execute malware, exploit
payloads, Atomic Red Team tests, CALDERA agents, or live adversary emulation.
Raw logs, reviewer files, identities, API keys, and local secrets are excluded
from version control, and tracked artifacts contain only aggregate or
anonymized results.

### Reproducibility Paragraph

The repository includes an offline reproducibility path that runs without API
keys or raw logs. The CI workflow installs locked dependencies, regenerates
paper figures from tracked aggregate outputs, verifies figure hashes through a
manifest, runs the smoke pipeline, and performs repository hygiene checks for
large files and secret-like values. Fresh LLM generation and some external data
fetching steps remain separately documented because they require API access or
network availability.
