# Phase 6 Real Baseline Audit

This phase replaces purely author-constructed baselines with public
metadata baselines computed with the same active ATT&CK v14.1 denominator.

No baseline command, payload, agent, or atomic test is executed. The scripts
download and parse metadata YAML only.

## Table XIV Candidate

| Corpus | Units | Unique active IDs | Base techniques | Base coverage | Transition corroboration | Avg edges |
|---|---:|---:|---:|---:|---:|---:|
| AdverSim | 1000 | 145 | 98 | 48.8% | 61.4% | 5.08 |
| CALDERA Stockpile adversary profiles | 27 | 47 | 39 | 19.4% | 83.6% | 4.37 |
| Atomic Red Team technique set | 1621 | 320 | 143 | 71.1% | n/a | 0.00 |

## Fairness Notes

- All rows are filtered to active Enterprise ATT&CK v14.1 technique IDs.
- Base coverage uses the same active base-technique denominator.
- CALDERA Stockpile adversary profiles are ordered sequences, so transition
  corroboration is comparable to AdverSim's stage-to-stage pair metric.
- Atomic Red Team is a technique-set corpus, not an adversary-sequence
  corpus; transition corroboration is therefore reported as not applicable.

## Paper Framing

Use this to soften the old Random/Template baseline claims. The key result
is not that AdverSim beats every public corpus on every metric, but that
Table XIV now includes real, public systems under identical ATT&CK coverage
accounting.
