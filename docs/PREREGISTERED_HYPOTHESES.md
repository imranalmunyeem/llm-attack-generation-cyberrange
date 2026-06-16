# Preregistered Supplemental Hypotheses

This document is the paper-facing preregistration note for the supplemental
robustness/validity analyses.

## H1 - External Discriminative Validity

Third-party CTI/report-derived ATT&CK sequences should receive higher R(S)
scores than length-matched random active-technique sequences.

Decision rule: supported if the third-party mean exceeds the random-control
mean by at least 0.05 and the one-sided Mann-Whitney test is directionally
consistent.

## H2 - Comparable Realism Across Sources

AdverSim scenarios should remain close to third-party report-derived scenarios
on R(S), because both are intended to represent plausible multi-stage attack
structure.

Decision rule: supported if the absolute mean R(S) difference is no more than
0.10 in the blinded evaluation harness.

## H3 - Temporal Matrix Robustness

The validate-and-requery loop should be matrix-version agnostic: when supplied
with a different ATT&CK Enterprise release, it should identify inactive IDs and
produce an explicit remediation target rather than silently accepting stale
techniques.

Decision rule: report scenario all-active rate and unique-ID active rate for
each available official ATT&CK STIX release. Historical releases unavailable
from the official source are marked unavailable, not substituted.

## Detection Proxy Handling

Detection scores in the blinded harness use the Phase 3 ATT&CK data-source
prior as a descriptive proxy only. They must not be described as empirical SOC
detection measurements.
