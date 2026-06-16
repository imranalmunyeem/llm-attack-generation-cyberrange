# External R(S) Validation Audit

This evaluates an R(S)-style score on public CTI/report annotations from
CTID TRAM and compares those report-derived technique sequences with
matched random active-ATT&CK sequences.

Reports used: 40
Real mean score: 0.977
Random mean score: 0.777
Mann-Whitney p-value: 4.92e-15
Cliff's delta: 1.000

## Interpretation

This is an external discriminative-validity check, not a human realism study.
It asks whether the metric assigns higher scores to public report-derived
ATT&CK sequences than to length-matched random active-technique sequences.
