# Cross-ATT&CK-Version Robustness Audit

This audit validates the committed v14-clean AdverSim corpus against
official MITRE ATT&CK Enterprise STIX bundles for matrix-version shift.
Only compact active-ID indices are cached locally; raw STIX bundles are not committed.

| Version | Status | Scenario all-active rate | Unique ID active rate | Base coverage | Notes |
|---|---|---:|---:|---:|---|
| v13.1 | completed | 100.0% | 100.0% | 50.0% | inactive unique IDs: 0 |
| v14.1 | completed | 100.0% | 100.0% | 48.8% | inactive unique IDs: 0 |
| v15.1 | completed | 100.0% | 100.0% | 48.5% | inactive unique IDs: 0 |

## Interpretation

Use this as temporal-shift evidence for the validation loop. The key
claim is not that every historical matrix is identical, but that active
ID validation can be re-run against a selected ATT&CK release and report
which identifiers require remediation.
