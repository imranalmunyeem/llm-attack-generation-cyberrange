# Preregistered Blinded Evaluation

This artifact freezes hypotheses, metrics, sampling seed, and blind-ID
construction before manual interpretation of the results.

## Hypotheses

- H1: Third-party report-derived scenarios score higher on R(S) than matched random controls. Decision: True.
- H2: AdverSim scenarios remain comparable to third-party report scenarios on R(S). Decision: True.
- H3: Technique-prior detection proxy is evaluated blinded and reported separately from realism. Decision: None.

## Group Summary

{
  "adversim": {
    "realism": {
      "n": 40,
      "mean": 0.88244,
      "min": 0.7975,
      "max": 0.958333
    },
    "detection_proxy": {
      "n": 40,
      "mean": 0.937589,
      "min": 0.792619,
      "max": 0.996431
    }
  },
  "third_party_report": {
    "realism": {
      "n": 40,
      "mean": 0.977183,
      "min": 0.916667,
      "max": 1.0
    },
    "detection_proxy": {
      "n": 40,
      "mean": 0.995792,
      "min": 0.86725,
      "max": 1.0
    }
  },
  "random_control": {
    "realism": {
      "n": 40,
      "mean": 0.789206,
      "min": 0.6975,
      "max": 0.875
    },
    "detection_proxy": {
      "n": 40,
      "mean": 0.996116,
      "min": 0.879883,
      "max": 1.0
    }
  }
}