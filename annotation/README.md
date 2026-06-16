# Annotation Harness

This folder contains the code for preparing blinded scenario-rating packets and analyzing completed rating CSV files.

Generated packets, reviewer profiles, raw responses, and aggregate outputs are local-only and ignored by git.

Prepare a packet:

```powershell
.\.venv\Scripts\python.exe annotation\harness.py prepare --n 150
```

Place completed reviewer CSV files under:

```text
annotation/raw/
```

Analyze completed ratings:

```powershell
.\.venv\Scripts\python.exe annotation\harness.py analyze
```

Keep reviewer identities and raw ratings out of the public repository.
