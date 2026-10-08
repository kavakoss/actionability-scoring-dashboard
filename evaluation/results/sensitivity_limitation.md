# Sensitivity test (T1105 #7 A vs B) — reported as a limitation

Decision: **report as a limitation**, no rerun. The experiment as executed does
not cleanly isolate the effect of removing Sysmon Event ID 3, so the sensitivity
claim cannot be made with confidence.

## What was tested

Same atomic test **T1105 #7 (certutil -urlcache download)**, 3 repetitions each:
- **Condition A** — Sysmon EID 3 (network) ON.
- **Condition B** — Sysmon EID 3 OFF.

Hypothesis: removing network telemetry should lower the actionability score.

## Observation

Case-level (per run, then averaged):

| Condition | Runs | Runs with an EID3-seeded case | Mean case score |
|---|---:|---:|---:|
| A | 3 | 1 | 92.0 |
| B | 3 | 0 | 90.2 |
| A − B | | | **+1.8** |

Direction is correct but the contrast is negligible.

## Why this is a limitation

1. **EID3 capture was inconsistent in Condition A.** From the Wazuh archives,
   certutil.exe produced **0** EID3 events in the A-016 (Oct 2 19:00) and A-037
   (Oct 2 22:37) windows, and **2** EID3 events in the A-058 (Oct 3 02:13)
   window (`2606:50c0:8000::154:443`, GitHub/Fastly over IPv6). Sysmon was
   otherwise working in those same minutes (340 other EID3 events). So the "A"
   condition did not reliably contain the network evidence it was meant to add.
2. **A run produces several seed cases** (the `cmd` wrapper and the `certutil`
   process). The wrapper case still scores high without network fields, so the
   case mean is dominated by non-network evidence.
3. **The network-field penalty is small** at this scale: the EID1 certutil seed
   already scores 82.3/100 without destination IP/port, and the correlated case
   recovers most of the rest from other events.

## Honest statement for the thesis

> The direction of the effect was as expected (Condition A ≥ Condition B), but
> because Sysmon Event ID 3 was captured in only one of three Condition-A runs,
> the sensitivity test was inconclusive. The network fields carried by EID 3
> contributed only a small amount to the case actionability in this setup.

## If a definitive result is needed later

1. Confirm EID3 is emitted before running, e.g. on the endpoint:
   `Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=3}`
   and check for the invoked process.
2. Rerun T1105 #7 with 3 Condition-A and 3 Condition-B repetitions and confirm
   each A run has a certutil EID3 event.
3. Compare the **certutil file-transfer case only** (not the wrapper), so the
   measurement matches the behaviour under test.
