# Failed and skipped runs — Phase 3 decision

Source: `runs.csv` (9 variations, 66 Condition-A/B rows, 2–3 Oct 2026).
Decision: **document as failed; do not rerun.** The thesis measures alert
actionability and reports detection coverage as a result, so a documented
non-execution is a valid observation rather than a defect to erase.

## Summary

| Status | Rows |
|---|---:|
| SUCCESS | 51 |
| FAILED | 12 |
| SKIPPED | 3 |
| **Total** | **66** |

Non-success rows come from 5 atomics, each repeated 3 times:

| Atomic | Variation (step) | Status | Cause | Decision |
|---|---|---|---|---|
| T1059.001 #19 PowerUp Invoke-AllChecks | V3 step 1 | FAILED (exit -1) | `iwr`+`iex` download/execute of an external script; failed in this environment | document |
| T1059.001 #7 Powershell XML requests | V3 step 2 | FAILED (exit 255) | download cradle failed (network/AV) | document |
| T1105 #25 certreq download | V1 step 3 | FAILED (exit -1) | upstream test posts synthetic body to `example.com`, which rejects it | document |
| T1105 #9 BITSAdmin BITS Download | V3 step 1 | FAILED (HRESULT `0x800700E9`) | BITS job could not complete the transfer | document |
| T1105 #13 MpCmdRun download | V3 step 2 | SKIPPED | prerequisite: Windows Defender build without `MpCmdRun.exe` | document |

## Impact on the per-variation results

- **T1059.001 V3**: 6 of 9 steps failed (#19, #7); only step 3 (#8 mshta) ran.
  Detection 0% therefore reflects (a) failed steps and (b) no rule match on #8.
- **T1105 V1**: step 3 (#25 certreq) failed in all reps, but steps 1–2 (#7, #8)
  ran, so the variation is still represented.
- **T1105 V3**: steps 1–2 (#9, #13) failed/skipped; only step 3 (#38 OneDrive)
  ran. Detection 88.9% comes from #38 (and the #9 alerts that fired despite the
  failed BITS job).

## How to read this in the thesis

- Report FAILED/SKIPPED with reasons; do not hide them.
- A variation whose steps did not execute cannot be used to claim detection
  coverage for that behaviour — mark it "insufficient execution" rather than
  "not detected".
- Reruns are possible (install Defender `MpCmdRun`, allow the downloads, use a
  reachable POST endpoint), but are out of scope once this version is frozen.
