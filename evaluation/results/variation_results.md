# ART variation results

- Window: `2026-10-02T16:50:00.000Z` → `2026-10-03T05:00:00.000Z`
- Seed policy: Wazuh `rule.level >= 15`
- Detected = at least one seed alert in the run window (pad −5s/+20s).
- Actionability = mean AHP score of seed alerts in that window.

| Technique | Cond | Var | Runs | Success | Failed | Skipped | Detected | Detection % | Mean actionability |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| T1059.001 | A | 1 | 3 | 3 | 0 | 0 | 0/3 | 0.0 |  |
| T1059.001 | A | 2 | 9 | 9 | 0 | 0 | 9/9 | 100.0 | 100.0 |
| T1059.001 | A | 3 | 9 | 3 | 6 | 0 | 0/9 | 0.0 |  |
| T1059.003 | A | 1 | 3 | 3 | 0 | 0 | 3/3 | 100.0 | 100.0 |
| T1059.003 | A | 2 | 6 | 6 | 0 | 0 | 6/6 | 100.0 | 100.0 |
| T1059.003 | A | 3 | 6 | 6 | 0 | 0 | 6/6 | 100.0 | 100.0 |
| T1105 | A | 1 | 9 | 6 | 3 | 0 | 9/9 | 100.0 | 72.1 |
| T1105 | A | 2 | 9 | 9 | 0 | 0 | 9/9 | 100.0 | 95.6 |
| T1105 | A | 3 | 9 | 3 | 3 | 3 | 8/9 | 88.9 | 69.5 |
| T1105 | B | 1 | 3 | 3 | 0 | 0 | 3/3 | 100.0 | 91.1 |

## Sensitivity test — T1105 #7 (certutil download), Condition A vs B

### Case-level (the thesis metric: correlated case actionability)

| Atomic test | Condition | Runs | Runs with cases | Runs with EID3 case | Mean case score |
|---|---|---:|---:|---:|---:|
| T1105-7 | A | 3 | 3 | 1 | 92.0 |
| T1105-7 | B | 3 | 3 | 0 | 90.2 |
| T1105-7 | A-B delta |  |  |  | 1.8 |

Reported as a limitation: EID3 was captured in only 1 of 3 Condition-A runs,
so the A/B contrast is inconclusive. See `sensitivity_limitation.md`.

### Seed-alert level (diagnostic, not the thesis metric)

| Atomic test | Condition | Runs | Scored alerts | Mean actionability |
|---|---|---:|---:|---:|
| T1105-7 | A | 3 | 8 | 77.6 |
| T1105-7 | B | 3 | 6 | 91.1 |
| T1105-7 | A-B delta |  |  | -13.5 |

## Notes
- Failed/SKIPPED runs (e.g. missing prerequisites, blocked network) still count as a run;
  they are reported, not hidden.
- Detection here reflects this ruleset (evaluation/wazuh/local_rules.xml v1).
  Rules were tuned after observing these runs — disclose this bias.
- Legacy pilot runs before the 9-variation plan are excluded.
- Failed/SKIPPED runs are detailed with causes in `failed_runs.md`.
- The T1105 #7 A/B sensitivity test is reported as a limitation; see
  `sensitivity_limitation.md` (EID3 capture was inconsistent).
- Seed-level mean mixes EID1 alerts (no network fields) with EID3 alerts (no command line),
  which is why the case-level view is the correct unit for the sensitivity test.
