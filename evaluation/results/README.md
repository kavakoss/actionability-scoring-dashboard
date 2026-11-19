# Evaluation scripts and results

Scripts behind the results reported in the ICIMCIS 2026 paper. The code state
used for the camera-ready version is tagged `icimcis2026-camera-ready`:

```bash
git checkout icimcis2026-camera-ready
```

All scripts read live data from a Wazuh Indexer. Raw Wazuh/Sysmon telemetry is
not included in this repository, so the scripts need access to an Indexer that
still holds the evaluation window.

## Configure the evaluation window

Copy `backend/.env.example` to `backend/.env`, fill in the Indexer connection,
and pin the window of the ART campaign:

```ini
USE_LIVE_WAZUH=true
LIVE_FROM=2026-10-02T16:50:00.000Z
LIVE_TO=2026-10-03T05:00:00.000Z
SEED_MIN_LEVEL=15
```

`LIVE_ALERT_LIMIT` caps how many eligible seeds are loaded (default 100).

## Scripts

| Paper | Script | Run | Output |
|---|---|---|---|
| Table V (detection and evidence completeness per variant) | `compute_results.py` | backend running (`python main.py`), then `python compute_results.py --runs <runs.csv> --api http://127.0.0.1:8000 --out-dir .` | `variation_results.csv`, `variation_results.md` |
| Section IV.D (score distribution) | `score_distribution.py` | backend running, then `python score_distribution.py --api http://127.0.0.1:8000 --out-dir .` | `score_distribution.md` |
| Table VI (S_seed, S_case, ΔS per technique) | `backend/recalc_delta_s.py` | `cd backend && python recalc_delta_s.py` (reads `backend/.env`, no API needed) | table printed to stdout |

`compute_results.py` needs the ART run log (`run_id, technique, condition,
atomic_test, host, start_utc, end_utc, notes`); `evaluation/runs.csv` shows the
format.

## Other files

| File | Contents |
|---|---|
| `variation_results.csv`, `variation_results.md` | Per-variant results (Table V) |
| `failed_runs.md` | Why failed and skipped runs failed |
| `sensitivity_limitation.md` | Sysmon EID 3 on/off contrast for T1105 and why it is treated as a limitation |

Detection rules are in [`../wazuh/`](../wazuh/); the ART procedure is in
[`../ART_RUNBOOK.md`](../ART_RUNBOOK.md), [`../ATTACK_VARIATIONS.md`](../ATTACK_VARIATIONS.md)
and [`../windows/`](../windows/).
