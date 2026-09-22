# Actionability Scoring Dashboard — Setup Guide

## Quick Start (Docker) 🐳

```bash
git clone https://github.com/kavakoss/actionability-scoring-dashboard.git
cd actionability-scoring-dashboard
docker-compose up --build
```

Buka **http://localhost** (atau **http://localhost:8080** kalau port 80 bentrok).

| URL | Description |
|-----|-------------|
| `http://localhost` | Dashboard React |
| `http://localhost/api/docs` | Swagger API docs |
| `http://localhost/api/health` | Health check |

### Stop

```bash
docker-compose down
```

---

## Manual Setup (Development)

### Prerequisites

- **Python 3.10+** (tested on 3.12)
- **Node.js 18+** (tested on 20)
- **npm** (comes with Node.js)

---

## Project Structure

```
dashboard/
├── backend/
│   ├── main.py           # FastAPI server
│   ├── scoring.py        # AHP actionability scoring (technique-aware)
│   ├── correlation.py    # Typed-edge correlation + bounded BFS
│   ├── normalizer.py     # Canonical Wazuh/Sysmon schema (OSSEM-referenced)
│   ├── field_metadata.py # Wazuh path -> OSSEM -> MITRE component mapping
│   ├── technique_profiles.py  # Expected fields per ATT&CK technique
│   ├── ahp/              # Pairwise matrices + weight generation
│   ├── data/             # Generated artifacts (traceability CSV)
│   ├── weights.json      # Generated AHP weights (single source of truth)
│   ├── AHP_RESULTS.md    # Full matrix/CR report for the thesis appendix
│   ├── live_demo.py      # Bounded live case expansion demo
│   ├── tests/            # pytest suite (AHP, normalization, correlation, scoring)
│   ├── wazuh_client.py   # OpenSearch client (live mode)
│   ├── mock_data.py      # Mock Wazuh alerts (3 MITRE techniques)
│   ├── .env.example      # Environment template
│   ├── Dockerfile
│   └── requirements.txt
├── frontend/
│   ├── package.json
│   ├── vite.config.js
│   ├── Dockerfile
│   ├── index.html
│   └── src/
│       ├── main.jsx
│       ├── App.jsx
│       ├── api.js
│       └── components/
│           ├── StatsOverview.jsx
│           ├── ScoringDashboard.jsx
│           ├── AlertDetail.jsx
│           └── TimelineView.jsx
└── README.md
```

---

## Step 1: Backend Setup

```powershell
# Navigate to backend
cd dashboard/backend

# (Optional) Create virtual environment
python -m venv venv
venv\Scripts\activate      # Windows
# source venv/bin/activate  # Linux/Mac

# Install dependencies
pip install -r requirements.txt
```

### Required packages:
```
fastapi
uvicorn
networkx
pydantic
opensearch-py   # for real Wazuh Indexer later, not needed for mock
```

---

## Step 2: Start Backend

```powershell
cd dashboard/backend
python main.py
```

Backend runs at: **http://localhost:8000**

### Verify:
- http://localhost:8000/api/health
- http://localhost:8000/api/alerts
- http://localhost:8000/api/stats
- http://localhost:8000/docs (auto-generated Swagger UI)

---

## Step 3: Frontend Setup

```powershell
# Open a NEW terminal
cd dashboard/frontend

# Install dependencies
npm install
```

---

## Step 4: Start Frontend

```powershell
cd dashboard/frontend
npm run dev
```

Frontend runs at: **http://localhost:3000**

The Vite dev server proxies `/api` requests to `http://localhost:8000` automatically.

---

## Usage Walkthrough

### Cases View (default)
- Correlated cases ranked by case-level actionability score
- Filter by technique and level; each row shows required-evidence coverage and graph size
- Click a case row → case detail

### Case Detail
- Case score, required-evidence coverage and relation count
- Evidence facts table: field, role, AHP weight, quality Q, evidence confidence E, contribution
- Score composition (top contributions) and typed relations (relation, confidence, decision)
- Chronological case timeline with the seed event marked

### Alerts View
- Per-alert AHP score for every alert, filterable by technique and level
- Click an alert → field-level breakdown per category with expected/required roles

### Manual development run

```bash
# terminal 1 — backend (mock data unless USE_LIVE_WAZUH=true)
cd backend && python main.py                 # http://localhost:8000

# terminal 2 — frontend dev server
cd frontend && npm install && npm run dev    # http://localhost:3000, proxies /api to :8000
```

Set `VITE_API_TARGET` if the backend runs elsewhere.

---

## Scoring Model (AHP, technique-aware)

Weights are generated from the pairwise matrices in `backend/ahp/matrices.py`
and stored in `backend/weights.json` (single source of truth):

```bash
cd backend
python -m ahp.run_ahp   # regenerates weights.json, AHP_RESULTS.md, data/mitre_traceability.csv
```

- `w_f = category_weight x local_field_weight` (global weight of a field)
- `S_alert = 100 x SUM(w_f * A_f) / SUM(w_f)` over the technique's expected
  fields (`technique_profiles.py`), where `A_f = 1` if the field is present.
- Levels: Low < 25, Medium 25-50, High > 50 (provisional; calibrated during
  the sensitivity evaluation).
- All matrices must satisfy CR < 0.10; this is enforced by `tests/test_ahp.py`.

Correlation (typed edges + confidence) runs on the normalized schema produced
by `normalizer.py`; the case-level score aggregates deduplicated evidence and
weights each fact by the confidence of the relationship that delivered it.

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/health` | Health check + mode (mock/live) |
| GET | `/api/alerts` | List alerts (filterable: `?technique=&level=&agent=`) |
| GET | `/api/alerts/{id}` | Single alert detail + full scoring breakdown |
| GET | `/api/cases` | List correlated cases with case-level actionability score |
| GET | `/api/cases/{case_id}` | Case detail: per-fact evidence (Q, E, carriers) + required coverage |
| GET | `/api/timeline/{id}` | Timeline graph (nodes + edges) from seed alert |
| POST | `/api/webhook` | **Wazuh Integration webhook** — alert → bounded expansion → case score |
| GET | `/api/stats` | Aggregate statistics |
| GET | `/docs` | Interactive Swagger documentation |

---

## Switching from Mock Data to Real Wazuh Indexer

### Step 1: Copy & configure .env

```powershell
cd dashboard/backend
copy .env.example .env
# Edit .env — isi WAZUH_INDEXER_PASS dengan password sebenarnya
```

### Step 2: Set USE_LIVE_WAZUH=true

Di `.env`:
```
USE_LIVE_WAZUH=true
```

### Step 3: Restart backend

```powershell
python main.py
# → Health check akan tampil "mode": "live"
```

### How it works (live mode)

```text
Wazuh Integration            Backend (FastAPI)           Wazuh Indexer
───────────────              ─────────────────           ──────────────
Alert fired (level>=7)
    │
    └──POST /api/webhook────► 1. Score the alert
                              2. Extract entities
                                 (processGuid, user,
                                  host, dstIp...)
                              3. query_related_events()
                                 ──────────────────────► OpenSearch:
                                                         "Cari semua event
                                                          dgn processGuid /
                                                          user / IP yg sama"
                                 ◄────────────────────── Return related events
                              4. Score semua related events
                              5. Build correlation graph
                              6. Return scoring + timeline
```

### Wazuh Manager Integration Config

Tambahkan di `/var/ossec/etc/ossec.conf` pada Wazuh Manager:

```xml
<integration>
    <name>actionability-scoring</name>
    <hook_url>http://172.16.11.1:8000/api/webhook</hook_url>
    <level>7</level>
    <group>sysmon</group>
    <alert_format>json</alert_format>
</integration>
```

Setelah edit, restart Wazuh Manager:
```bash
sudo systemctl restart wazuh-manager
```

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| Backend won't start (port 8000 in use) | Change port in `main.py` line: `uvicorn.run(app, port=8001)` |
| Frontend can't reach API | Check backend is running. Verify proxy in `vite.config.js` |
| `npm install` fails | Try `npm install --legacy-peer-deps` |
| Blank page in browser | Check browser console for errors (F12) |
