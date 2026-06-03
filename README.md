# Actionability Scoring Dashboard — Setup Guide

## Prerequisites

- **Python 3.10+** (tested on 3.12)
- **Node.js 18+** (tested on 20)
- **npm** (comes with Node.js)

---

## Project Structure

```
dashboard/
├── backend/
│   ├── main.py           # FastAPI server
│   ├── scoring.py        # Actionability scoring engine
│   ├── correlation.py    # Graph-based correlation + BFS
│   ├── mock_data.py      # Mock Wazuh alerts (3 MITRE techniques)
│   └── requirements.txt
├── frontend/
│   ├── package.json
│   ├── vite.config.js
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

### Dashboard View (default)
- See all 8 mock alerts across 3 MITRE techniques
- Filter by technique (T1059.001 / T1059.003 / T1105)
- Filter by actionability level (Low / Medium / High)
- Click any alert row → see detailed scoring breakdown

### Alert Detail
- Shows per-category score breakdown (Identity, Behavioral, Relationship, IOC, Network, Timeline)
- Each category shows which fields are present/absent
- "View Attack Timeline" button → reconstruct timeline from this alert

### Timeline View
- Select a seed alert from dropdown
- System builds correlation graph using BFS traversal
- Connected events shown in chronological vertical timeline
- Right panel shows correlation edges with weights
- Color-coded by MITRE technique

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/health` | Health check + mode (mock/live) |
| GET | `/api/alerts` | List alerts (filterable: `?technique=&level=&agent=`) |
| GET | `/api/alerts/{id}` | Single alert detail + full scoring breakdown |
| GET | `/api/timeline/{id}` | Timeline graph (nodes + edges) from seed alert |
| POST | `/api/webhook` | **Wazuh Integration webhook** — receive alert → score + find related |
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
