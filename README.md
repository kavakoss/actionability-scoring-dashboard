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
| GET | `/api/health` | Health check + alert count |
| GET | `/api/alerts` | List alerts (filterable: `?technique=&level=&agent=`) |
| GET | `/api/alerts/{id}` | Single alert detail + full scoring breakdown |
| GET | `/api/timeline/{id}` | Timeline graph (nodes + edges) from seed alert |
| GET | `/api/stats` | Aggregate statistics |
| GET | `/docs` | Interactive Swagger documentation |

---

## Switching from Mock Data to Real Wazuh Indexer

When ready to connect to real Wazuh Indexer (OpenSearch):

1. Update `backend/main.py` — replace `MOCK_ALERTS` import with OpenSearch queries:

```python
from opensearchpy import OpenSearch

client = OpenSearch(
    hosts=[{"host": "36.93.185.111", "port": 9200}],
    http_auth=("admin", "your-password"),
    use_ssl=True,
    verify_certs=False,
)

# Query alerts
response = client.search(
    index="wazuh-alerts-*",
    body={"query": {"match_all": {}}, "size": 100},
)
```

2. Map the OpenSearch `_source` fields to match the expected structure in `scoring.py`.
3. The scoring engine and correlation logic remain unchanged.

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| Backend won't start (port 8000 in use) | Change port in `main.py` line: `uvicorn.run(app, port=8001)` |
| Frontend can't reach API | Check backend is running. Verify proxy in `vite.config.js` |
| `npm install` fails | Try `npm install --legacy-peer-deps` |
| Blank page in browser | Check browser console for errors (F12) |
