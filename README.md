# Actionability Scoring Dashboard — Wazuh / Sysmon Telemetry Quality

Prototype sistem untuk skripsi **"Context-Aware Telemetry Observability Evaluation Agent for MITRE ATT&CK-Aligned Wazuh Events"**.

Sistem ini **bukan alat deteksi**. Dia menjawab pertanyaan yang berbeda: *"alert atau case yang sudah terbentuk ini sudah cukup lengkap untuk diinvestigasi, atau masih perlu hunting manual?"* — diukur sebagai **actionability score** 0–100, per alert dan per correlated case.

---

## 1. Latar belakang singkat

- Wazuh + Sysmon menghasilkan alert yang sering **minim konteks**: ada indikasi eksekusi, tapi command line, parent process, user, atau network destination tidak ada di alert tersebut.
- MITRE ATT&CK mapping tidak sama dengan kualitas deteksi (Shen et al., 2024); SOC analyst juga sudah kelebihan alert (Alahmadi et al., 2022).
- Karena itu, kualitas telemetri perlu **diukur terpisah** dari pembuatan alert. Di sinilah kontribusi sistem ini.

### Kontribusi

1. **Alert-level actionability score** — bobot field dihitung dengan **AHP (Saaty)** dan divalidasi lewat Consistency Ratio (semua CR < 0.10), lalu disesuaikan per teknik (technique-aware expected fields dari MITRE ATT&CK Data Sources).
2. **Typed-edge correlation** — event dihubungkan dengan relationship yang punya tipe dan confidence (`SAME_PROCESS`, `PARENT_CHILD`, `SAME_BINARY`, `PROCESS_CONNECTED_TO`, ...), bukan sekadar "ada field yang sama".
3. **Case-level actionability score** — bukti dari event-event yang terkorrelasi diagregasi dan dideduplikasi, lalu dinilai dengan `Q` (completeness, validity, confidence-weighted corroboration proxy, provenance) dikali confidence relasi.
4. **Reproducible artifacts untuk paper** — matriks AHP, laporan CR, dan traceability field → OSSEM → MITRE data component.

**Research questions:** (RQ1) bagaimana menyusun skor actionability yang explainable untuk alert Wazuh/Sysmon; (RQ2) apakah case-level scoring berbasis korelasi meningkatkan penilaian dibanding skor per-alert; (RQ3) seberapa sensitif skor terhadap degradasi telemetri (mis. Sysmon EID 3 dimatikan).

---

## 2. Cara kerja

```text
Wazuh alert / archive event
        │
        ▼
normalizer.py         canonical schema (OSSEM-referenced):
                      process.guid, file.hash.sha256, destination.ip, ...
        │
        ├──────────────► scoring.py        alert-level score (AHP, technique-aware)
        │
        ▼
correlation.py        typed edges + confidence + bounded expansion
        │             (pivots: process guid, parent-child, sha256, ...)
        ▼
case_scoring.py       aggregate + deduplicate evidence, case-level score
        │
        ▼
FastAPI (main.py) → React dashboard (Cases / Alerts)
```

Data source bisa **mock** (fixture deterministik) atau **live** (Wazuh Indexer), dan bisa diganti saat runtime dari UI.

---

## 3. Model scoring

**Bobot AHP.** Matriks pairwise ada di `backend/ahp/matrices.py`; hasilnya disimpan di `backend/weights.json` (single source of truth):

```
w_f = category_weight × local_field_weight        (global weight per field)
```

**Alert score** — dihitung hanya atas field yang diharapkan untuk teknik tersebut:

```
S_alert = 100 × Σ (w_f × A_f) / Σ w_f
A_f = 1 jika field ada dan non-empty, else 0
```

**Relationship confidence** (typed edge):

```
C_r = 0.45·P + 0.20·T + 0.15·H + 0.10·S + 0.10·X
P = pivot strength, T = temporal decay e^(−Δt/τ), H = host consistency,
S = session/user consistency, X = corroborating evidence
```

**Case score** — bukti lintas event, dideduplikasi, dibobot kualitas dan confidence:

```
Q_f = 0.30·C + 0.30·V + 0.25·K + 0.15·R
      C = completeness, V = validity, K = confidence-weighted corroboration,
      R = provenance
S_case = 100 × Σ (w_f × Q_f × E_f) / Σ w_f
E_f = confidence relasi yang membawa fakta (1.0 untuk fakta dari seed alert)
```

`K` pada kode adalah **operational corroboration proxy** (confidence carrier,
identity-backed vs context-only, maksimal tiga carrier), bukan pemeriksaan bahwa
semua nilai field identik. Role `required` / `supporting` / `context` pada
`technique_profiles.py` adalah klasifikasi penelitian ini yang diturunkan dari
ATT&CK data components; MITRE sendiri tidak menetapkan tier wajib per field.

Level: **Low < 25**, **Medium 25–50**, **High > 50** (provisional; dikalibrasi pada fase evaluasi).

**Kenapa case score bisa 100 sedangkan alert score tidak?** Alert EID 1 tidak punya destination IP dan alert EID 3 tidak punya command line — jadi skor alert memang dibatasi tipe event. Case score menggabungkan EID 1 + EID 3 dari proses yang sama, sehingga seluruh evidence yang diharapkan bisa terpenuhi.

Regenerate bobot + artefak paper:

```bash
cd backend
python -m ahp.run_ahp
# → weights.json, AHP_RESULTS.md, data/mitre_traceability.csv
```

---

## 4. Correlation model

- **Pivot tiers**: identity (`process.guid`, `parentProcessGuid`, SHA-256) → behavioral (destination tuple, DNS, registry, file) → scope (user, host, time).
- **Typed relationships**: `SAME_PROCESS`, `PARENT_CHILD`, `SAME_BINARY`, `PROCESS_CONNECTED_TO`, `PROCESS_QUERIED_DNS`, `PROCESS_CREATED_FILE`, `PROCESS_MODIFIED_REGISTRY`, `PROCESS_TERMINATED`, `DESTINATION_SHARED`, `SUPPORTING_CONTEXT`.
- **Bounded expansion**: depth ≤ 3, hanya identity-backed edge yang boleh rekursi; scope/context edge tidak pernah jadi titik ekspansi.
- **Deduplication**: fakta yang sama dikumpulkan sebagai satu evidence dengan daftar carrier + occurrence count, supaya 200 event network identik tidak menggelembungkan skor.
- **Caps**: maksimal 5 context leaf per node, konsistensi dihitung dari maksimal 3 carrier terkuat (identity dihitung penuh, context setengah).

---

## 5. Quick Start

### Docker (nginx, port 8080)

```bash
git clone https://github.com/kavakoss/actionability-scoring-dashboard.git
cd actionability-scoring-dashboard
cp backend/.env.example backend/.env   # edit values only if using the real Indexer
docker-compose up --build
```

The Docker backend reads Wazuh settings from `backend/.env` at runtime. The
example defaults to mock mode; for live mode, edit `backend/.env` locally
(`USE_LIVE_WAZUH=true` and valid Indexer settings). That file is gitignored and
excluded from the backend image build context.

| URL | Keterangan |
|---|---|
| `http://localhost:8080` | Dashboard React |
| `http://localhost:8080/docs` | Swagger API |
| `http://localhost:8080/api/health` | Health check |

```bash
docker-compose down   # stop
```

### Manual (development)

```bash
# terminal 1 — backend
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python main.py                                  # http://localhost:8000

# terminal 2 — frontend
cd frontend
npm install
npm run dev                                     # http://localhost:3000
```

Vite dev server mem-proxy `/api` ke `http://localhost:8000` (override dengan `VITE_API_TARGET`).

### Tests

```bash
cd backend
pytest -q          # 42 tests: AHP, normalizer, correlation, scoring, case scoring
```

---

## 6. Mock vs Live data

Data source bisa diganti **saat runtime**:

- **UI** — toggle `MOCK` / `LIVE` di kanan atas header.
- **API** — `POST /api/source` dengan `{"source": "mock"}` atau `{"source": "live"}`.
- **Startup default** — `USE_LIVE_WAZUH=true` di `backend/.env` (window: `LIVE_HOURS_BACK`, `LIVE_ALERT_LIMIT`). Kalau Indexer tidak reachable, backend fallback ke mock dan menyimpan pesan di `last_error` — dashboard tidak pernah kosong.

Live mode memuat alert terbaru dari `wazuh-alerts-*`, men-skor, membangun graph + case. Webhook (`POST /api/webhook`) menjalankan bounded expansion ke `wazuh-archives-*` untuk kasus yang masuk real-time.

### Konfigurasi `.env`

```bash
cd backend
cp .env.example .env
```

```ini
WAZUH_INDEXER_HOST=...
WAZUH_INDEXER_PORT=9200
WAZUH_INDEXER_USER=admin
WAZUH_INDEXER_PASS=...
WAZUH_INDEXER_SSL=true
WAZUH_INDEXER_VERIFY_CERTS=false
USE_LIVE_WAZUH=true
LIVE_HOURS_BACK=48
LIVE_ALERT_LIMIT=100
```

`.env` sudah di-gitignore — **jangan pernah commit credentials**.

### Wazuh Manager integration (webhook)

Tambahkan di `/var/ossec/etc/ossec.conf`, lalu restart Wazuh Manager:

```xml
<integration>
    <name>actionability-scoring</name>
    <hook_url>http://<backend-host>:8000/api/webhook</hook_url>
    <level>7</level>
    <group>sysmon</group>
    <alert_format>json</alert_format>
</integration>
```

---

## 7. UI walkthrough

### Cases (default)
- Daftar **correlated case** diurutkan berdasarkan case score, beserta required-evidence coverage dan ukuran graph.
- Filter by technique / level.

### Case detail
- Case score, required coverage, jumlah node/edge.
- **Evidence facts**: field, role (`required`/`supporting`/`context`), AHP weight, `Q`, `E`, contribution, dan carrier (value + event asal).
- Toggle **Hide missing** dan tombol **Export report** (Markdown, siap jadi lampiran skripsi).
- **Score composition** dan daftar **typed relations** (`relation`, confidence, decision).
- **Case timeline** kronologis dengan chip relasi inline antar event.
- Deep link: `?view=cases&case=<id>`, `?view=alerts&alert=<id>`.

### Alerts
- Skor per-alert (AHP, technique-aware), filter by technique / level.
- Klik alert → breakdown per kategori (identity, behavioral, relationship, IOC, network, timeline) dengan MITRE data component tiap field.

---

## 8. API endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/health` | Health check + current source |
| GET | `/api/source` | Current source, availability, config |
| POST | `/api/source` | Switch source: `{"source": "mock" \| "live"}` |
| GET | `/api/alerts` | List alerts (`?technique=&level=&agent=&sort_by=score`) |
| GET | `/api/alerts/{id}` | Alert detail + full scoring breakdown |
| GET | `/api/cases` | List cases + case-level score (`?technique=&level=`) |
| GET | `/api/cases/{case_id}` | Case detail: per-fact evidence (Q, E, carriers) + required coverage |
| GET | `/api/timeline/{id}` | Timeline graph (nodes + typed edges) from a seed |
| POST | `/api/webhook` | Wazuh integration: alert → bounded expansion → case score |
| GET | `/api/stats` | Aggregate statistics |
| GET | `/docs` | Swagger UI |

---

## 9. Artifacts untuk paper

| File | Isi | Dipakai untuk |
|---|---|---|
| `backend/weights.json` | Bobot AHP final (per kategori & field) | single source of truth |
| `backend/AHP_RESULTS.md` | Semua matriks pairwise, λmax, CI, CR, global weights | lampiran + methodology |
| `backend/data/mitre_traceability.csv` | `technique → field → role → weight → Wazuh path → OSSEM → MITRE component` | content validity / lampiran |
| `backend/field_metadata.py` | sumber mapping field | reproducibility |
| `backend/technique_profiles.py` | expected fields per teknik + kutipan data source | methodology |
| `evaluation/` | runbook ART, template run log, script evaluasi | bab evaluasi (fase 4) |

---

## 10. Struktur project

```
actionability-scoring-dashboard/
├── backend/
│   ├── main.py                # FastAPI server + source switching
│   ├── normalizer.py          # canonical schema (OSSEM-referenced)
│   ├── correlation.py         # typed edges, confidence, bounded expansion
│   ├── case_scoring.py        # case-level Q/E scoring + caps
│   ├── scoring.py             # alert-level AHP scoring (technique-aware)
│   ├── field_metadata.py      # Wazuh path → OSSEM → MITRE component
│   ├── technique_profiles.py  # expected fields per ATT&CK technique
│   ├── wazuh_client.py        # OpenSearch client, pivot queries
│   ├── mock_data.py           # mock alerts (deterministic demo/tests)
│   ├── ahp/                   # AHP core, pairwise matrices, generator
│   ├── data/                  # generated: traceability CSV
│   ├── weights.json           # generated: AHP weights
│   ├── AHP_RESULTS.md         # generated: full AHP report
│   ├── live_demo.py           # CLI: bounded live case expansion
│   ├── tests/                 # pytest suite
│   └── requirements.txt
├── frontend/
│   └── src/
│       ├── App.jsx            # shell, tabs, source toggle, deep links
│       ├── api.js
│       └── components/
│           ├── CasesView.jsx      # case list
│           ├── CaseDetail.jsx     # case score + evidence + export
│           ├── TimelineView.jsx   # timeline with inline relation chips
│           ├── ScoringDashboard.jsx / AlertDetail.jsx / StatsOverview.jsx
│           └── ui.jsx             # design primitives
├── evaluation/                # ART runbook, run log, evaluation scripts
├── nginx/                     # reverse proxy for docker-compose
└── docker-compose.yml
```

---

## 11. Limitations (jujur, untuk bab pembahasan)

- Lab terbatas: 1 Windows endpoint, 3 teknik (T1059.001, T1059.003, T1105), Sysmon EID 1/3/5.
- Sysmon EID 22 (DNS) praktis tidak aktif → pivot DNS tidak dipakai; registry/file/pipe pivot belum tersedia.
- SHA-256 pivot live memakai exact `term` pada field `hashes`; data lab yang dicek berisi satu hash SHA256 per field. Kalau konfigurasi Sysmon mengirim beberapa algoritma dalam satu string, perlu ingest normalization atau query fallback sebelum mengandalkan pivot ini.
- EID 5 (Process Termination) **tidak** dipakai untuk scoring (bukan data component ATT&CK untuk 3 teknik ini) — hanya untuk correlation/lifetime.
- Archives retention terbatas; Process Create milik proses yang sudah berjalan sebelum archive window hilang → lineage bisa terputus.
- `originalFileName` dan `signatureStatus` tidak punya atribut OSSEM CDM (tercatat di traceability CSV).
- Role `required`/`supporting`/`context` adalah klasifikasi operasional penelitian, bukan label wajib resmi dari MITRE ATT&CK.
- Threshold Low/Medium/High masih provisional sampai kalibrasi di fase evaluasi.
- Skor mengukur **kelengkapan bukti**, bukan tingkat kebahayaan; adversary yang mengisi field bisa menaikkan skor (dibahas sebagai limitation).
- API prototype belum memiliki authentication/authorization; jalankan hanya di trusted lab network/Tailscale, jangan expose ke public internet.

---

## 12. Troubleshooting

| Masalah | Solusi |
|---|---|
| Backend tidak start (port 8000 terpakai) | Ubah port di `main.py` (`uvicorn.run(app, port=8001)`) |
| Frontend tidak bisa akses API | Pastikan backend jalan; cek `VITE_API_TARGET` / `vite.config.js` |
| `npm install` gagal | Coba `npm install --legacy-peer-deps` |
| Live mode kosong / error | Cek `last_error` di `/api/health`; pastikan `.env` benar dan Indexer reachable |
| Halaman blank | Cek console browser (F12) |

---

## 13. Authors

Jason Tanuwidjaja · Johan Davin Hermawan · Kevin Diaz Pramono — Computer Science, Bina Nusantara University.

Skripsi: *Context-Aware Telemetry Observability Evaluation Agent for MITRE ATT&CK-Aligned Wazuh Events*.
