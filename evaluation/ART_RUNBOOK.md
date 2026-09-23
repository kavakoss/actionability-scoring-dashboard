# ART Runbook — Controlled Atomic Red Team Runs

> **Cara termudah:** gunakan script otomatis
> [`windows/Invoke-ArtPlan.ps1`](windows/Invoke-ArtPlan.ps1) dengan panduan
> [`windows/STEP-BY-STEP.md`](windows/STEP-BY-STEP.md). Script itu sudah melakukan
> semua langkah manual di bawah (backup config, install ART, baseline, Condition A/B,
> restore, dan menulis `runs.csv`). Dokumen ini tetap disimpan sebagai referensi
> prosedur dan penjelasan tiap langkah.

Tujuan: menghasilkan **run berlabel** untuk fase evaluasi (sensitivity, ablation korelasi,
discrimination) pada endpoint Windows yang dimonitor Wazuh + Sysmon.

Target: 3 teknik × 3 repetisi (Condition A: Sysmon EID 3 **ON**), 1 teknik × 3 repetisi
(Condition B: EID 3 **OFF**), plus 3 jendela benign baseline.

> Catatan: semua perintah dijalankan di **endpoint Windows** (WIN-THESIS-01), bukan di server Wazuh.
> Setiap run **harus dicatat** di `runs.csv` (UTC) supaya script evaluasi bisa memotong window datanya.

---

## 0. Prasyarat

- [ ] Wazuh agent + Sysmon64 aktif di endpoint (`Get-Service WazuhSvc, sysmon64`).
- [ ] Clock Windows sinkron (Wazuh memakai UTC; script evaluasi pakai UTC).
- [ ] PowerShell **Administrator**.
- [ ] Tidak ada aktivitas berat lain saat run (tutup browser/update kalau bisa, supaya hasil bersih).
- [ ] Jeda antar run **≥ 10 menit** supaya event antar run tidak saling nyambung sebagai context.

---

## 1. Simpan config Sysmon saat ini (baseline)

```powershell
sysmon64 -c | Out-File C:\ART\sysmon-config-full.xml -Encoding utf8
Get-Service sysmon64
```

Pastikan EID 1, 3, 5 aktif di config tersebut (ada baris `ProcessCreate`, `NetworkConnect`,
`ProcessTerminate`). Kalau tidak, beri tahu Jason dulu.

---

## 2. Install Atomic Red Team

```powershell
Install-Module -Name invoke-atomicredteam,powershell-yaml -Scope CurrentUser -Force
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics -Force
```

Cek daftar test (pilih sebelum eksekusi):

```powershell
Invoke-AtomicTest T1059.001 -ShowDetailsBrief
Invoke-AtomicTest T1059.003 -ShowDetailsBrief
Invoke-AtomicTest T1105    -ShowDetailsBrief
```

Pilih test yang: (a) tidak berbahaya, (b) tidak butuh internet selain URL uji, (c) konsisten
antar repetisi. Catat nomor test yang dipilih di `runs.csv`.

---

## 3. Urutan eksekusi

### 3a. Baseline benign (3 jendela × 30–60 menit)
Lakukan aktivitas normal (dokumen, browsing ringan) **tanpa ART**. Catat start/end di `runs.csv`
dengan `condition = baseline`.

### 3b. Condition A — EID 3 ON (default)

Jalankan berurutan, 3 repetisi per teknik, jeda ≥10 menit:

```powershell
# T1059.001 (PowerShell)
Invoke-AtomicTest T1059.001 -TestNumbers <pilihan>
Invoke-AtomicTest T1059.001 -Cleanup

# T1059.003 (Windows Command Shell)
Invoke-AtomicTest T1059.003 -TestNumbers <pilihan>
Invoke-AtomicTest T1059.003 -Cleanup

# T1105 (Ingress Tool Transfer)
Invoke-AtomicTest T1105 -TestNumbers <pilihan>
Invoke-AtomicTest T1105 -Cleanup
```

Catat tiap run sebagai baris terpisah dengan `condition = A`.

### 3c. Condition B — EID 3 OFF (khusus T1105)

1. Buat config tanpa NetworkConnect dari file baseline (hapus blok `<NetworkConnect ...>`),
   simpan sebagai `C:\ART\sysmon-config-no-eid3.xml`.
2. Terapkan:

```powershell
sysmon64 -c C:\ART\sysmon-config-no-eid3.xml
sysmon64 -c | Select-String NetworkConnect    # harus kosong
```

3. Jalankan `Invoke-AtomicTest T1105` 3 repetisi, catat dengan `condition = B`.
4. **Kembalikan config**:

```powershell
sysmon64 -c C:\ART\sysmon-config-full.xml
sysmon64 -c | Select-String NetworkConnect    # pastikan kembali ada
```

---

## 4. Isi `runs.csv`

Kolom: `run_id,technique,condition,atomic_test,host,start_utc,end_utc,notes`

Ambil timestamp UTC:

```powershell
(Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
```

Contoh baris:

```
run-001,T1059.001,A,T1059.001-1,WIN-THESIS-01,2026-09-23T02:00:00Z,2026-09-23T02:01:10Z,encoded command
```

Isi satu baris **sebelum** run (start) dan lengkapi end setelah run.

---

## 5. Verifikasi data masuk ke Wazuh

Setelah beberapa run, cek dari server/Wazuh API (atau minta Jason):

```bash
curl -sk -u admin:*** "https://<wazuh-indexer>:9200/wazuh-archives-4.x-*/_count" \
  -H 'Content-Type: application/json' \
  -d '{"query":{"bool":{"filter":[{"range":{"@timestamp":{"gte":"<start>","lte":"<end>"}}}]}}}'
```

Kalau count 0 untuk window run, berarti agent/archives bermasalah — stop dan beri tahu Jason.

---

## 6. Setelah selesai

- Kirim `runs.csv` (dan catatan anomali apa pun) ke Jason.
- Jangan hapus data archives/alerts; script evaluasi akan menariknya langsung dari Indexer.
- Simpan `sysmon-config-full.xml` dan `sysmon-config-no-eid3.xml` sebagai bukti reproducibility.
