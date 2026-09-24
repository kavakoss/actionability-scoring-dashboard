# STEP-BY-STEP — Menjalankan Evaluasi ART di Laptop Windows

Panduan untuk operator (teman Jason). Estimasi total: **± 2,5–3,5 jam** (baseline + 9 run Condition A + 3 run Condition B + jeda otomatis).

Semua dijalankan **di laptop Windows** yang menjalankan Wazuh agent + Sysmon (WIN-THESIS-01), **bukan** di server Wazuh.

---

## 0. Persiapan (5 menit)

- [ ] Colok charger, set **Sleep = Never** (Settings → System → Power → Screen and sleep).
- [ ] Wazuh agent + Sysmon jalan (script cek otomatis).
- [ ] Buka **PowerShell → Run as Administrator**.
- [ ] Siapkan folder `C:\ART`.

Ambil script (pilih salah satu):

```powershell
# opsi A — clone repo
git clone https://github.com/kavakoss/actionability-scoring-dashboard.git C:\ART\repo
copy C:\ART\repo\evaluation\windows\Invoke-ArtPlan.ps1 C:\ART\

# opsi B — terima file dari Jason, taruh Invoke-ArtPlan.ps1 di C:\ART\
```

---

## 1. Jalankan script

```powershell
cd C:\ART
powershell -ExecutionPolicy Bypass -File .\Invoke-ArtPlan.ps1
```

Script otomatis melakukan:

1. **Preflight**: cek Administrator, sysmon, Wazuh agent, jam.
2. **Backup** config Sysmon → `C:\ART\sysmon-config-full.xml`.
3. **Install ART** kalau belum ada (`invoke-atomicredteam` + atomics).
4. **Pilih test** — Anda diminta memilih nomor per teknik (lihat langkah 2).
5. **Baseline** (3 jendela × 30 menit) — Anda hanya menekan Enter lalu melakukan aktivitas normal.
6. **Condition A (EID 3 ON)** — 3 teknik × 3 repetisi, jeda 10 menit otomatis.
7. **Condition B (EID 3 OFF)** — T1105 × 3; config Sysmon diubah & dikembalikan otomatis.
8. **Tulis `C:\ART\runs.csv`** (semua timestamp UTC).

Kalau `sysmon64 -c` gagal dan script menawarkan daftar XML kandidat, pilih hanya
file config yang benar-benar dipakai untuk Sysmon saat ini. Script memakai file
tersebut untuk restore setelah Condition B. Kalau ragu, batalkan dan konfirmasi
dengan Jason dulu.

Ketik `YES` saat diminta konfirmasi.

---

## 2. Cara memilih test atomic (aman)

Script menampilkan daftar test per teknik + **saran default** (tekan Enter untuk pakai saran). Panduan aman:

| Teknik | Cari yang mengandung | Hindari |
|---|---|---|
| T1059.001 | `execution`, `encoded`, `invoke-expression` | `mimikatz`, `bloodhound`, `remote share` |
| T1059.003 | `echo`, `whoami`, `builtin` | `mimikatz`, `bloodhound` |
| T1105 | `certutil`, `download`, `urlcache`, `invoke-webrequest` | `mimikatz`, `putty`, `sftp` |

Yang penting: **pilih satu test yang sama** untuk semua repetisi (script yang menjamin).

---

## 3. Uji coba dulu (opsional, 5 menit)

Kalau mau memastikan script jalan sebelum sesi panjang:

```powershell
# tidak menjalankan atomic / tidak mengubah EID 3; preflight + backup tetap dilakukan
powershell -ExecutionPolicy Bypass -File .\Invoke-ArtPlan.ps1 -DryRun

# sesi ngebut (BUKAN untuk data resmi, hanya uji mekanisme)
powershell -ExecutionPolicy Bypass -File .\Invoke-ArtPlan.ps1 -SkipBaseline -SpacingMinutes 1 -Repetitions 1
```

`-DryRun` tidak menjalankan atomic dan tidak mengganti config EID 3, tetapi tetap melakukan preflight, bisa memasang ART bila belum ada, dan menyimpan backup config Sysmon ke `C:\ART`.

Untuk data resmi, jalankan tanpa opsi tambahan (default: baseline 30 menit, 3 repetisi, jeda 10 menit).

---

## 4. Setelah selesai

Script menampilkan lokasi:

- `C:\ART\runs.csv` — log semua run (UTC)
- `C:\ART\sysmon-config-full.xml` — config Sysmon asli
- `C:\ART\sysmon-config-no-eid3.xml` — config Condition B

**Kirim ketiga file itu ke Jason.** Jangan hapus data Wazuh/archives.

---

## 5. Troubleshooting

| Masalah | Solusi |
|---|---|
| "running scripts is disabled" | Jalankan dengan `powershell -ExecutionPolicy Bypass -File ...` (jangan pakai `.\` langsung) |
| "Script harus dijalankan sebagai Administrator" | Tutup PowerShell, buka lagi dengan **Run as Administrator** |
| "sysmon tidak ditemukan" | Cek `where.exe sysmon64`; kalau kosong berarti Sysmon belum terinstall |
| Install module gagal | Jalankan `Install-Module PowerShellGet, PackageManagement -Force` lalu ulangi |
| ART error saat run | Script tetap mencatat baris dengan catatan `ERROR: ...` — laporkan ke Jason |
| Laptop restart di tengah jalan | Jalankan ulang dengan `-SkipBaseline`; run yang sudah tercatat tetap valid |
| NetworkConnect tidak terdeteksi | Kabari Jason — Condition A tidak bisa dijalankan sebelum ini beres |
| `NativeCommandError` / `Tidak bisa membaca config Sysmon` | Script terbaru otomatis mencari file config Sysmon di disk (`C:\Windows`, `C:\Tools`, Downloads, Documents, Desktop) dan meminta Anda memilih. Kalau sudah tahu file-nya, langsung jalankan: `powershell -ExecutionPolicy Bypass -File .\Invoke-ArtPlan.ps1 -SysmonConfigPath "C:\path\sysmonconfig.xml"` |
| Tidak tahu file config Sysmon yang mana | Jalankan di PowerShell admin: `Get-ChildItem C:\ -Filter *.xml -Recurse -Depth 3 -ErrorAction SilentlyContinue \| Select-String -Pattern '<Sysmon' -List \| Select-Object Path` — pilih yang namanya seperti `sysmonconfig.xml` / `sysmon-modular.xml` |
| Ingin tahu kenapa `sysmon -c` gagal | Jalankan: `cd C:\Windows; .\Sysmon64.exe -c; "exit=$LASTEXITCODE"` dan kirim outputnya ke Jason |
| Peringatan `Windows Time service tidak Running` | Bukan error; pastikan jam Windows benar (Settings → Time & language → Sync now) atau jalankan `w32tm /resync` di PowerShell admin |
