# Variasi Perilaku per Teknik (Attack Flow Mapping)

Dokumen ini memetakan setiap teknik MITRE ATT&CK yang diuji ke **3 behavioral class**, lalu
menentukan **flow atomic test** (nomor + judul) untuk tiap variasi.

Nomor test diverifikasi dari `redcanaryco/atomic-red-team` master per **30 Sep 2026**; nomor
bisa bergeser antar versi — script `Invoke-ArtPlan.ps1` selalu menampilkan daftar terkini.

Prinsip pemilihan:
- Bebas dependency bila memungkinkan (`AtomicTestHarnesses`, file pendukung, versi khusus).
- Aman dijalankan berulang (tidak memakai malware nyata; Mimikatz/BloodHound/Rubeus dikecualikan).
- Menghasilkan telemetri yang kita ukur: **EID 1** (process create) dan **EID 3** (network connect).

---

## T1059.001 — PowerShell

| Variasi | Definisi | Flow (urutan run) | Telemetri |
|---|---|---|---|
| **V1 — direct command/script execution** | PowerShell menjalankan command/script langsung tanpa encoding | **18** (PowerShell Invoke Known Malicious Cmdlets) | EID 1 `powershell.exe` + command line |
| **V2 — encoded / fileless / alternative execution** | Payload di-encode atau dijalankan tanpa file di disk / lewat mekanisme alternatif | **17** (PowerShell Command Execution — `powershell.exe -e <base64>`) → **10** (PowerShell Fileless Script Execution — registry + IEX) → **11** (NTFS Alternate Data Stream Access) | EID 1 `powershell.exe` + command line encoded; EID 12/13 (registry) tidak aktif di lab |
| **V3 — network/download-enabled PowerShell** | PowerShell mengambil payload dari jaringan lalu mengeksekusi | **19** (PowerUp Invoke-AllChecks — `iwr` + `iex`) → **7** (Powershell XML requests) → **8** (Powershell invoke mshta.exe download) | EID 1 `powershell.exe`/`mshta.exe` + **EID 3** ke internet |

Alternatif per variasi (opsional, ada syarat):
- V1: **13 → 14** (ATHPowerShell `-Command` parameter variations) — butuh module `AtomicTestHarnesses`; **12** (PowerShell Session Creation and Use) — butuh PSRemoting.
- V2: **15 → 16** (ATH `-EncodedCommand` variations) — butuh module; **5** (Invoke-AppPathBypass) — eksekusi alternatif (juga download).
- V3: **6** (MsXml COM object download+execute), **20** (Abuse Nslookup with DNS Records).

Tidak dipakai: **1/4** (Mimikatz), **2/3** (BloodHound/SharpHound), **21/22** (SOAPHound) —
di luar 3 behavioral class dan berat/dikarantina AV.

## T1059.003 — Windows Command Shell

| Variasi | Definisi | Flow (urutan run) | Telemetri |
|---|---|---|---|
| **V1 — direct command** | `cmd.exe` menjalankan command sederhana | **3** (Suspicious Execution via Windows Command Shell — `cmd /c echo …`) | EID 1 `cmd.exe` + command line |
| **V2 — batch/script execution** | Shell menjalan/menulis script lalu mengeksekusinya | **6** (Command prompt writing script to file then executes it — VBS dari cmd) → **1** (Create and Execute Batch Script)* | EID 1 `cmd.exe` + `wscript`/`cmd.exe` anak |
| **V3 — redirected/script-fed command execution** | Command dibaca dari file/stream (stdin redirection) | **5** (Command Prompt read contents from CMD file and execute — `cmd /r cmd<file`) → **2** (Writes text to a file and displays it — `echo > file & type file`) | EID 1 `cmd.exe` + command line redirection |

\* **1** punya dependency: file `.bat` harus dibuat lebih dulu (`Invoke-AtomicTest T1059.003 -TestNumbers 1 -GetPrereqs`).
Kalau tidak mau repot, cukup pakai **6** sebagai flow V2.
Tidak dipakai: **4** (BlackByte Print Bombing — Wordpad, bukan perilaku shell).

## T1105 — Ingress Tool Transfer

| Variasi | Definisi | Flow (urutan run) | Telemetri |
|---|---|---|---|
| **V1 — native/LOLBin transfer** | Binary bawaan Windows untuk download (certutil dsb.) | **7** (certutil download urlcache) → **8** (certutil download verifyctl) → **25** (certreq download) | EID 1 `certutil.exe`/`certreq.exe` + **EID 3** ke internet |
| **V2 — PowerShell/web-client transfer** | Transfer lewat PowerShell WebClient / web request | **10** (Windows - PowerShell Download) → **15** (File Download via PowerShell) → **29** (iwr / Invoke-WebRequest) | EID 1 `powershell.exe` + **EID 3** |
| **V3 — alternate native transfer** | Mekanisme native lain (BITS, Defender, updater) | **9** (BITSAdmin BITS Download) → **13** (Windows Defender MpCmdRun)* → **38** (OneDrive Standalone Updater)* | EID 1 `bitsadmin.exe`/`MpCmdRun.exe`/updater + **EID 3** |

Alternatif V1: **18** (curl; butuh curl), **16** (finger.exe), **17** (IMEWDBLD.exe), **32** (Sqlcmd; butuh).
Alternatif V3: **20** (cmdl32; butuh file pendukung), **30** (GUP.exe Notepad++), **26** (wscript).
\* **13** butuh Windows Defender versi 4.18; **38** butuh `OneDriveStandaloneUpdater.exe` ada di disk.

Semua test di atas mengunduh file benign (`LICENSE.txt` dari GitHub), jadi aman dan repeatable.
Eksekusi payload hasil transfer **bukan** bagian T1105 — kalau butuh rantai penuh, sambungkan dengan
teknik eksekusi, contoh: **T1105 V2 #10 (download) → T1059.001 V2 #17 (execute encoded)**.

---

## Skenario run per variasi (pakai script yang ada)

Tiap variasi dijalankan sebagai sesi terpisah supaya labelnya bersih di `runs.csv`:

```powershell
# V1 — direct/script & native-lolbin
powershell -ExecutionPolicy Bypass -File .\Invoke-ArtPlan.ps1 -Pilot -Unattended `
  -SkipBaseline -SkipConditionB -Repetitions 1 -SpacingMinutes 5 -OutCsv C:\ART\runs-v1.csv `
  -T1059001 18 -T1059003 3 -T1105 7

# V2 — encoded/fileless & batch/script & powershell-transfer
powershell -ExecutionPolicy Bypass -File .\Invoke-ArtPlan.ps1 -Pilot -Unattended `
  -SkipBaseline -SkipConditionB -Repetitions 1 -SpacingMinutes 5 -OutCsv C:\ART\runs-v2.csv `
  -T1059001 17 -T1059003 6 -T1105 10

# V3 — network-enabled & redirected/script-fed & alternate-native
powershell -ExecutionPolicy Bypass -File .\Invoke-ArtPlan.ps1 -Pilot -Unattended `
  -SkipBaseline -SkipConditionB -Repetitions 1 -SpacingMinutes 5 -OutCsv C:\ART\runs-v3.csv `
  -T1059001 19 -T1059003 5 -T1105 9
```

Catatan:
- Script menjalankan **satu test per teknik per sesi**; flow multi-test (mis. V2 = 17 → 10 → 11)
  dijalankan dengan mengulang sesi memakai nomor test berikutnya (`-T1059001 10`, dst.) dan
  `-OutCsv` yang sama/berbeda sesuai kebutuhan label.
- `-SkipBaseline -SkipConditionB` hanya untuk sesi variasi (bukan sesi evaluasi utama).
- Untuk evaluasi resmi: setiap variasi diulang **2–3 kali** dan Condition A/EID 3 tetap ON;
  Condition B (EID 3 OFF) hanya untuk **T1105 V1 #7** sebagai uji sensitivitas.
