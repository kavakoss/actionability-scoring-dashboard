<#
.SYNOPSIS
    Menjalankan rencana evaluasi Atomic Red Team (ART) untuk skripsi
    "Actionability Scoring Dashboard - Wazuh/Sysmon".

.DESCRIPTION
    Script ini otomatis:
      1. Preflight check (Administrator, Sysmon, Wazuh agent, jam)
      2. Backup config Sysmon
      3. Install Atomic Red Team bila belum ada
      4. Baseline benign windows (opsional)
      5. Condition A - EID 3 ON: 3 teknik x N repetisi (jeda >= SpacingMinutes)
      6. Condition B - EID 3 OFF: T1105 x N repetisi (Sysmon dikonfigurasi ulang otomatis)
      7. Restore config Sysmon
      8. Menulis log run (UTC) ke runs.csv

    Jalankan di endpoint Windows yang dimonitor Wazuh + Sysmon, sebagai Administrator.
    Lihat STEP-BY-STEP.md untuk instruksi lengkap.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Invoke-ArtPlan.ps1

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Invoke-ArtPlan.ps1 -T1059001 4 -T1059003 1 -T1105 1 -BaselineMinutes 30
#>
[CmdletBinding()]
param(
    # Nomor test atomic; 0 = pilih interaktif (dengan saran otomatis)
    [int]$T1059001 = 0,
    [int]$T1059003 = 0,
    [int]$T1105 = 0,

    [int]$Repetitions = 3,
    [int]$SpacingMinutes = 10,

    [int]$BaselineWindows = 3,
    [int]$BaselineMinutes = 30,
    [switch]$SkipBaseline,

    [switch]$SkipConditionB,
    [switch]$DryRun,

    [string]$WorkDir = "C:\ART",
    [string]$OutCsv = "C:\ART\runs.csv"
)

$ErrorActionPreference = "Stop"
$script:HostName = $env:COMPUTERNAME
$script:RunCounter = 0

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
function Write-Step([string]$Text) {
    Write-Host ""
    Write-Host ("=" * 78) -ForegroundColor DarkCyan
    Write-Host ("  $Text") -ForegroundColor Cyan
    Write-Host ("=" * 78) -ForegroundColor DarkCyan
}

function Write-Info([string]$Text) { Write-Host "  $Text" -ForegroundColor Gray }
function Write-Ok([string]$Text) { Write-Host "  [OK] $Text" -ForegroundColor Green }
function Write-Warn2([string]$Text) { Write-Host "  [!] $Text" -ForegroundColor Yellow }

function New-RunId {
    $script:RunCounter++
    return ("run-{0}-{1:D2}" -f (Get-Date).ToUniversalTime().ToString("yyyyMMdd-HHmmss"), $script:RunCounter)
}

# Native commands (sysmon64) write to stderr; with ErrorActionPreference=Stop
# PowerShell 5.1 turns that into a terminating NativeCommandError. Capturing
# with a temporarily relaxed preference avoids the false error.
function Invoke-NativeCapture {
    param(
        [string]$Executable,
        [string[]]$Arguments
    )
    $previousPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $output = & $Executable @Arguments 2>&1
    } finally {
        $ErrorActionPreference = $previousPreference
    }
    return ($output | Out-String)
}

function Add-RunRow {
    param(
        [string]$RunId,
        [string]$Technique,
        [string]$Condition,
        [string]$AtomicTest,
        [datetime]$Start,
        [datetime]$End,
        [string]$Notes
    )
    $row = [pscustomobject]@{
        run_id      = $RunId
        technique   = $Technique
        condition   = $Condition
        atomic_test = $AtomicTest
        host        = $script:HostName
        start_utc   = $Start.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        end_utc     = $End.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        notes       = $Notes
    }
    if (Test-Path $OutCsv) {
        $row | Export-Csv -Path $OutCsv -NoTypeInformation -Encoding UTF8 -Append
    } else {
        $row | Export-Csv -Path $OutCsv -NoTypeInformation -Encoding UTF8
    }
    Write-Info ("[csv] {0} | {1} | {2} | {3}" -f $row.run_id, $Technique, $Condition, $row.atomic_test)
}

function Wait-WithCountdown([int]$Minutes, [string]$Context) {
    if ($Minutes -le 0) { return }
    $remaining = $Minutes * 60
    Write-Info ("Jeda {0} menit sebelum {1} ..." -f $Minutes, $Context)
    while ($remaining -gt 0) {
        $chunk = [Math]::Min(30, $remaining)
        Write-Host ("`r  tersisa {0:mm\:ss}   " -f [timespan]::FromSeconds($remaining)) -NoNewline -ForegroundColor DarkGray
        Start-Sleep -Seconds $chunk
        $remaining -= $chunk
    }
    Write-Host "`r  jeda selesai.                    " -ForegroundColor DarkGray
}

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------
function Assert-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Script harus dijalankan sebagai Administrator (Run as Administrator)."
    }
}

function Get-SysmonExecutable {
    foreach ($name in @("sysmon64", "sysmon")) {
        $command = Get-Command $name -ErrorAction SilentlyContinue
        if ($command) { return $command.Source }
    }
    throw "sysmon tidak ditemukan. Pastikan Microsoft Sysmon terinstall."
}

function Assert-Services {
    $sysmonService = @("sysmon64", "sysmon") |
        ForEach-Object { Get-Service $_ -ErrorAction SilentlyContinue } |
        Select-Object -First 1
    if (-not $sysmonService -or $sysmonService.Status -ne "Running") {
        throw "Service Sysmon tidak Running."
    }
    Write-Ok ("Sysmon service: {0} ({1})" -f $sysmonService.Name, $sysmonService.Status)

    $wazuhService = Get-Service WazuhSvc -ErrorAction SilentlyContinue
    if (-not $wazuhService -or $wazuhService.Status -ne "Running") {
        Write-Warn2 "Service WazuhSvc tidak Running - event tidak akan terkirim ke Wazuh!"
    } else {
        Write-Ok ("Wazuh agent: {0}" -f $wazuhService.Status)
    }

    $w32time = Get-Service w32time -ErrorAction SilentlyContinue
    if ($w32time -and $w32time.Status -ne "Running") {
        Write-Warn2 "Windows Time service tidak Running - pastikan jam sinkron (evaluasi memakai UTC)."
    }
}

function Get-SysmonConfigXml([string]$SysmonExe) {
    $text = Invoke-NativeCapture -Executable $SysmonExe -Arguments @("-c")
    $start = $text.IndexOf("<Sysmon")
    $end = $text.LastIndexOf("</Sysmon>")
    if ($start -lt 0 -or $end -lt 0) {
        $preview = $text.Trim()
        if ($preview.Length -gt 300) { $preview = $preview.Substring(0, 300) + "..." }
        throw "Tidak bisa membaca config Sysmon (sysmon -c). Output: $preview"
    }
    return $text.Substring($start, ($end - $start) + "</Sysmon>".Length)
}

function Ensure-AtomicRedTeam {
    if (-not (Get-Module -ListAvailable -Name invoke-atomicredteam)) {
        Write-Info "Install module invoke-atomicredteam + powershell-yaml ..."
        Install-Module -Name invoke-atomicredteam, powershell-yaml -Scope CurrentUser -Force
    }
    Import-Module invoke-atomicredteam -Force

    try {
        Get-AtomicTechnique -Technique T1059.001 | Out-Null
        Write-Ok "Atomic Red Team siap."
    } catch {
        Write-Info "Atomics belum ada, menjalankan installer ART ..."
        IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
        Install-AtomicRedTeam -getAtomics -Force
        Import-Module invoke-atomicredteam -Force
        Get-AtomicTechnique -Technique T1059.001 | Out-Null
        Write-Ok "Atomic Red Team terinstall."
    }
}

function Select-AtomicTest {
    param(
        [string]$Technique,
        [string[]]$PreferKeywords,
        [string[]]$ExcludeKeywords
    )
    $data = Get-AtomicTechnique -Technique $Technique
    $tests = @($data.atomic_tests)

    Write-Host ""
    Write-Host ("Test tersedia untuk {0}:" -f $Technique) -ForegroundColor White
    for ($i = 0; $i -lt $tests.Count; $i++) {
        $desc = ($tests[$i].description -replace "\s+", " ")
        if ($desc.Length -gt 88) { $desc = $desc.Substring(0, 88) + "..." }
        Write-Host ("  [{0,2}] {1}" -f ($i + 1), $tests[$i].name)
        Write-Host ("        {0}" -f $desc) -ForegroundColor DarkGray
    }

    $scores = New-Object System.Collections.ArrayList
    for ($i = 0; $i -lt $tests.Count; $i++) {
        $text = (([string]$tests[$i].name) + " " + ([string]$tests[$i].description)).ToLower()
        $score = 0
        foreach ($keyword in $ExcludeKeywords) {
            if ($text -like "*$keyword*") { $score = -1000; break }
        }
        if ($score -ge 0) {
            for ($k = 0; $k -lt $PreferKeywords.Count; $k++) {
                if ($text -like "*$($PreferKeywords[$k])*") { $score += (100 - ($k * 10)) }
            }
        }
        [void]$scores.Add($score)
    }

    $best = 0; $bestScore = -100000
    for ($i = 0; $i -lt $scores.Count; $i++) {
        if ($scores[$i] -gt $bestScore) { $bestScore = $scores[$i]; $best = $i + 1 }
    }
    if ($bestScore -le 0) { $best = 1 }

    $answer = Read-Host ("Pilih nomor test {0} [default {1}]" -f $Technique, $best)
    if ([string]::IsNullOrWhiteSpace($answer)) { return $best }
    return [int]$answer
}

function Invoke-RepetitionSet {
    param(
        [string]$Technique,
        [int]$TestNumber,
        [int]$Count,
        [string]$Condition,
        [string]$Notes,
        [int]$Spacing
    )
    for ($rep = 1; $rep -le $Count; $rep++) {
        $runId = New-RunId
        $label = "{0}-{1}" -f $Technique, $TestNumber
        Write-Host ""
        Write-Host ("  -> Run {0}/{1}: {2} (condition {3})" -f $rep, $Count, $label, $Condition) -ForegroundColor White

        if ($DryRun) {
            Write-Info "[dry-run] tidak mengeksekusi atomic."
            continue
        }

        $start = (Get-Date).ToUniversalTime()
        $errorNote = ""
        try {
            Invoke-AtomicTest $Technique -TestNumbers $TestNumber -Confirm:$false -ErrorAction Stop | Out-Null
            Write-Ok "atomic selesai dieksekusi."
        } catch {
            $errorNote = "ERROR: " + $_.Exception.Message
            Write-Warn2 $errorNote
        }
        try {
            Invoke-AtomicTest $Technique -TestNumbers $TestNumber -Cleanup -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
        } catch { }
        $end = (Get-Date).ToUniversalTime()

        $rowNotes = $Notes
        if ($errorNote) { $rowNotes = ($rowNotes + " | " + $errorNote).Trim(" |") }
        Add-RunRow -RunId $runId -Technique $Technique -Condition $Condition -AtomicTest $label `
            -Start $start -End $end -Notes $rowNotes

        if ($rep -lt $Count) { Wait-WithCountdown -Minutes $Spacing -Context ("repetisi berikutnya ({0})" -f $Technique) }
    }
}

function Set-SysmonConfig([string]$SysmonExe, [string]$Path) {
    Invoke-NativeCapture -Executable $SysmonExe -Arguments @("-c", $Path) | Out-Null
    Start-Sleep -Seconds 2
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
Write-Step "Actionability Scoring - ART Evaluation Plan"
Write-Info ("Host     : {0}" -f $script:HostName)
Write-Info ("WorkDir  : {0}" -f $WorkDir)
Write-Info ("runs.csv : {0}" -f $OutCsv)
Write-Info ("Waktu    : {0}" -f (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"))

Assert-Admin
New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
$sysmon = Get-SysmonExecutable
Write-Ok ("sysmon   : {0}" -f $sysmon)
Assert-Services

Write-Step "Backup config Sysmon"
$fullConfigPath = Join-Path $WorkDir "sysmon-config-full.xml"
$noEid3ConfigPath = Join-Path $WorkDir "sysmon-config-no-eid3.xml"
$fullXml = Get-SysmonConfigXml -SysmonExe $sysmon
$fullXml | Out-File -FilePath $fullConfigPath -Encoding utf8
Write-Ok ("config tersimpan: {0}" -f $fullConfigPath)
$hasNetworkConnect = $fullXml -match "<NetworkConnect"
if (-not $hasNetworkConnect) {
    Write-Warn2 "Config Sysmon saat ini TIDAK punya NetworkConnect (EID 3) - Condition A tidak valid. Beri tahu Jason."
} else {
    Write-Ok "NetworkConnect (EID 3) terdeteksi di config."
}

Write-Step "Install / cek Atomic Red Team"
Ensure-AtomicRedTeam

Write-Step "Pilih test atomic"
if ($T1059001 -le 0) {
    $T1059001 = Select-AtomicTest -Technique "T1059.001" `
        -PreferKeywords @("encoded", "invoke-expression", "execution", "powershell") `
        -ExcludeKeywords @("mimikatz", "bloodhound", "rubeus", "cobalt", "remote share", "wmi")
}
if ($T1059003 -le 0) {
    $T1059003 = Select-AtomicTest -Technique "T1059.003" `
        -PreferKeywords @("echo", "whoami", "builtin", "command") `
        -ExcludeKeywords @("mimikatz", "bloodhound", "rubeus")
}
if ($T1105 -le 0) {
    $T1105 = Select-AtomicTest -Technique "T1105" `
        -PreferKeywords @("certutil", "download", "invoke-webrequest", "urlcache") `
        -ExcludeKeywords @("mimikatz", "bloodhound", "rubeus", "putty", "sftp")
}
Write-Ok ("T1059.001 -> test {0} | T1059.003 -> test {1} | T1105 -> test {2}" -f $T1059001, $T1059003, $T1105)

Write-Step "Rencana eksekusi"
$plan = @()
if (-not $SkipBaseline) {
    $plan += ("Baseline benign: {0} jendela x {1} menit (tanpa ART)" -f $BaselineWindows, $BaselineMinutes)
}
$plan += ("Condition A (EID 3 ON): T1059.001 x{0}, T1059.003 x{0}, T1105 x{0} (jeda {1} menit)" -f $Repetitions, $SpacingMinutes)
if (-not $SkipConditionB) {
    $plan += ("Condition B (EID 3 OFF): T1105 x{0} (jeda {1} menit)" -f $Repetitions, $SpacingMinutes)
}
$plan | ForEach-Object { Write-Info ("- " + $_) }
if ($DryRun) { Write-Info "[dry-run] selesai tanpa eksekusi."; return }

$confirm = Read-Host "`nKetik YES untuk mulai"
if ($confirm -ne "YES") { Write-Info "Dibatalkan."; return }

$overallStart = (Get-Date).ToUniversalTime()

# --- Baseline -------------------------------------------------------------
if (-not $SkipBaseline) {
    Write-Step "Baseline benign"
    Write-Info "Lakukan aktivitas normal (dokumen/browsing ringan). JANGAN jalankan ART."
    for ($w = 1; $w -le $BaselineWindows; $w++) {
        Read-Host ("Tekan Enter untuk mulai baseline window {0}/{1}" -f $w, $BaselineWindows)
        $start = (Get-Date).ToUniversalTime()
        Write-Info ("Baseline window {0} berjalan {1} menit ..." -f $w, $BaselineMinutes)
        Start-Sleep -Seconds ($BaselineMinutes * 60)
        $end = (Get-Date).ToUniversalTime()
        Add-RunRow -RunId (New-RunId) -Technique "" -Condition "baseline" -AtomicTest "" `
            -Start $start -End $end -Notes ("benign window {0}/{1}" -f $w, $BaselineWindows)
    }
}

# --- Condition A ----------------------------------------------------------
Write-Step "Condition A - EID 3 ON"
Invoke-RepetitionSet -Technique "T1059.001" -TestNumber $T1059001 -Count $Repetitions -Condition "A" -Notes "EID3 ON" -Spacing $SpacingMinutes
Invoke-RepetitionSet -Technique "T1059.003" -TestNumber $T1059003 -Count $Repetitions -Condition "A" -Notes "EID3 ON" -Spacing $SpacingMinutes
Invoke-RepetitionSet -Technique "T1105" -TestNumber $T1105 -Count $Repetitions -Condition "A" -Notes "EID3 ON" -Spacing $SpacingMinutes

# --- Condition B ----------------------------------------------------------
if (-not $SkipConditionB) {
    Write-Step "Condition B - EID 3 OFF (T1105)"
    $noEid3Xml = $fullXml -replace '(?s)<NetworkConnect.*?</NetworkConnect>', '' -replace '(?s)<NetworkConnect[^>]*/>', ''
    if ($noEid3Xml -match "<NetworkConnect") {
        throw "Gagal menghapus NetworkConnect dari config Sysmon."
    }
    $noEid3Xml | Out-File -FilePath $noEid3ConfigPath -Encoding utf8
    Set-SysmonConfig -SysmonExe $sysmon -Path $noEid3ConfigPath
    $verify = Get-SysmonConfigXml -SysmonExe $sysmon
    if ($verify -match "<NetworkConnect") {
        throw "Verifikasi gagal: NetworkConnect masih ada. Batalkan Condition B."
    }
    Write-Ok "EID 3 dinonaktifkan untuk Condition B."

    Invoke-RepetitionSet -Technique "T1105" -TestNumber $T1105 -Count $Repetitions -Condition "B" -Notes "EID3 OFF" -Spacing $SpacingMinutes

    Write-Step "Restore config Sysmon"
    Set-SysmonConfig -SysmonExe $sysmon -Path $fullConfigPath
    $verify = Get-SysmonConfigXml -SysmonExe $sysmon
    if ($verify -match "<NetworkConnect") {
        Write-Ok "NetworkConnect (EID 3) aktif kembali."
    } else {
        Write-Warn2 "NetworkConnect belum terdeteksi setelah restore - cek manual dengan 'sysmon64 -c'."
    }
}

$overallEnd = (Get-Date).ToUniversalTime()
Write-Step "Selesai"
Write-Info ("Durasi total : {0:hh\:mm\:ss}" -f ($overallEnd - $overallStart))
Write-Info ("Log run      : {0}" -f $OutCsv)
Write-Info ("Config full  : {0}" -f $fullConfigPath)
if (Test-Path $noEid3ConfigPath) { Write-Info ("Config no-EID3: {0}" -f $noEid3ConfigPath) }
Write-Host ""
Write-Info "Kirim file-file di atas ke Jason. JANGAN hapus data Wazuh."
