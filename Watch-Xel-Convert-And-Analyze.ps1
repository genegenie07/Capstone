# PowerShell 7 - Polling watcher with per-file stability (recommended)
$ErrorActionPreference = "Stop"

$xelFolder        = "C:\Users\tanlx\Capstone\SQL Audit Logs"
$pythonScriptPath = "C:\Users\tanlx\Capstone\Automated.py"
$outputRoot       = "C:\Users\tanlx\Capstone"

$pollIntervalSec  = 2
$stableSeconds    = 15   # process a file after it hasn't changed for N seconds

function Get-PathsForToday {
    $d = Get-Date -Format "yyyy-MM-dd"
    [pscustomobject]@{
        Date       = $d
        OutputCsv  = Join-Path $outputRoot "audit_output_$d.csv"
        TempFolder = Join-Path $outputRoot "tmp_csv_$d"
    }
}

function Ensure-Folder([string]$p) {
    if (-not (Test-Path $p)) { New-Item -ItemType Directory -Path $p | Out-Null }
}

function Wait-FileReady {
    param([string]$Path, [int]$TimeoutSeconds = 120)
    $sw = [Diagnostics.Stopwatch]::StartNew()
    while ($sw.Elapsed.TotalSeconds -lt $TimeoutSeconds) {
        try {
            if (-not (Test-Path $Path)) { return $false }
            $fs = [System.IO.File]::Open($Path, 'Open', 'Read', 'ReadWrite')
            $fs.Close(); $fs.Dispose()
            return $true
        } catch {
            Start-Sleep -Milliseconds 500
        }
    }
    return $false
}

function Append-CsvSkippingHeader {
    param([string]$SourceCsv, [string]$DestCsv)

    if (-not (Test-Path $DestCsv)) {
        Copy-Item $SourceCsv $DestCsv -Force
        return
    }

    $w = [System.IO.StreamWriter]::new($DestCsv, $true, [System.Text.UTF8Encoding]::new($false))
    try {
        $r = [System.IO.StreamReader]::new($SourceCsv, [System.Text.UTF8Encoding]::new($true))
        try {
            $lineNo = 0
            while (-not $r.EndOfStream) {
                $line = $r.ReadLine()
                if ($lineNo -eq 0) { $lineNo++; continue }
                $w.WriteLine($line)
                $lineNo++
            }
        } finally { $r.Close(); $r.Dispose() }
    } finally { $w.Close(); $w.Dispose() }
}

if (-not (Test-Path $xelFolder)) { throw "XEL folder not found: $xelFolder" }
if (-not (Test-Path $pythonScriptPath)) { throw "Python script not found: $pythonScriptPath" }

Import-Module SqlServer -WarningAction SilentlyContinue

$paths = Get-PathsForToday
Ensure-Folder $paths.TempFolder

# FullName -> "LastWriteUtcTicks|Length"
$seen = @{}

# pending paths + when we last saw a change for that path
$pending = New-Object System.Collections.Generic.HashSet[string] ([StringComparer]::OrdinalIgnoreCase)
$lastSeenChange = @{}  # path -> DateTime

# Initialize seen with existing files (so only new/changed triggers)
Get-ChildItem -Path $xelFolder -Filter "*.xel" -File -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -notlike ".azDownload*" } |
    ForEach-Object {
        $seen[$_.FullName] = "$($_.LastWriteTimeUtc.Ticks)|$($_.Length)"
    }

Write-Host "Polling: $xelFolder (filter: *.xel)" -ForegroundColor Cyan
Write-Host "Stable seconds: $stableSeconds. Poll: $pollIntervalSec sec. Stop with Ctrl+C" -ForegroundColor Cyan

while ($true) {
    # Date rollover
    $newPaths = Get-PathsForToday
    if ($newPaths.Date -ne $paths.Date) {
        $paths = $newPaths
        Ensure-Folder $paths.TempFolder
        Write-Host "Date changed. New daily output CSV: $($paths.OutputCsv)" -ForegroundColor Cyan
    }

    # Scan folder
    $files = Get-ChildItem -Path $xelFolder -Filter "*.xel" -File -ErrorAction SilentlyContinue |
             Where-Object { $_.Name -notlike ".azDownload*" }

    foreach ($f in $files) {
        $sig = "$($f.LastWriteTimeUtc.Ticks)|$($f.Length)"
        if (-not $seen.ContainsKey($f.FullName) -or $seen[$f.FullName] -ne $sig) {
            $seen[$f.FullName] = $sig
            [void]$pending.Add($f.FullName)
            $lastSeenChange[$f.FullName] = Get-Date
            Write-Host "[DETECTED] $($f.Name)" -ForegroundColor Yellow
        }
    }

    # Process files that have been stable for $stableSeconds
    $now = Get-Date
    $ready = @()

    foreach ($p in @($pending)) {
        if ($lastSeenChange.ContainsKey($p)) {
            if (($now - $lastSeenChange[$p]).TotalSeconds -ge $stableSeconds) {
                $ready += $p
            }
        }
    }

    $processedAny = $false

    foreach ($xelPath in $ready) {
        [void]$pending.Remove($xelPath)
        $lastSeenChange.Remove($xelPath) | Out-Null

        if (-not (Test-Path $xelPath)) { continue }
        if (-not (Wait-FileReady -Path $xelPath -TimeoutSeconds 120)) {
            Write-Warning "Timed out waiting for file ready: $xelPath"
            continue
        }

        $base = [IO.Path]::GetFileNameWithoutExtension($xelPath)
        $tempCsv = Join-Path $paths.TempFolder "$base.csv"

        try {
            $DataXel = Read-SqlXEvent $xelPath -ErrorAction Stop

            $rows = foreach ($row in $DataXel) {
                $fieldData = @{}
                foreach ($field in $row.Fields.GetEnumerator()) { $fieldData[$field.Key] = $field.Value }
                [PSCustomObject]@{ Statement = $fieldData["statement"] }
            }

            if ($rows) {
                $rows | Export-Csv -Path $tempCsv -NoTypeInformation -Encoding UTF8NoBOM
                Append-CsvSkippingHeader -SourceCsv $tempCsv -DestCsv $paths.OutputCsv
                Write-Host "Appended: $([IO.Path]::GetFileName($xelPath))" -ForegroundColor Green
                $processedAny = $true
            } else {
                Write-Warning "No rows produced from: $([IO.Path]::GetFileName($xelPath))"
            }
        }
        catch {
            Write-Warning "Failed to read $([IO.Path]::GetFileName($xelPath)): $($_.Exception.Message)"
        }
        finally {
            if (Test-Path $tempCsv) { Remove-Item $tempCsv -Force -ErrorAction SilentlyContinue }
        }
    }

    # Run Python once after processing at least one stable file
    if ($processedAny) {
        Write-Host "Triggering Python analysis..." -ForegroundColor Yellow
        & python $pythonScriptPath "$($paths.OutputCsv)"
        Write-Host "Python analysis script completed." -ForegroundColor Yellow
    }

    Start-Sleep -Seconds $pollIntervalSec
}
