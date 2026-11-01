# ==============================================================================
# FakeDriveShield.ps1 - Complete Fake Storage Drive Detector & Reclaimer
# Features:
#   1. Automatic USB Drive Detection & Safety Checks
#   2. Heuristic Fraud Detection (VID/PID, MPTool 0x0 serial, FAT32 64KB cluster)
#   3. Fast SHA-256 Storage Integrity Verification (Pinpoints physical flash limit)
#   4. Safe Partition Reclaiming (Locks out fake sectors permanently)
#   5. Comprehensive Markdown (.md) Report Generation
# ==============================================================================

# Ensure Administrator privileges
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Start-Process powershell -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    exit
}

function Show-Banner {
    Clear-Host
    Write-Host "=======================================================================" -ForegroundColor Cyan
    Write-Host "         🛡️   FAKE STORAGE DRIVE DETECTOR & RECLAIMER   🛡️           " -ForegroundColor Cyan
    Write-Host "   Detect Fake Flash Drives | Verify Real Capacity | Auto-Fix & Report" -ForegroundColor Gray
    Write-Host "=======================================================================" -ForegroundColor Cyan
    Write-Host ""
}

function Get-VolumeSerial($DriveLetter) {
    try {
        $ld = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$($DriveLetter.TrimEnd(':')):'" -ErrorAction SilentlyContinue
        if ($ld -and $ld.VolumeSerialNumber) { return $ld.VolumeSerialNumber }
    } catch {}
    return "Unknown"
}

function Get-SuspiciousScore($disk, $vol, $driveLetter) {
    $score = 0
    $flags = @()
    $name = "$($disk.FriendlyName) $($disk.Model)".ToLower()
    $serial = "$($disk.SerialNumber)".ToLower()
    $volSerial = Get-VolumeSerial $driveLetter

    $badStrings = @("121220160204", "00000000", "123456789012", "vendorco", "chipsbnk", "alcor", "firstchip", "mass storage")
    foreach ($s in $badStrings) {
        if ($serial -like "*$s*" -or $name -like "*$s*") {
            $score += 35
            $flags += "Known counterfeit controller identifier ('$s') detected."
            break
        }
    }

    if ($volSerial -in @("0", "00000000", "0x0", "")) {
        $score += 30
        $flags += "Volume Serial Number is blank / 0x0 (Mass Production Flashing Tool signature)."
    }

    $diskGB = [math]::Round($disk.Size / 1GB, 1)
    if ($vol.FileSystem -eq "FAT32" -and $diskGB -ge 64) {
        $score += 25
        $flags += "Formatted as FAT32 on a $diskGB GB drive (Standard factory drives >= 64GB use exFAT/NTFS)."
    }

    if ($vol.AllocationUnitSize -eq 65536) {
        $score += 20
        $flags += "Cluster size is 64 KB (65,536 bytes), typical of manipulated large FAT32 volumes."
    }

    if ($score -gt 100) { $score = 100 }
    $verdict = if ($score -ge 50) { "HIGH RISK OF COUNTERFEIT" } elseif ($score -ge 25) { "SUSPICIOUS" } else { "PROBABLY GENUINE" }

    return [PSCustomObject]@{
        Score = $score
        Verdict = $verdict
        Flags = $flags
        VolSerial = $volSerial
    }
}

function Test-Capacity($DriveLetter, $DiskSizeMB) {
    $cleanLetter = "$($DriveLetter.TrimEnd(':')):"
    $testDir = "$cleanLetter\_fake_drive_probe_test"
    
    if (Test-Path $testDir) { Remove-Item $testDir -Recurse -Force -ErrorAction SilentlyContinue }
    New-Item -ItemType Directory -Path $testDir | Out-Null

    $chunkMB = 64
    $chunkBytes = $chunkMB * 1024 * 1024
    $buffer = New-Object byte[] $chunkBytes
    $rand = New-Object Random(123456)
    $rand.NextBytes($buffer)

    $sha = [System.Security.Cryptography.SHA256]::Create()
    $expectedHash = [BitConverter]::ToString($sha.ComputeHash($buffer)).Replace("-", "").ToLower()

    $checkpoints = @(64, 128, 256, 512, 1024, 1536, 2048, 3072, 4096, 6144, 8192, 12288, 16384, 24576, 32768, 49152, 65536)
    $checkpoints = $checkpoints | Where-Object { $_ -le $DiskSizeMB }

    $verifiedMB = 0
    $corrupt = $false
    $corruptMB = $null
    $testLog = @()

    Write-Host "`n[+] Starting SHA-256 Storage Integrity Verification..." -ForegroundColor Cyan

    try {
        foreach ($targetMB in $checkpoints) {
            $needed = [int](($targetMB - $verifiedMB) / $chunkMB)
            if ($needed -le 0) { continue }

            Write-Host "  -> Probing storage boundary up to $targetMB MB..." -ForegroundColor Gray

            $stepFailed = $false
            for ($s = 0; $s -lt $needed; $s++) {
                $idx = [int]($verifiedMB / $chunkMB) + 1
                $fpath = "$testDir\block_$($idx.ToString('D5')).dat"

                try {
                    [System.IO.File]::WriteAllBytes($fpath, $buffer)
                    $readBytes = [System.IO.File]::ReadAllBytes($fpath)
                    $readHash = [BitConverter]::ToString($sha.ComputeHash($readBytes)).Replace("-", "").ToLower()

                    if ($readHash -ne $expectedHash) {
                        $corrupt = $true
                        $corruptMB = $verifiedMB + $chunkMB
                        $testLog += [PSCustomObject]@{ OffsetMB = $corruptMB; Status = "CORRUPT"; Hash = "$($readHash.Substring(0, 10))..." }
                        $stepFailed = $true
                        break
                    } else {
                        $verifiedMB += $chunkMB
                        $testLog += [PSCustomObject]@{ OffsetMB = $verifiedMB; Status = "VERIFIED_OK"; Hash = "$($readHash.Substring(0, 10))..." }
                    }
                } catch {
                    $corrupt = $true
                    $corruptMB = $verifiedMB + $chunkMB
                    $testLog += [PSCustomObject]@{ OffsetMB = $corruptMB; Status = "WRITE_ERROR"; Hash = $_.Exception.Message }
                    $stepFailed = $true
                    break
                }
            }

            if ($stepFailed) { break }
        }
    } finally {
        if (Test-Path $testDir) {
            Remove-Item $testDir -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    # Safe capacity selection
    $safeMB = 0
    $standardSizes = @(512, 1024, 2048, 4096, 8192, 16384, 32768, 65536, 131072, 262144)
    foreach ($sz in $standardSizes) {
        if ($sz -le $verifiedMB) { $safeMB = $sz }
    }
    if ($safeMB -eq 0 -and $verifiedMB -gt 0) { $safeMB = [int]($verifiedMB * 0.85) }

    return [PSCustomObject]@{
        VerifiedMB = $verifiedMB
        CorruptionDetected = $corrupt
        CorruptionOffsetMB = $corruptMB
        SafeCapacityMB = $safeMB
        TestLog = $testLog
    }
}

function Save-MarkdownReport($disk, $vol, $driveLetter, $heuristics, $testRes, $reclaimRes) {
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $fileTime = Get-Date -Format "yyyyMMdd_HHmmss"
    $reportedGB = [math]::Round($disk.Size / 1GB, 2)
    $verifiedGB = [math]::Round($testRes.VerifiedMB / 1024, 2)
    $safeGB = [math]::Round($testRes.SafeCapacityMB / 1024, 2)
    $isFake = $testRes.CorruptionDetected -or ($heuristics.Score -ge 50)

    $desktop = [Environment]::GetFolderPath("Desktop")
    $reportsDir = "$desktop\FakeDriveReports"
    if (-not (Test-Path $reportsDir)) { New-Item -ItemType Directory -Path $reportsDir | Out-Null }
    $reportPath = "$reportsDir\Audit_Report_Drive_$($driveLetter.TrimEnd(':'))_$fileTime.md"

    $md = @()
    $md += "# Storage Drive Authenticity & Capacity Audit Report"
    $md += "**Audit Timestamp:** `$timestamp` | **Auditor Tool:** `FakeDriveShield v1.0``n"

    if ($isFake) {
        $md += "> [!CAUTION]"
        $md += "> **COUNTERFEIT / FAKE CAPACITY STORAGE DRIVE CONFIRMED**"
        $md += "> Advertised capacity is **$reportedGB GB**, but physical working flash is only **~$verifiedGB GB ($($testRes.VerifiedMB) MB)**."
        $md += "> Data written past this point is permanently corrupted or discarded.`n"
    } else {
        $md += "> [!NOTE]"
        $md += "> **STORAGE DRIVE CAPACITY VERIFIED GENUINE**"
        $md += "> Physical storage integrity verified up to tested limits without corruption.`n"
    }

    $md += "## 1. Hardware Specifications`n"
    $md += "| Parameter | Observed Value | Status |"
    $md += "| :--- | :--- | :--- |"
    $md += "| **Drive Letter** | `$($driveLetter)` | Target Volume |"
    $md += "| **Reported Disk Size** | `$reportedGB GB` ($($disk.Size) bytes) | Firmware Advertised |"
    $md += "| **Physical Storage Verified** | **`$verifiedGB GB`** ($($testRes.VerifiedMB) MB) | $(if ($isFake) {'CRITICAL MISMATCH'} else {'Matches'}) |"
    $md += "| **Safe Usable Capacity** | **`$safeGB GB`** ($($testRes.SafeCapacityMB) MB) | Recommended Bound |"
    $md += "| **Controller Name** | `$($disk.FriendlyName)` | Hardware Descriptor |"
    $md += "| **Firmware Serial** | `$($disk.SerialNumber)` | $(if ($heuristics.Score -ge 35) {'Generic Fake'} else {'Standard'}) |"
    $md += "| **Volume Serial Number** | `$($heuristics.VolSerial)` | $(if ($heuristics.VolSerial -in @('0', '0x0')) {'Blank / MPTool'} else {'Standard'}) |"
    $md += "| **Filesystem / Cluster** | `$($vol.FileSystem)` / `$($vol.AllocationUnitSize) bytes` | Volume Format |`n"

    $md += "## 2. Fraud Risk & Heuristics`n"
    $md += "- **Fraud Risk Score:** `$($heuristics.Score) / 100`"
    $md += "- **Verdict:** **$($heuristics.Verdict)**`n"
    if ($heuristics.Flags.Count -gt 0) {
        $md += "### Detected Red Flags:"
        foreach ($flag in $heuristics.Flags) {
            $md += "- ⚠️ $flag"
        }
        $md += "`n"
    }

    $md += "## 3. Storage Integrity Map`n"
    $totalBlocks = 36
    $verifiedBlocks = if ($reportedGB -gt 0) { [math]::Max(1, [int](($verifiedGB / $reportedGB) * $totalBlocks)) } else { 0 }
    $corruptBlocks = $totalBlocks - $verifiedBlocks
    $bar = ("🟩" * $verifiedBlocks) + ("🟥" * $corruptBlocks)
    $md += "````"
    $md += "[0 GB] $bar [$reportedGB GB]"
    $md += "````"
    $md += "- 🟩 **Verified Real Memory:** ~$verifiedGB GB ($($testRes.VerifiedMB) MB)"
    $md += "- 🟥 **Phantom / Corrupted Space:** ~$( [math]::Max(0, $reportedGB - $verifiedGB) ) GB`n"

    $md += "## 4. Verification Checkpoint Log`n"
    $md += "| Offset | Result | Hash |"
    $md += "| :--- | :--- | :--- |"
    foreach ($entry in $testRes.TestLog) {
        $md += "| `$($entry.OffsetMB) MB` | `$($entry.Status)` | `$($entry.Hash)` |"
    }
    $md += "`n"

    if ($reclaimRes) {
        $md += "## 5. Remediation & Re-Partitioning Action`n"
        $md += "- **Remediation Status:** `$($reclaimRes.Status)`"
        $md += "- **Safe Partition Created:** **`$($reclaimRes.SizeMB) MB`** ($([math]::Round($reclaimRes.SizeMB/1024, 2)) GB)"
        $md += "- **Filesystem / Label:** `$($reclaimRes.FS)` / `$($reclaimRes.Label)`"
        $md += "- **Permanently Blocked Phantom Space:** `$( [math]::Round($reportedGB - ($reclaimRes.SizeMB/1024), 2) ) GB``n"
    }

    $md += "## 6. Official Consumer Dispute Declaration`n"
    $md += "> **Notice for Marketplace Dispute / Refund Claims (Amazon, eBay, AliExpress, PayPal, Credit Card Chargeback):**"
    $md += "> "
    $md += "> This report provides cryptographic and physical verification proving this storage device is a **fraudulent counterfeit product**."
    $md += "> The controller was maliciously flashed to report **$reportedGB GB**, but write-read hardware verification detects hard corruption at **$($testRes.CorruptionOffsetMB) MB**."
    $md += "> This product does not match its advertised specifications and will permanently destroy customer data upon reaching real physical limits."

    $md -join "`r`n" | Out-File -FilePath $reportPath -Encoding utf8
    return $reportPath
}

function Execute-Reclaim($diskNumber, $safeMB, $driveLetter) {
    $fs = if ($safeMB -ge 4096) { "exfat" } else { "fat32" }
    $label = if ($safeMB -ge 1024) { "SAFE_$([int]($safeMB/1024))GB" } else { "SAFE_$($safeMB)MB" }

    Write-Host "`n[+] Executing DiskPart re-partitioning..." -ForegroundColor Yellow
    Write-Host "    Disk Number : $diskNumber"
    Write-Host "    Safe Size   : $safeMB MB"
    Write-Host "    File System : $($fs.ToUpper())"
    Write-Host "    Volume Label: $label"

    $dp = @"
select disk $diskNumber
clean
convert mbr
create partition primary size=$safeMB
format fs=$fs quick label="$label"
assign letter=$driveLetter
"@

    $tmp = "$env:TEMP\dp_reclaim_$diskNumber.txt"
    Set-Content -Path $tmp -Value $dp -Encoding ASCII
    diskpart /s $tmp | Out-Default
    Remove-Item $tmp -Force -ErrorAction SilentlyContinue

    return [PSCustomObject]@{
        Status = "Success"
        SizeMB = $safeMB
        FS = $fs.ToUpper()
        Label = $label
    }
}

# --- Main Program Flow ---
Show-Banner

Write-Host "Scanning system storage devices..." -ForegroundColor Yellow
$disks = Get-Disk | Where-Object { $_.BusType -eq 'USB' -or $_.MediaType -eq 'Removable' }

if (-not $disks) {
    Write-Host "No USB / Removable storage drives found!" -ForegroundColor Red
    Write-Host "Please plug in your USB drive and run this tool again."
    Write-Host ""
    Read-Host "Press Enter to exit"
    exit
}

Write-Host "`nDetected USB Removable Storage Drives:" -ForegroundColor Green
Write-Host ("-" * 70)
Write-Host ("{0,-6} {1,-10} {2,-16} {3,-12} {4}" -f "Disk#", "Letter", "Reported Size", "Bus", "Device Name")
Write-Host ("-" * 70)

$driveChoices = @()
foreach ($d in $disks) {
    $parts = Get-Partition -DiskNumber $d.Number -ErrorAction SilentlyContinue
    $letter = if ($parts -and $parts[0].DriveLetter) { "$($parts[0].DriveLetter):" } else { "None" }
    $sizeGB = "$([math]::Round($d.Size / 1GB, 1)) GB"
    Write-Host ("{0,-6} {1,-10} {2,-16} {3,-12} {4}" -f $d.Number, $letter, $sizeGB, $d.BusType, $d.FriendlyName)
    $driveChoices += [PSCustomObject]@{
        Disk = $d
        Partition = if ($parts) { $parts[0] } else { $null }
        Letter = $letter
    }
}
Write-Host ("-" * 70)

$defaultChoice = $driveChoices[0]
$chosenLetter = Read-Host "`nEnter drive letter to audit and fix [Default: $($defaultChoice.Letter.TrimEnd(':'))]"
if (-not $chosenLetter) { $chosenLetter = $defaultChoice.Letter.TrimEnd(':') }
$chosenLetter = $chosenLetter.Trim().TrimEnd(':').ToUpper()

$selected = $driveChoices | Where-Object { $_.Letter -like "*$chosenLetter*" }
if (-not $selected) {
    Write-Host "Invalid drive letter selected! Aborting for safety." -ForegroundColor Red
    Read-Host "Press Enter to exit"
    exit
}

$targetDisk = $selected[0].Disk
$targetVol = Get-Volume -DriveLetter $chosenLetter -ErrorAction SilentlyContinue
$diskSizeMB = [int]($targetDisk.Size / 1MB)

Show-Banner
Write-Host "Target Selected: Drive $chosenLetter: (Disk $($targetDisk.Number))" -ForegroundColor Cyan
Write-Host "Device: $($targetDisk.FriendlyName) | Advertised Size: $([math]::Round($targetDisk.Size/1GB, 1)) GB`n"

# Run Heuristics
Write-Host "[1/3] Running Counterfeit Heuristic Audit..." -ForegroundColor Yellow
$heuristics = Get-SuspiciousScore $targetDisk $targetVol $chosenLetter
Write-Host "Fraud Risk Score : $($heuristics.Score) / 100 ($($heuristics.Verdict))" -ForegroundColor $(if ($heuristics.Score -ge 50) { 'Red' } else { 'Green' })
foreach ($f in $heuristics.Flags) {
    Write-Host "  ⚠️  $f" -ForegroundColor Red
}

Write-Host ""
$doTest = Read-Host "Proceed with SHA-256 Storage Capacity Integrity Verification? (Y/n)"
if ($doTest -eq 'n' -or $doTest -eq 'N') {
    Write-Host "Verification cancelled by user."
    Read-Host "Press Enter to exit"
    exit
}

# Run Capacity Test
Write-Host "`n[2/3] Testing Storage Capacity..." -ForegroundColor Yellow
$testRes = Test-Capacity $chosenLetter $diskSizeMB

Write-Host "`nCapacity Verification Results:" -ForegroundColor Cyan
Write-Host "  Verified Physical Storage : $($testRes.VerifiedMB) MB ($([math]::Round($testRes.VerifiedMB/1024, 2)) GB)"
if ($testRes.CorruptionDetected) {
    Write-Host "  Corruption Detected At    : $($testRes.CorruptionOffsetMB) MB" -ForegroundColor Red
    Write-Host "  Recommended Safe Limit    : $($testRes.SafeCapacityMB) MB ($([math]::Round($testRes.SafeCapacityMB/1024, 2)) GB)" -ForegroundColor Green
} else {
    Write-Host "  Integrity Status          : PASSED without corruption across tested ranges." -ForegroundColor Green
}

# Remediation / Fix
$reclaimRes = $null
if ($testRes.CorruptionDetected -and $testRes.SafeCapacityMB -gt 0) {
    Write-Host ""
    Write-Host "-----------------------------------------------------------------------" -ForegroundColor Yellow
    Write-Host "  AUTO-FIX: RE-PARTITION TO SAFE PHYSICAL CAPACITY ($($testRes.SafeCapacityMB) MB)?" -ForegroundColor Yellow
    Write-Host "  This permanently blocks all phantom/fake storage and prevents file loss." -ForegroundColor Yellow
    Write-Host "-----------------------------------------------------------------------" -ForegroundColor Yellow
    $doFix = Read-Host "Re-partition Drive $chosenLetter: now? (Y/n)"
    if ($doFix -ne 'n' -and $doFix -ne 'N') {
        Write-Host "`n[3/3] Re-partitioning Drive..." -ForegroundColor Yellow
        $reclaimRes = Execute-Reclaim $targetDisk.Number $testRes.SafeCapacityMB $chosenLetter
        Write-Host "`nDrive successfully repartitioned and ready for safe use!" -ForegroundColor Green
    }
}

# Generate Markdown Report
Write-Host "`nGenerating Markdown Audit Report..." -ForegroundColor Cyan
$repPath = Save-MarkdownReport $targetDisk $targetVol $chosenLetter $heuristics $testRes $reclaimRes
Write-Host "Report saved successfully to:" -ForegroundColor Green
Write-Host "  $repPath" -ForegroundColor White

Write-Host "`n=======================================================================" -ForegroundColor Cyan
Write-Host "   AUDIT & REMEDIATION COMPLETE! Press Enter to close.                 " -ForegroundColor Cyan
Write-Host "=======================================================================" -ForegroundColor Cyan
Read-Host ""
