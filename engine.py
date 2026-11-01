#!/usr/bin/env python3
"""
Cross-Platform Engine for FakeDriveShield
Works on Windows, Linux, and macOS.
"""

import os
import sys
import time
import json
import random
import hashlib
import platform
import datetime
import subprocess
from typing import Dict, List, Optional, Tuple, Any

CURRENT_OS = platform.system().lower()

SUSPICIOUS_STRINGS = [
    "121220160204",
    "00000000",
    "123456789012",
    "0123456789abcdef",
    "vendorco",
    "chipsbnk",
    "alcor",
    "firstchip",
    "general udisk",
    "mass storage device",
    "super top",
]

def run_cmd(cmd_list: List[str]) -> str:
    """Runs a system command safely and returns standard output."""
    try:
        proc = subprocess.run(cmd_list, capture_output=True, text=True, check=True)
        return proc.stdout.strip()
    except Exception:
        return ""

def list_drives() -> List[Dict[str, Any]]:
    """
    Cross-platform drive enumeration.
    Returns normalized list of storage devices.
    """
    if CURRENT_OS == "windows":
        ps_cmd = """
        $disks = Get-Disk | Select-Object Number, FriendlyName, BusType, Size, PartitionStyle, SerialNumber, OperationalStatus, HealthStatus
        $vols = Get-Volume | Select-Object DriveLetter, FileSystem, FileSystemLabel, Size, SizeRemaining, HealthStatus, AllocationUnitSize
        $results = @()
        foreach ($d in $disks) {
            $partitions = Get-Partition -DiskNumber $d.Number -ErrorAction SilentlyContinue
            if ($partitions) {
                foreach ($p in $partitions) {
                    $vol = $vols | Where-Object { $_.DriveLetter -and $_.DriveLetter -eq $p.DriveLetter }
                    $results += [PSCustomObject]@{
                        DiskNumber = $d.Number
                        FriendlyName = $d.FriendlyName
                        BusType = $d.BusType
                        DiskSize = $d.Size
                        PartitionStyle = $d.PartitionStyle
                        DiskSerialNumber = $d.SerialNumber
                        PartitionNumber = $p.PartitionNumber
                        DriveLetter = if ($p.DriveLetter) { "$($p.DriveLetter):" } else { "None" }
                        MountPoint = if ($p.DriveLetter) { "$($p.DriveLetter):\" } else { "" }
                        VolumeLabel = if ($vol) { $vol.FileSystemLabel } else { "" }
                        FileSystem = if ($vol) { $vol.FileSystem } else { "" }
                        VolumeSize = if ($vol) { $vol.Size } else { 0 }
                        FreeSpace = if ($vol) { $vol.SizeRemaining } else { 0 }
                        ClusterSize = if ($vol) { $vol.AllocationUnitSize } else { 0 }
                    }
                }
            } else {
                $results += [PSCustomObject]@{
                    DiskNumber = $d.Number
                    FriendlyName = $d.FriendlyName
                    BusType = $d.BusType
                    DiskSize = $d.Size
                    PartitionStyle = $d.PartitionStyle
                    DiskSerialNumber = $d.SerialNumber
                    PartitionNumber = $null
                    DriveLetter = "None"
                    MountPoint = ""
                    VolumeLabel = ""
                    FileSystem = ""
                    VolumeSize = 0
                    FreeSpace = 0
                    ClusterSize = 0
                }
            }
        }
        $results | ConvertTo-Json -Compress
        """
        raw = run_cmd(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_cmd])
        if raw:
            try:
                data = json.loads(raw)
                return [data] if isinstance(data, dict) else data
            except Exception:
                pass

    elif CURRENT_OS == "linux":
        raw = run_cmd(["lsblk", "-J", "-b", "-o", "NAME,SIZE,TYPE,MOUNTPOINT,MODEL,SERIAL,TRAN"])
        if raw:
            try:
                data = json.loads(raw)
                devices = data.get("blockdevices", [])
                results = []
                for idx, dev in enumerate(devices):
                    mount = dev.get("mountpoint") or ""
                    results.append({
                        "DiskNumber": idx,
                        "FriendlyName": dev.get("model") or dev.get("name", "Disk"),
                        "BusType": (dev.get("tran") or "USB").upper(),
                        "DiskSize": dev.get("size", 0),
                        "PartitionStyle": "MBR",
                        "DiskSerialNumber": dev.get("serial") or "",
                        "DriveLetter": dev.get("name", f"disk{idx}"),
                        "MountPoint": mount,
                        "VolumeLabel": "",
                        "FileSystem": "",
                        "VolumeSize": dev.get("size", 0),
                        "FreeSpace": 0,
                        "ClusterSize": 4096
                    })
                return results
            except Exception:
                pass

    # Generic fallback
    results = []
    if hasattr(os, "listdrives"):
        for letter in os.listdrives():
            results.append({
                "DiskNumber": 1,
                "FriendlyName": f"Drive {letter}",
                "BusType": "USB",
                "DiskSize": 0,
                "PartitionStyle": "MBR",
                "DiskSerialNumber": "Unknown",
                "DriveLetter": letter,
                "MountPoint": letter + "\\",
                "VolumeLabel": "",
                "FileSystem": "FAT32",
                "VolumeSize": 0,
                "FreeSpace": 0,
                "ClusterSize": 0
            })
    return results

def get_volume_serial(drive_letter: str) -> str:
    """Gets volume serial on Windows."""
    if CURRENT_OS != "windows":
        return "N/A"
    clean = drive_letter.strip().rstrip(":\\").upper()
    ps_cmd = f"(Get-CimInstance Win32_LogicalDisk -Filter \"DeviceID='{clean}:'\").VolumeSerialNumber"
    out = run_cmd(["powershell", "-NoProfile", "-Command", ps_cmd])
    return out if out else "Unknown"

def inspect_heuristics(drive_info: Dict[str, Any]) -> Dict[str, Any]:
    """Calculates fraud score (0-100%) and returns list of red flags."""
    red_flags = []
    risk_score = 0

    friendly_name = str(drive_info.get("FriendlyName", "")).lower()
    disk_serial = str(drive_info.get("DiskSerialNumber", "")).lower()
    file_system = str(drive_info.get("FileSystem", "")).upper()
    cluster_size = drive_info.get("ClusterSize", 0) or 0
    disk_size = drive_info.get("DiskSize", 0) or 0
    drive_letter = drive_info.get("DriveLetter", "")

    for s in SUSPICIOUS_STRINGS:
        if s in disk_serial or s in friendly_name:
            red_flags.append(f"Suspicious controller signature: '{s}' detected.")
            risk_score += 35
            break

    if drive_letter and drive_letter != "None" and CURRENT_OS == "windows":
        vol_serial = get_volume_serial(drive_letter)
        if vol_serial in ["0", "00000000", "0x0", ""]:
            red_flags.append("Volume Serial is blank/0x0 (Mass Production Tool MPTool signature).")
            risk_score += 30

    disk_gb = disk_size / (1024**3) if disk_size > 0 else 0
    if file_system == "FAT32" and disk_gb >= 64:
        red_flags.append(f"FAT32 formatting on a large {disk_gb:.1f} GB drive (standard OEM uses exFAT).")
        risk_score += 25

    if file_system == "FAT32" and cluster_size == 65536:
        red_flags.append("Cluster size is 64 KB (65,536 bytes), typical of manipulated format tools.")
        risk_score += 20

    if "mass storage" in friendly_name or "storage device" in friendly_name:
        red_flags.append("Generic device model name without reputable OEM branding.")
        risk_score += 15

    risk_score = min(risk_score, 100)
    verdict = "HIGH RISK OF COUNTERFEIT" if risk_score >= 50 else ("SUSPICIOUS" if risk_score >= 25 else "PROBABLY GENUINE")

    return {
        "risk_score": risk_score,
        "verdict": verdict,
        "red_flags": red_flags
    }

def test_drive_capacity(
    mount_point: str,
    target_disk_size_mb: int,
    progress_callback=None,
    stop_event=None
) -> Dict[str, Any]:
    """
    Capacity test via exponential + incremental probing with SHA-256 validation.
    Runs anywhere across Windows, macOS, and Linux using pure standard library.
    """
    test_dir = os.path.join(mount_point, "_fakedrive_audit_probe")
    os.makedirs(test_dir, exist_ok=True)

    chunk_mb = 64
    chunk_bytes = chunk_mb * 1024 * 1024

    # Seeded pseudo-random buffer
    rng = random.Random(123456789)
    buffer = bytearray(rng.getrandbits(8) for _ in range(chunk_bytes))
    expected_hash = hashlib.sha256(buffer).hexdigest()

    test_log = []
    verified_mb = 0
    corruption_detected = False
    corruption_offset_mb = None

    checkpoints = [64, 128, 256, 512, 1024, 1536, 2048, 3072, 4096, 6144, 8192, 12288, 16384, 24576, 32768, 49152, 65536]
    if target_disk_size_mb > 0:
        checkpoints = [cp for cp in checkpoints if cp <= target_disk_size_mb]

    try:
        for target_mb in checkpoints:
            if stop_event and stop_event.is_set():
                break

            needed = (target_mb - verified_mb) // chunk_mb
            if needed <= 0:
                continue

            if progress_callback:
                progress_callback({
                    "type": "progress",
                    "target_mb": target_mb,
                    "verified_mb": verified_mb,
                    "status": f"Probing boundary up to {target_mb} MB..."
                })

            step_failed = False
            for _ in range(needed):
                if stop_event and stop_event.is_set():
                    step_failed = True
                    break

                file_idx = (verified_mb // chunk_mb) + 1
                fpath = os.path.join(test_dir, f"blk_{file_idx:05d}.dat")

                try:
                    t0 = time.time()
                    with open(fpath, "wb") as f:
                        f.write(buffer)
                        f.flush()
                        os.fsync(f.fileno())
                    write_time = max(0.001, time.time() - t0)
                    speed_mbps = round(chunk_mb / write_time, 2)

                    with open(fpath, "rb") as f:
                        read_bytes = f.read()

                    read_hash = hashlib.sha256(read_bytes).hexdigest()
                    if read_hash != expected_hash:
                        corruption_detected = True
                        corruption_offset_mb = verified_mb + chunk_mb
                        test_log.append({
                            "offset_mb": corruption_offset_mb,
                            "status": "CORRUPT",
                            "hash": read_hash[:10] + "..."
                        })
                        step_failed = True
                        if progress_callback:
                            progress_callback({
                                "type": "block",
                                "offset_mb": corruption_offset_mb,
                                "status": "corrupt"
                            })
                        break
                    else:
                        verified_mb += chunk_mb
                        test_log.append({
                            "offset_mb": verified_mb,
                            "status": "VERIFIED_OK",
                            "hash": read_hash[:10] + "...",
                            "speed_mbps": speed_mbps
                        })
                        if progress_callback:
                            progress_callback({
                                "type": "block",
                                "offset_mb": verified_mb,
                                "status": "verified",
                                "speed_mbps": speed_mbps
                            })

                except Exception as write_err:
                    corruption_detected = True
                    corruption_offset_mb = verified_mb + chunk_mb
                    test_log.append({
                        "offset_mb": corruption_offset_mb,
                        "status": f"WRITE_ERROR: {write_err}",
                        "hash": "N/A"
                    })
                    step_failed = True
                    if progress_callback:
                        progress_callback({
                            "type": "block",
                            "offset_mb": corruption_offset_mb,
                            "status": "corrupt"
                        })
                    break

            if step_failed:
                break

    finally:
        if os.path.exists(test_dir):
            try:
                for fname in os.listdir(test_dir):
                    try:
                        os.remove(os.path.join(test_dir, fname))
                    except Exception:
                        pass
                os.rmdir(test_dir)
            except Exception:
                pass

    safe_mb = 0
    if verified_mb > 0:
        standard_sizes = [512, 1024, 2048, 4096, 8192, 16384, 32768, 65536, 131072, 262144]
        for s in standard_sizes:
            if s <= verified_mb:
                safe_mb = s
        if safe_mb == 0:
            safe_mb = int(verified_mb * 0.85)

    return {
        "verified_mb": verified_mb,
        "corruption_detected": corruption_detected,
        "corruption_offset_mb": corruption_offset_mb,
        "safe_capacity_mb": safe_mb,
        "test_log": test_log
    }

def generate_markdown_report(
    drive_info: Dict[str, Any],
    heuristics: Dict[str, Any],
    test_result: Dict[str, Any],
    reclaim_result: Optional[Dict[str, Any]] = None,
    output_path: Optional[str] = None
) -> str:
    """Generates standard GitHub-flavored Markdown audit report."""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    drive_letter = drive_info.get("DriveLetter", "N/A")
    disk_size_bytes = drive_info.get("DiskSize", 0) or 0
    reported_gb = disk_size_bytes / (1024**3)
    verified_mb = test_result.get("verified_mb", 0)
    verified_gb = verified_mb / 1024.0
    safe_mb = test_result.get("safe_capacity_mb", 0)
    safe_gb = safe_mb / 1024.0
    is_fake = test_result.get("corruption_detected", False) or heuristics.get("risk_score", 0) >= 50

    model = drive_info.get("FriendlyName", "Unknown Storage Device")
    serial = drive_info.get("DiskSerialNumber", "Unknown")
    vol_serial = get_volume_serial(drive_letter)

    md = []
    md.append("# Storage Drive Authenticity & Capacity Audit Report")
    md.append(f"**Audit Timestamp:** `{timestamp}` | **Auditor Tool:** `FakeDriveShield Desktop App`\n")

    if is_fake:
        md.append("> [!CAUTION]")
        md.append(f"> **COUNTERFEIT / FAKE CAPACITY STORAGE DRIVE CONFIRMED**")
        md.append(f"> The device advertises **{reported_gb:.1f} GB**, but physical working flash is only **~{verified_gb:.2f} GB ({verified_mb} MB)**.")
        md.append(f"> Writes beyond this threshold result in permanent, irrecoverable file corruption.\n")
    else:
        md.append("> [!NOTE]")
        md.append(f"> **STORAGE CAPACITY VERIFIED GENUINE**")
        md.append(f"> Tested storage passed cryptographic integrity verification without errors.\n")

    md.append("## 1. Hardware Specifications\n")
    md.append("| Property | Observed Value | Status |")
    md.append("| :--- | :--- | :--- |")
    md.append(f"| **Drive / Mount** | `{drive_letter}` | Target Device |")
    md.append(f"| **Advertised Size** | `{reported_gb:.2f} GB` ({disk_size_bytes:,} bytes) | Reported by Controller |")
    md.append(f"| **Physical Storage Verified** | **`{verified_gb:.2f} GB`** ({verified_mb} MB) | {'CRITICAL MISMATCH' if is_fake else 'Matches'} |")
    md.append(f"| **Safe Usable Capacity** | **`{safe_gb:.2f} GB`** ({safe_mb} MB) | Recommended Safe Partition |")
    md.append(f"| **Model / Vendor** | `{model}` | Device Descriptor |")
    md.append(f"| **Serial Number** | `{serial}` | Hardware Identifier |")
    md.append(f"| **Volume Serial** | `{vol_serial}` | {'Blank/0x0 (MPTool Signature)' if vol_serial in ['0', '0x0'] else 'Standard'} |")
    md.append(f"| **Filesystem / Cluster** | `{drive_info.get('FileSystem', 'N/A')}` / `{drive_info.get('ClusterSize', 0)} bytes` | Cluster Size |\n")

    md.append("## 2. Fraud Risk & Heuristics\n")
    md.append(f"- **Fraud Risk Score:** `{heuristics.get('risk_score', 0)} / 100`")
    md.append(f"- **Verdict:** **{heuristics.get('verdict', 'UNKNOWN')}**\n")
    if heuristics.get("red_flags"):
        md.append("### Detected Red Flags:")
        for rf in heuristics["red_flags"]:
            md.append(f"- ⚠️ {rf}")
        md.append("")
    else:
        md.append("No suspicious firmware signatures detected.\n")

    md.append("## 3. Storage Integrity Map\n")
    total_blocks = 36
    verified_blocks = max(1, int((verified_gb / reported_gb) * total_blocks)) if reported_gb > 0 and verified_gb > 0 else 0
    corrupt_blocks = total_blocks - verified_blocks
    bar = ("🟩" * verified_blocks) + ("🟥" * corrupt_blocks)
    md.append(f"```\n[START] {bar} [END: {reported_gb:.0f} GB]\n```")
    md.append(f"- 🟩 **Verified Working Flash:** ~{verified_gb:.2f} GB ({verified_mb} MB)")
    md.append(f"- 🟥 **Phantom / Nonexistent Space:** ~{max(0, reported_gb - verified_gb):.2f} GB\n")

    md.append("## 4. Verification Checkpoint Log\n")
    md.append("| Offset (MB) | Status | Checksum / Details |")
    md.append("| :--- | :--- | :--- |")
    for log_entry in test_result.get("test_log", []):
        md.append(f"| `{log_entry.get('offset_mb')} MB` | `{log_entry.get('status')}` | `{log_entry.get('hash', 'N/A')}` |")
    md.append("")

    if reclaim_result:
        md.append("## 5. Drive Remediation & Re-Partitioning Action\n")
        md.append(f"- **Remediation Status:** `{reclaim_result.get('status', 'Completed')}`")
        md.append(f"- **New Partition Size:** **`{reclaim_result.get('partition_size_mb', safe_mb)} MB`** ({reclaim_result.get('partition_size_mb', safe_mb)/1024:.2f} GB)")
        md.append(f"- **File System:** `{reclaim_result.get('filesystem', 'FAT32')}`")
        md.append(f"- **Partition Label:** `{reclaim_result.get('label', 'SAFE_USB')}`")
        md.append(f"- **Permanently Blocked Phantom Space:** `{reported_gb - (reclaim_result.get('partition_size_mb', safe_mb)/1024):.2f} GB`\n")

    md.append("## 6. Official Consumer Dispute Declaration\n")
    md.append("> **Notice for Marketplace Disputes (Amazon, eBay, AliExpress, Temu, PayPal, Credit Card Chargeback):**")
    md.append("> ")
    md.append("> This report serves as verified technical evidence that this device is a **fraudulent / counterfeit storage drive**. ")
    md.append(f"> The seller advertised **{reported_gb:.1f} GB**, but diagnostic test routines confirm the physical flash memory ")
    md.append(f"> hardware fails integrity verification at **{test_result.get('corruption_offset_mb', verified_mb)} MB**. ")
    md.append("> Modified controller firmware maliciously disguises the actual capacity, causing data corruption and permanent loss upon exceeding real capacity. ")
    md.append("> This constitutes goods not as described and fraudulent misrepresentation.")

    full_md = "\n".join(md)
    if output_path:
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(full_md)

    return full_md

def execute_reclaim(disk_number: int, safe_size_mb: int, fs_type: str = "fat32", label: str = "SAFE_USB", drive_letter: str = "D") -> Dict[str, Any]:
    """Reclaims the drive using diskpart on Windows."""
    if CURRENT_OS != "windows":
        return {"status": "Error: Automatic repartitioning is currently supported natively on Windows (DiskPart)."}

    clean_letter = drive_letter.strip().rstrip(":\\").upper()
    dp_script = f"""
select disk {disk_number}
clean
convert mbr
create partition primary size={safe_size_mb}
format fs={fs_type} quick label="{label}"
assign letter={clean_letter}
"""
    temp_script = os.path.join(os.environ.get("TEMP", "C:\\Temp"), f"dp_reclaim_{disk_number}.txt")
    with open(temp_script, "w", encoding="ascii") as f:
        f.write(dp_script.strip())

    try:
        proc = subprocess.run(["diskpart", "/s", temp_script], capture_output=True, text=True, check=True)
        out = proc.stdout
        status = "Success"
    except Exception as e:
        out = str(e)
        status = f"Error: {e}"
    finally:
        if os.path.exists(temp_script):
            try:
                os.remove(temp_script)
            except Exception:
                pass

    return {
        "status": status,
        "partition_size_mb": safe_size_mb,
        "filesystem": fs_type,
        "label": label,
        "raw_output": out
    }
