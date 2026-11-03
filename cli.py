#!/usr/bin/env python3
"""
CLI interface for Fake Drive Detector & Reclaimer
"""

import os
import sys
import argparse
import datetime
from engine import (
    list_drives,
    inspect_heuristics,
    test_drive_capacity,
    generate_markdown_report,
    execute_diskpart_reclaim,
    get_pnp_details
)

def print_banner():
    print("""
======================================================================
         🛡️  FAKE DRIVE DETECTOR & RECLAIMER SHIELD v1.0  🛡️
   Detect Fake Flash Drives | Verify Real Capacity | Auto-Fix & Report
======================================================================
""")

def list_all_drives():
    drives = list_drives()
    if not drives:
        print("No storage drives detected.")
        return []

    print("\nConnected Storage Devices:")
    print(f"{'#':<3} {'Drive':<7} {'Bus':<8} {'Type':<6} {'Reported Size':<15} {'Device Name':<28}")
    print("-" * 72)
    for idx, d in enumerate(drives):
        letter = d.get("DriveLetter") or "N/A"
        bus = d.get("BusType") or "Unknown"
        fs = d.get("FileSystem") or "RAW"
        size_bytes = d.get("DiskSize", 0) or 0
        size_gb = f"{size_bytes / (1024**3):.1f} GB"
        name = (d.get("FriendlyName") or "Unknown")[:27]
        is_usb = "USB" in bus.upper() or "REMOVABLE" in str(d.get("MediaType", "")).upper()
        marker = "👉" if is_usb else "  "
        print(f"{marker} {d.get('DiskNumber'):<2} {letter:<7} {bus:<8} {fs:<6} {size_gb:<15} {name:<28}")
    print("")
    return drives

def interactive_wizard():
    print_banner()
    drives = list_all_drives()
    if not drives:
        input("Press Enter to exit...")
        return

    usb_drives = [d for d in drives if "USB" in str(d.get("BusType", "")).upper() and d.get("DriveLetter")]
    if not usb_drives:
        print("⚠️ No USB drives with assigned drive letters found.")
        target_letter = input("Enter drive letter manually (e.g. D): ").strip().upper().rstrip(":")
    else:
        default_target = usb_drives[0].get("DriveLetter")
        target_letter = input(f"Enter target drive letter to inspect/test [Default: {default_target}]: ").strip().upper().rstrip(":")
        if not target_letter:
            target_letter = default_target

    target_drive = next((d for d in drives if d.get("DriveLetter") == target_letter), None)
    if not target_drive:
        print(f"Drive {target_letter}: not found.")
        input("Press Enter to exit...")
        return

    disk_num = target_drive.get("DiskNumber", 1)
    disk_size_mb = int((target_drive.get("DiskSize", 0) or 0) / (1024**2))

    print(f"\n[+] Inspecting Drive {target_letter}: (Disk {disk_num})...")
    heuristics = inspect_heuristics(target_drive)
    print(f"Risk Score: {heuristics['risk_score']} / 100 ({heuristics['verdict']})")
    for rf in heuristics.get("red_flags", []):
        print(f"  ⚠️  {rf}")

    ans = input("\nProceed with SHA-256 capacity integrity testing? (Y/n): ").strip().lower()
    if ans in ['n', 'no']:
        print("Aborted.")
        return

    print("\nSelect Verification Strategy:")
    print("  [1] ⚡ Fast Smart Audit (~30s, Canary Wrap-Around + Boundary Sampling) [Recommended]")
    print("  [2] 🔍 Full Surface Scan (Thorough sequential verification)")
    mode_sel = input("Choose mode (1/2) [Default: 1]: ").strip()
    test_mode = "full" if mode_sel == "2" else "fast"

    print(f"\n[+] Starting {'⚡ Fast Smart Audit' if test_mode == 'fast' else '🔍 Full Surface Scan'}...")
    def on_prog(evt):
        if isinstance(evt, dict):
            if evt.get("type") == "progress":
                print(f"  -> {evt.get('status')}")
            elif evt.get("type") == "block":
                status = evt.get("status")
                offset = evt.get("offset_mb")
                spd = evt.get("speed_mbps", 0)
                if status == "verified":
                    print(f"  [✓] Verified OK up to {offset} MB ({spd} MB/s)")
                else:
                    print(f"  [✗] CORRUPTION DETECTED at {offset} MB!")
        else:
            print(f"  -> {evt}")

    test_res = test_drive_capacity(target_letter, disk_size_mb, progress_callback=on_prog, test_mode=test_mode)
    print("\n--- Test Results ---")
    print(f"Verified Physical Capacity: {test_res['verified_mb']} MB ({test_res['verified_mb']/1024:.2f} GB)")
    if test_res["corruption_detected"]:
        print(f"⚠️ CORRUPTION DETECTED at offset {test_res['corruption_offset_mb']} MB!")
        print(f"Recommended Safe Partition Size: {test_res['safe_capacity_mb']} MB ({test_res['safe_capacity_mb']/1024:.2f} GB)")
    else:
        print("✅ No corruption detected across tested range.")

    # Reclaim option
    reclaim_res = None
    if test_res["corruption_detected"] and test_res["safe_capacity_mb"] > 0:
        ans_fix = input(f"\nDo you want to safely re-partition Drive {target_letter}: to {test_res['safe_capacity_mb']} MB? (Y/n): ").strip().lower()
        if ans_fix in ['y', 'yes', '']:
            # Choose filesystem: if safe_mb >= 4096, exfat; otherwise fat32
            fs = "exfat" if test_res["safe_capacity_mb"] >= 4096 else "fat32"
            label = f"SAFE_{test_res['safe_capacity_mb']//1024}GB" if test_res['safe_capacity_mb'] >= 1024 else f"SAFE_{test_res['safe_capacity_mb']}MB"
            print(f"Re-partitioning Disk {disk_num} to {test_res['safe_capacity_mb']} MB ({fs.upper()})...")
            reclaim_res = execute_diskpart_reclaim(disk_num, test_res['safe_capacity_mb'], fs_type=fs, label=label, drive_letter=target_letter)
            print(f"Remediation: {reclaim_res['status']}")

    # Generate Markdown Report
    desktop_dir = os.path.join(os.environ.get("USERPROFILE", ""), "OneDrive", "Desktop")
    if not os.path.exists(desktop_dir):
        desktop_dir = os.path.join(os.environ.get("USERPROFILE", ""), "Desktop")
    
    reports_dir = os.path.join(desktop_dir, "FakeDriveReports")
    os.makedirs(reports_dir, exist_ok=True)
    report_fname = f"Audit_Report_Drive_{target_letter}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
    report_path = os.path.join(reports_dir, report_fname)

    generate_markdown_report(target_drive, heuristics, test_res, reclaim_res, output_path=report_path)
    print(f"\n📄 Markdown Audit Report generated at:\n   {report_path}")

    input("\nCompleted! Press Enter to exit...")

def main():
    parser = argparse.ArgumentParser(description="Fake Storage Drive Detector & Reclaimer")
    parser.add_argument("--list", action="store_true", help="List all connected drives")
    parser.add_argument("--inspect", type=str, metavar="LETTER", help="Inspect heuristics of drive (e.g. D)")
    parser.add_argument("--test", type=str, metavar="LETTER", help="Test capacity and generate Markdown report")
    parser.add_argument("--mode", type=str, choices=["fast", "full"], default="fast", help="Verification strategy: fast (~30s, default) or full")
    parser.add_argument("--fix", type=str, metavar="LETTER", help="Safely repartition drive to verified size")
    parser.add_argument("--report-dir", type=str, default=None, help="Directory to save Markdown reports")

    args = parser.parse_args()

    if len(sys.argv) == 1:
        interactive_wizard()
        return

    if args.list:
        list_all_drives()
        return

    if args.inspect:
        drives = list_drives()
        target = next((d for d in drives if d.get("DriveLetter") == args.inspect.upper().rstrip(":")), None)
        if not target:
            print(f"Drive {args.inspect} not found.")
            return
        res = inspect_heuristics(target)
        print(f"Drive {args.inspect}: Risk Score: {res['risk_score']}/100 ({res['verdict']})")
        for rf in res["red_flags"]:
            print(f"  - {rf}")
        return

    if args.test:
        letter = args.test.upper().rstrip(":")
        drives = list_drives()
        target = next((d for d in drives if d.get("DriveLetter") == letter), None)
        if not target:
            print(f"Drive {letter}: not found.")
            return
        size_mb = int((target.get("DiskSize", 0) or 0) / (1024**2))
        heuristics = inspect_heuristics(target)
        print(f"Testing Drive {letter}: ({size_mb} MB advertised, mode: {args.mode})...")
        def on_cli_prog(evt):
            if isinstance(evt, dict):
                st = evt.get("status", "")
                if evt.get("type") == "block":
                    off = evt.get("offset_mb", 0)
                    spd = evt.get("speed_mbps", 0)
                    print(f"  [{evt.get('status').upper()}] Offset: {off} MB ({spd} MB/s)")
                elif evt.get("type") == "progress":
                    print(f"  -> {st}")
            else:
                print(f"  -> {evt}")
        test_res = test_drive_capacity(letter, size_mb, progress_callback=on_cli_prog, test_mode=args.mode)

        out_dir = args.report_dir or os.getcwd()
        fname = f"Audit_Report_Drive_{letter}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        out_path = os.path.join(out_dir, fname)
        generate_markdown_report(target, heuristics, test_res, output_path=out_path)
        print(f"\nReport written to: {out_path}")
        return

if __name__ == "__main__":
    main()
