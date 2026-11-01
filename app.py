#!/usr/bin/env python3
"""
FakeDriveShield Desktop Application (GUI)
Runs anywhere on Windows, macOS, and Linux with pure Python standard library (Tkinter).
Visualizes storage cells, tests real hardware capacity, auto-fixes drives, and outputs .md reports.
"""

import os
import sys

# Ensure stdout/stderr are valid streams when packaged with --noconsole
if sys.stdout is None:
    sys.stdout = open(os.devnull, "w")
if sys.stderr is None:
    sys.stderr = open(os.devnull, "w")

import time
import threading
import datetime
import platform
import subprocess
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

# Try DPI awareness on Windows
if platform.system().lower() == "windows":
    try:
        import ctypes
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass

import engine

# Color Palette (Modern Dark / Slate)
BG_MAIN = "#0F172A"       # Slate 900
BG_CARD = "#1E293B"       # Slate 800
BG_CARD_LIGHT = "#334155" # Slate 700
TEXT_MAIN = "#F8FAFC"     # Slate 50
TEXT_MUTED = "#94A3B8"    # Slate 400
ACCENT_BLUE = "#3B82F6"   # Blue 500
ACCENT_GREEN = "#10B981"  # Emerald 500
ACCENT_RED = "#EF4444"    # Red 500
ACCENT_YELLOW = "#F59E0B" # Amber 500
BLOCK_UNTESTED = "#334155"# Slate 700
BLOCK_VERIFIED = "#10B981"# Emerald 500
BLOCK_CORRUPT = "#EF4444" # Red 500
BLOCK_TESTING = "#F59E0B" # Amber 500

class FakeDriveShieldApp(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("FakeDriveShield - Storage Authenticity & Reclaimer")
        self.geometry("860x720")
        self.minsize(780, 650)
        self.configure(bg=BG_MAIN)

        self.drives = []
        self.selected_drive = None
        self.test_thread = None
        self.stop_event = threading.Event()
        self.last_test_result = None
        self.last_heuristics = None
        self.last_report_path = None

        self._setup_styles()
        self._build_ui()
        self.refresh_drives()

    def _setup_styles(self):
        self.style = ttk.Style(self)
        self.style.theme_use("clam")

        # Combobox style
        self.style.configure(
            "TCombobox",
            fieldbackground=BG_CARD,
            background=BG_CARD_LIGHT,
            foreground=TEXT_MAIN,
            arrowcolor=TEXT_MAIN,
            bordercolor=BG_CARD_LIGHT
        )

        # Progress bar
        self.style.configure(
            "Custom.Horizontal.TProgressbar",
            troughcolor=BG_CARD,
            background=ACCENT_BLUE,
            thickness=14
        )

    def _build_ui(self):
        # Header Frame
        header = tk.Frame(self, bg=BG_MAIN, pady=12, padx=20)
        header.pack(fill=tk.X)

        title_lbl = tk.Label(
            header,
            text="🛡️ FakeDriveShield",
            font=("Segoe UI", 18, "bold"),
            bg=BG_MAIN,
            fg=TEXT_MAIN
        )
        title_lbl.pack(side=tk.LEFT)

        subtitle_lbl = tk.Label(
            header,
            text="Universal Storage Authenticity & Capacity Reclaimer",
            font=("Segoe UI", 10),
            bg=BG_MAIN,
            fg=TEXT_MUTED
        )
        subtitle_lbl.pack(side=tk.LEFT, padx=12, pady=(4, 0))

        # Main Scrollable / Stacked Container
        container = tk.Frame(self, bg=BG_MAIN, padx=20, pady=5)
        container.pack(fill=tk.BOTH, expand=True)

        # 1. Drive Selection Panel
        select_card = tk.Frame(container, bg=BG_CARD, padx=15, pady=12, relief=tk.FLAT)
        select_card.pack(fill=tk.X, pady=(0, 10))

        lbl_select = tk.Label(
            select_card,
            text="TARGET DRIVE SELECTION:",
            font=("Segoe UI", 9, "bold"),
            bg=BG_CARD,
            fg=TEXT_MUTED
        )
        lbl_select.pack(anchor=tk.W)

        row_sel = tk.Frame(select_card, bg=BG_CARD, pady=6)
        row_sel.pack(fill=tk.X)

        self.drive_var = tk.StringVar()
        self.drive_combo = ttk.Combobox(
            row_sel,
            textvariable=self.drive_var,
            state="readonly",
            font=("Segoe UI", 10),
            style="TCombobox"
        )
        self.drive_combo.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        self.drive_combo.bind("<<ComboboxSelected>>", self._on_drive_selected)

        btn_refresh = tk.Button(
            row_sel,
            text="🔄 Refresh",
            font=("Segoe UI", 9, "bold"),
            bg=BG_CARD_LIGHT,
            fg=TEXT_MAIN,
            activebackground=ACCENT_BLUE,
            activeforeground=TEXT_MAIN,
            relief=tk.FLAT,
            padx=12,
            pady=4,
            cursor="hand2",
            command=self.refresh_drives
        )
        btn_refresh.pack(side=tk.RIGHT)

        # 2. Drive Metadata & Heuristic Audit Card
        self.meta_card = tk.Frame(container, bg=BG_CARD, padx=15, pady=10)
        self.meta_card.pack(fill=tk.X, pady=(0, 10))

        meta_header = tk.Frame(self.meta_card, bg=BG_CARD)
        meta_header.pack(fill=tk.X)

        self.lbl_device_title = tk.Label(
            meta_header,
            text="No USB drive selected",
            font=("Segoe UI", 11, "bold"),
            bg=BG_CARD,
            fg=TEXT_MAIN
        )
        self.lbl_device_title.pack(side=tk.LEFT)

        self.lbl_risk_badge = tk.Label(
            meta_header,
            text="",
            font=("Segoe UI", 9, "bold"),
            bg=BG_CARD,
            fg=TEXT_MUTED,
            padx=8,
            pady=2
        )
        self.lbl_risk_badge.pack(side=tk.RIGHT)

        self.lbl_meta_details = tk.Label(
            self.meta_card,
            text="Select a drive above to inspect hardware attributes.",
            font=("Segoe UI", 9),
            bg=BG_CARD,
            fg=TEXT_MUTED,
            justify=tk.LEFT
        )
        self.lbl_meta_details.pack(anchor=tk.W, pady=(4, 0))

        # 3. Visual Storage Map (Canvas Grid like ValiDrive)
        map_card = tk.Frame(container, bg=BG_CARD, padx=15, pady=10)
        map_card.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        map_top = tk.Frame(map_card, bg=BG_CARD)
        map_top.pack(fill=tk.X)

        lbl_map_title = tk.Label(
            map_top,
            text="STORAGE INTEGRITY MAP",
            font=("Segoe UI", 9, "bold"),
            bg=BG_CARD,
            fg=TEXT_MUTED
        )
        lbl_map_title.pack(side=tk.LEFT)

        self.lbl_map_stats = tk.Label(
            map_top,
            text="Untested",
            font=("Segoe UI", 9),
            bg=BG_CARD,
            fg=TEXT_MUTED
        )
        self.lbl_map_stats.pack(side=tk.RIGHT)

        # Canvas for blocks
        self.canvas_cols = 32
        self.canvas_rows = 12
        self.total_blocks = self.canvas_cols * self.canvas_rows
        self.block_items = []

        self.canvas = tk.Canvas(
            map_card,
            bg="#0B0F19",
            highlightthickness=1,
            highlightbackground=BG_CARD_LIGHT
        )
        self.canvas.pack(fill=tk.BOTH, expand=True, pady=8)
        self.canvas.bind("<Configure>", lambda e: self._draw_grid())

        # Legend
        legend_frame = tk.Frame(map_card, bg=BG_CARD)
        legend_frame.pack(fill=tk.X, pady=(2, 0))

        self._add_legend_item(legend_frame, BLOCK_VERIFIED, "Verified Physical Storage")
        self._add_legend_item(legend_frame, BLOCK_CORRUPT, "Missing / Fake Storage")
        self._add_legend_item(legend_frame, BLOCK_TESTING, "Currently Testing")
        self._add_legend_item(legend_frame, BLOCK_UNTESTED, "Untested")

        # 4. Progress & Status
        prog_frame = tk.Frame(container, bg=BG_CARD, padx=15, pady=8)
        prog_frame.pack(fill=tk.X, pady=(0, 10))

        self.prog_bar = ttk.Progressbar(
            prog_frame,
            orient="horizontal",
            mode="determinate",
            style="Custom.Horizontal.TProgressbar"
        )
        self.prog_bar.pack(fill=tk.X)

        self.lbl_status = tk.Label(
            prog_frame,
            text="Ready. Select a drive and click 'Start Audit & Test'.",
            font=("Segoe UI", 9),
            bg=BG_CARD,
            fg=TEXT_MAIN,
            anchor=tk.W
        )
        self.lbl_status.pack(fill=tk.X, pady=(4, 0))

        # 5. Bottom Action Controls
        ctrl_frame = tk.Frame(self, bg=BG_MAIN, padx=20, pady=10)
        ctrl_frame.pack(fill=tk.X)

        self.btn_start = tk.Button(
            ctrl_frame,
            text="▶️ Start Audit & Test",
            font=("Segoe UI", 10, "bold"),
            bg=ACCENT_BLUE,
            fg="#FFFFFF",
            activebackground="#2563EB",
            relief=tk.FLAT,
            padx=16,
            pady=6,
            cursor="hand2",
            command=self.start_test
        )
        self.btn_start.pack(side=tk.LEFT, padx=(0, 10))

        self.btn_stop = tk.Button(
            ctrl_frame,
            text="⏹️ Stop",
            font=("Segoe UI", 10),
            bg=BG_CARD_LIGHT,
            fg=TEXT_MAIN,
            relief=tk.FLAT,
            padx=14,
            pady=6,
            state=tk.DISABLED,
            command=self.stop_test
        )
        self.btn_stop.pack(side=tk.LEFT, padx=(0, 10))

        self.btn_fix = tk.Button(
            ctrl_frame,
            text="🛠️ Reclaim Safe Storage",
            font=("Segoe UI", 10, "bold"),
            bg=ACCENT_GREEN,
            fg="#FFFFFF",
            relief=tk.FLAT,
            padx=16,
            pady=6,
            state=tk.DISABLED,
            command=self.reclaim_drive
        )
        self.btn_fix.pack(side=tk.LEFT, padx=(0, 10))

        self.btn_report = tk.Button(
            ctrl_frame,
            text="📄 View Markdown Report",
            font=("Segoe UI", 10),
            bg=BG_CARD_LIGHT,
            fg=TEXT_MAIN,
            relief=tk.FLAT,
            padx=14,
            pady=6,
            state=tk.DISABLED,
            command=self.view_report
        )
        self.btn_report.pack(side=tk.RIGHT)

    def _add_legend_item(self, parent, color, text):
        f = tk.Frame(parent, bg=BG_CARD)
        f.pack(side=tk.LEFT, padx=(0, 15))
        c = tk.Canvas(f, width=12, height=12, bg=color, highlightthickness=0)
        c.pack(side=tk.LEFT, padx=(0, 5))
        l = tk.Label(f, text=text, font=("Segoe UI", 8), bg=BG_CARD, fg=TEXT_MUTED)
        l.pack(side=tk.LEFT)

    def _draw_grid(self):
        self.canvas.delete("all")
        self.block_items = []

        w = self.canvas.winfo_width()
        h = self.canvas.winfo_height()
        if w < 10 or h < 10:
            return

        pad = 2
        block_w = (w - (self.canvas_cols + 1) * pad) / self.canvas_cols
        block_h = (h - (self.canvas_rows + 1) * pad) / self.canvas_rows

        for r in range(self.canvas_rows):
            row_items = []
            for c in range(self.canvas_cols):
                x1 = pad + c * (block_w + pad)
                y1 = pad + r * (block_h + pad)
                x2 = x1 + block_w
                y2 = y1 + block_h

                item = self.canvas.create_rectangle(
                    x1, y1, x2, y2,
                    fill=BLOCK_UNTESTED,
                    outline=""
                )
                row_items.append(item)
            self.block_items.append(row_items)

    def _set_block_color(self, idx, color):
        if idx < 0 or idx >= self.total_blocks:
            return
        r = idx // self.canvas_cols
        c = idx % self.canvas_cols
        if r < len(self.block_items) and c < len(self.block_items[r]):
            self.canvas.itemconfig(self.block_items[r][c], fill=color)

    def refresh_drives(self):
        self.drives = engine.list_drives()
        options = []
        for d in self.drives:
            letter = d.get("DriveLetter", "N/A")
            size_gb = (d.get("DiskSize", 0) or 0) / (1024**3)
            name = d.get("FriendlyName", "Storage Device")
            bus = d.get("BusType", "USB")
            options.append(f"{letter} - {name} ({size_gb:.1f} GB, {bus})")

        self.drive_combo["values"] = options
        if options:
            self.drive_combo.current(0)
            self._on_drive_selected()
        else:
            self.drive_var.set("No drives detected")
            self.lbl_device_title.config(text="No removable drives found")
            self.lbl_meta_details.config(text="Please plug in a USB flash drive and click Refresh.")

    def _on_drive_selected(self, event=None):
        idx = self.drive_combo.current()
        if idx < 0 or idx >= len(self.drives):
            return

        self.selected_drive = self.drives[idx]
        d = self.selected_drive

        size_gb = (d.get("DiskSize", 0) or 0) / (1024**3)
        name = d.get("FriendlyName", "Storage Device")
        letter = d.get("DriveLetter", "N/A")
        fs = d.get("FileSystem", "N/A")
        cluster = d.get("ClusterSize", 0)

        heuristics = engine.inspect_heuristics(d)
        self.last_heuristics = heuristics

        self.lbl_device_title.config(text=f"{name} ({letter}) - {size_gb:.1f} GB")

        score = heuristics["risk_score"]
        if score >= 50:
            badge_color = ACCENT_RED
            badge_text = f"🚨 {heuristics['verdict']} ({score}%)"
        elif score >= 25:
            badge_color = ACCENT_YELLOW
            badge_text = f"⚠️ {heuristics['verdict']} ({score}%)"
        else:
            badge_color = ACCENT_GREEN
            badge_text = f"✅ {heuristics['verdict']} ({score}%)"

        self.lbl_risk_badge.config(text=badge_text, fg=badge_color)

        red_flags_str = "; ".join(heuristics.get("red_flags", [])) if heuristics.get("red_flags") else "None"
        detail_text = (
            f"Filesystem: {fs} | Cluster: {cluster} bytes | Bus: {d.get('BusType', 'USB')}\n"
            f"Serial: {d.get('DiskSerialNumber', 'Unknown')} | Heuristic Red Flags: {red_flags_str}"
        )
        self.lbl_meta_details.config(text=detail_text)
        self._reset_map()

    def _reset_map(self):
        for r in range(len(self.block_items)):
            for c in range(len(self.block_items[r])):
                self.canvas.itemconfig(self.block_items[r][c], fill=BLOCK_UNTESTED)
        self.lbl_map_stats.config(text="Untested")
        self.prog_bar["value"] = 0
        self.btn_fix.config(state=tk.DISABLED)
        self.btn_report.config(state=tk.DISABLED)

    def start_test(self):
        if not self.selected_drive:
            messagebox.showwarning("No Target", "Please select a target drive first.")
            return

        mount = self.selected_drive.get("MountPoint") or (self.selected_drive.get("DriveLetter") + "\\")
        if not mount or not os.path.exists(mount):
            messagebox.showerror("Error", f"Mount point '{mount}' is not accessible.")
            return

        disk_size_mb = int((self.selected_drive.get("DiskSize", 0) or 0) / (1024**2))

        self.stop_event.clear()
        self.btn_start.config(state=tk.DISABLED)
        self.btn_stop.config(state=tk.NORMAL)
        self.btn_fix.config(state=tk.DISABLED)
        self.btn_report.config(state=tk.DISABLED)
        self._reset_map()

        self.test_thread = threading.Thread(
            target=self._run_capacity_test_thread,
            args=(mount, disk_size_mb),
            daemon=True
        )
        self.test_thread.start()

    def stop_test(self):
        self.stop_event.set()
        self.lbl_status.config(text="Stopping test...")

    def _run_capacity_test_thread(self, mount, disk_size_mb):
        def on_progress(event):
            self.after(0, self._handle_test_event, event, disk_size_mb)

        res = engine.test_drive_capacity(
            mount,
            disk_size_mb,
            progress_callback=on_progress,
            stop_event=self.stop_event
        )

        self.last_test_result = res
        self.after(0, self._finish_test, res, disk_size_mb)

    def _handle_test_event(self, event, disk_size_mb):
        etype = event.get("type")
        if etype == "progress":
            self.lbl_status.config(text=event.get("status", "Testing..."))
            target_mb = event.get("target_mb", 0)
            if disk_size_mb > 0:
                pct = min(100, int((target_mb / disk_size_mb) * 100))
                self.prog_bar["value"] = pct

        elif etype == "block":
            offset_mb = event.get("offset_mb", 0)
            status = event.get("status")
            speed = event.get("speed_mbps", 0)

            block_idx = int((offset_mb / disk_size_mb) * self.total_blocks) if disk_size_mb > 0 else 0
            block_idx = min(self.total_blocks - 1, block_idx)

            if status == "verified":
                for i in range(block_idx + 1):
                    self._set_block_color(i, BLOCK_VERIFIED)
                self.lbl_status.config(text=f"Verified {offset_mb} MB OK (Write Speed: {speed} MB/s)")
            elif status == "corrupt":
                for i in range(block_idx, self.total_blocks):
                    self._set_block_color(i, BLOCK_CORRUPT)
                self.lbl_status.config(text=f"⚠️ HARD CORRUPTION DETECTED at {offset_mb} MB!")

    def _finish_test(self, res, disk_size_mb):
        self.btn_start.config(state=tk.NORMAL)
        self.btn_stop.config(state=tk.DISABLED)

        verified_mb = res.get("verified_mb", 0)
        is_corrupt = res.get("corruption_detected", False)
        corrupt_mb = res.get("corruption_offset_mb")
        safe_mb = res.get("safe_capacity_mb", 0)

        # Update block map visually to final state
        verified_blocks = max(1, int((verified_mb / disk_size_mb) * self.total_blocks)) if disk_size_mb > 0 and verified_mb > 0 else 0
        for i in range(self.total_blocks):
            if i < verified_blocks:
                self._set_block_color(i, BLOCK_VERIFIED)
            else:
                self._set_block_color(i, BLOCK_CORRUPT if is_corrupt else BLOCK_UNTESTED)

        if is_corrupt:
            self.lbl_map_stats.config(
                text=f"Physical: {verified_mb/1024:.2f} GB | Phantom: {(disk_size_mb - verified_mb)/1024:.2f} GB",
                fg=ACCENT_RED
            )
            self.lbl_status.config(
                text=f"COUNTERFEIT DETECTED! Corruption at {corrupt_mb} MB. Recommended safe capacity: {safe_mb} MB.",
                fg=ACCENT_RED
            )
            self.btn_fix.config(state=tk.NORMAL)
        else:
            self.lbl_map_stats.config(
                text=f"100% Genuine Verified ({verified_mb/1024:.1f} GB)",
                fg=ACCENT_GREEN
            )
            self.lbl_status.config(
                text=f"SUCCESS: Physical storage verified without corruption up to {verified_mb} MB.",
                fg=ACCENT_GREEN
            )

        # Auto-generate Markdown Report
        desktop = os.path.join(os.environ.get("USERPROFILE", ""), "OneDrive", "Desktop")
        if not os.path.exists(desktop):
            desktop = os.path.join(os.environ.get("USERPROFILE", ""), "Desktop")
        rep_dir = os.path.join(desktop, "FakeDriveReports")

        letter = self.selected_drive.get("DriveLetter", "USB").rstrip(":")
        fpath = os.path.join(rep_dir, f"Audit_Report_Drive_{letter}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.md")
        engine.generate_markdown_report(self.selected_drive, self.last_heuristics, res, output_path=fpath)
        self.last_report_path = fpath
        self.btn_report.config(state=tk.NORMAL)

    def reclaim_drive(self):
        if not self.last_test_result or not self.selected_drive:
            return

        safe_mb = self.last_test_result.get("safe_capacity_mb", 1024)
        disk_num = self.selected_drive.get("DiskNumber", 1)
        letter = self.selected_drive.get("DriveLetter", "D").rstrip(":")

        msg = (
            f"Are you sure you want to re-partition Drive {letter}: (Disk {disk_num})?\n\n"
            f"• Verified Safe Size: {safe_mb} MB ({safe_mb/1024:.2f} GB)\n"
            f"• All phantom fake sectors will be permanently locked out.\n\n"
            "This will format the safe partition. Proceed?"
        )
        if not messagebox.askyesno("Confirm Reclaim", msg):
            return

        fs = "exfat" if safe_mb >= 4096 else "fat32"
        label = f"SAFE_{safe_mb//1024}GB" if safe_mb >= 1024 else f"SAFE_{safe_mb}MB"

        self.lbl_status.config(text=f"Re-partitioning Disk {disk_num} to {safe_mb} MB...")
        reclaim_res = engine.execute_reclaim(disk_num, safe_mb, fs_type=fs, label=label, drive_letter=letter)

        if reclaim_res.get("status") == "Success":
            messagebox.showinfo("Success", f"Drive {letter}: successfully repartitioned to {safe_mb} MB ({fs.upper()})!\nAll fake space is locked out.")
            self.refresh_drives()
        else:
            messagebox.showerror("Error", f"Repartitioning failed: {reclaim_res.get('status')}")

    def view_report(self):
        if self.last_report_path and os.path.exists(self.last_report_path):
            if platform.system().lower() == "windows":
                os.startfile(self.last_report_path)
            elif platform.system().lower() == "darwin":
                subprocess.run(["open", self.last_report_path])
            else:
                subprocess.run(["xdg-open", self.last_report_path])
        else:
            messagebox.showinfo("Report", "No report file generated yet.")

if __name__ == "__main__":
    app = FakeDriveShieldApp()
    app.mainloop()
