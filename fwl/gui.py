"""Graphical interface: ``filewarden_gui.py`` (tkinter, zero mandatory deps).

Drag & drop is available when the optional ``tkinterdnd2`` package is
installed; without it the file/folder buttons cover the same workflow.
"""

from __future__ import annotations

import os
import queue
import sys
import threading
import time
import tkinter as tk
import webbrowser
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from . import __version__, config
from .client import VirusTotalClient
from .errors import ApiKeyError, CancelledError, FileWardenError
from .report import (
    format_detections,
    format_duration,
    format_size,
    summarize,
    write_csv_report,
    write_json_report,
)
from .scanner import Decision, ScanResult, Scanner, Status, UploadPolicy

try:  # optional dependency, purely for drag & drop
    from tkinterdnd2 import DND_FILES, TkinterDnD

    HAS_DND = True
except Exception:  # pragma: no cover - depends on the installation
    DND_FILES = None  # type: ignore[assignment]
    TkinterDnD = None  # type: ignore[assignment]
    HAS_DND = False

#: Set by ``main()`` once a DnD-enabled Tk root was really created; the layout
#: hint relies on this instead of the mere import so it never lies.
DND_ACTIVE = False

ROW_TAGS = {
    Status.MALICIOUS: ("malicious", "#f8d7da", "#842029"),
    Status.SUSPICIOUS: ("suspicious", "#fff3cd", "#664d03"),
    Status.CLEAN: ("clean", "#d1e7dd", "#0f5132"),
    Status.UNKNOWN: ("unknown", "#cff4fc", "#055160"),
    Status.TOO_BIG: ("too_big", "#e2e3e5", "#41464b"),
    Status.ERROR: ("error", "#e2d9f3", "#59359a"),
}

STATUS_MARKS = {
    Status.MALICIOUS: "✖ MALICIOUS",
    Status.SUSPICIOUS: "⚠ suspicious",
    Status.CLEAN: "✔ clean",
    Status.UNKNOWN: "? not in VT",
    Status.TOO_BIG: "· oversized",
    Status.ERROR: "✖ error",
}

POLICY_LABELS = {
    "Ask before uploading (recommended)": UploadPolicy.ASK,
    "Never upload (hash lookup only)": UploadPolicy.NEVER,
    "Upload without asking": UploadPolicy.ALWAYS,
}


class SettingsDialog(tk.Toplevel):
    """API key plus API-related knobs, stored in the config file."""

    def __init__(self, parent: "FileWardenApp"):
        super().__init__(parent.root)
        self.parent = parent
        self.title("Settings")
        self.transient(parent.root)
        self.resizable(False, False)
        cfg = config.load_config()

        body = ttk.Frame(self, padding=12)
        body.grid(row=0, column=0, sticky="nsew")

        ttk.Label(body, text="VirusTotal API key:").grid(row=0, column=0, sticky="w")
        self.key_var = tk.StringVar(value=str(cfg.get("api_key") or ""))
        key_entry = ttk.Entry(body, textvariable=self.key_var, width=52, show="•")
        key_entry.grid(row=1, column=0, columnspan=2, sticky="we", pady=(2, 6))

        ttk.Label(
            body,
            text="The key is stored in " + str(config.config_path()) + " with owner-only permissions.",
            foreground="#666666",
        ).grid(row=2, column=0, columnspan=2, sticky="w", pady=(0, 8))

        ttk.Label(body, text="Request rate limit, requests/min:").grid(row=3, column=0, sticky="w")
        self.rpm_var = tk.StringVar(value=str(cfg.get("rpm") or 4))
        ttk.Spinbox(body, from_=1, to=10000, textvariable=self.rpm_var, width=8).grid(
            row=3, column=1, sticky="e"
        )

        ttk.Label(body, text="Maximum upload size, MB:").grid(
            row=4, column=0, sticky="w", pady=(4, 0)
        )
        self.max_upload_var = tk.StringVar(value=str(cfg.get("max_upload_mb") or 32))
        ttk.Spinbox(body, from_=1, to=650, textvariable=self.max_upload_var, width=8).grid(
            row=4, column=1, sticky="e", pady=(4, 0)
        )

        ttk.Label(body, text="Upload policy:").grid(row=5, column=0, sticky="w", pady=(4, 0))
        current = str(cfg.get("upload_policy") or "ask")
        label = next(
            (text for text, policy in POLICY_LABELS.items() if policy.value == current),
            list(POLICY_LABELS)[0],
        )
        self.policy_var = tk.StringVar(value=label)
        ttk.Combobox(
            body, textvariable=self.policy_var, state="readonly", width=44,
            values=list(POLICY_LABELS),
        ).grid(row=6, column=0, columnspan=2, sticky="we", pady=(2, 0))

        self.status_var = tk.StringVar(value="")
        ttk.Label(body, textvariable=self.status_var, foreground="#0f5132").grid(
            row=7, column=0, columnspan=2, sticky="w", pady=(8, 0)
        )

        buttons = ttk.Frame(body)
        buttons.grid(row=8, column=0, columnspan=2, sticky="e", pady=(12, 0))
        ttk.Button(buttons, text="Check key", command=self._check_key).pack(
            side="left", padx=(0, 6)
        )
        ttk.Button(buttons, text="Save", command=self._save).pack(side="left", padx=(0, 6))
        ttk.Button(buttons, text="Close", command=self.destroy).pack(side="left")

        key_entry.focus_set()
        self.grab_set()
        parent.root.wait_window(self)

    def _check_key(self) -> None:
        key = self.key_var.get().strip()
        if not key:
            self.status_var.set("Enter a key first.")
            return
        self.status_var.set("Checking the key…")
        self.update_idletasks()

        def worker() -> None:
            try:
                VirusTotalClient(key, rpm=0).verify_key()
                message = "The key is valid."
            except ApiKeyError:
                message = "VirusTotal rejected the key."
            except FileWardenError as exc:
                message = f"Could not verify: {exc}"
            self.after(0, lambda: self.status_var.set(message))

        threading.Thread(target=worker, daemon=True).start()

    def _save(self) -> None:
        cfg = config.load_config()
        cfg["api_key"] = self.key_var.get().strip()
        try:
            cfg["rpm"] = max(1.0, float(self.rpm_var.get().replace(",", ".")))
            cfg["max_upload_mb"] = max(1.0, float(self.max_upload_var.get().replace(",", ".")))
        except ValueError:
            messagebox.showerror("Settings", "The rate limit and size must be numbers.", parent=self)
            return
        cfg["upload_policy"] = POLICY_LABELS[self.policy_var.get()].value
        path = config.save_config(cfg)
        self.parent.on_settings_saved(path)
        self.destroy()


class UploadDialog(tk.Toplevel):
    """Explicit consent before a file is uploaded to VirusTotal."""

    def __init__(self, parent: "FileWardenApp", path: Path, size: int, sha256: str):
        super().__init__(parent.root)
        self.title("Confirm upload")
        self.transient(parent.root)
        self.resizable(False, False)
        self.answer: Decision = Decision.SKIP

        body = ttk.Frame(self, padding=16)
        body.grid(row=0, column=0, sticky="nsew")

        ttk.Label(body, text="File not found on VirusTotal", font=("TkDefaultFont", 13, "bold")).grid(
            row=0, column=0, sticky="w"
        )
        ttk.Label(body, text=str(path), wraplength=520).grid(row=1, column=0, sticky="w", pady=(6, 0))
        ttk.Label(body, text=f"Size: {format_size(size)}").grid(row=2, column=0, sticky="w")
        ttk.Label(body, text=f"SHA-256: {sha256}", wraplength=520, foreground="#666666").grid(
            row=3, column=0, sticky="w"
        )
        warning = (
            "Uploading makes the file available to researchers and vendors on VirusTotal. "
            "Do not upload personal or confidential documents."
        )
        ttk.Label(body, text=warning, wraplength=520, foreground="#842029").grid(
            row=4, column=0, sticky="w", pady=(10, 0)
        )

        buttons = ttk.Frame(body)
        buttons.grid(row=5, column=0, sticky="e", pady=(16, 0))
        ttk.Button(buttons, text="Upload", command=lambda: self._finish(Decision.UPLOAD)).pack(
            side="left", padx=(0, 6)
        )
        ttk.Button(buttons, text="Skip", command=lambda: self._finish(Decision.SKIP)).pack(
            side="left", padx=(0, 6)
        )
        ttk.Button(
            buttons, text="Upload all", command=lambda: self._finish(Decision.UPLOAD_ALL)
        ).pack(side="left", padx=(0, 6))
        ttk.Button(
            buttons, text="Skip all", command=lambda: self._finish(Decision.SKIP_ALL)
        ).pack(side="left")

        self.protocol("WM_DELETE_WINDOW", lambda: self._finish(Decision.SKIP))
        self.grab_set()
        self.focus_set()

    def _finish(self, decision: Decision) -> None:
        self.answer = decision
        self.destroy()


class FileWardenApp:
    """Main window."""

    def __init__(self, root: tk.Tk):
        self.root = root
        self.queue: queue.Queue = queue.Queue()
        self.worker: threading.Thread | None = None
        self.cancel_token = threading.Event()
        self.results: list[ScanResult] = []
        self.items: dict[str, ScanResult] = {}
        self.started_at = 0.0
        self.total_files = 0

        root.title(f"FileWarden {__version__} — scan files with VirusTotal")
        root.geometry("1000x680")
        root.minsize(820, 520)

        self.ask_var = tk.BooleanVar(value=True)
        self.status_var = tk.StringVar(value="Ready")
        self.summary_var = tk.StringVar(value="Pick a file or folder and press “Scan”")
        self.key_var = tk.StringVar(value=f"API key: {config.api_key_source()}")

        self._build_menu()
        self._build_layout()
        self._refresh_options_from_config()
        self._apply_dnd()

        root.protocol("WM_DELETE_WINDOW", self._on_close)
        root.after(80, self._poll)

    # ------------------------------------------------------------------- ui

    def _build_menu(self) -> None:
        menubar = tk.Menu(self.root)

        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Add file…", command=self.add_files)
        file_menu.add_command(label="Add folder…", command=self.add_folder)
        file_menu.add_separator()
        file_menu.add_command(label="Save report (JSON)…", command=lambda: self.save_report("json"))
        file_menu.add_command(label="Save report (CSV)…", command=lambda: self.save_report("csv"))
        file_menu.add_separator()
        file_menu.add_command(label="Quit", command=self._on_close)
        menubar.add_cascade(label="File", menu=file_menu)

        tools_menu = tk.Menu(menubar, tearoff=0)
        tools_menu.add_command(label="Settings…", command=self.open_settings)
        menubar.add_cascade(label="Settings", menu=tools_menu)

        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="About", command=self.show_about)
        menubar.add_cascade(label="Help", menu=help_menu)

        self.root.config(menu=menubar)

    def _build_layout(self) -> None:
        main = ttk.Frame(self.root, padding=10)
        main.pack(fill="both", expand=True)
        main.columnconfigure(0, weight=1)
        main.rowconfigure(2, weight=1)

        paths_box = ttk.LabelFrame(main, text="What to scan", padding=8)
        paths_box.grid(row=0, column=0, sticky="nsew")
        paths_box.columnconfigure(0, weight=1)

        list_holder = ttk.Frame(paths_box)
        list_holder.grid(row=0, column=0, sticky="nsew")
        list_holder.columnconfigure(0, weight=1)
        self.path_list = tk.Listbox(list_holder, height=4, selectmode=tk.EXTENDED)
        self.path_list.grid(row=0, column=0, sticky="nsew")
        scroll = ttk.Scrollbar(list_holder, orient="vertical", command=self.path_list.yview)
        scroll.grid(row=0, column=1, sticky="ns")
        self.path_list.configure(yscrollcommand=scroll.set)
        self.path_list.bind("<Delete>", lambda _event: self.remove_selected())

        buttons = ttk.Frame(paths_box)
        buttons.grid(row=0, column=1, sticky="n", padx=(8, 0))
        ttk.Button(buttons, text="File…", command=self.add_files).pack(fill="x", pady=1)
        ttk.Button(buttons, text="Folder…", command=self.add_folder).pack(fill="x", pady=1)
        ttk.Button(buttons, text="Remove", command=self.remove_selected).pack(fill="x", pady=1)
        ttk.Button(buttons, text="Clear", command=self.clear_paths).pack(fill="x", pady=1)

        hint = (
            "Drag files or folders into this window."
            if DND_ACTIVE
            else "Drag and drop is unavailable (pip install tkinterdnd2) — "
                 "use the “File…” and “Folder…” buttons."
        )
        ttk.Label(paths_box, text=hint, foreground="#666666").grid(
            row=1, column=0, columnspan=2, sticky="w", pady=(6, 0)
        )

        options = ttk.Frame(main)
        options.grid(row=1, column=0, sticky="we", pady=(8, 4))
        ttk.Checkbutton(
            options,
            text="Ask before uploading files missing from VirusTotal",
            variable=self.ask_var,
        ).pack(side="left")
        ttk.Button(options, text="Browse…", command=self.add_files).pack(side="left", padx=(10, 0))
        ttk.Button(options, text="Settings…", command=self.open_settings).pack(side="left", padx=(6, 0))
        ttk.Label(options, textvariable=self.key_var, foreground="#666666").pack(side="right")

        table_box = ttk.LabelFrame(main, text="Results", padding=4)
        table_box.grid(row=2, column=0, sticky="nsew")
        table_box.columnconfigure(0, weight=1)
        table_box.rowconfigure(0, weight=1)

        columns = ("size", "verdict", "detections", "sha256", "note")
        self.tree = ttk.Treeview(table_box, columns=columns, show="tree headings", height=14)
        self.tree.grid(row=0, column=0, sticky="nsew")
        self.tree.heading("#0", text="File")
        self.tree.column("#0", width=300, anchor="w")
        headings = {
            "size": ("Size", 90),
            "verdict": ("Verdict", 170),
            "detections": ("Detections", 80),
            "sha256": ("SHA-256", 150),
            "note": ("Note", 320),
        }
        for key, (title, width) in headings.items():
            self.tree.heading(key, text=title)
            self.tree.column(key, width=width, anchor="w", stretch=(key == "note"))

        for status, (tag, background, foreground) in ROW_TAGS.items():
            self.tree.tag_configure(tag, background=background, foreground=foreground)

        tree_scroll = ttk.Scrollbar(table_box, orient="vertical", command=self.tree.yview)
        tree_scroll.grid(row=0, column=1, sticky="ns")
        self.tree.configure(yscrollcommand=tree_scroll.set)
        self.tree.bind("<Double-1>", lambda _event: self.open_report())
        self.tree.bind("<Button-2>", self._popup_menu)
        self.tree.bind("<Button-3>", self._popup_menu)

        self.context_menu = tk.Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="Open VirusTotal report", command=self.open_report)
        self.context_menu.add_command(label="Reveal in folder", command=self.reveal_file)
        self.context_menu.add_command(label="Copy SHA-256", command=self.copy_sha)
        self.context_menu.add_command(label="Copy path", command=self.copy_path)

        progress_box = ttk.Frame(main)
        progress_box.grid(row=3, column=0, sticky="we", pady=(8, 0))
        progress_box.columnconfigure(0, weight=1)
        self.progress = ttk.Progressbar(progress_box, mode="determinate", maximum=100)
        self.progress.grid(row=0, column=0, sticky="we")
        self.status_label = ttk.Label(progress_box, textvariable=self.status_var)
        self.status_label.grid(row=1, column=0, sticky="w", pady=(4, 0))

        actions = ttk.Frame(main)
        actions.grid(row=4, column=0, sticky="we", pady=(6, 0))
        self.scan_button = ttk.Button(actions, text="Scan", command=self.start_scan)
        self.scan_button.pack(side="left")
        self.stop_button = ttk.Button(
            actions, text="Stop", command=self.stop_scan, state="disabled"
        )
        self.stop_button.pack(side="left", padx=(6, 0))
        ttk.Button(
            actions, text="Save report…", command=lambda: self.save_report(None)
        ).pack(side="left", padx=(6, 0))
        ttk.Label(actions, textvariable=self.summary_var, foreground="#333333").pack(
            side="right"
        )

    def _apply_dnd(self) -> None:
        if not DND_ACTIVE:
            return
        try:
            for widget in (self.path_list, self.tree):
                widget.drop_target_register(DND_FILES)  # type: ignore[attr-defined]
                widget.dnd_bind("<<Drop>>", self._on_drop)  # type: ignore[attr-defined]
        except Exception:  # pragma: no cover - depends on the tkdnd build
            pass

    def _refresh_options_from_config(self) -> None:
        policy = str(config.load_config().get("upload_policy") or "ask")
        self.ask_var.set(policy != UploadPolicy.NEVER.value)

    # -------------------------------------------------------------- utilities

    def on_settings_saved(self, path: Path) -> None:
        self.key_var.set(f"API key: {config.api_key_source()}")
        self._refresh_options_from_config()
        self.status_var.set(f"Settings saved: {path}")

    def _selected_result(self) -> ScanResult | None:
        selection = self.tree.selection()
        if not selection:
            return None
        return self.items.get(selection[0])

    def _current_policy(self) -> UploadPolicy:
        if self.ask_var.get():
            return UploadPolicy.ASK
        cfg_policy = str(config.load_config().get("upload_policy") or "ask")
        if cfg_policy == UploadPolicy.ALWAYS.value:
            return UploadPolicy.ALWAYS
        return UploadPolicy.NEVER

    # ----------------------------------------------------------------- paths

    def add_files(self) -> None:
        paths = filedialog.askopenfilenames(title="Select files to scan")
        self._append_paths(paths)

    def add_folder(self) -> None:
        path = filedialog.askdirectory(title="Select a folder to scan")
        if path:
            self._append_paths([path])

    def _append_paths(self, paths) -> None:
        existing = set(self.path_list.get(0, tk.END))
        added = 0
        for path in paths:
            path = str(path).strip()
            if not path or path in existing:
                continue
            self.path_list.insert(tk.END, path)
            existing.add(path)
            added += 1
        if added:
            self.status_var.set(f"Added {added} path(s)")

    def remove_selected(self) -> None:
        for index in reversed(self.path_list.curselection()):
            self.path_list.delete(index)

    def clear_paths(self) -> None:
        self.path_list.delete(0, tk.END)

    def _on_drop(self, event) -> str:  # pragma: no cover - needs a real window
        paths = self.root.tk.splitlist(event.data)
        self._append_paths(paths)
        return getattr(event, "action", "copy")

    # ------------------------------------------------------------------ scan

    def start_scan(self) -> None:
        if self.worker is not None:
            return
        paths = list(self.path_list.get(0, tk.END))
        if not paths:
            messagebox.showinfo("FileWarden", "Add a file or folder to scan.")
            return
        key = config.resolve_api_key(None)
        if not key:
            messagebox.showwarning(
                "FileWarden",
                "No API key configured. Opening settings — paste a key from "
                "https://www.virustotal.com/gui/my-apikey",
            )
            self.open_settings()
            key = config.resolve_api_key(None)
            if not key:
                return

        cfg = config.load_config()
        rpm = float(cfg.get("rpm") or 4.0)
        max_upload_mb = float(cfg.get("max_upload_mb") or 32.0)
        policy = self._current_policy()

        self.results.clear()
        self.items.clear()
        self.tree.delete(*self.tree.get_children())
        self.total_files = 0
        self.started_at = time.monotonic()
        self.progress.configure(maximum=100, value=0)
        self.cancel_token = threading.Event()
        self.scan_button.configure(state="disabled")
        self.stop_button.configure(state="normal")
        self.status_var.set("Collecting the file list…")
        self.summary_var.set("")

        client = VirusTotalClient(key, rpm=rpm)
        scanner = Scanner(
            client,
            policy=policy,
            max_upload_mb=max_upload_mb,
            confirm_upload=self._confirm_upload_from_worker,
            cancel=self.cancel_token,
            on_status=lambda text: self.queue.put(("status", text)),
            on_note=lambda text: self.queue.put(("status", text)),
            on_progress=lambda done, total, path: self.queue.put(("progress", done, total, path)),
        )

        def worker() -> None:
            try:
                for result in scanner.scan(paths):
                    self.queue.put(("file", result))
            except CancelledError:
                self.queue.put(("cancelled",))
            except ApiKeyError as exc:
                self.queue.put(("error", f"Invalid API key: {exc}"))
            except FileWardenError as exc:
                self.queue.put(("error", str(exc)))
            else:
                self.queue.put(("done",))

        self.worker = threading.Thread(target=worker, daemon=True, name="filewarden-scan")
        self.worker.start()

    def _confirm_upload_from_worker(self, path: Path, size: int, sha256: str) -> Decision:
        """Ask the UI thread and block the worker until it answers."""
        reply: queue.Queue = queue.Queue(maxsize=1)
        self.queue.put(("ask", path, size, sha256, reply))
        return reply.get()

    def stop_scan(self) -> None:
        if self.worker is None:
            return
        self.cancel_token.set()
        self.status_var.set("Stopping…")

    def _finish_scan(self) -> None:
        self.worker = None
        self.scan_button.configure(state="normal")
        self.stop_button.configure(state="disabled")
        if self.total_files:
            self.progress.configure(value=self.total_files)
        totals = summarize(self.results)
        elapsed = time.monotonic() - self.started_at if self.started_at else 0.0
        self.summary_var.set(
            f"Scanned: {totals['files']} • clean: {totals['clean']} • "
            f"suspicious: {totals['suspicious']} • malicious: {totals['malicious']} • "
            f"not in VT: {totals['unknown'] + totals['too_big']} • errors: {totals['errors']} • "
            f"uploaded: {totals['uploaded']} • {format_duration(elapsed)}"
        )
        if totals["malicious"] or totals["suspicious"]:
            self.root.bell()

    # ---------------------------------------------------------------- events

    def _poll(self) -> None:
        try:
            while True:
                self._handle_event(self.queue.get_nowait())
        except queue.Empty:
            pass
        self.root.after(80, self._poll)

    def _handle_event(self, event: tuple) -> None:
        kind = event[0]
        if kind == "status":
            self.status_var.set(str(event[1]))
        elif kind == "progress":
            done, total, path = event[1], event[2], event[3]
            self.total_files = total
            self.progress.configure(maximum=max(1, total), value=done)
            if path is not None:
                self.status_var.set(f"[{done}/{total}] {Path(path).name}")
        elif kind == "file":
            self._add_result(event[1])
        elif kind == "ask":
            _, path, size, sha256, reply = event
            dialog = UploadDialog(self, path, size, sha256)
            self.root.wait_window(dialog)
            reply.put(dialog.answer)
        elif kind == "done":
            self.status_var.set("Scan complete.")
            self._finish_scan()
        elif kind == "cancelled":
            self.status_var.set("Scan cancelled.")
            self._finish_scan()
        elif kind == "error":
            self.status_var.set(str(event[1]))
            self._finish_scan()
            messagebox.showerror("FileWarden", str(event[1]))

    def _add_result(self, result: ScanResult) -> None:
        self.results.append(result)
        tag, _, _ = ROW_TAGS[result.status]
        note = result.message or ""
        if not note and result.detections:
            note = format_detections(result.detections)
        if result.uploaded and not note:
            note = "uploaded to VirusTotal"
        item_id = self.tree.insert(
            "",
            "end",
            text=result.name,
            values=(
                format_size(result.size),
                STATUS_MARKS[result.status],
                result.detection_ratio(),
                result.sha256[:16] + "…" if len(result.sha256) > 16 else (result.sha256 or "—"),
                note,
            ),
            tags=(tag,),
        )
        self.items[item_id] = result
        self.tree.see(item_id)

    # ------------------------------------------------------------- row actions

    def _popup_menu(self, event) -> None:  # pragma: no cover - needs a real window
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            self.context_menu.tk_popup(event.x_root, event.y_root)

    def open_report(self) -> None:
        result = self._selected_result()
        if result is None:
            return
        if result.permalink:
            webbrowser.open(result.permalink)
        else:
            messagebox.showinfo(
                "FileWarden",
                "No report available: the file is not on VirusTotal and was not uploaded.",
            )

    def reveal_file(self) -> None:
        result = self._selected_result()
        if result is None:
            return
        path = Path(result.path)
        try:
            if sys.platform == "darwin":
                import subprocess

                subprocess.Popen(["open", "-R", str(path)])
            elif os.name == "nt":
                os.startfile(str(path.parent))  # type: ignore[attr-defined]
            else:
                import subprocess

                subprocess.Popen(["xdg-open", str(path.parent)])
        except Exception as exc:  # pragma: no cover
            messagebox.showerror("FileWarden", f"Could not open the folder: {exc}")

    def copy_sha(self) -> None:
        result = self._selected_result()
        if result and result.sha256:
            self._copy(result.sha256)

    def copy_path(self) -> None:
        result = self._selected_result()
        if result:
            self._copy(result.path)

    def _copy(self, text: str) -> None:
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.status_var.set("Copied to clipboard.")

    # -------------------------------------------------------------- reports

    def save_report(self, kind: str | None) -> None:
        if not self.results:
            messagebox.showinfo("FileWarden", "Nothing to save yet — run a scan first.")
            return
        if kind is None:
            path = filedialog.asksaveasfilename(
                title="Save report",
                defaultextension=".json",
                filetypes=[("JSON", "*.json"), ("CSV", "*.csv")],
            )
        else:
            path = filedialog.asksaveasfilename(
                title="Save report",
                defaultextension=f".{kind}",
                filetypes=[("JSON", "*.json")] if kind == "json" else [("CSV", "*.csv")],
            )
        if not path:
            return
        try:
            if path.lower().endswith(".csv"):
                write_csv_report(self.results, path)
            else:
                write_json_report(
                    self.results,
                    path,
                    meta={"paths": list(self.path_list.get(0, tk.END)), "source": "gui"},
                )
        except OSError as exc:
            messagebox.showerror("FileWarden", f"Could not save the report: {exc}")
            return
        self.status_var.set(f"Report saved: {path}")

    # -------------------------------------------------------------- dialogs

    def open_settings(self) -> None:
        SettingsDialog(self)

    def show_about(self) -> None:
        messagebox.showinfo(
            "About FileWarden",
            f"FileWarden {__version__}\n\n"
            "Scan files and folders with VirusTotal.\n"
            "Every file is looked up by its SHA-256 first — nothing is uploaded "
            "until you confirm it. Uploaded files become available to researchers "
            "and vendors on VirusTotal, so never upload personal or confidential "
            "documents.\n\n"
            "MIT license. Data is provided by VirusTotal; this tool does not "
            "replace antivirus software.",
        )

    # ----------------------------------------------------------------- close

    def _on_close(self) -> None:
        if self.worker is not None:
            if not messagebox.askyesno("FileWarden", "A scan is running. Cancel it and quit?"):
                return
            self.cancel_token.set()
        self.root.destroy()


def main(argv: list[str] | None = None) -> int:
    global DND_ACTIVE
    argv = list(sys.argv[1:] if argv is None else argv)
    if "--check" in argv:
        print(f"filewarden_gui {__version__}")
        print("tkinter: ok")
        if not HAS_DND:
            print("tkinterdnd2 (drag & drop): not installed")
        else:
            try:
                probe = TkinterDnD.Tk()
                probe.destroy()
                print("tkinterdnd2 (drag & drop): available")
            except Exception as exc:
                print(f"tkinterdnd2 (drag & drop): present but not working ({exc})")
        print(f"config: {config.config_path()}")
        print(f"API key: {config.api_key_source()}")
        return 0

    root: tk.Tk
    if HAS_DND and TkinterDnD is not None:
        try:
            root = TkinterDnD.Tk()
        except Exception:
            root = tk.Tk()
        else:
            DND_ACTIVE = True
    else:
        root = tk.Tk()
    app = FileWardenApp(root)
    for path in argv:
        if os.path.exists(path):
            app._append_paths([path])
    root.mainloop()
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
