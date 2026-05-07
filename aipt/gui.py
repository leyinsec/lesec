#!/usr/bin/env python3
"""
AiPT Pro - Desktop GUI Application
Built with tkinter for cross-platform compatibility.
"""

import asyncio
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
from typing import Optional, Dict, Any
from datetime import datetime
import os
import sys
import webbrowser

from .core.config import Config
from .core.engine import ScanEngine
from .core.models import ScanResult, Severity


class RedirectText:
    """Redirects stdout/stderr to a tkinter Text widget."""
    def __init__(self, text_widget: scrolledtext.ScrolledText):
        self.text_widget = text_widget
        self._lock = threading.Lock()

    def write(self, string: str):
        with self._lock:
            self.text_widget.insert(tk.END, string)
            self.text_widget.see(tk.END)

    def flush(self):
        pass


class AIPTGui:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("AiPT Pro - AI-Enhanced Penetration Testing Platform v2.0.0")
        self.root.geometry("1200x800")
        self.root.minsize(1000, 700)

        # Scan state
        self.scan_thread: Optional[threading.Thread] = None
        self.is_scanning = False
        self.last_result: Optional[ScanResult] = None

        self._setup_styles()
        self._build_ui()
        self._center_window()

    def _setup_styles(self):
        style = ttk.Style()
        style.theme_use('clam')

        # Colors
        self.bg_color = "#f5f5f5"
        self.accent_color = "#667eea"
        self.accent_hover = "#5a6fd6"
        self.success_color = "#28a745"
        self.warning_color = "#ffc107"
        self.danger_color = "#dc3545"
        self.info_color = "#17a2b8"

        style.configure("TFrame", background=self.bg_color)
        style.configure("TLabel", background=self.bg_color, font=("Segoe UI", 10))
        style.configure("TButton", font=("Segoe UI", 10, "bold"), padding=8)
        style.configure("Accent.TButton", background=self.accent_color, foreground="white")
        style.map("Accent.TButton",
                  background=[("active", self.accent_hover), ("pressed", self.accent_color)])

        style.configure("TEntry", font=("Segoe UI", 10))
        style.configure("TCombobox", font=("Segoe UI", 10))
        style.configure("TCheckbutton", background=self.bg_color, font=("Segoe UI", 10))

        self.root.configure(bg=self.bg_color)

    def _center_window(self):
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f"{width}x{height}+{x}+{y}")

    def _build_ui(self):
        # Main container
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Header
        self._build_header(main_frame)

        # Content area with left config and right output
        content_frame = ttk.Frame(main_frame)
        content_frame.pack(fill=tk.BOTH, expand=True, pady=(15, 0))
        content_frame.columnconfigure(0, weight=1)
        content_frame.columnconfigure(1, weight=2)
        content_frame.rowconfigure(0, weight=1)

        # Left panel - Configuration
        left_panel = ttk.Frame(content_frame, padding="10")
        left_panel.grid(row=0, column=0, sticky="nsew", padx=(0, 10))
        self._build_config_panel(left_panel)

        # Right panel - Output & Results
        right_panel = ttk.Frame(content_frame, padding="10")
        right_panel.grid(row=0, column=1, sticky="nsew")
        self._build_output_panel(right_panel)

        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var,
                               font=("Segoe UI", 9), foreground="#666")
        status_bar.pack(fill=tk.X, pady=(10, 0))

    def _build_header(self, parent):
        header = ttk.Frame(parent)
        header.pack(fill=tk.X)

        title = tk.Label(header, text="AiPT Pro",
                         font=("Segoe UI", 24, "bold"),
                         fg=self.accent_color, bg=self.bg_color)
        title.pack(side=tk.LEFT)

        subtitle = tk.Label(header,
                            text="AI-Enhanced Web Application Penetration Testing",
                            font=("Segoe UI", 12),
                            fg="#666", bg=self.bg_color)
        subtitle.pack(side=tk.LEFT, padx=(15, 0), pady=(8, 0))

    def _build_config_panel(self, parent):
        # Target URL
        ttk.Label(parent, text="Target URL", font=("Segoe UI", 11, "bold")).pack(anchor=tk.W, pady=(0, 5))
        self.target_var = tk.StringVar()
        target_entry = ttk.Entry(parent, textvariable=self.target_var, width=40)
        target_entry.pack(fill=tk.X, pady=(0, 15))
        target_entry.insert(0, "https://example.com")

        # Notebook for config sections
        notebook = ttk.Notebook(parent)
        notebook.pack(fill=tk.BOTH, expand=True)

        # Scan Options Tab
        scan_tab = ttk.Frame(notebook, padding="10")
        notebook.add(scan_tab, text="Scan Options")
        self._build_scan_options(scan_tab)

        # Auth Tab
        auth_tab = ttk.Frame(notebook, padding="10")
        notebook.add(auth_tab, text="Authentication")
        self._build_auth_options(auth_tab)

        # Detection Tab
        detection_tab = ttk.Frame(notebook, padding="10")
        notebook.add(detection_tab, text="Detection")
        self._build_detection_options(detection_tab)

        # Proxy Tab
        proxy_tab = ttk.Frame(notebook, padding="10")
        notebook.add(proxy_tab, text="Proxy")
        self._build_proxy_options(proxy_tab)

        # Action Buttons
        btn_frame = ttk.Frame(parent)
        btn_frame.pack(fill=tk.X, pady=(15, 0))

        self.scan_btn = ttk.Button(btn_frame, text="Start Scan",
                                   command=self._start_scan, style="Accent.TButton")
        self.scan_btn.pack(fill=tk.X, pady=(0, 5))

        ttk.Button(btn_frame, text="Open Report Folder",
                   command=self._open_report_folder).pack(fill=tk.X, pady=(0, 5))

        ttk.Button(btn_frame, text="Export Results",
                   command=self._export_results).pack(fill=tk.X)

    def _build_scan_options(self, parent):
        # Depth
        ttk.Label(parent, text="Crawl Depth:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.depth_var = tk.IntVar(value=2)
        ttk.Spinbox(parent, from_=1, to=5, textvariable=self.depth_var, width=10).grid(row=0, column=1, sticky=tk.W, padx=5)

        # Concurrency
        ttk.Label(parent, text="Concurrency:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.concurrency_var = tk.IntVar(value=100)
        ttk.Spinbox(parent, from_=10, to=500, textvariable=self.concurrency_var, width=10).grid(row=1, column=1, sticky=tk.W, padx=5)

        # Timeout
        ttk.Label(parent, text="Timeout (s):").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.timeout_var = tk.DoubleVar(value=15.0)
        ttk.Spinbox(parent, from_=5.0, to=60.0, textvariable=self.timeout_var, width=10).grid(row=2, column=1, sticky=tk.W, padx=5)

        # Max URLs
        ttk.Label(parent, text="Max URLs:").grid(row=3, column=0, sticky=tk.W, pady=5)
        self.max_urls_var = tk.IntVar(value=1000)
        ttk.Spinbox(parent, from_=100, to=5000, textvariable=self.max_urls_var, width=10).grid(row=3, column=1, sticky=tk.W, padx=5)

        # SSL Verification
        self.verify_ssl_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(parent, text="Verify SSL", variable=self.verify_ssl_var).grid(row=4, column=0, columnspan=2, sticky=tk.W, pady=5)

        # Report Formats
        ttk.Label(parent, text="Report Formats:").grid(row=5, column=0, sticky=tk.W, pady=(15, 5))
        self.report_json_var = tk.BooleanVar(value=True)
        self.report_html_var = tk.BooleanVar(value=True)
        self.report_csv_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(parent, text="JSON", variable=self.report_json_var).grid(row=6, column=0, sticky=tk.W)
        ttk.Checkbutton(parent, text="HTML", variable=self.report_html_var).grid(row=6, column=1, sticky=tk.W)
        ttk.Checkbutton(parent, text="CSV", variable=self.report_csv_var).grid(row=7, column=0, sticky=tk.W)

    def _build_auth_options(self, parent):
        ttk.Label(parent, text="Auth Type:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.auth_type_var = tk.StringVar(value="none")
        auth_types = ["none", "token", "basic", "cookie"]
        ttk.Combobox(parent, textvariable=self.auth_type_var, values=auth_types, state="readonly", width=18).grid(row=0, column=1, sticky=tk.W, padx=5)

        ttk.Label(parent, text="Token:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.auth_token_var = tk.StringVar()
        ttk.Entry(parent, textvariable=self.auth_token_var, width=25, show="*").grid(row=1, column=1, sticky=tk.W, padx=5)

        ttk.Label(parent, text="Username:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.auth_user_var = tk.StringVar()
        ttk.Entry(parent, textvariable=self.auth_user_var, width=25).grid(row=2, column=1, sticky=tk.W, padx=5)

        ttk.Label(parent, text="Password:").grid(row=3, column=0, sticky=tk.W, pady=5)
        self.auth_pass_var = tk.StringVar()
        ttk.Entry(parent, textvariable=self.auth_pass_var, width=25, show="*").grid(row=3, column=1, sticky=tk.W, padx=5)

        ttk.Label(parent, text="Cookie:").grid(row=4, column=0, sticky=tk.W, pady=5)
        self.auth_cookie_var = tk.StringVar()
        ttk.Entry(parent, textvariable=self.auth_cookie_var, width=25).grid(row=4, column=1, sticky=tk.W, padx=5)

    def _build_detection_options(self, parent):
        self.detect_sqli_var = tk.BooleanVar(value=True)
        self.detect_xss_var = tk.BooleanVar(value=True)
        self.detect_ssrf_var = tk.BooleanVar(value=True)
        self.detect_idor_var = tk.BooleanVar(value=True)
        self.detect_cmdi_var = tk.BooleanVar(value=True)
        self.detect_ai_var = tk.BooleanVar(value=True)
        self.detect_js_var = tk.BooleanVar(value=True)
        self.detect_full_var = tk.BooleanVar(value=False)

        ttk.Checkbutton(parent, text="SQL Injection", variable=self.detect_sqli_var).grid(row=0, column=0, sticky=tk.W, pady=3)
        ttk.Checkbutton(parent, text="XSS", variable=self.detect_xss_var).grid(row=0, column=1, sticky=tk.W, pady=3)
        ttk.Checkbutton(parent, text="SSRF", variable=self.detect_ssrf_var).grid(row=1, column=0, sticky=tk.W, pady=3)
        ttk.Checkbutton(parent, text="IDOR", variable=self.detect_idor_var).grid(row=1, column=1, sticky=tk.W, pady=3)
        ttk.Checkbutton(parent, text="Command Injection", variable=self.detect_cmdi_var).grid(row=2, column=0, sticky=tk.W, pady=3)
        ttk.Checkbutton(parent, text="AI Detection", variable=self.detect_ai_var).grid(row=2, column=1, sticky=tk.W, pady=3)
        ttk.Checkbutton(parent, text="JS Audit", variable=self.detect_js_var).grid(row=3, column=0, sticky=tk.W, pady=3)
        ttk.Checkbutton(parent, text="Full Scan (All Modules)", variable=self.detect_full_var).grid(row=4, column=0, columnspan=2, sticky=tk.W, pady=(10, 3))

    def _build_proxy_options(self, parent):
        ttk.Label(parent, text="Proxy URL:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.proxy_var = tk.StringVar()
        ttk.Entry(parent, textvariable=self.proxy_var, width=30).grid(row=0, column=1, sticky=tk.W, padx=5)

        self.proxy_rotation_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(parent, text="Enable Proxy Rotation", variable=self.proxy_rotation_var).grid(row=1, column=0, columnspan=2, sticky=tk.W, pady=5)

    def _build_output_panel(self, parent):
        # Output tabs
        out_notebook = ttk.Notebook(parent)
        out_notebook.pack(fill=tk.BOTH, expand=True)

        # Console tab
        console_tab = ttk.Frame(out_notebook, padding="5")
        out_notebook.add(console_tab, text="Console Output")
        self.console_text = scrolledtext.ScrolledText(
            console_tab, wrap=tk.WORD, font=("Consolas", 10),
            bg="#1e1e1e", fg="#d4d4d4", insertbackground="white"
        )
        self.console_text.pack(fill=tk.BOTH, expand=True)

        # Results tab
        results_tab = ttk.Frame(out_notebook, padding="5")
        out_notebook.add(results_tab, text="Scan Results")
        self._build_results_panel(results_tab)

        # Progress bar
        self.progress_var = tk.DoubleVar(value=0)
        self.progress = ttk.Progressbar(parent, variable=self.progress_var, maximum=100, mode='determinate')
        self.progress.pack(fill=tk.X, pady=(10, 0))

    def _build_results_panel(self, parent):
        # Summary cards frame
        summary_frame = ttk.Frame(parent)
        summary_frame.pack(fill=tk.X, pady=(0, 10))

        self.summary_labels: Dict[str, tk.Label] = {}
        metrics = [
            ("URLs", "#17a2b8"),
            ("Forms", "#ffc107"),
            ("Vulns", "#dc3545"),
            ("Duration", "#28a745"),
        ]
        for i, (name, color) in enumerate(metrics):
            card = tk.Frame(summary_frame, bg="white", bd=1, relief=tk.SOLID,
                            highlightbackground="#ddd", highlightthickness=1)
            card.grid(row=0, column=i, padx=5, pady=5, sticky="nsew")
            summary_frame.columnconfigure(i, weight=1)

            tk.Label(card, text=name, font=("Segoe UI", 10),
                     bg="white", fg="#666").pack(pady=(10, 0))
            lbl = tk.Label(card, text="0", font=("Segoe UI", 18, "bold"),
                           bg="white", fg=color)
            lbl.pack(pady=(0, 10))
            self.summary_labels[name.lower()] = lbl

        # Vulnerability list
        ttk.Label(parent, text="Vulnerabilities:", font=("Segoe UI", 11, "bold")).pack(anchor=tk.W, pady=(10, 5))

        # Treeview for vulnerabilities
        tree_frame = ttk.Frame(parent)
        tree_frame.pack(fill=tk.BOTH, expand=True)

        columns = ("severity", "type", "url", "parameter")
        self.vuln_tree = ttk.Treeview(tree_frame, columns=columns, show="headings", height=12)
        self.vuln_tree.heading("severity", text="Severity")
        self.vuln_tree.heading("type", text="Type")
        self.vuln_tree.heading("url", text="URL")
        self.vuln_tree.heading("parameter", text="Parameter")
        self.vuln_tree.column("severity", width=80, anchor=tk.CENTER)
        self.vuln_tree.column("type", width=180)
        self.vuln_tree.column("url", width=300)
        self.vuln_tree.column("parameter", width=120)

        scrollbar = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.vuln_tree.yview)
        self.vuln_tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.vuln_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Severity tag colors
        self.vuln_tree.tag_configure("CRITICAL", background="#f8d7da", foreground="#721c24")
        self.vuln_tree.tag_configure("HIGH", background="#fff3cd", foreground="#856404")
        self.vuln_tree.tag_configure("MEDIUM", background="#d1ecf1", foreground="#0c5460")
        self.vuln_tree.tag_configure("LOW", background="#d4edda", foreground="#155724")
        self.vuln_tree.tag_configure("INFO", background="#e2e3e5", foreground="#383d41")

        # Detail text
        ttk.Label(parent, text="Details:", font=("Segoe UI", 10, "bold")).pack(anchor=tk.W, pady=(10, 5))
        self.detail_text = scrolledtext.ScrolledText(
            parent, wrap=tk.WORD, font=("Consolas", 9),
            height=6, bg="#f8f9fa", fg="#333"
        )
        self.detail_text.pack(fill=tk.X)

        self.vuln_tree.bind("<<TreeviewSelect>>", self._on_vuln_select)

    def _build_config(self) -> Config:
        config = Config()

        # Scan options
        config.scan.max_depth = self.depth_var.get()
        config.scan.concurrency = self.concurrency_var.get()
        config.scan.request_timeout = self.timeout_var.get()
        config.scan.max_urls = self.max_urls_var.get()
        config.scan.verify_ssl = self.verify_ssl_var.get()

        # Report formats
        formats = []
        if self.report_json_var.get():
            formats.append("json")
        if self.report_html_var.get():
            formats.append("html")
        if self.report_csv_var.get():
            formats.append("csv")
        config.report.formats = formats if formats else ["json"]

        # Auth
        auth_type = self.auth_type_var.get()
        if auth_type != "none":
            config.auth.enabled = True
            config.auth.type = auth_type
            config.auth.token = self.auth_token_var.get()
            config.auth.username = self.auth_user_var.get()
            config.auth.password = self.auth_pass_var.get()
            if self.auth_cookie_var.get():
                config.auth.type = "cookie"
                config.auth.cookie_auth = dict(
                    item.split("=") for item in self.auth_cookie_var.get().split(";") if "=" in item
                )

        # Proxy
        proxy = self.proxy_var.get()
        if proxy:
            config.proxy.enabled = True
            config.proxy.proxies = [proxy]
            config.proxy.proxy_rotation = self.proxy_rotation_var.get()

        # Detection modules
        if self.detect_full_var.get():
            config.detection.sqli_enabled = True
            config.detection.xss_enabled = True
            config.detection.ssrf_enabled = True
            config.detection.idor_enabled = True
            config.detection.cmd_injection_enabled = True
            config.detection.lfi_enabled = True
            config.detection.rfi_enabled = True
            config.detection.xxe_enabled = True
            config.detection.nosql_injection_enabled = True
            config.detection.template_injection_enabled = True
        else:
            config.detection.sqli_enabled = self.detect_sqli_var.get()
            config.detection.xss_enabled = self.detect_xss_var.get()
            config.detection.ssrf_enabled = self.detect_ssrf_var.get()
            config.detection.idor_enabled = self.detect_idor_var.get()
            config.detection.cmd_injection_enabled = self.detect_cmdi_var.get()

        config.ai.enabled = self.detect_ai_var.get()
        config.js_audit.enabled = self.detect_js_var.get()

        return config

    def _start_scan(self):
        if self.is_scanning:
            messagebox.showwarning("Scan in Progress", "A scan is already running.")
            return

        target = self.target_var.get().strip()
        if not target:
            messagebox.showerror("Error", "Please enter a target URL.")
            return

        if not target.startswith(("http://", "https://")):
            messagebox.showerror("Error", "Target URL must start with http:// or https://")
            return

        self.is_scanning = True
        self.scan_btn.configure(text="Scanning...", state="disabled")
        self.status_var.set("Scanning...")
        self.progress_var.set(0)

        # Clear previous results
        self.console_text.delete(1.0, tk.END)
        for item in self.vuln_tree.get_children():
            self.vuln_tree.delete(item)
        self.detail_text.delete(1.0, tk.END)

        # Redirect stdout to console
        redirect = RedirectText(self.console_text)
        old_stdout = sys.stdout
        sys.stdout = redirect

        config = self._build_config()

        def run_scan():
            try:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)

                engine = ScanEngine(config)

                # Progress simulation
                self.root.after(0, lambda: self.progress_var.set(10))

                result = loop.run_until_complete(engine.run_full_scan(target))
                self.last_result = result

                loop.close()

                self.root.after(0, lambda: self._scan_complete(result))
            except Exception as e:
                self.root.after(0, lambda: self._scan_error(str(e)))
            finally:
                sys.stdout = old_stdout

        self.scan_thread = threading.Thread(target=run_scan, daemon=True)
        self.scan_thread.start()

        # Animate progress
        self._animate_progress()

    def _animate_progress(self):
        if self.is_scanning and self.progress_var.get() < 90:
            self.progress_var.set(self.progress_var.get() + 2)
            self.root.after(500, self._animate_progress)

    def _scan_complete(self, result: ScanResult):
        self.is_scanning = False
        self.progress_var.set(100)
        self.scan_btn.configure(text="Start Scan", state="normal")
        self.status_var.set(f"Scan complete - {len(result.vulnerabilities)} vulnerabilities found")

        # Update summary
        self.summary_labels["urls"].configure(text=str(result.urls_discovered))
        self.summary_labels["forms"].configure(text=str(result.forms_discovered))
        self.summary_labels["vulns"].configure(text=str(len(result.vulnerabilities)))
        self.summary_labels["duration"].configure(text=f"{result.duration:.1f}s")

        # Populate vulnerability tree
        for vuln in sorted(result.vulnerabilities, key=lambda v: v.risk_score, reverse=True):
            self.vuln_tree.insert(
                "", tk.END,
                values=(vuln.severity.value, vuln.type.value, vuln.url, vuln.parameter),
                tags=(vuln.severity.value,)
            )

        messagebox.showinfo("Scan Complete",
                            f"Scan finished!\n"
                            f"URLs: {result.urls_discovered}\n"
                            f"Forms: {result.forms_discovered}\n"
                            f"Vulnerabilities: {len(result.vulnerabilities)}\n"
                            f"Duration: {result.duration:.2f}s")

    def _scan_error(self, error: str):
        self.is_scanning = False
        self.progress_var.set(0)
        self.scan_btn.configure(text="Start Scan", state="normal")
        self.status_var.set("Scan failed")
        messagebox.showerror("Scan Error", f"An error occurred during scanning:\n{error}")

    def _on_vuln_select(self, event):
        selection = self.vuln_tree.selection()
        if not selection:
            return

        item = self.vuln_tree.item(selection[0])
        values = item["values"]

        self.detail_text.delete(1.0, tk.END)
        if self.last_result:
            # Find matching vulnerability
            for vuln in self.last_result.vulnerabilities:
                if (vuln.severity.value == values[0] and
                    vuln.type.value == values[1] and
                    vuln.url == values[2]):
                    self.detail_text.insert(tk.END, f"Title: {vuln.title}\n")
                    self.detail_text.insert(tk.END, f"Description: {vuln.description}\n")
                    self.detail_text.insert(tk.END, f"Payload: {vuln.payload}\n")
                    self.detail_text.insert(tk.END, f"CWE: {vuln.cwe_id or 'N/A'}\n")
                    self.detail_text.insert(tk.END, f"Risk Score: {vuln.risk_score:.1f}\n")
                    if vuln.remediation:
                        self.detail_text.insert(tk.END, f"\nRemediation:\n{vuln.remediation}\n")
                    break

    def _open_report_folder(self):
        report_dir = os.path.abspath("reports")
        if os.path.exists(report_dir):
            if sys.platform == "win32":
                os.startfile(report_dir)
            elif sys.platform == "darwin":
                os.system(f'open "{report_dir}"')
            else:
                os.system(f'xdg-open "{report_dir}"')
        else:
            messagebox.showinfo("Info", "No reports folder found. Run a scan first.")

    def _export_results(self):
        if not self.last_result:
            messagebox.showwarning("No Results", "No scan results to export. Run a scan first.")
            return

        filepath = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON", "*.json"), ("HTML", "*.html"), ("CSV", "*.csv")]
        )
        if not filepath:
            return

        try:
            import json
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(self.last_result.to_dict(), f, indent=2, ensure_ascii=False, default=str)
            messagebox.showinfo("Export Complete", f"Results exported to:\n{filepath}")
        except Exception as e:
            messagebox.showerror("Export Error", str(e))

    def run(self):
        self.root.mainloop()


def run_gui():
    app = AIPTGui()
    app.run()


if __name__ == '__main__':
    run_gui()
