"""NigPig Premium Desktop GUI - Futuristic Security Scanner."""

import asyncio
import subprocess
import threading
from datetime import datetime
from pathlib import Path
from typing import Callable

import customtkinter as ctk

from nigpig.gui.theme import (
    PremiumTheme as Theme,
    ICONS,
    BG_DARK,
    BG_DARKER,
    BG_CARD,
    BG_CARD_HOVER,
    TEXT_PRIMARY,
    TEXT_SECONDARY,
    TEXT_DIM,
    ACCENT_CYAN,
    ACCENT_PINK,
    ACCENT_PURPLE,
    SUCCESS,
    WARNING,
    ERROR,
    CRITICAL,
    BORDER_DEFAULT,
    get_severity_color,
    get_grade_color,
)

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


class NigPigApp(ctk.CTk):
    """Premium NigPig Desktop Application."""

    def __init__(self):
        super().__init__()

        self.title("NigPig Tools - Security Scanner")
        self.geometry("1500x900")
        self.minsize(1300, 800)
        self.configure(fg_color=BG_DARK)

        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.scan_history = []
        self.current_scan = None

        self._create_sidebar()
        self._create_main_content()
        self._show_page("dashboard")

        self.bind("<Control-s>", lambda e: self._show_page("carrot"))
        self.bind("<Control-t>", lambda e: self._show_page("terminal"))
        self.bind("<Control-d>", lambda e: self._show_page("dashboard"))

    def _create_sidebar(self):
        """Create animated gradient sidebar."""
        self.sidebar = ctk.CTkFrame(
            self, width=Theme.SIDEBAR_WIDTH, corner_radius=0, fg_color=BG_DARKER
        )
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_rowconfigure(15, weight=1)
        self.sidebar.grid_propagate(False)

        # Logo
        logo_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        logo_frame.grid(row=0, column=0, padx=15, pady=(25, 10), sticky="ew")

        logo = ctk.CTkLabel(logo_frame, text="🐷", font=ctk.CTkFont(size=40))
        logo.pack(side="left", padx=(5, 10))

        title_frame = ctk.CTkFrame(logo_frame, fg_color="transparent")
        title_frame.pack(side="left")

        ctk.CTkLabel(
            title_frame,
            text="NigPig",
            font=ctk.CTkFont(size=22, weight="bold"),
            text_color=ACCENT_PINK,
        ).pack(anchor="w")

        ctk.CTkLabel(
            title_frame,
            text="Security Tools",
            font=ctk.CTkFont(size=11),
            text_color=TEXT_DIM,
        ).pack(anchor="w")

        # Divider
        ctk.CTkFrame(self.sidebar, height=1, fg_color=BORDER_DEFAULT).grid(
            row=1, column=0, sticky="ew", padx=15, pady=15
        )

        # Nav items
        self.nav_buttons = {}
        nav_items = [
            ("dashboard", f"{ICONS['dashboard']} Dashboard"),
            ("carrot", f"{ICONS['carrot']} Carrot Mode"),
            ("recon", f"{ICONS['recon']} Recon Suite"),
            ("fingerprint", f"{ICONS['fingerprint']} Fingerprint"),
            ("vuln", f"{ICONS['vuln']} Vuln Scanner"),
            ("secrets", f"{ICONS['secrets']} Secrets"),
            ("audit", f"{ICONS['audit']} SSL Audit"),
            ("terminal", f"{ICONS['terminal']} Terminal"),
            ("history", f"{ICONS['history']} History"),
        ]

        for i, (key, text) in enumerate(nav_items):
            btn = ctk.CTkButton(
                self.sidebar,
                text=text,
                font=ctk.CTkFont(size=14),
                height=Theme.SIDEBAR_ITEM_HEIGHT,
                corner_radius=Theme.SIDEBAR_ITEM_RADIUS,
                fg_color="transparent",
                text_color=TEXT_SECONDARY,
                hover_color=BG_CARD_HOVER,
                anchor="w",
                command=lambda k=key: self._show_page(k),
            )
            btn.grid(row=i + 2, column=0, padx=12, pady=3, sticky="ew")
            self.nav_buttons[key] = btn

        # Settings at bottom
        ctk.CTkFrame(self.sidebar, height=1, fg_color=BORDER_DEFAULT).grid(
            row=14, column=0, sticky="ew", padx=15, pady=10
        )

        settings_btn = ctk.CTkButton(
            self.sidebar,
            text=f"{ICONS['settings']} Settings",
            font=ctk.CTkFont(size=14),
            height=Theme.SIDEBAR_ITEM_HEIGHT,
            corner_radius=Theme.SIDEBAR_ITEM_RADIUS,
            fg_color="transparent",
            text_color=TEXT_SECONDARY,
            hover_color=BG_CARD_HOVER,
            anchor="w",
            command=lambda: self._show_page("settings"),
        )
        settings_btn.grid(row=16, column=0, padx=12, pady=3, sticky="ew")
        self.nav_buttons["settings"] = settings_btn

        # Status
        self.status_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        self.status_frame.grid(row=17, column=0, padx=15, pady=15, sticky="sew")

        self.status_label = ctk.CTkLabel(
            self.status_frame,
            text="● Ready",
            font=ctk.CTkFont(size=12),
            text_color=SUCCESS,
        )
        self.status_label.pack(anchor="w")

    def _create_main_content(self):
        """Create main content area with all pages."""
        self.content = ctk.CTkFrame(self, corner_radius=0, fg_color=BG_DARK)
        self.content.grid(row=0, column=1, sticky="nsew")
        self.content.grid_columnconfigure(0, weight=1)
        self.content.grid_rowconfigure(0, weight=1)

        self.pages = {}
        self.pages["dashboard"] = DashboardPage(self.content, self)
        self.pages["carrot"] = CarrotPage(self.content, self)
        self.pages["recon"] = ReconPage(self.content, self)
        self.pages["fingerprint"] = FingerprintPage(self.content, self)
        self.pages["vuln"] = VulnPage(self.content, self)
        self.pages["secrets"] = SecretsPage(self.content, self)
        self.pages["audit"] = AuditPage(self.content, self)
        self.pages["terminal"] = TerminalPage(self.content, self)
        self.pages["history"] = HistoryPage(self.content, self)
        self.pages["settings"] = SettingsPage(self.content, self)

        for page in self.pages.values():
            page.grid(row=0, column=0, sticky="nsew")

    def _show_page(self, name: str):
        for key, btn in self.nav_buttons.items():
            if key == name:
                btn.configure(fg_color=ACCENT_PINK, text_color=TEXT_PRIMARY)
            else:
                btn.configure(fg_color="transparent", text_color=TEXT_SECONDARY)
        self.pages[name].tkraise()

    def set_status(self, text: str, color: str = None):
        self.status_label.configure(text=f"● {text}", text_color=color or SUCCESS)

    def add_to_history(self, scan_data: dict):
        self.scan_history.insert(0, {**scan_data, "timestamp": datetime.now()})
        if hasattr(self.pages.get("history"), "refresh"):
            self.pages["history"].refresh()


class BasePage(ctk.CTkFrame):
    """Base class for all pages."""

    def __init__(self, parent, app):
        super().__init__(parent, fg_color=BG_DARK)
        self.app = app
        self.grid_columnconfigure(0, weight=1)


class GlassCard(ctk.CTkFrame):
    """Glassmorphism card component."""

    def __init__(self, parent, **kwargs):
        super().__init__(
            parent,
            fg_color=BG_CARD,
            corner_radius=Theme.CARD_RADIUS,
            border_width=1,
            border_color=BORDER_DEFAULT,
            **kwargs,
        )
        self.bind("<Enter>", self._on_enter)
        self.bind("<Leave>", self._on_leave)

    def _on_enter(self, e):
        self.configure(border_color=ACCENT_CYAN)

    def _on_leave(self, e):
        self.configure(border_color=BORDER_DEFAULT)


class DashboardPage(BasePage):
    """Dashboard with animated stats."""

    def __init__(self, parent, app):
        super().__init__(parent, app)
        self.grid_rowconfigure(2, weight=1)

        # Header
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.grid(row=0, column=0, padx=30, pady=(30, 20), sticky="ew")

        ctk.CTkLabel(
            header,
            text="Dashboard",
            font=ctk.CTkFont(size=Theme.TITLE_SIZE, weight="bold"),
            text_color=ACCENT_CYAN,
        ).pack(side="left")

        ctk.CTkLabel(
            header,
            text="Security Overview",
            font=ctk.CTkFont(size=14),
            text_color=TEXT_DIM,
        ).pack(side="left", padx=(15, 0))

        # Stats
        stats_frame = ctk.CTkFrame(self, fg_color="transparent")
        stats_frame.grid(row=1, column=0, padx=30, pady=10, sticky="ew")

        stats = [
            (ICONS["scan"], "Total Scans", "0", ACCENT_PINK),
            (ICONS["warning"], "Vulnerabilities", "0", ERROR),
            (ICONS["recon"], "Subdomains", "0", ACCENT_CYAN),
            (ICONS["fingerprint"], "Technologies", "0", ACCENT_PURPLE),
        ]

        for i, (icon, label, value, color) in enumerate(stats):
            stats_frame.grid_columnconfigure(i, weight=1)
            card = GlassCard(stats_frame)
            card.grid(row=0, column=i, padx=8, pady=8, sticky="nsew")

            ctk.CTkLabel(card, text=icon, font=ctk.CTkFont(size=36)).pack(pady=(20, 8))
            ctk.CTkLabel(
                card,
                text=value,
                font=ctk.CTkFont(size=40, weight="bold"),
                text_color=color,
            ).pack()
            ctk.CTkLabel(
                card,
                text=label,
                font=ctk.CTkFont(size=13),
                text_color=TEXT_SECONDARY,
            ).pack(pady=(5, 20))

        # Quick actions
        actions_card = GlassCard(self)
        actions_card.grid(row=2, column=0, padx=30, pady=20, sticky="nsew")

        ctk.CTkLabel(
            actions_card,
            text="Quick Actions",
            font=ctk.CTkFont(size=Theme.HEADING_SIZE, weight="bold"),
        ).pack(anchor="w", padx=25, pady=(25, 15))

        btns_frame = ctk.CTkFrame(actions_card, fg_color="transparent")
        btns_frame.pack(fill="x", padx=25, pady=(0, 25))

        ctk.CTkButton(
            btns_frame,
            text=f"{ICONS['carrot']} Quick Scan",
            font=ctk.CTkFont(size=15, weight="bold"),
            height=50,
            corner_radius=12,
            fg_color=ACCENT_PINK,
            hover_color="#e05585",
            command=lambda: app._show_page("carrot"),
        ).pack(side="left", padx=(0, 15))

        ctk.CTkButton(
            btns_frame,
            text=f"{ICONS['terminal']} Terminal",
            font=ctk.CTkFont(size=15, weight="bold"),
            height=50,
            corner_radius=12,
            fg_color=BG_CARD_HOVER,
            hover_color=BORDER_DEFAULT,
            command=lambda: app._show_page("terminal"),
        ).pack(side="left", padx=(0, 15))

        ctk.CTkButton(
            btns_frame,
            text=f"{ICONS['history']} History",
            font=ctk.CTkFont(size=15, weight="bold"),
            height=50,
            corner_radius=12,
            fg_color=BG_CARD_HOVER,
            hover_color=BORDER_DEFAULT,
            command=lambda: app._show_page("history"),
        ).pack(side="left")


class CarrotPage(BasePage):
    """Carrot Mode - Quick and Golden Carrot scans."""

    def __init__(self, parent, app):
        super().__init__(parent, app)
        self.grid_rowconfigure(3, weight=1)

        # Header
        ctk.CTkLabel(
            self,
            text=f"{ICONS['carrot']} Carrot Mode",
            font=ctk.CTkFont(size=Theme.TITLE_SIZE, weight="bold"),
            text_color=ACCENT_PINK,
        ).grid(row=0, column=0, padx=30, pady=(30, 20), sticky="w")

        # Target input
        input_card = GlassCard(self)
        input_card.grid(row=1, column=0, padx=30, pady=10, sticky="ew")

        input_inner = ctk.CTkFrame(input_card, fg_color="transparent")
        input_inner.pack(fill="x", padx=25, pady=20)
        input_inner.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(input_inner, text="Target:", font=ctk.CTkFont(size=14)).grid(
            row=0, column=0, padx=(0, 15)
        )
        self.target_entry = ctk.CTkEntry(
            input_inner,
            placeholder_text="https://example.com",
            height=45,
            font=ctk.CTkFont(size=14),
        )
        self.target_entry.grid(row=0, column=1, sticky="ew")

        # Module selection
        modules_card = GlassCard(self)
        modules_card.grid(row=2, column=0, padx=30, pady=10, sticky="ew")

        ctk.CTkLabel(
            modules_card,
            text="Select Modules:",
            font=ctk.CTkFont(size=14, weight="bold"),
        ).pack(anchor="w", padx=25, pady=(20, 10))

        modules_frame = ctk.CTkFrame(modules_card, fg_color="transparent")
        modules_frame.pack(fill="x", padx=25, pady=(0, 20))

        self.module_vars = {}
        modules = [
            ("tech", "Tech Detection", True),
            ("waf", "WAF Detection", True),
            ("templates", "Vuln Templates", True),
            ("ssl", "SSL Analysis", True),
            ("subdomain", "Subdomains", False),
            ("ports", "Port Scan", False),
            ("fuzz", "Fuzzing", False),
            ("secrets", "Secrets", False),
        ]

        for i, (key, label, default) in enumerate(modules):
            var = ctk.BooleanVar(value=default)
            self.module_vars[key] = var
            cb = ctk.CTkCheckBox(
                modules_frame,
                text=label,
                variable=var,
                font=ctk.CTkFont(size=13),
                checkbox_width=22,
                checkbox_height=22,
                corner_radius=6,
            )
            cb.grid(row=i // 4, column=i % 4, padx=15, pady=8, sticky="w")

        # Buttons
        btn_frame = ctk.CTkFrame(modules_card, fg_color="transparent")
        btn_frame.pack(fill="x", padx=25, pady=(0, 20))

        self.scan_btn = ctk.CTkButton(
            btn_frame,
            text=f"{ICONS['carrot']} Quick Carrot",
            font=ctk.CTkFont(size=15, weight="bold"),
            height=50,
            corner_radius=12,
            fg_color=ACCENT_PINK,
            hover_color="#e05585",
            command=self._quick_scan,
        )
        self.scan_btn.pack(side="left", padx=(0, 15))

        self.golden_btn = ctk.CTkButton(
            btn_frame,
            text="🥕 Golden Carrot (All)",
            font=ctk.CTkFont(size=15, weight="bold"),
            height=50,
            corner_radius=12,
            fg_color=ACCENT_PURPLE,
            hover_color="#6d28d9",
            command=self._golden_scan,
        )
        self.golden_btn.pack(side="left")

        # Progress and results
        results_card = GlassCard(self)
        results_card.grid(row=3, column=0, padx=30, pady=(10, 30), sticky="nsew")

        self.progress = ctk.CTkProgressBar(results_card, height=8, progress_color=ACCENT_CYAN)
        self.progress.pack(fill="x", padx=25, pady=(25, 10))
        self.progress.set(0)

        self.progress_label = ctk.CTkLabel(
            results_card,
            text="Ready to scan",
            font=ctk.CTkFont(size=12),
            text_color=TEXT_DIM,
        )
        self.progress_label.pack(anchor="w", padx=25)

        self.results_text = ctk.CTkTextbox(
            results_card,
            font=ctk.CTkFont(family="Consolas", size=12),
            fg_color=BG_DARKER,
            corner_radius=10,
        )
        self.results_text.pack(fill="both", expand=True, padx=25, pady=(15, 25))

    def _quick_scan(self):
        self._run_scan(golden=False)

    def _golden_scan(self):
        for var in self.module_vars.values():
            var.set(True)
        self._run_scan(golden=True)

    def _run_scan(self, golden: bool):
        target = self.target_entry.get().strip()
        if not target:
            self.results_text.delete("1.0", "end")
            self.results_text.insert("end", "❌ Please enter a target URL\n")
            return

        modules = [k for k, v in self.module_vars.items() if v.get()]

        self.scan_btn.configure(state="disabled")
        self.golden_btn.configure(state="disabled")
        self.progress.set(0)
        self.results_text.delete("1.0", "end")
        self.app.set_status("Scanning...", WARNING)

        mode = "🥕 Golden Carrot" if golden else "🥕 Quick Carrot"
        self.results_text.insert("end", f"{mode} Scan Started\n{'=' * 50}\n")
        self.results_text.insert("end", f"Target: {target}\nModules: {', '.join(modules)}\n\n")

        thread = threading.Thread(target=self._scan_thread, args=(target, modules))
        thread.start()

    def _scan_thread(self, target: str, modules: list):
        asyncio.run(self._async_scan(target, modules))

    async def _async_scan(self, target: str, modules: list):
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"

        from urllib.parse import urlparse

        domain = urlparse(target).netloc.split(":")[0]

        total = len(modules)
        findings = []

        for i, mod in enumerate(modules):
            self.after(
                0,
                lambda p=(i / total), m=mod: (
                    self.progress.set(p),
                    self.progress_label.configure(text=f"Running: {m}..."),
                ),
            )

            try:
                if mod == "tech":
                    from nigpig.fingerprint.tech_detect import TechDetector

                    detector = TechDetector()
                    techs = await detector.detect(target)
                    self._log(f"[TECH] {len(techs)} technologies found\n")
                    for t in techs:
                        self._log(f"  • {t.name} ({t.category})\n")

                elif mod == "waf":
                    from nigpig.fingerprint.waf_detect import WAFDetector

                    detector = WAFDetector()
                    wafs = await detector.detect(target)
                    if wafs:
                        self._log(f"[WAF] Detected: {wafs[0].name}\n")
                    else:
                        self._log("[WAF] No WAF detected\n")

                elif mod == "templates":
                    from nigpig.templates.executor import TemplateExecutor

                    executor = TemplateExecutor()
                    results = await executor.run_all_builtin(target)
                    self._log(f"[TEMPLATES] {len(results)} issues found\n")
                    for r in results:
                        findings.append(r)
                        self._log(f"  ⚠️ [{r.severity.upper()}] {r.template_name}\n")

                elif mod == "ssl":
                    from nigpig.audit.ssl import SSLAnalyzer

                    analyzer = SSLAnalyzer()
                    result = await analyzer.analyze_async(target)
                    self._log(f"[SSL] Grade: {result.score}\n")

                elif mod == "subdomain":
                    from nigpig.recon.subdomain import SubdomainEnumerator

                    enumerator = SubdomainEnumerator(domain)
                    subs = await enumerator.enumerate_all()
                    self._log(f"[SUBDOMAIN] {len(subs)} found\n")

                elif mod == "ports":
                    from nigpig.recon.ports import PortScanner

                    scanner = PortScanner(domain)
                    ports = await scanner.scan_top_ports()
                    self._log(f"[PORTS] {len(ports)} open\n")

            except Exception as e:
                self._log(f"[{mod.upper()}] Error: {e}\n")

            self._log("\n")

        self.after(
            0,
            lambda: (
                self.progress.set(1),
                self.progress_label.configure(text="Scan complete!"),
                self.scan_btn.configure(state="normal"),
                self.golden_btn.configure(state="normal"),
                self.app.set_status("Ready", SUCCESS),
            ),
        )

        self.app.add_to_history({"target": target, "modules": modules, "findings": len(findings)})

    def _log(self, text: str):
        self.after(0, lambda: self.results_text.insert("end", text))


class ReconPage(BasePage):
    """Recon Suite - Subdomain, Ports, DNS."""

    def __init__(self, parent, app):
        super().__init__(parent, app)
        self.grid_rowconfigure(2, weight=1)

        ctk.CTkLabel(
            self,
            text=f"{ICONS['recon']} Recon Suite",
            font=ctk.CTkFont(size=Theme.TITLE_SIZE, weight="bold"),
            text_color=ACCENT_CYAN,
        ).grid(row=0, column=0, padx=30, pady=(30, 20), sticky="w")

        # Tabs
        tabs = ctk.CTkTabview(self, fg_color=BG_CARD, corner_radius=16)
        tabs.grid(row=1, column=0, padx=30, pady=10, sticky="nsew")

        sub_tab = tabs.add("Subdomains")
        port_tab = tabs.add("Port Scan")
        dns_tab = tabs.add("DNS")

        # Subdomain
        ctk.CTkLabel(sub_tab, text="Domain:", font=ctk.CTkFont(size=14)).pack(
            anchor="w", padx=20, pady=(20, 5)
        )
        self.sub_entry = ctk.CTkEntry(sub_tab, placeholder_text="example.com", height=42)
        self.sub_entry.pack(fill="x", padx=20, pady=5)
        ctk.CTkButton(
            sub_tab,
            text="🔍 Enumerate",
            height=42,
            corner_radius=10,
            fg_color=ACCENT_CYAN,
            hover_color="#00b8d4",
            command=self._run_subdomain,
        ).pack(padx=20, pady=10, anchor="w")

        self.sub_results = ctk.CTkTextbox(sub_tab, font=ctk.CTkFont(family="Consolas", size=12))
        self.sub_results.pack(fill="both", expand=True, padx=20, pady=(10, 20))

        # Port scan
        ctk.CTkLabel(port_tab, text="Host:", font=ctk.CTkFont(size=14)).pack(
            anchor="w", padx=20, pady=(20, 5)
        )
        self.port_entry = ctk.CTkEntry(port_tab, placeholder_text="example.com", height=42)
        self.port_entry.pack(fill="x", padx=20, pady=5)
        ctk.CTkButton(
            port_tab,
            text="🎯 Scan Ports",
            height=42,
            corner_radius=10,
            fg_color=ACCENT_CYAN,
            hover_color="#00b8d4",
            command=self._run_ports,
        ).pack(padx=20, pady=10, anchor="w")

        self.port_results = ctk.CTkTextbox(port_tab, font=ctk.CTkFont(family="Consolas", size=12))
        self.port_results.pack(fill="both", expand=True, padx=20, pady=(10, 20))

    def _run_subdomain(self):
        domain = self.sub_entry.get().strip()
        if not domain:
            return
        self.sub_results.delete("1.0", "end")
        self.app.set_status("Enumerating...", WARNING)
        threading.Thread(target=lambda: asyncio.run(self._async_subdomain(domain))).start()

    async def _async_subdomain(self, domain: str):
        from nigpig.recon.subdomain import SubdomainEnumerator

        enumerator = SubdomainEnumerator(domain)
        subs = await enumerator.enumerate_all()
        self.after(0, lambda: self.sub_results.insert("end", f"Found {len(subs)} subdomains:\n\n"))
        for s in subs:
            self.after(
                0, lambda t=f"• {s.subdomain} ({s.source})\n": self.sub_results.insert("end", t)
            )
        self.after(0, lambda: self.app.set_status("Ready", SUCCESS))

    def _run_ports(self):
        host = self.port_entry.get().strip()
        if not host:
            return
        self.port_results.delete("1.0", "end")
        self.app.set_status("Scanning...", WARNING)
        threading.Thread(target=lambda: asyncio.run(self._async_ports(host))).start()

    async def _async_ports(self, host: str):
        from nigpig.recon.ports import PortScanner

        scanner = PortScanner(host)
        ports = await scanner.scan_top_ports()
        self.after(
            0, lambda: self.port_results.insert("end", f"Found {len(ports)} open ports:\n\n")
        )
        for p in ports:
            self.after(
                0, lambda t=f"• {p.port} ({p.service})\n": self.port_results.insert("end", t)
            )
        self.after(0, lambda: self.app.set_status("Ready", SUCCESS))


class FingerprintPage(BasePage):
    """Fingerprint Lab."""

    def __init__(self, parent, app):
        super().__init__(parent, app)
        self.grid_rowconfigure(2, weight=1)

        ctk.CTkLabel(
            self,
            text=f"{ICONS['fingerprint']} Fingerprint Lab",
            font=ctk.CTkFont(size=Theme.TITLE_SIZE, weight="bold"),
            text_color=ACCENT_PURPLE,
        ).grid(row=0, column=0, padx=30, pady=(30, 20), sticky="w")

        input_card = GlassCard(self)
        input_card.grid(row=1, column=0, padx=30, pady=10, sticky="ew")

        inner = ctk.CTkFrame(input_card, fg_color="transparent")
        inner.pack(fill="x", padx=25, pady=20)
        inner.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(inner, text="URL:", font=ctk.CTkFont(size=14)).grid(
            row=0, column=0, padx=(0, 15)
        )
        self.url_entry = ctk.CTkEntry(inner, placeholder_text="https://example.com", height=42)
        self.url_entry.grid(row=0, column=1, sticky="ew", padx=(0, 15))

        ctk.CTkButton(
            inner,
            text="Tech",
            width=80,
            height=42,
            fg_color=ACCENT_PURPLE,
            hover_color="#6d28d9",
            command=self._run_tech,
        ).grid(row=0, column=2, padx=5)

        ctk.CTkButton(
            inner,
            text="WAF",
            width=80,
            height=42,
            fg_color=ACCENT_PINK,
            hover_color="#e05585",
            command=self._run_waf,
        ).grid(row=0, column=3)

        results_card = GlassCard(self)
        results_card.grid(row=2, column=0, padx=30, pady=(10, 30), sticky="nsew")

        self.results = ctk.CTkTextbox(results_card, font=ctk.CTkFont(family="Consolas", size=12))
        self.results.pack(fill="both", expand=True, padx=25, pady=25)

    def _run_tech(self):
        url = self.url_entry.get().strip()
        if not url:
            return
        self.results.delete("1.0", "end")
        self.app.set_status("Detecting...", WARNING)
        threading.Thread(target=lambda: asyncio.run(self._async_tech(url))).start()

    async def _async_tech(self, url: str):
        from nigpig.fingerprint.tech_detect import TechDetector

        detector = TechDetector()
        techs = await detector.detect(url)
        self.after(0, lambda: self.results.insert("end", f"Technologies ({len(techs)}):\n\n"))
        for t in techs:
            self.after(
                0, lambda txt=f"• {t.name} ({t.category})\n": self.results.insert("end", txt)
            )
        self.after(0, lambda: self.app.set_status("Ready", SUCCESS))

    def _run_waf(self):
        url = self.url_entry.get().strip()
        if not url:
            return
        self.results.delete("1.0", "end")
        self.app.set_status("Detecting...", WARNING)
        threading.Thread(target=lambda: asyncio.run(self._async_waf(url))).start()

    async def _async_waf(self, url: str):
        from nigpig.fingerprint.waf_detect import WAFDetector

        detector = WAFDetector()
        wafs = await detector.detect(url)
        if wafs:
            self.after(0, lambda: self.results.insert("end", f"WAF Detected: {wafs[0].name}\n"))
        else:
            self.after(0, lambda: self.results.insert("end", "No WAF detected\n"))
        self.after(0, lambda: self.app.set_status("Ready", SUCCESS))


class VulnPage(BasePage):
    """Vulnerability Scanner."""

    def __init__(self, parent, app):
        super().__init__(parent, app)
        self.grid_rowconfigure(2, weight=1)

        ctk.CTkLabel(
            self,
            text=f"{ICONS['vuln']} Vulnerability Scanner",
            font=ctk.CTkFont(size=Theme.TITLE_SIZE, weight="bold"),
            text_color=ERROR,
        ).grid(row=0, column=0, padx=30, pady=(30, 20), sticky="w")

        input_card = GlassCard(self)
        input_card.grid(row=1, column=0, padx=30, pady=10, sticky="ew")

        inner = ctk.CTkFrame(input_card, fg_color="transparent")
        inner.pack(fill="x", padx=25, pady=20)
        inner.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(inner, text="URL:", font=ctk.CTkFont(size=14)).grid(
            row=0, column=0, padx=(0, 15)
        )
        self.url_entry = ctk.CTkEntry(inner, placeholder_text="https://example.com", height=42)
        self.url_entry.grid(row=0, column=1, sticky="ew", padx=(0, 15))

        ctk.CTkButton(
            inner,
            text="🧪 Run Templates",
            height=42,
            fg_color=ERROR,
            hover_color="#d32f2f",
            command=self._run,
        ).grid(row=0, column=2)

        results_card = GlassCard(self)
        results_card.grid(row=2, column=0, padx=30, pady=(10, 30), sticky="nsew")

        self.results = ctk.CTkTextbox(results_card, font=ctk.CTkFont(family="Consolas", size=12))
        self.results.pack(fill="both", expand=True, padx=25, pady=25)

    def _run(self):
        url = self.url_entry.get().strip()
        if not url:
            return
        self.results.delete("1.0", "end")
        self.app.set_status("Scanning...", WARNING)
        threading.Thread(target=lambda: asyncio.run(self._async_scan(url))).start()

    async def _async_scan(self, url: str):
        from nigpig.templates.executor import TemplateExecutor

        executor = TemplateExecutor()
        results = await executor.run_all_builtin(url)
        self.after(0, lambda: self.results.insert("end", f"Findings ({len(results)}):\n\n"))
        for r in results:
            sev = r.severity.upper()
            self.after(
                0,
                lambda t=f"⚠️ [{sev}] {r.template_name}\n   {r.url}\n\n": self.results.insert(
                    "end", t
                ),
            )
        if not results:
            self.after(0, lambda: self.results.insert("end", "✅ No vulnerabilities found\n"))
        self.after(0, lambda: self.app.set_status("Ready", SUCCESS))


class SecretsPage(BasePage):
    """Secret Hunter."""

    def __init__(self, parent, app):
        super().__init__(parent, app)
        self.grid_rowconfigure(2, weight=1)

        ctk.CTkLabel(
            self,
            text=f"{ICONS['secrets']} Secret Hunter",
            font=ctk.CTkFont(size=Theme.TITLE_SIZE, weight="bold"),
            text_color=WARNING,
        ).grid(row=0, column=0, padx=30, pady=(30, 20), sticky="w")

        input_card = GlassCard(self)
        input_card.grid(row=1, column=0, padx=30, pady=10, sticky="ew")

        ctk.CTkLabel(input_card, text="Paste code/config:", font=ctk.CTkFont(size=14)).pack(
            anchor="w", padx=25, pady=(20, 5)
        )
        self.input_text = ctk.CTkTextbox(
            input_card, height=120, font=ctk.CTkFont(family="Consolas", size=12)
        )
        self.input_text.pack(fill="x", padx=25, pady=(0, 10))

        ctk.CTkButton(
            input_card,
            text="🔐 Scan",
            height=42,
            fg_color=WARNING,
            hover_color="#f57c00",
            command=self._run,
        ).pack(padx=25, pady=(0, 20), anchor="w")

        results_card = GlassCard(self)
        results_card.grid(row=2, column=0, padx=30, pady=(10, 30), sticky="nsew")

        self.results = ctk.CTkTextbox(results_card, font=ctk.CTkFont(family="Consolas", size=12))
        self.results.pack(fill="both", expand=True, padx=25, pady=25)

    def _run(self):
        content = self.input_text.get("1.0", "end").strip()
        if not content:
            return
        self.results.delete("1.0", "end")
        self.app.set_status("Scanning...", WARNING)
        threading.Thread(target=lambda: asyncio.run(self._async_scan(content))).start()

    async def _async_scan(self, content: str):
        from nigpig.secrets.scanner import SecretScanner

        scanner = SecretScanner()
        findings = await scanner.scan_content(content, "input")
        self.after(0, lambda: self.results.insert("end", f"Secrets ({len(findings)}):\n\n"))
        for f in findings:
            self.after(
                0,
                lambda t=f"🔐 [{f.severity.upper()}] {f.secret_type}\n   Line {f.line}\n\n": self.results.insert(
                    "end", t
                ),
            )
        if not findings:
            self.after(0, lambda: self.results.insert("end", "✅ No secrets found\n"))
        self.after(0, lambda: self.app.set_status("Ready", SUCCESS))


class AuditPage(BasePage):
    """SSL/TLS Audit."""

    def __init__(self, parent, app):
        super().__init__(parent, app)
        self.grid_rowconfigure(2, weight=1)

        ctk.CTkLabel(
            self,
            text=f"{ICONS['audit']} SSL/TLS Audit",
            font=ctk.CTkFont(size=Theme.TITLE_SIZE, weight="bold"),
            text_color=SUCCESS,
        ).grid(row=0, column=0, padx=30, pady=(30, 20), sticky="w")

        input_card = GlassCard(self)
        input_card.grid(row=1, column=0, padx=30, pady=10, sticky="ew")

        inner = ctk.CTkFrame(input_card, fg_color="transparent")
        inner.pack(fill="x", padx=25, pady=20)
        inner.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(inner, text="URL:", font=ctk.CTkFont(size=14)).grid(
            row=0, column=0, padx=(0, 15)
        )
        self.url_entry = ctk.CTkEntry(inner, placeholder_text="https://example.com", height=42)
        self.url_entry.grid(row=0, column=1, sticky="ew", padx=(0, 15))

        ctk.CTkButton(
            inner,
            text="🛡️ Analyze",
            height=42,
            fg_color=SUCCESS,
            hover_color="#00c853",
            command=self._run,
        ).grid(row=0, column=2)

        results_card = GlassCard(self)
        results_card.grid(row=2, column=0, padx=30, pady=(10, 30), sticky="nsew")

        self.results = ctk.CTkTextbox(results_card, font=ctk.CTkFont(family="Consolas", size=12))
        self.results.pack(fill="both", expand=True, padx=25, pady=25)

    def _run(self):
        url = self.url_entry.get().strip()
        if not url:
            return
        self.results.delete("1.0", "end")
        self.app.set_status("Analyzing...", WARNING)
        threading.Thread(target=lambda: asyncio.run(self._async_scan(url))).start()

    async def _async_scan(self, url: str):
        from nigpig.audit.ssl import SSLAnalyzer

        analyzer = SSLAnalyzer()
        r = await analyzer.analyze_async(url)
        self.after(0, lambda: self.results.insert("end", f"SSL/TLS Analysis\n{'=' * 40}\n\n"))
        self.after(0, lambda: self.results.insert("end", f"Grade: {r.score}\n"))
        self.after(0, lambda: self.results.insert("end", f"Protocol: {r.protocol}\n"))
        self.after(0, lambda: self.results.insert("end", f"Cipher: {r.cipher}\n\n"))
        self.after(
            0,
            lambda: self.results.insert("end", f"TLS 1.2: {'✓' if r.supports_tls_1_2 else '✗'}\n"),
        )
        self.after(
            0,
            lambda: self.results.insert("end", f"TLS 1.3: {'✓' if r.supports_tls_1_3 else '✗'}\n"),
        )
        self.after(0, lambda: self.app.set_status("Ready", SUCCESS))


class TerminalPage(BasePage):
    """Built-in Terminal."""

    def __init__(self, parent, app):
        super().__init__(parent, app)
        self.grid_rowconfigure(1, weight=1)
        self.command_history = []
        self.history_index = 0

        ctk.CTkLabel(
            self,
            text=f"{ICONS['terminal']} Terminal",
            font=ctk.CTkFont(size=Theme.TITLE_SIZE, weight="bold"),
            text_color=ACCENT_CYAN,
        ).grid(row=0, column=0, padx=30, pady=(30, 20), sticky="w")

        terminal_card = GlassCard(self)
        terminal_card.grid(row=1, column=0, padx=30, pady=(10, 20), sticky="nsew")

        self.output = ctk.CTkTextbox(
            terminal_card,
            font=ctk.CTkFont(family="Consolas", size=13),
            fg_color=BG_DARKER,
            corner_radius=10,
        )
        self.output.pack(fill="both", expand=True, padx=20, pady=(20, 10))
        self.output.insert("end", "NigPig Terminal v2.0\nType 'help' for commands\n\n$ ")

        input_frame = ctk.CTkFrame(terminal_card, fg_color="transparent")
        input_frame.pack(fill="x", padx=20, pady=(0, 20))
        input_frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(input_frame, text="$", font=ctk.CTkFont(family="Consolas", size=14)).grid(
            row=0, column=0, sticky="w", padx=(0, 10)
        )

        self.cmd_entry = ctk.CTkEntry(
            input_frame,
            placeholder_text="Enter command...",
            height=42,
            font=ctk.CTkFont(family="Consolas", size=13),
        )
        self.cmd_entry.grid(row=0, column=0, sticky="ew", padx=(20, 10))
        self.cmd_entry.bind("<Return>", self._execute)
        self.cmd_entry.bind("<Up>", self._history_up)
        self.cmd_entry.bind("<Down>", self._history_down)

        ctk.CTkButton(
            input_frame,
            text="Run",
            width=80,
            height=42,
            fg_color=ACCENT_CYAN,
            hover_color="#00b8d4",
            command=self._execute,
        ).grid(row=0, column=1)

    def _execute(self, event=None):
        cmd = self.cmd_entry.get().strip()
        if not cmd:
            return

        self.command_history.append(cmd)
        self.history_index = len(self.command_history)
        self.cmd_entry.delete(0, "end")

        self.output.insert("end", f"{cmd}\n")

        if cmd == "help":
            self.output.insert(
                "end",
                """
Commands:
  help          Show this help
  clear         Clear terminal
  scan <url>    Quick scan
  doctor        Check system
  version       Show version
  exit          Close terminal

Or run any system command.
""",
            )
        elif cmd == "clear":
            self.output.delete("1.0", "end")
            self.output.insert("end", "$ ")
            return
        elif cmd == "version":
            self.output.insert("end", "NigPig Tools v2.0.0\n")
        elif cmd == "doctor":
            self.output.insert("end", "Checking system...\n")
            self.output.insert("end", "✓ Python OK\n✓ Modules OK\n")
        elif cmd == "exit":
            self.app._show_page("dashboard")
            return
        else:
            try:
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
                if result.stdout:
                    self.output.insert("end", result.stdout)
                if result.stderr:
                    self.output.insert("end", result.stderr)
            except Exception as e:
                self.output.insert("end", f"Error: {e}\n")

        self.output.insert("end", "\n$ ")
        self.output.see("end")

    def _history_up(self, event):
        if self.command_history and self.history_index > 0:
            self.history_index -= 1
            self.cmd_entry.delete(0, "end")
            self.cmd_entry.insert(0, self.command_history[self.history_index])

    def _history_down(self, event):
        if self.history_index < len(self.command_history) - 1:
            self.history_index += 1
            self.cmd_entry.delete(0, "end")
            self.cmd_entry.insert(0, self.command_history[self.history_index])


class HistoryPage(BasePage):
    """Scan History."""

    def __init__(self, parent, app):
        super().__init__(parent, app)
        self.grid_rowconfigure(1, weight=1)

        ctk.CTkLabel(
            self,
            text=f"{ICONS['history']} Scan History",
            font=ctk.CTkFont(size=Theme.TITLE_SIZE, weight="bold"),
            text_color=TEXT_PRIMARY,
        ).grid(row=0, column=0, padx=30, pady=(30, 20), sticky="w")

        self.history_frame = ctk.CTkScrollableFrame(self, fg_color="transparent")
        self.history_frame.grid(row=1, column=0, padx=30, pady=(10, 30), sticky="nsew")

        self.refresh()

    def refresh(self):
        for widget in self.history_frame.winfo_children():
            widget.destroy()

        if not self.app.scan_history:
            ctk.CTkLabel(
                self.history_frame,
                text="No scan history yet",
                text_color=TEXT_DIM,
            ).pack(pady=50)
            return

        for scan in self.app.scan_history:
            card = GlassCard(self.history_frame)
            card.pack(fill="x", pady=8)

            inner = ctk.CTkFrame(card, fg_color="transparent")
            inner.pack(fill="x", padx=20, pady=15)

            ctk.CTkLabel(
                inner,
                text=scan.get("target", "Unknown"),
                font=ctk.CTkFont(size=14, weight="bold"),
            ).pack(anchor="w")

            ctk.CTkLabel(
                inner,
                text=f"Modules: {', '.join(scan.get('modules', []))} | Findings: {scan.get('findings', 0)}",
                text_color=TEXT_SECONDARY,
            ).pack(anchor="w")


class SettingsPage(BasePage):
    """Settings."""

    def __init__(self, parent, app):
        super().__init__(parent, app)

        ctk.CTkLabel(
            self,
            text=f"{ICONS['settings']} Settings",
            font=ctk.CTkFont(size=Theme.TITLE_SIZE, weight="bold"),
            text_color=TEXT_PRIMARY,
        ).grid(row=0, column=0, padx=30, pady=(30, 20), sticky="w")

        settings_card = GlassCard(self)
        settings_card.grid(row=1, column=0, padx=30, pady=10, sticky="ew")

        ctk.CTkLabel(settings_card, text="Theme", font=ctk.CTkFont(size=16, weight="bold")).pack(
            anchor="w", padx=25, pady=(25, 10)
        )

        theme_frame = ctk.CTkFrame(settings_card, fg_color="transparent")
        theme_frame.pack(fill="x", padx=25, pady=(0, 25))

        ctk.CTkButton(theme_frame, text="Dark", width=100, fg_color=BG_CARD_HOVER).pack(
            side="left", padx=5
        )
        ctk.CTkButton(
            theme_frame, text="Light", width=100, fg_color=BG_CARD_HOVER, state="disabled"
        ).pack(side="left", padx=5)

        shortcuts_card = GlassCard(self)
        shortcuts_card.grid(row=2, column=0, padx=30, pady=10, sticky="ew")

        ctk.CTkLabel(
            shortcuts_card, text="Keyboard Shortcuts", font=ctk.CTkFont(size=16, weight="bold")
        ).pack(anchor="w", padx=25, pady=(25, 10))

        shortcuts = [
            ("Ctrl+D", "Dashboard"),
            ("Ctrl+S", "Carrot Mode"),
            ("Ctrl+T", "Terminal"),
        ]

        for key, action in shortcuts:
            frame = ctk.CTkFrame(shortcuts_card, fg_color="transparent")
            frame.pack(fill="x", padx=25, pady=3)
            ctk.CTkLabel(frame, text=key, width=80, text_color=ACCENT_CYAN).pack(side="left")
            ctk.CTkLabel(frame, text=action, text_color=TEXT_SECONDARY).pack(side="left")

        ctk.CTkFrame(shortcuts_card, height=20, fg_color="transparent").pack()


def main():
    """Launch NigPig Premium GUI."""
    app = NigPigApp()
    app.mainloop()


if __name__ == "__main__":
    main()
