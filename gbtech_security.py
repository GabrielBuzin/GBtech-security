"""GBTech Security — monitoramento local e quarentena reversível para Windows.

Protótipo pessoal: não substitui uma solução de segurança com proteção em nível
de sistema. Ele não envia arquivos para a internet e nunca apaga itens sozinho.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import queue
import shutil
import smtplib
import sqlite3
import ssl
import sys
import threading
import time
import tkinter as tk
from datetime import datetime
from email.message import EmailMessage
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

import pystray
import keyring
from PIL import Image


APP_NAME = "GBTech Security"
DATA_DIR = Path(os.environ.get("LOCALAPPDATA", Path.home())) / "GBTechSecurity"
QUARANTINE_DIR = DATA_DIR / "quarantine"
DB_PATH = DATA_DIR / "security.db"
LOG_PATH = DATA_DIR / "gbtech-security.log"
SCAN_INTERVAL_SECONDS = 8
SUSPICIOUS_EXTENSIONS = {".exe", ".msi", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".scr", ".com", ".jar", ".hta", ".lnk", ".reg"}
ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".iso", ".img"}
DECOY_EXTENSIONS = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".jpeg", ".png", ".txt"}


def now() -> str:
    return datetime.now().strftime("%d/%m/%Y %H:%M")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class Storage:
    def __init__(self) -> None:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
        logging.basicConfig(filename=LOG_PATH, level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
        self.connection = sqlite3.connect(DB_PATH, check_same_thread=False)
        self.connection.execute(
            """CREATE TABLE IF NOT EXISTS quarantine (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                stored_name TEXT NOT NULL, original_path TEXT NOT NULL,
                display_name TEXT NOT NULL, reason TEXT NOT NULL,
                digest TEXT NOT NULL, quarantined_at TEXT NOT NULL
            )"""
        )
        self.connection.execute("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        self.connection.execute(
            """CREATE TABLE IF NOT EXISTS accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                provider TEXT NOT NULL, email TEXT NOT NULL, status TEXT NOT NULL
            )"""
        )
        self.connection.execute(
            """CREATE TABLE IF NOT EXISTS activity (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action TEXT NOT NULL, file_name TEXT NOT NULL,
                details TEXT NOT NULL, happened_at TEXT NOT NULL
            )"""
        )
        self.connection.commit()

    def watched_paths(self) -> list[str]:
        row = self.connection.execute("SELECT value FROM settings WHERE key='watched_paths'").fetchone()
        if row:
            return json.loads(row[0])
        downloads = Path.home() / "Downloads"
        desktop = Path.home() / "Desktop"
        paths = [str(p) for p in (downloads, desktop) if p.exists()]
        self.set_watched_paths(paths)
        return paths

    def set_watched_paths(self, paths: list[str]) -> None:
        self.connection.execute("INSERT OR REPLACE INTO settings(key, value) VALUES('watched_paths', ?)", (json.dumps(paths),))
        self.connection.commit()

    def setting(self, key: str, default: str = "") -> str:
        row = self.connection.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
        return row[0] if row else default

    def set_setting(self, key: str, value: str) -> None:
        self.connection.execute("INSERT OR REPLACE INTO settings(key, value) VALUES(?, ?)", (key, value))
        self.connection.commit()

    def add_quarantine(self, stored_name: str, original_path: str, display_name: str, reason: str, digest: str) -> None:
        self.connection.execute(
            "INSERT INTO quarantine(stored_name, original_path, display_name, reason, digest, quarantined_at) VALUES(?,?,?,?,?,?)",
            (stored_name, original_path, display_name, reason, digest, now()),
        )
        self.connection.commit()

    def items(self) -> list[tuple]:
        return self.connection.execute("SELECT id, display_name, reason, quarantined_at, original_path, digest, stored_name FROM quarantine ORDER BY id DESC").fetchall()

    def remove(self, item_id: int) -> None:
        self.connection.execute("DELETE FROM quarantine WHERE id=?", (item_id,))
        self.connection.commit()

    def accounts(self) -> list[tuple]:
        return self.connection.execute("SELECT id, provider, email, status FROM accounts ORDER BY id DESC").fetchall()

    def add_account(self, provider: str, email: str) -> None:
        self.connection.execute("INSERT INTO accounts(provider, email, status) VALUES(?,?,?)", (provider, email, "Não conectado"))
        self.connection.commit()

    def remove_account(self, account_id: int) -> None:
        self.connection.execute("DELETE FROM accounts WHERE id=?", (account_id,))
        self.connection.commit()

    def log_activity(self, action: str, file_name: str, details: str) -> None:
        self.connection.execute(
            "INSERT INTO activity(action, file_name, details, happened_at) VALUES(?,?,?,?)",
            (action, file_name, details, now()),
        )
        self.connection.commit()

    def activity(self) -> list[tuple]:
        return self.connection.execute(
            "SELECT action, file_name, details, happened_at FROM activity ORDER BY id DESC LIMIT 250"
        ).fetchall()

    def gmail_config(self) -> tuple[str, str]:
        return self.setting("gmail_sender"), self.setting("gmail_recipient")

    def set_gmail_config(self, sender: str, recipient: str) -> None:
        self.set_setting("gmail_sender", sender)
        self.set_setting("gmail_recipient", recipient)


class Monitor(threading.Thread):
    def __init__(self, store: Storage, events: queue.Queue) -> None:
        super().__init__(daemon=True)
        self.store, self.events = store, events
        self.running = threading.Event()
        self.running.set()
        self.seen: set[str] = set()

    def stop(self) -> None:
        self.running.clear()

    @staticmethod
    def reason_for(path: Path) -> str | None:
        suffixes = [part.lower() for part in path.suffixes]
        last = path.suffix.lower()
        if len(suffixes) >= 2 and suffixes[-1] in SUSPICIOUS_EXTENSIONS:
            return "Extensão dupla que pode ocultar um arquivo executável"
        if last in SUSPICIOUS_EXTENSIONS:
            return f"Arquivo executável ou script ({last}) detectado em pasta monitorada"
        if "\u202e" in path.name:
            return "Nome de arquivo usa um caractere que pode ocultar a extensão real"
        if path.name.startswith("."):
            return "Arquivo oculto criado em uma pasta monitorada"
        try:
            with path.open("rb") as file:
                header = file.read(4)
            if header[:2] == b"MZ" and last in DECOY_EXTENSIONS:
                return "Arquivo tem formato executável, mas usa uma extensão de documento ou imagem"
        except OSError:
            return None
        if last in ARCHIVE_EXTENSIONS:
            return f"Arquivo compactado para revisão ({last})"
        return None

    def isolate(self, path: Path, reason: str) -> None:
        try:
            digest = sha256(path)
            stored_name = f"{int(time.time() * 1000)}_{digest[:12]}.gbq"
            target = QUARANTINE_DIR / stored_name
            shutil.move(str(path), str(target))
            self.store.add_quarantine(stored_name, str(path), path.name, reason, digest)
            self.store.log_activity("Arquivo isolado", path.name, reason)
            self.events.put(("quarantined", path.name, reason))
        except (OSError, PermissionError) as error:
            self.events.put(("error", path.name, f"Não foi possível isolar: {error}"))

    def run(self) -> None:
        while self.running.is_set():
            for folder_name in self.store.watched_paths():
                folder = Path(folder_name)
                if not folder.exists():
                    continue
                try:
                    files = [p for p in folder.rglob("*") if p.is_file() and QUARANTINE_DIR not in p.parents]
                except OSError:
                    continue
                for path in files:
                    key = str(path).lower()
                    if key in self.seen:
                        continue
                    self.seen.add(key)
                    reason = self.reason_for(path)
                    if reason:
                        self.isolate(path, reason)
            time.sleep(SCAN_INTERVAL_SECONDS)


class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.store = Storage()
        self.events: queue.Queue = queue.Queue()
        self.monitor: Monitor | None = None
        self.logo_image: tk.PhotoImage | None = None
        self.taskbar_icon: tk.PhotoImage | None = None
        self.tray_icon: pystray.Icon | None = None
        self.title(APP_NAME)
        self.geometry("1060x700")
        self.minsize(920, 600)
        self.configure(bg="#101828")
        self.style = ttk.Style(self)
        self.style.theme_use("clam")
        self._style()
        logo_path = Path(__file__).with_name("gbtech-logo.png")
        if logo_path.exists():
            self.taskbar_icon = tk.PhotoImage(file=str(logo_path))
            self.iconphoto(True, self.taskbar_icon)
        self._ui()
        self.start_monitor()
        self.start_tray()
        self.after(500, self.process_events)
        self.protocol("WM_DELETE_WINDOW", self.minimize_to_background)
        self.bind("<Control-Shift-Q>", lambda _event: self.close())

    def _style(self) -> None:
        self.style.configure("Main.TFrame", background="#101828")
        self.style.configure("Panel.TFrame", background="#182230")
        self.style.configure("Card.TFrame", background="#243246")
        self.style.configure("Hero.TFrame", background="#152d34")
        self.style.configure("Title.TLabel", background="#101828", foreground="#ffffff", font=("Segoe UI", 22, "bold"))
        self.style.configure("Subtitle.TLabel", background="#101828", foreground="#98a2b3", font=("Segoe UI", 10))
        self.style.configure("HeroTitle.TLabel", background="#152d34", foreground="#ffffff", font=("Segoe UI", 20, "bold"))
        self.style.configure("HeroText.TLabel", background="#152d34", foreground="#d0d5dd", font=("Segoe UI", 10))
        self.style.configure("Text.TLabel", background="#182230", foreground="#d0d5dd", font=("Segoe UI", 10))
        self.style.configure("CardTitle.TLabel", background="#243246", foreground="#ffffff", font=("Segoe UI", 12, "bold"))
        self.style.configure("CardText.TLabel", background="#243246", foreground="#d0d5dd", font=("Segoe UI", 10))
        self.style.configure("Status.TLabel", background="#182230", foreground="#6ce9a6", font=("Segoe UI", 11, "bold"))
        self.style.configure("HeroStatus.TLabel", background="#152d34", foreground="#6ce9a6", font=("Segoe UI", 11, "bold"))
        self.style.configure("Accent.TButton", background="#16a34a", foreground="#ffffff", padding=(14, 8), font=("Segoe UI", 10, "bold"))
        self.style.map("Accent.TButton", background=[("active", "#15803d")])
        self.style.configure("Quiet.TButton", background="#243246", foreground="#ffffff", padding=(12, 8), font=("Segoe UI", 9))
        self.style.configure("Treeview", background="#ffffff", fieldbackground="#ffffff", foreground="#101828", rowheight=30, font=("Segoe UI", 9))
        self.style.configure("Treeview.Heading", font=("Segoe UI", 9, "bold"))

    def _ui(self) -> None:
        shell = ttk.Frame(self, style="Main.TFrame", padding=24)
        shell.pack(fill="both", expand=True)
        header = ttk.Frame(shell, style="Main.TFrame")
        header.pack(fill="x")
        logo_path = Path(__file__).with_name("gbtech-logo.png")
        if logo_path.exists():
            self.logo_image = tk.PhotoImage(file=str(logo_path)).subsample(3, 3)
            tk.Label(header, image=self.logo_image, bg="#101828").pack(side="left", padx=(0, 10))
        brand = ttk.Frame(header, style="Main.TFrame")
        brand.pack(side="left")
        ttk.Label(brand, text="GBTech", style="Title.TLabel").pack(anchor="w")
        ttk.Label(brand, text="Security center", style="Subtitle.TLabel").pack(anchor="w")
        tk.Label(header, text="  PROTEÇÃO LOCAL", bg="#11332b", fg="#6ce9a6", font=("Segoe UI", 9, "bold"), padx=10, pady=5).pack(side="right", pady=8)

        self.style.configure("TNotebook", background="#101828", borderwidth=0)
        self.style.configure("TNotebook.Tab", background="#182230", foreground="#d0d5dd", padding=(16, 9), font=("Segoe UI", 9, "bold"))
        self.style.map("TNotebook.Tab", background=[("selected", "#16a34a")], foreground=[("selected", "#ffffff")])
        notebook = ttk.Notebook(shell)
        notebook.pack(fill="both", expand=True, pady=(20, 0))
        dashboard = ttk.Frame(notebook, style="Main.TFrame", padding=(0, 18, 0, 0))
        quarantine = ttk.Frame(notebook, style="Main.TFrame", padding=(0, 18, 0, 0))
        activity = ttk.Frame(notebook, style="Main.TFrame", padding=(0, 18, 0, 0))
        protection = ttk.Frame(notebook, style="Main.TFrame", padding=(0, 18, 0, 0))
        settings = ttk.Frame(notebook, style="Main.TFrame", padding=(0, 18, 0, 0))
        notebook.add(dashboard, text="Painel")
        notebook.add(quarantine, text="Quarentena")
        notebook.add(activity, text="Atividade")
        notebook.add(protection, text="Proteção")
        notebook.add(settings, text="Configurações")

        overview = ttk.Frame(dashboard, style="Hero.TFrame", padding=24)
        overview.pack(fill="x", pady=(0, 16))
        hero_left = ttk.Frame(overview, style="Hero.TFrame")
        hero_left.pack(side="left", fill="both", expand=True)
        ttk.Label(hero_left, text="●  PROTEÇÃO ATIVA", style="HeroStatus.TLabel").pack(anchor="w")
        ttk.Label(hero_left, text="Seu computador está sendo monitorado", style="HeroTitle.TLabel").pack(anchor="w", pady=(8, 4))
        self.summary = ttk.Label(hero_left, text="Pastas selecionadas são verificadas continuamente e itens suspeitos vão para quarentena.", style="HeroText.TLabel", wraplength=650)
        self.summary.pack(anchor="w", pady=(6, 14))
        ttk.Button(hero_left, text="Verificar agora", style="Accent.TButton", command=self.scan_now).pack(anchor="w")
        if self.logo_image:
            tk.Label(overview, image=self.logo_image, bg="#152d34").pack(side="right", padx=(20, 8))

        cards = ttk.Frame(dashboard, style="Main.TFrame")
        cards.pack(fill="x", pady=(0, 16))
        self.card(cards, "Monitoramento", "Ativo", "Pastas verificadas continuamente", 0)
        self.card(cards, "Quarentena", "0 itens", "Arquivos isolados de forma reversível", 1)
        self.card(cards, "Contas", "Local", "Integrações futuras, sem senha salva", 2)

        quick = ttk.Frame(dashboard, style="Panel.TFrame", padding=18)
        quick.pack(fill="x")
        ttk.Label(quick, text="Resumo rápido", style="Text.TLabel", font=("Segoe UI", 11, "bold")).pack(anchor="w")
        ttk.Label(quick, text="O monitoramento continua funcionando mesmo quando a janela fica na área de notificação.", style="Text.TLabel").pack(anchor="w", pady=(6, 0))

        section = ttk.Frame(quarantine, style="Main.TFrame")
        section.pack(fill="both", expand=True)
        section_header = ttk.Frame(section, style="Main.TFrame")
        section_header.pack(fill="x", pady=(0, 8))
        ttk.Label(section_header, text="Quarentena", style="Title.TLabel", font=("Segoe UI", 15, "bold")).pack(side="left")
        ttk.Label(section_header, text="Itens isolados aguardando sua decisão", style="Subtitle.TLabel").pack(side="left", padx=12)
        columns = ("name", "reason", "date")
        self.tree = ttk.Treeview(section, columns=columns, show="headings", selectmode="extended")
        self.tree.heading("name", text="Arquivo")
        self.tree.heading("reason", text="Motivo")
        self.tree.heading("date", text="Isolado em")
        self.tree.column("name", width=210)
        self.tree.column("reason", width=500)
        self.tree.column("date", width=140)
        self.tree.pack(fill="both", expand=True)
        actions = ttk.Frame(quarantine, style="Main.TFrame")
        actions.pack(fill="x", pady=(12, 0))
        self.select_all_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(actions, text="Selecionar todos", variable=self.select_all_var, command=self.toggle_select_all).pack(side="left", padx=(0, 12))
        ttk.Button(actions, text="Restaurar selecionados", style="Quiet.TButton", command=self.restore_selected).pack(side="left")
        ttk.Button(actions, text="Excluir selecionados", style="Quiet.TButton", command=self.delete_selected).pack(side="left", padx=8)
        ttk.Button(actions, text="Gerenciar pastas", style="Quiet.TButton", command=self.manage_folders).pack(side="right")
        ttk.Button(actions, text="Contas", style="Quiet.TButton", command=self.manage_accounts).pack(side="right", padx=8)
        ttk.Button(actions, text="Minimizar", style="Quiet.TButton", command=self.minimize_to_background).pack(side="right", padx=8)

        ttk.Label(activity, text="Histórico de atividade", style="Title.TLabel", font=("Segoe UI", 15, "bold")).pack(anchor="w", pady=(0, 8))
        ttk.Label(activity, text="Registro local das decisões do GBTech Security.", style="Subtitle.TLabel").pack(anchor="w", pady=(0, 12))
        activity_columns = ("action", "file", "details", "date")
        self.activity_tree = ttk.Treeview(activity, columns=activity_columns, show="headings")
        for key, label, width in (("action", "Ação", 150), ("file", "Arquivo", 190), ("details", "Detalhes", 480), ("date", "Data", 150)):
            self.activity_tree.heading(key, text=label)
            self.activity_tree.column(key, width=width)
        self.activity_tree.pack(fill="both", expand=True)

        ttk.Label(protection, text="Central de proteção", style="Title.TLabel", font=("Segoe UI", 15, "bold")).pack(anchor="w", pady=(0, 8))
        ttk.Label(protection, text="Pastas monitoradas", style="Subtitle.TLabel").pack(anchor="w")
        self.paths_list = tk.Listbox(protection, bg="#243246", fg="#ffffff", selectbackground="#16a34a", borderwidth=0, font=("Segoe UI", 10), height=9)
        self.paths_list.pack(fill="x", pady=(8, 14))
        protection_actions = ttk.Frame(protection, style="Main.TFrame")
        protection_actions.pack(fill="x")
        ttk.Button(protection_actions, text="Gerenciar pastas", style="Accent.TButton", command=self.manage_folders).pack(side="left")
        ttk.Button(protection_actions, text="Verificar agora", style="Quiet.TButton", command=self.scan_now).pack(side="left", padx=8)
        self.monitor_button = ttk.Button(protection_actions, text="Pausar monitoramento", style="Quiet.TButton", command=self.toggle_monitor)
        self.monitor_button.pack(side="left")

        ttk.Label(settings, text="Configurações", style="Title.TLabel", font=("Segoe UI", 15, "bold")).pack(anchor="w", pady=(0, 8))
        preferences = ttk.Frame(settings, style="Panel.TFrame", padding=20)
        preferences.pack(fill="x")
        ttk.Label(preferences, text="Contas e integrações", style="Text.TLabel", font=("Segoe UI", 12, "bold")).pack(anchor="w")
        ttk.Label(preferences, text="Registre contas futuras sem salvar senhas ou chaves no aplicativo.", style="Text.TLabel").pack(anchor="w", pady=(5, 14))
        ttk.Button(preferences, text="Gerenciar contas", style="Accent.TButton", command=self.manage_accounts).pack(anchor="w")
        privacy = ttk.Frame(settings, style="Panel.TFrame", padding=20)
        privacy.pack(fill="x", pady=14)
        ttk.Label(privacy, text="Privacidade", style="Text.TLabel", font=("Segoe UI", 12, "bold")).pack(anchor="w")
        ttk.Label(privacy, text="Arquivos, hashes e registros permanecem neste computador. Consultas online só serão ativadas se você configurar um serviço externo.", style="Text.TLabel", wraplength=820).pack(anchor="w", pady=(5, 0))
        email_alerts = ttk.Frame(settings, style="Panel.TFrame", padding=20)
        email_alerts.pack(fill="x")
        ttk.Label(email_alerts, text="Alertas por Gmail", style="Text.TLabel", font=("Segoe UI", 12, "bold")).pack(anchor="w")
        ttk.Label(email_alerts, text="Envie um e-mail quando um arquivo for isolado. A senha de aplicativo fica somente no cofre de credenciais do Windows.", style="Text.TLabel", wraplength=820).pack(anchor="w", pady=(5, 14))
        ttk.Button(email_alerts, text="Configurar Gmail", style="Accent.TButton", command=self.configure_gmail).pack(anchor="w")
        self.refresh()

    def card(self, parent: ttk.Frame, title: str, value: str, description: str, column: int) -> None:
        parent.columnconfigure(column, weight=1)
        frame = ttk.Frame(parent, style="Card.TFrame", padding=16)
        frame.grid(row=0, column=column, padx=(0 if column == 0 else 8, 0), sticky="nsew")
        ttk.Label(frame, text=title, style="CardText.TLabel").pack(anchor="w")
        label = ttk.Label(frame, text=value, style="CardTitle.TLabel")
        label.pack(anchor="w", pady=5)
        if title == "Quarentena":
            self.quarantine_count = label
        ttk.Label(frame, text=description, style="CardText.TLabel").pack(anchor="w")

    def start_monitor(self) -> None:
        self.monitor = Monitor(self.store, self.events)
        self.monitor.start()

    def start_tray(self) -> None:
        try:
            logo_path = Path(__file__).with_name("gbtech-logo.png")
            image = Image.open(logo_path).convert("RGBA").resize((64, 64)) if logo_path.exists() else Image.new("RGBA", (64, 64), "#16a34a")
            menu = pystray.Menu(
                pystray.MenuItem("Abrir GBTech Security", lambda *_: self.events.put(("open", "", "")), default=True),
                pystray.MenuItem("Encerrar monitoramento", lambda *_: self.events.put(("quit", "", ""))),
            )
            self.tray_icon = pystray.Icon("GBTechSecurity", image, "GBTech Security", menu)
            threading.Thread(target=self.run_tray, daemon=True).start()
        except Exception:
            logging.exception("Não foi possível iniciar o ícone da área de notificação")

    def run_tray(self) -> None:
        try:
            if self.tray_icon:
                self.tray_icon.run()
        except Exception:
            logging.exception("O ícone da área de notificação foi encerrado")

    def process_events(self) -> None:
        try:
            while True:
                kind, name, detail = self.events.get_nowait()
                if kind == "quarantined":
                    self.summary.configure(text=f"{name} foi isolado para revisão: {detail}")
                    self.show_alert(name, detail)
                    self.send_email_alert_async(name, detail)
                    self.refresh()
                elif kind == "error":
                    self.summary.configure(text=detail)
                elif kind == "open":
                    self.deiconify()
                    self.lift()
                    self.focus_force()
                elif kind == "quit":
                    self.close()
                elif kind == "mail_sent":
                    self.store.log_activity("E-mail enviado", name, detail)
                    self.refresh_activity()
                elif kind == "mail_error":
                    self.store.log_activity("Falha no e-mail", name, detail)
                    self.refresh_activity()
        except queue.Empty:
            pass
        self.after(500, self.process_events)

    def show_alert(self, name: str, detail: str) -> None:
        """A non-blocking desktop alert, useful even while the main window is minimized."""
        try:
            import winsound
            winsound.MessageBeep(winsound.MB_ICONEXCLAMATION)
        except (ImportError, RuntimeError):
            pass
        toast = tk.Toplevel(self)
        toast.title(APP_NAME)
        toast.configure(bg="#182230")
        toast.attributes("-topmost", True)
        toast.resizable(False, False)
        tk.Label(toast, text="GBTech Security", bg="#182230", fg="#6ce9a6", font=("Segoe UI", 11, "bold")).pack(anchor="w", padx=18, pady=(14, 2))
        tk.Label(toast, text="Arquivo isolado para revisão", bg="#182230", fg="white", font=("Segoe UI", 10, "bold")).pack(anchor="w", padx=18)
        tk.Label(toast, text=f"{name}\n{detail}", bg="#182230", fg="#d0d5dd", justify="left", wraplength=350, font=("Segoe UI", 9)).pack(anchor="w", padx=18, pady=(5, 12))
        ttk.Button(toast, text="Abrir quarentena", command=lambda: (toast.destroy(), self.deiconify(), self.lift())).pack(anchor="e", padx=18, pady=(0, 14))
        toast.geometry("410x175+900+650")
        toast.after(12000, lambda: toast.winfo_exists() and toast.destroy())

    def send_email_alert_async(self, name: str, detail: str) -> None:
        sender, recipient = self.store.gmail_config()
        if sender and recipient:
            threading.Thread(target=self.send_email_alert, args=(sender, recipient, name, detail), daemon=True).start()

    def send_email_alert(self, sender: str, recipient: str, name: str, detail: str) -> None:
        try:
            password = keyring.get_password("GBTech Security Gmail", sender)
            if not password:
                raise RuntimeError("A senha de aplicativo do Gmail não está configurada")
            message = EmailMessage()
            message["Subject"] = f"GBTech Security: arquivo isolado — {name}"
            message["From"] = sender
            message["To"] = recipient
            message.set_content(f"O GBTech Security isolou o arquivo '{name}'.\n\nMotivo: {detail}\n\nRevise o item na tela de Quarentena.")
            with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=ssl.create_default_context(), timeout=20) as server:
                server.login(sender, password)
                server.send_message(message)
            self.events.put(("mail_sent", name, f"Alerta enviado para {recipient}"))
        except Exception as error:
            logging.exception("Não foi possível enviar alerta por Gmail")
            self.events.put(("mail_error", name, f"Não foi possível enviar o alerta por Gmail: {error}"))

    def refresh(self) -> None:
        for row in self.tree.get_children():
            self.tree.delete(row)
        items = self.store.items()
        for item in items:
            self.tree.insert("", "end", iid=str(item[0]), values=(item[1], item[2], item[3]))
        self.quarantine_count.configure(text=f"{len(items)} item" + ("" if len(items) == 1 else "s"))
        self.select_all_var.set(False)
        self.refresh_activity()
        self.refresh_protection()

    def refresh_activity(self) -> None:
        for row in self.activity_tree.get_children():
            self.activity_tree.delete(row)
        for action, file_name, details, happened_at in self.store.activity():
            self.activity_tree.insert("", "end", values=(action, file_name, details, happened_at))

    def refresh_protection(self) -> None:
        self.paths_list.delete(0, "end")
        for path in self.store.watched_paths():
            self.paths_list.insert("end", path)
        is_active = self.monitor is not None and self.monitor.running.is_set()
        self.monitor_button.configure(text="Pausar monitoramento" if is_active else "Ativar monitoramento")

    def toggle_monitor(self) -> None:
        if self.monitor and self.monitor.running.is_set():
            self.monitor.stop()
            self.store.log_activity("Monitoramento pausado", "Proteção local", "A verificação contínua foi pausada pelo usuário")
            self.summary.configure(text="Monitoramento pausado. Os arquivos existentes continuam na quarentena.")
        else:
            self.start_monitor()
            self.store.log_activity("Monitoramento ativado", "Proteção local", "A verificação contínua foi retomada")
            self.summary.configure(text="Monitoramento ativo novamente.")
        self.refresh()

    def scan_now(self) -> None:
        self.summary.configure(text="A verificação usa as mesmas regras locais do monitoramento. Aguarde alguns segundos.")
        if self.monitor:
            self.monitor.seen.clear()

    def selected_item(self) -> tuple | None:
        items = self.selected_items()
        return items[0] if items else None

    def selected_items(self) -> list[tuple]:
        selected = self.tree.selection()
        if not selected:
            messagebox.showinfo(APP_NAME, "Selecione um item da quarentena primeiro.")
            return []
        indexed = {item[0]: item for item in self.store.items()}
        return [indexed[int(item_id)] for item_id in selected if int(item_id) in indexed]

    def toggle_select_all(self) -> None:
        rows = self.tree.get_children()
        if self.select_all_var.get():
            self.tree.selection_set(rows)
        else:
            self.tree.selection_remove(rows)

    def restore_selected(self) -> None:
        items = self.selected_items()
        if not items:
            return
        if not messagebox.askyesno(APP_NAME, f"Restaurar {len(items)} item(ns) pode permitir a execução de arquivos. Deseja continuar?"):
            return
        restored = 0
        for item in items:
            try:
                original = Path(item[4])
                original.parent.mkdir(parents=True, exist_ok=True)
                shutil.move(str(QUARANTINE_DIR / item[6]), str(original))
                self.store.remove(item[0])
                self.store.log_activity("Arquivo restaurado", item[1], "O arquivo foi devolvido à pasta original")
                restored += 1
            except OSError as error:
                logging.exception("Não foi possível restaurar %s: %s", item[1], error)
        self.refresh()
        self.summary.configure(text=f"{restored} item(ns) restaurado(s) para a pasta original.")

    def delete_selected(self) -> None:
        items = self.selected_items()
        if not items or not messagebox.askyesno(APP_NAME, f"Excluir {len(items)} item(ns) da quarentena permanentemente?"):
            return
        deleted = 0
        for item in items:
            try:
                (QUARANTINE_DIR / item[6]).unlink(missing_ok=True)
                self.store.remove(item[0])
                self.store.log_activity("Arquivo excluído", item[1], "O item foi excluído permanentemente da quarentena")
                deleted += 1
            except OSError as error:
                logging.exception("Não foi possível excluir %s: %s", item[1], error)
        self.refresh()
        self.summary.configure(text=f"{deleted} item(ns) excluído(s) da quarentena.")

    def manage_folders(self) -> None:
        chosen = filedialog.askdirectory(title="Escolha uma pasta para monitorar", initialdir=str(Path.home()))
        if not chosen:
            return
        paths = self.store.watched_paths()
        if chosen in paths:
            messagebox.showinfo(APP_NAME, "Essa pasta já está sendo monitorada.")
            return
        paths.append(chosen)
        self.store.set_watched_paths(paths)
        if self.monitor:
            self.monitor.seen.clear()
        self.store.log_activity("Pasta adicionada", "Proteção local", f"A pasta {chosen} foi adicionada ao monitoramento")
        self.summary.configure(text="Nova pasta adicionada ao monitoramento.")
        self.refresh()

    def configure_gmail(self) -> None:
        dialog = tk.Toplevel(self)
        dialog.title("Configurar alertas por Gmail")
        dialog.geometry("560x360")
        dialog.configure(bg="#182230")
        sender_saved, recipient_saved = self.store.gmail_config()
        tk.Label(dialog, text="Alertas por Gmail", bg="#182230", fg="white", font=("Segoe UI", 14, "bold")).pack(anchor="w", padx=20, pady=(20, 4))
        tk.Label(dialog, text="Use uma senha de aplicativo do Google. Ela não é salva no projeto nem enviada para o GBTech.", bg="#182230", fg="#d0d5dd", wraplength=500, justify="left", font=("Segoe UI", 9)).pack(anchor="w", padx=20, pady=(0, 14))
        form = ttk.Frame(dialog, style="Panel.TFrame", padding=14)
        form.pack(fill="x", padx=20)
        ttk.Label(form, text="Seu endereço Gmail", style="Text.TLabel").grid(row=0, column=0, sticky="w")
        sender = ttk.Entry(form, width=42)
        sender.insert(0, sender_saved)
        sender.grid(row=1, column=0, sticky="ew", pady=(2, 10))
        ttk.Label(form, text="E-mail que receberá os alertas", style="Text.TLabel").grid(row=2, column=0, sticky="w")
        recipient = ttk.Entry(form, width=42)
        recipient.insert(0, recipient_saved or sender_saved)
        recipient.grid(row=3, column=0, sticky="ew", pady=(2, 10))
        ttk.Label(form, text="Senha de aplicativo do Google", style="Text.TLabel").grid(row=4, column=0, sticky="w")
        password = ttk.Entry(form, width=42, show="•")
        password.grid(row=5, column=0, sticky="ew", pady=(2, 0))
        form.columnconfigure(0, weight=1)
        def save() -> None:
            sender_value, recipient_value, password_value = sender.get().strip(), recipient.get().strip(), password.get().strip()
            if "@" not in sender_value or "@" not in recipient_value or not password_value:
                messagebox.showinfo(APP_NAME, "Informe os dois e-mails e a senha de aplicativo do Google.")
                return
            keyring.set_password("GBTech Security Gmail", sender_value, password_value)
            self.store.set_gmail_config(sender_value, recipient_value)
            self.store.log_activity("Gmail configurado", "Alertas por e-mail", f"Alertas serão enviados para {recipient_value}")
            dialog.destroy()
            self.refresh_activity()
            self.summary.configure(text="Alertas por Gmail configurados. O próximo arquivo isolado enviará um aviso.")
        ttk.Button(dialog, text="Salvar configuração", style="Accent.TButton", command=save).pack(anchor="e", padx=20, pady=16)

    def manage_accounts(self) -> None:
        dialog = tk.Toplevel(self)
        dialog.title("Contas e integrações")
        dialog.geometry("620x380")
        dialog.configure(bg="#182230")
        tk.Label(dialog, text="Contas e integrações", bg="#182230", fg="white", font=("Segoe UI", 14, "bold")).pack(anchor="w", padx=18, pady=(18, 3))
        tk.Label(dialog, text="Guarde apenas o e-mail de referência. Senhas e chaves não são armazenadas neste protótipo.", bg="#182230", fg="#d0d5dd", font=("Segoe UI", 9)).pack(anchor="w", padx=18, pady=(0, 12))
        tree = ttk.Treeview(dialog, columns=("provider", "email", "status"), show="headings", height=7)
        for key, label, width in (("provider", "Serviço", 150), ("email", "E-mail ou identificação", 280), ("status", "Status", 130)):
            tree.heading(key, text=label)
            tree.column(key, width=width)
        tree.pack(fill="both", expand=True, padx=18)
        def refresh_accounts() -> None:
            for row in tree.get_children():
                tree.delete(row)
            for account in self.store.accounts():
                tree.insert("", "end", iid=str(account[0]), values=account[1:])
        bottom = ttk.Frame(dialog, style="Panel.TFrame", padding=12)
        bottom.pack(fill="x", padx=18, pady=14)
        ttk.Label(bottom, text="Serviço", style="Text.TLabel").grid(row=0, column=0, sticky="w")
        provider = ttk.Combobox(bottom, values=("Bitdefender GravityZone", "Microsoft", "Outro"), state="readonly", width=22)
        provider.set("Bitdefender GravityZone")
        provider.grid(row=1, column=0, padx=(0, 8), sticky="ew")
        ttk.Label(bottom, text="E-mail ou identificação", style="Text.TLabel").grid(row=0, column=1, sticky="w")
        email = ttk.Entry(bottom, width=30)
        email.grid(row=1, column=1, padx=(0, 8), sticky="ew")
        bottom.columnconfigure(1, weight=1)
        def add() -> None:
            value = email.get().strip()
            if not value:
                messagebox.showinfo(APP_NAME, "Informe um e-mail ou identificação para a conta.")
                return
            self.store.add_account(provider.get(), value)
            email.delete(0, "end")
            refresh_accounts()
        def remove() -> None:
            picked = tree.selection()
            if picked:
                self.store.remove_account(int(picked[0]))
                refresh_accounts()
        ttk.Button(bottom, text="Adicionar", command=add).grid(row=1, column=2, padx=(0, 8))
        ttk.Button(bottom, text="Remover", command=remove).grid(row=1, column=3)
        refresh_accounts()

    def close(self) -> None:
        if self.monitor:
            self.monitor.stop()
        if self.tray_icon:
            self.tray_icon.stop()
        self.destroy()

    def minimize_to_background(self) -> None:
        """Keep monitoring active while the application stays minimized on the taskbar."""
        self.summary.configure(text="GBTech Security continua monitorando na área de notificação do Windows.")
        self.withdraw()


if __name__ == "__main__":
    if sys.platform != "win32":
        print("Este protótipo foi criado para Windows.")
    else:
        App().mainloop()
