"""GBTech Security — monitoramento local e quarentena reversível para Windows.

Protótipo pessoal: não substitui uma solução de segurança com proteção em nível
de sistema. Ele não envia arquivos para a internet e nunca apaga itens sozinho.
"""

from __future__ import annotations

import hashlib
import json
import os
import queue
import shutil
import sqlite3
import sys
import threading
import time
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import messagebox, ttk

import pystray
from PIL import Image


APP_NAME = "GBTech Security"
DATA_DIR = Path(os.environ.get("LOCALAPPDATA", Path.home())) / "GBTechSecurity"
QUARANTINE_DIR = DATA_DIR / "quarantine"
DB_PATH = DATA_DIR / "security.db"
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
        self.tray_icon: pystray.Icon | None = None
        self.title(APP_NAME)
        self.geometry("980x640")
        self.minsize(860, 540)
        self.configure(bg="#101828")
        self.style = ttk.Style(self)
        self.style.theme_use("clam")
        self._style()
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
        self.style.configure("Title.TLabel", background="#101828", foreground="#ffffff", font=("Segoe UI", 22, "bold"))
        self.style.configure("Text.TLabel", background="#182230", foreground="#d0d5dd", font=("Segoe UI", 10))
        self.style.configure("CardTitle.TLabel", background="#243246", foreground="#ffffff", font=("Segoe UI", 12, "bold"))
        self.style.configure("CardText.TLabel", background="#243246", foreground="#d0d5dd", font=("Segoe UI", 10))
        self.style.configure("Status.TLabel", background="#182230", foreground="#6ce9a6", font=("Segoe UI", 11, "bold"))
        self.style.configure("Accent.TButton", background="#16a34a", foreground="#ffffff", padding=(14, 8), font=("Segoe UI", 10, "bold"))
        self.style.map("Accent.TButton", background=[("active", "#15803d")])
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
        ttk.Label(header, text="GBTech", style="Title.TLabel").pack(side="left")
        ttk.Label(header, text=" SECURITY", style="Title.TLabel", foreground="#6ce9a6").pack(side="left")
        ttk.Label(header, text="Proteção pessoal local", style="Text.TLabel").pack(side="right")

        overview = ttk.Frame(shell, style="Panel.TFrame", padding=22)
        overview.pack(fill="x", pady=(22, 16))
        ttk.Label(overview, text="Proteção ativa", style="Status.TLabel").pack(anchor="w")
        self.summary = ttk.Label(overview, text="Monitorando pastas selecionadas e isolando arquivos que exigem revisão.", style="Text.TLabel")
        self.summary.pack(anchor="w", pady=(6, 14))
        ttk.Button(overview, text="Verificar agora", style="Accent.TButton", command=self.scan_now).pack(anchor="w")

        cards = ttk.Frame(shell, style="Main.TFrame")
        cards.pack(fill="x", pady=(0, 16))
        self.card(cards, "Monitoramento", "Ativo", "Pastas verificadas continuamente", 0)
        self.card(cards, "Quarentena", "0 itens", "Arquivos isolados de forma reversível", 1)
        self.card(cards, "Contas", "Local", "Integrações futuras, sem senha salva", 2)

        section = ttk.Frame(shell, style="Main.TFrame")
        section.pack(fill="both", expand=True)
        ttk.Label(section, text="Quarentena", style="Title.TLabel", font=("Segoe UI", 14, "bold")).pack(anchor="w", pady=(0, 8))
        columns = ("name", "reason", "date")
        self.tree = ttk.Treeview(section, columns=columns, show="headings", selectmode="browse")
        self.tree.heading("name", text="Arquivo")
        self.tree.heading("reason", text="Motivo")
        self.tree.heading("date", text="Isolado em")
        self.tree.column("name", width=210)
        self.tree.column("reason", width=500)
        self.tree.column("date", width=140)
        self.tree.pack(fill="both", expand=True)
        actions = ttk.Frame(shell, style="Main.TFrame")
        actions.pack(fill="x", pady=(12, 0))
        ttk.Button(actions, text="Restaurar selecionado", command=self.restore_selected).pack(side="left")
        ttk.Button(actions, text="Excluir selecionado", command=self.delete_selected).pack(side="left", padx=8)
        ttk.Button(actions, text="Gerenciar pastas", command=self.manage_folders).pack(side="right")
        ttk.Button(actions, text="Contas", command=self.manage_accounts).pack(side="right", padx=8)
        ttk.Button(actions, text="Minimizar", command=self.minimize_to_background).pack(side="right", padx=8)
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
        logo_path = Path(__file__).with_name("gbtech-logo.png")
        image = Image.open(logo_path).convert("RGBA").resize((64, 64)) if logo_path.exists() else Image.new("RGBA", (64, 64), "#16a34a")
        menu = pystray.Menu(
            pystray.MenuItem("Abrir GBTech Security", lambda *_: self.events.put(("open", "", "")), default=True),
            pystray.MenuItem("Encerrar monitoramento", lambda *_: self.events.put(("quit", "", ""))),
        )
        self.tray_icon = pystray.Icon("GBTechSecurity", "GBTech Security", image, menu)
        threading.Thread(target=self.tray_icon.run, daemon=True).start()

    def process_events(self) -> None:
        try:
            while True:
                kind, name, detail = self.events.get_nowait()
                if kind == "quarantined":
                    self.summary.configure(text=f"{name} foi isolado para revisão: {detail}")
                    self.show_alert(name, detail)
                    self.refresh()
                elif kind == "error":
                    self.summary.configure(text=detail)
                elif kind == "open":
                    self.deiconify()
                    self.lift()
                    self.focus_force()
                elif kind == "quit":
                    self.close()
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

    def refresh(self) -> None:
        for row in self.tree.get_children():
            self.tree.delete(row)
        items = self.store.items()
        for item in items:
            self.tree.insert("", "end", iid=str(item[0]), values=(item[1], item[2], item[3]))
        self.quarantine_count.configure(text=f"{len(items)} item" + ("" if len(items) == 1 else "s"))

    def scan_now(self) -> None:
        self.summary.configure(text="A verificação usa as mesmas regras locais do monitoramento. Aguarde alguns segundos.")
        if self.monitor:
            self.monitor.seen.clear()

    def selected_item(self) -> tuple | None:
        selected = self.tree.selection()
        if not selected:
            messagebox.showinfo(APP_NAME, "Selecione um item da quarentena primeiro.")
            return None
        item_id = int(selected[0])
        return next((item for item in self.store.items() if item[0] == item_id), None)

    def restore_selected(self) -> None:
        item = self.selected_item()
        if not item:
            return
        if not messagebox.askyesno(APP_NAME, "Restaurar este arquivo pode permitir sua execução. Deseja continuar?"):
            return
        original = Path(item[4])
        source = QUARANTINE_DIR / item[6]
        try:
            original.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(source), str(original))
            self.store.remove(item[0])
            self.refresh()
            self.summary.configure(text=f"{item[1]} foi restaurado para a pasta original.")
        except OSError as error:
            messagebox.showerror(APP_NAME, f"Não foi possível restaurar o arquivo.\n{error}")

    def delete_selected(self) -> None:
        item = self.selected_item()
        if not item or not messagebox.askyesno(APP_NAME, "Excluir este arquivo da quarentena permanentemente?"):
            return
        try:
            (QUARANTINE_DIR / item[6]).unlink(missing_ok=True)
            self.store.remove(item[0])
            self.refresh()
            self.summary.configure(text=f"{item[1]} foi excluído da quarentena.")
        except OSError as error:
            messagebox.showerror(APP_NAME, f"Não foi possível excluir o arquivo.\n{error}")

    def manage_folders(self) -> None:
        dialog = tk.Toplevel(self)
        dialog.title("Pastas monitoradas")
        dialog.geometry("520x300")
        dialog.configure(bg="#182230")
        tk.Label(dialog, text="Uma pasta por linha", bg="#182230", fg="white", font=("Segoe UI", 11, "bold")).pack(anchor="w", padx=18, pady=(18, 4))
        text = tk.Text(dialog, height=10, font=("Segoe UI", 10))
        text.insert("1.0", "\n".join(self.store.watched_paths()))
        text.pack(fill="both", expand=True, padx=18, pady=8)
        def save() -> None:
            paths = [line.strip() for line in text.get("1.0", "end").splitlines() if line.strip()]
            self.store.set_watched_paths(paths)
            if self.monitor:
                self.monitor.seen.clear()
            dialog.destroy()
            self.summary.configure(text="Pastas monitoradas atualizadas.")
        ttk.Button(dialog, text="Salvar pastas", style="Accent.TButton", command=save).pack(pady=(0, 16))

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
