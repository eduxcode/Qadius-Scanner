"""Interface gráfica do Qadius Scanner."""
from __future__ import annotations

import os
import platform
import queue
import subprocess
import sys
import threading
import tkinter as tk
import tkinter.font as tkfont
from pathlib import Path
from tkinter import filedialog, messagebox
from typing import Optional

import ttkbootstrap as ttk
from ttkbootstrap.constants import *  # noqa: F401,F403

from report import save_report
from scanner import (
    DEFAULT_REPORTS_DIR,
    DEFAULT_RULES_DIR,
    RISK_HIGH,
    RISK_LOW,
    RISK_MEDIUM,
    FileResult,
    RuleSet,
    ScanSummary,
    Scanner,
    load_rules,
)

THEME = "darkly"
RISK_ORDER = {RISK_HIGH: 0, RISK_MEDIUM: 1, RISK_LOW: 2}
POLL_MS = 100
MUTED = "#a9b4c2"    # texto secundário legível sobre fundo escuro
ACCENT = "#5aa9ff"   # azul do título


def open_path(path: os.PathLike | str, reveal: bool = False) -> None:
    """Abre um arquivo/pasta no sistema; com reveal=True, mostra o item no gerenciador de arquivos."""
    path = str(path)
    system = platform.system()
    try:
        if system == "Darwin":
            subprocess.Popen(["open", "-R", path] if reveal else ["open", path])
        elif system == "Windows":
            if reveal:
                subprocess.Popen(["explorer", f"/select,{path}"])
            else:
                os.startfile(path)  # type: ignore[attr-defined]
        else:
            target = os.path.dirname(path) if reveal else path
            subprocess.Popen(["xdg-open", target])
    except OSError as exc:
        messagebox.showerror("Não foi possível abrir", str(exc))


def default_scan_folder() -> str:
    downloads = Path.home() / "Downloads"
    return str(downloads if downloads.is_dir() else Path.home())


class QadiusApp:
    def __init__(self, root: ttk.Window, rules: Optional[RuleSet] = None):
        self.root = root
        self.rules = rules if rules is not None else load_rules(DEFAULT_RULES_DIR)
        self.events: queue.Queue = queue.Queue()
        self.scanner: Optional[Scanner] = None
        self.worker: Optional[threading.Thread] = None
        self.last_report: Optional[Path] = None
        self.threat_count = 0
        self.rows: dict[str, FileResult] = {}
        self._resize_job = None

        root.title("Qadius Scanner")
        root.geometry("960x780")
        root.minsize(780, 680)

        self.path_var = tk.StringVar(value=default_scan_folder())
        self.status_var = tk.StringVar()
        self.files_var = tk.StringVar(value="0")
        self.threats_var = tk.StringVar(value="0")
        self.errors_var = tk.StringVar(value="0")

        self._build()
        self._set_idle("Escolha uma pasta e clique em Iniciar verificação.")
        self.root.after(POLL_MS, self._poll)
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    # ------------------------------------------------------------------ UI
    def _build(self) -> None:
        outer = ttk.Frame(self.root, padding=(28, 22))
        outer.pack(fill=BOTH, expand=YES)

        # Cabeçalho
        header = ttk.Frame(outer)
        header.pack(fill=X)
        titles = ttk.Frame(header)
        titles.pack(side=LEFT)
        ttk.Label(titles, text="Qadius", font=("Helvetica", 26, "bold"), foreground=ACCENT).pack(anchor=W)
        ttk.Label(titles, text="Verificação de malware com regras YARA", foreground=MUTED).pack(anchor=W)
        self.rules_label = ttk.Label(header, bootstyle=SECONDARY)
        self.rules_label.pack(side=RIGHT, anchor=N)
        self._update_rules_label()

        # Escolha do alvo
        pick = ttk.Frame(outer)
        pick.pack(fill=X, pady=(22, 0))
        ttk.Label(pick, text="O que verificar", font=("Helvetica", 11, "bold")).pack(anchor=W, pady=(0, 6))
        row = ttk.Frame(pick)
        row.pack(fill=X)
        self.path_entry = ttk.Entry(row, textvariable=self.path_var, font=("Helvetica", 12))
        self.path_entry.pack(side=LEFT, fill=X, expand=YES, ipady=4)
        self.folder_btn = ttk.Button(row, text="Pasta…", bootstyle="secondary", command=self._choose_folder)
        self.folder_btn.pack(side=LEFT, padx=(8, 0))
        self.file_btn = ttk.Button(row, text="Arquivo…", bootstyle="secondary", command=self._choose_file)
        self.file_btn.pack(side=LEFT, padx=(8, 0))

        # Ações
        actions = ttk.Frame(outer)
        actions.pack(fill=X, pady=(16, 0))
        self.start_btn = ttk.Button(actions, text="Iniciar verificação", bootstyle="success", width=22,
                                    command=self.start_scan)
        self.start_btn.pack(side=LEFT, ipady=6)
        self.stop_btn = ttk.Button(actions, text="Parar", bootstyle="danger-outline", width=10,
                                   command=self.stop_scan, state=DISABLED)
        self.stop_btn.pack(side=LEFT, padx=(10, 0), ipady=6)

        # Progresso + contadores
        self.progress = ttk.Progressbar(outer, mode="determinate", bootstyle="success-striped")
        self.progress.pack(fill=X, pady=(20, 6))
        ttk.Label(outer, textvariable=self.status_var, foreground=MUTED).pack(anchor=W)

        stats = ttk.Frame(outer)
        stats.pack(fill=X, pady=(14, 0))
        for i, (title, var, style) in enumerate([
            ("Arquivos verificados", self.files_var, INFO),
            ("Ameaças encontradas", self.threats_var, DANGER),
            ("Não puderam ser lidos", self.errors_var, WARNING),
        ]):
            stats.columnconfigure(i, weight=1, uniform="stat")
            card = ttk.Labelframe(stats, text=f" {title} ", padding=(14, 6))
            card.grid(row=0, column=i, sticky="ew", padx=(0 if i == 0 else 8, 0))
            ttk.Label(card, textvariable=var, font=("Helvetica", 24, "bold"), bootstyle=style).pack(anchor=W)

        # Rodapé
        footer = ttk.Frame(outer)
        footer.pack(side=BOTTOM, fill=X, pady=(12, 0))
        self.reveal_btn = ttk.Button(footer, text="Mostrar na pasta", bootstyle="light-outline",
                                     command=self._reveal_selected, state=DISABLED)
        self.reveal_btn.pack(side=LEFT)
        self.reports_btn = ttk.Button(footer, text="Pasta de relatórios", bootstyle="link", command=self._open_reports_dir)
        self.reports_btn.pack(side=RIGHT)
        self.report_btn = ttk.Button(footer, text="Abrir relatório PDF", bootstyle="info-outline",
                                     command=self._open_report, state=DISABLED)
        self.report_btn.pack(side=RIGHT, padx=(0, 8))

        # Detalhes da ameaça selecionada (texto completo, sem cortes)
        self.detail_box = ttk.Frame(outer, height=92)
        self.detail_box.pack(side=BOTTOM, fill=X, pady=(10, 0))
        self.detail_box.pack_propagate(False)
        self.detail_label = ttk.Label(self.detail_box, justify=LEFT, anchor=NW, foreground=MUTED, wraplength=800)
        self.detail_label.pack(fill=BOTH, expand=YES)
        self.detail_box.bind("<Configure>", lambda e: self.detail_label.config(wraplength=max(e.width - 8, 200)))
        self._show_details(None)

        # Resultados
        ttk.Label(outer, text="Ameaças", font=("Helvetica", 11, "bold")).pack(anchor=W, pady=(20, 6))
        table = ttk.Frame(outer)
        table.pack(fill=BOTH, expand=YES)
        self.tree_font = tkfont.Font(family="Helvetica", size=11)
        style = ttk.Style()
        style.configure("Treeview", rowheight=28, font=self.tree_font)
        style.configure("Treeview.Heading", font=("Helvetica", 11, "bold"))
        self.tree = ttk.Treeview(table, columns=("risk", "threat", "file"), show="headings", selectmode="browse", height=5)
        for col, text in (("risk", "Risco"), ("threat", "Ameaça"), ("file", "Arquivo")):
            self.tree.heading(col, text=text, anchor=W)
            self.tree.column(col, stretch=False, anchor=W, minwidth=60)
        self._set_column_widths(860)
        self.tree.tag_configure(RISK_HIGH, foreground="#e74c3c")
        self.tree.tag_configure(RISK_MEDIUM, foreground="#f39c12")
        self.tree.tag_configure(RISK_LOW, foreground="#5dade2")
        scroll = ttk.Scrollbar(table, orient=VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.pack(side=LEFT, fill=BOTH, expand=YES)
        scroll.pack(side=LEFT, fill=Y)
        self.tree.bind("<Double-1>", lambda _e: self._reveal_selected())
        self.tree.bind("<Configure>", self._on_tree_resize)
        self.tree.bind("<<TreeviewSelect>>", self._on_select)
        self.empty_label = ttk.Label(table, text="", foreground=MUTED, font=("Helvetica", 12))


    def _update_rules_label(self) -> None:
        if self.rules:
            self.rules_label.config(text=f"●  {len(self.rules.loaded)} arquivos de regras ativos", bootstyle=SUCCESS)
        else:
            self.rules_label.config(text="●  Nenhuma regra carregada", bootstyle=DANGER)

    # ------------------------------------------------- tabela responsiva
    def _set_column_widths(self, total: int) -> None:
        risk = 84
        threat = max(170, int(total * 0.28))
        file = max(150, total - risk - threat - 6)
        for col, width in (("risk", risk), ("threat", threat), ("file", file)):
            self.tree.column(col, width=width)

    def _fit(self, text: str, width: int, keep_end: bool = False) -> str:
        """Encurta `text` com "…" para caber em `width` pixels (keep_end preserva o final, ex.: nome do arquivo)."""
        width -= 16  # margem interna da célula
        if width < 60 or self.tree_font.measure(text) <= width:
            return text  # janela ainda não desenhada ou já cabe
        lo, hi = 0, len(text)
        while lo < hi:  # maior número de caracteres que cabe
            mid = (lo + hi + 1) // 2
            piece = ("…" + text[-mid:]) if keep_end else (text[:mid] + "…")
            if self.tree_font.measure(piece) <= width:
                lo = mid
            else:
                hi = mid - 1
        return ("…" + text[-lo:]) if keep_end else (text[:lo] + "…")

    @staticmethod
    def _threat_text(result: FileResult) -> str:
        return ", ".join(sorted({d.threat_name for d in result.detections}))

    @staticmethod
    def _file_text(result: FileResult) -> str:
        inner = sorted({d.location.split("!", 1)[1] for d in result.detections if "!" in d.location})
        return result.path + ("  ›  " + ", ".join(inner) if inner else "")

    def _row_values(self, result: FileResult) -> tuple:
        threat_w = int(self.tree.column("threat", "width"))
        file_w = int(self.tree.column("file", "width"))
        return (result.top_risk,
                self._fit(self._threat_text(result), threat_w),
                self._fit(self._file_text(result), file_w, keep_end=True))

    def _on_tree_resize(self, event) -> None:
        if self._resize_job:
            self.root.after_cancel(self._resize_job)
        self._resize_job = self.root.after(60, lambda: self._relayout(event.width))

    def _relayout(self, width: int) -> None:
        self._resize_job = None
        self._set_column_widths(width)
        for iid, result in self.rows.items():
            self.tree.item(iid, values=self._row_values(result))

    def _set_empty_message(self, text: str) -> None:
        """Mostra (ou esconde por completo) a mensagem no centro da tabela vazia."""
        self.empty_label.config(text=text)
        if text:
            self.empty_label.place(relx=0.5, rely=0.5, anchor=CENTER)
        else:
            self.empty_label.place_forget()

    def _on_select(self, _event=None) -> None:
        sel = self.tree.selection()
        self.reveal_btn.config(state=NORMAL if sel else DISABLED)
        self._show_details(self.rows.get(sel[0]) if sel else None)

    def _show_details(self, result: Optional[FileResult]) -> None:
        if result is None:
            self.detail_label.config(text="Selecione uma ameaça para ver os detalhes. "
                                          "Clique duas vezes para mostrar o arquivo na pasta.")
            return
        lines = [f"Arquivo:  {result.path}"]
        for d in result.detections[:4]:
            where = f"   (dentro de: {d.location.split('!', 1)[1]})" if "!" in d.location else ""
            lines.append(f"{d.risk}  ·  {d.threat_name}{where}")
        if len(result.detections) > 4:
            lines.append(f"… e mais {len(result.detections) - 4} detecção(ões) no relatório.")
        lines.append(f"O que fazer:  {result.detections[0].recommendation}")
        self.detail_label.config(text="\n".join(lines))

    # ------------------------------------------------------------- estados
    def _set_idle(self, message: str) -> None:
        self.status_var.set(message)
        self.start_btn.config(state=NORMAL if self.rules else DISABLED)
        self.stop_btn.config(state=DISABLED)
        for w in (self.folder_btn, self.file_btn, self.path_entry):
            w.config(state=NORMAL)

    def _set_running(self) -> None:
        self.start_btn.config(state=DISABLED)
        self.stop_btn.config(state=NORMAL)
        for w in (self.folder_btn, self.file_btn, self.path_entry):
            w.config(state=DISABLED)

    # ------------------------------------------------------------- escolhas
    def _choose_folder(self) -> None:
        chosen = filedialog.askdirectory(initialdir=self.path_var.get() or str(Path.home()))
        if chosen:
            self.path_var.set(chosen)

    def _choose_file(self) -> None:
        chosen = filedialog.askopenfilename(initialdir=self.path_var.get() or str(Path.home()))
        if chosen:
            self.path_var.set(chosen)

    def _reveal_selected(self) -> None:
        sel = self.tree.selection()
        if sel and sel[0] in self.rows:
            open_path(self.rows[sel[0]].path, reveal=True)

    def _open_report(self) -> None:
        if self.last_report and self.last_report.exists():
            open_path(self.last_report)

    def _open_reports_dir(self) -> None:
        DEFAULT_REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        open_path(DEFAULT_REPORTS_DIR)

    # ------------------------------------------------------------ varredura
    def start_scan(self) -> None:
        if self.worker and self.worker.is_alive():
            return
        target = os.path.expanduser(self.path_var.get().strip())
        if not target or not os.path.exists(target):
            messagebox.showwarning("Caminho inválido", "Escolha uma pasta ou arquivo que exista para verificar.")
            return

        self.tree.delete(*self.tree.get_children())
        self.rows.clear()
        self._show_details(None)
        self.threat_count = 0
        self.files_var.set("0")
        self.threats_var.set("0")
        self.errors_var.set("0")
        self._set_empty_message("")
        self.progress.config(mode="indeterminate", bootstyle="success-striped")
        self.progress.start(12)
        self.report_btn.config(state=DISABLED)
        self.status_var.set("Contando arquivos…")
        self._set_running()

        self.scanner = Scanner(self.rules)
        self.worker = threading.Thread(target=self._run_scan, args=(self.scanner, target), daemon=True)
        self.worker.start()

    def stop_scan(self) -> None:
        if self.scanner:
            self.scanner.cancel()
            self.stop_btn.config(state=DISABLED)
            self.status_var.set("Parando…")

    def _run_scan(self, scanner: Scanner, target: str) -> None:
        """Roda em outra thread: só se comunica com a interface pela fila."""
        put = self.events.put
        try:
            summary = scanner.scan(
                target,
                on_counting=lambda n: put(("counting", n)),
                on_progress=lambda done, total, path: put(("progress", done, total, path)),
                on_detection=lambda result: put(("threat", result)),
            )
            try:
                report = save_report(summary)
            except Exception as exc:  # o relatório não deve esconder o resultado da varredura
                put(("report_error", str(exc)))
                report = None
            put(("done", summary, report))
        except Exception as exc:
            put(("error", str(exc)))

    def _poll(self) -> None:
        latest_progress = None
        try:
            while True:
                event = self.events.get_nowait()
                kind = event[0]
                if kind == "progress":
                    latest_progress = event  # só o mais recente importa
                elif kind == "counting":
                    self.status_var.set(f"Contando arquivos… {event[1]}")
                elif kind == "threat":
                    self._add_threat(event[1])
                elif kind == "done":
                    if latest_progress:
                        self._apply_progress(latest_progress)
                        latest_progress = None
                    self._finish(event[1], event[2])
                elif kind == "report_error":
                    messagebox.showwarning("Relatório", f"Não foi possível salvar o relatório PDF:\n{event[1]}")
                elif kind == "error":
                    self.progress.stop()
                    self.progress.config(mode="determinate", value=0)
                    self._set_idle(f"Erro: {event[1]}")
                    messagebox.showerror("Erro na verificação", event[1])
        except queue.Empty:
            pass
        if latest_progress:
            self._apply_progress(latest_progress)
        self.root.after(POLL_MS, self._poll)

    def _apply_progress(self, event) -> None:
        _, done, total, path = event
        if str(self.progress.cget("mode")) != "determinate":
            self.progress.stop()
            self.progress.config(mode="determinate")
        self.progress.config(maximum=max(total, 1), value=done)
        self.files_var.set(f"{done:,}".replace(",", "."))
        name = os.path.basename(path)
        self.status_var.set(f"Verificando {done} de {total}  ·  {name}")

    def _add_threat(self, result: FileResult) -> None:
        self.threat_count += 1
        self.threats_var.set(str(self.threat_count))
        iid = self.tree.insert("", END, values=self._row_values(result), tags=(result.top_risk,))
        self.rows[iid] = result

    def _finish(self, summary: ScanSummary, report: Optional[Path]) -> None:
        self.progress.stop()
        self.progress.config(mode="determinate", maximum=max(summary.total_files, 1), value=summary.scanned_files)
        self.files_var.set(str(summary.scanned_files))
        self.errors_var.set(str(summary.error_count))
        self._sort_results()

        if report:
            self.last_report = report
            self.report_btn.config(state=NORMAL)
        if summary.cancelled:
            msg = f"Verificação interrompida após {summary.scanned_files} de {summary.total_files} arquivos."
        elif summary.threat_files:
            msg = f"Concluído: {summary.threat_files} arquivo(s) suspeito(s) em {summary.duration_seconds:.1f}s."
        else:
            msg = f"Concluído em {summary.duration_seconds:.1f}s: nenhuma ameaça encontrada."
        if report:
            msg += "  Relatório salvo."
        if not summary.threat_files:
            self.progress.config(bootstyle="success")
            self._set_empty_message("✓  Nenhuma ameaça encontrada" if not summary.cancelled else "")
        else:
            self.progress.config(bootstyle="danger")
        self._set_idle(msg)

    def _sort_results(self) -> None:
        rows = [(self.tree.set(i, "risk"), i) for i in self.tree.get_children()]
        for index, (_risk, iid) in enumerate(sorted(rows, key=lambda r: RISK_ORDER.get(r[0], 9))):
            self.tree.move(iid, "", index)

    def _on_close(self) -> None:
        if self.scanner and self.worker and self.worker.is_alive():
            if not messagebox.askyesno("Sair", "Há uma verificação em andamento. Deseja interrompê-la e sair?"):
                return
            self.scanner.cancel()
        self.root.destroy()


def self_test() -> int:
    """Verifica, sem abrir janela, o fluxo completo: regras, detecção (inclusive dentro de zip) e PDF.

    Útil para validar o executável empacotado:  "Qadius Scanner" --self-test
    """
    import io
    import tempfile
    import zipfile

    rules = load_rules(DEFAULT_RULES_DIR)
    print(f"regras carregadas: {len(rules.loaded)}  (ignoradas: {len(rules.skipped)})")
    if not rules:
        print("FALHA: nenhuma regra carregada")
        return 1
    eicar = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        (base / "eicar.txt").write_bytes(eicar)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("pasta/eicar.com", eicar)
        (base / "pacote.zip").write_bytes(buf.getvalue())
        (base / "limpo.txt").write_text("texto normal")
        summary = Scanner(rules).scan(base)
        pdf = save_report(summary, base / "reports")
        checks = {
            "detecção direta e dentro de zip (2 arquivos)": summary.threat_files == 2,
            "arquivo limpo não acusado": summary.scanned_files == 3,
            "relatório PDF": pdf.exists() and pdf.read_bytes().startswith(b"%PDF"),
        }
    for name, ok in checks.items():
        print(f"{name}: {'OK' if ok else 'FALHA'}")
    return 0 if all(checks.values()) else 1


def main() -> None:
    if "--self-test" in sys.argv:
        sys.exit(self_test())
    root = ttk.Window(themename=THEME)
    QadiusApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
