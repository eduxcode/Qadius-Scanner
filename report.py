"""Geração do relatório em PDF."""
from __future__ import annotations

import http.client
import urllib.request
from datetime import datetime
from pathlib import Path

# O executável é empacotado sem o módulo `ssl` (o app não usa rede). O fpdf2 só importa
# HTTPSHandler/HTTPSConnection para baixar imagens; estes atalhos evitam o erro de importação.
if not hasattr(urllib.request, "HTTPSHandler"):
    urllib.request.HTTPSHandler = urllib.request.HTTPHandler  # type: ignore[attr-defined]
if not hasattr(http.client, "HTTPSConnection"):
    http.client.HTTPSConnection = http.client.HTTPConnection  # type: ignore[attr-defined]

from fpdf import FPDF  # noqa: E402
from fpdf.enums import XPos, YPos

from scanner import DEFAULT_REPORTS_DIR, RISK_HIGH, RISK_LOW, RISK_MEDIUM, ScanSummary

RISK_COLORS = {RISK_HIGH: (200, 40, 40), RISK_MEDIUM: (220, 140, 20), RISK_LOW: (60, 130, 200)}


def _t(text: str) -> str:
    """Fontes padrão do PDF só aceitam latin-1; troca o que não couber."""
    return str(text).encode("latin-1", "replace").decode("latin-1")


class _Report(FPDF):
    def footer(self):
        self.set_y(-14)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(130)
        self.cell(0, 8, _t(f"Qadius Scanner  -  página {self.page_no()}"), align="C")


def save_report(summary: ScanSummary, reports_dir: Path | str = DEFAULT_REPORTS_DIR) -> Path:
    """Gera o PDF e devolve o caminho do arquivo criado."""
    reports_dir = Path(reports_dir)
    reports_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    out = reports_dir / f"qadius_relatorio_{stamp}.pdf"

    pdf = _Report()
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.add_page()

    pdf.set_font("Helvetica", "B", 20)
    pdf.set_text_color(30, 40, 60)
    pdf.cell(0, 12, "Relatório de Verificação", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(110)
    pdf.cell(0, 6, "Qadius Scanner", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(4)

    status = "Cancelada pelo usuário" if summary.cancelled else "Concluída"
    rows = [
        ("Data", summary.started.strftime("%d/%m/%Y %H:%M:%S")),
        ("Alvo", summary.directory),
        ("Situação", status),
        ("Duração", f"{summary.duration_seconds:.1f} s"),
        ("Arquivos verificados", f"{summary.scanned_files} de {summary.total_files}"),
        ("Arquivos com ameaças", str(summary.threat_files)),
        ("Pulados (muito grandes)", str(summary.skipped_files)),
        ("Não lidos (erros/permissão)", str(summary.error_count)),
    ]
    for label, value in rows:
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_text_color(40)
        pdf.cell(58, 7, _t(label))
        pdf.set_font("Helvetica", "", 10)
        pdf.multi_cell(0, 7, _t(value), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(6)

    pdf.set_font("Helvetica", "B", 14)
    pdf.set_text_color(30, 40, 60)
    pdf.cell(0, 9, "Detecções", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    if not summary.results:
        pdf.set_font("Helvetica", "", 11)
        pdf.set_text_color(30, 140, 70)
        pdf.cell(0, 9, "Nenhuma ameaça detectada.", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    for result in summary.results:
        pdf.ln(2)
        pdf.set_font("Helvetica", "B", 10)
        pdf.set_text_color(40)
        pdf.multi_cell(0, 6, _t(result.path), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        for d in result.detections:
            pdf.set_x(pdf.l_margin + 4)
            pdf.set_font("Helvetica", "B", 9)
            pdf.set_text_color(*RISK_COLORS.get(d.risk, (80, 80, 80)))
            pdf.multi_cell(0, 5, _t(f"[{d.risk}] {d.threat_name}" + (f"  (dentro de: {d.location.split('!', 1)[1]})" if d.location else "")), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.set_x(pdf.l_margin + 4)
            pdf.set_font("Helvetica", "", 9)
            pdf.set_text_color(90)
            detail = f"Regra: {d.rule} ({d.source}). {d.recommendation}"
            pdf.multi_cell(0, 5, _t(detail), new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    pdf.output(str(out))
    return out
