"""Motor de verificação do Qadius Scanner (sem dependência de interface gráfica).

Uso em linha de comando:
    python scanner.py CAMINHO [--rules rules] [--no-report]
"""
from __future__ import annotations

import argparse
import gzip
import io
import os
import sys
import tarfile
import threading
import time
import zipfile
import zlib
from dataclasses import dataclass, field, replace
from datetime import datetime
from pathlib import Path
from typing import Callable, Iterable, Optional

import yara

FROZEN = getattr(sys, "frozen", False)  # True quando rodando como executável (PyInstaller)
BASE_DIR = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
DEFAULT_RULES_DIR = BASE_DIR / "rules"
# Um app empacotado não pode gravar dentro de si mesmo: relatórios vão para Documentos.
DEFAULT_REPORTS_DIR = (Path.home() / "Documents" / "Qadius Scanner") if FROZEN else (BASE_DIR / "reports")
RULE_EXTENSIONS = (".yar", ".yara")

# Arquivos maiores que isso são pulados (evita travar com imagens de disco, VMs etc.)
DEFAULT_MAX_FILE_SIZE = 200 * 1024 * 1024
MATCH_TIMEOUT_SECONDS = 30

# Regras com estas tags só descrevem o arquivo (tipo, compilador, entropia, "capacidades"...) e não
# indicam ameaça. Sem esse filtro, quase todo arquivo apareceria como "suspeito".
# Limites ao olhar dentro de arquivos compactados (proteção contra "zip bombs").
ARCHIVE_MAX_DEPTH = 3                      # zip dentro de zip dentro de zip...
ARCHIVE_MAX_MEMBER_SIZE = 50 * 1024 * 1024  # tamanho máximo de cada item descompactado
ARCHIVE_MAX_TOTAL_SIZE = 500 * 1024 * 1024  # total descompactado por arquivo
ARCHIVE_MAX_MEMBERS = 10_000

INFORMATIONAL_TAGS = frozenset({"info", "statistics", "feature"})

RISK_HIGH = "Alto"
RISK_MEDIUM = "Médio"
RISK_LOW = "Baixo"

RECOMMENDATIONS = {
    RISK_HIGH: "Isole e remova o arquivo imediatamente e investigue possíveis danos.",
    RISK_MEDIUM: "Analise o arquivo com cuidado e considere removê-lo.",
    RISK_LOW: "Provavelmente inofensivo ou arquivo de teste. Monitore.",
}


# --------------------------------------------------------------------------- #
# Modelos
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Detection:
    rule: str
    threat_name: str
    severity: int
    risk: str
    source: str  # arquivo .yar de origem
    description: str = ""
    location: str = ""  # caminho dentro do arquivo compactado, ex.: "a.zip!pasta/x.exe"

    @property
    def recommendation(self) -> str:
        return RECOMMENDATIONS.get(self.risk, "")


@dataclass
class FileResult:
    path: str
    detections: list[Detection]

    @property
    def top_risk(self) -> str:
        order = {RISK_HIGH: 3, RISK_MEDIUM: 2, RISK_LOW: 1}
        return max((d.risk for d in self.detections), key=lambda r: order.get(r, 0))


@dataclass
class ScanSummary:
    directory: str
    started: datetime
    finished: Optional[datetime] = None
    total_files: int = 0
    scanned_files: int = 0
    skipped_files: int = 0
    error_count: int = 0
    cancelled: bool = False
    results: list[FileResult] = field(default_factory=list)

    @property
    def threat_files(self) -> int:
        return len(self.results)

    @property
    def duration_seconds(self) -> float:
        end = self.finished or datetime.now()
        return (end - self.started).total_seconds()


# --------------------------------------------------------------------------- #
# Regras
# --------------------------------------------------------------------------- #
def classify_severity(severity: Optional[int]) -> str:
    """Converte a severidade (1-100) do metadado da regra em Alto/Médio/Baixo."""
    if severity is None:
        return RISK_MEDIUM
    if severity >= 80:
        return RISK_HIGH
    if severity >= 40:
        return RISK_MEDIUM
    return RISK_LOW


def _parse_severity(value) -> Optional[int]:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


@dataclass
class RuleSet:
    compiled: Optional["yara.Rules"]
    loaded: list[str]
    skipped: dict[str, str]  # arquivo -> motivo

    def __bool__(self) -> bool:
        return self.compiled is not None


def load_rules(rules_dir: os.PathLike | str = DEFAULT_RULES_DIR) -> RuleSet:
    """Carrega as regras YARA de um diretório.

    Cada arquivo é validado separadamente; os inválidos são pulados (e reportados em
    `skipped`). Os válidos são compilados juntos, o que permite varrer cada arquivo
    uma única vez em vez de uma vez por arquivo de regra.
    """
    rules_dir = Path(rules_dir)
    if not rules_dir.is_dir():
        raise FileNotFoundError(f"Pasta de regras não encontrada: {rules_dir}")

    valid: dict[str, str] = {}
    skipped: dict[str, str] = {}
    for path in sorted(rules_dir.iterdir()):
        if path.suffix.lower() not in RULE_EXTENSIONS or not path.is_file():
            continue
        try:
            yara.compile(filepath=str(path))
        except yara.Error as exc:
            skipped[path.name] = str(exc)
        else:
            valid[path.name] = str(path)

    if not valid:
        return RuleSet(None, [], skipped)
    # O nome do arquivo vira o namespace: evita conflito entre regras homônimas.
    return RuleSet(yara.compile(filepaths=valid), list(valid), skipped)


# --------------------------------------------------------------------------- #
# Escaneamento
# --------------------------------------------------------------------------- #
def _to_detection(match) -> Detection:
    meta = match.meta or {}
    severity = _parse_severity(meta.get("severity"))
    return Detection(
        rule=match.rule,
        threat_name=str(meta.get("threat_name") or match.rule),
        severity=severity if severity is not None else 50,
        risk=classify_severity(severity),
        source=match.namespace,
        description=str(meta.get("description") or ""),
    )


def _scan_bytes(data: bytes, compiled: "yara.Rules") -> list[Detection]:
    matches = compiled.match(data=data, timeout=MATCH_TIMEOUT_SECONDS)
    return [_to_detection(m) for m in matches if not INFORMATIONAL_TAGS.intersection(m.tags)]


class _Budget:
    """Controla quanto já foi descompactado de um mesmo arquivo."""

    def __init__(self) -> None:
        self.remaining = ARCHIVE_MAX_TOTAL_SIZE
        self.members = 0

    def take(self, size: int) -> bool:
        self.members += 1
        if self.members > ARCHIVE_MAX_MEMBERS or size > self.remaining:
            return False
        self.remaining -= size
        return True


def _archive_kind(f) -> Optional[str]:
    """Identifica o formato pelo conteúdo (não pela extensão)."""
    head = f.read(262)
    f.seek(0)
    if head[:4] in (b"PK\x03\x04", b"PK\x05\x06"):
        return "zip"
    if head[:2] == b"\x1f\x8b":
        return "gz"
    if head[257:262] == b"ustar":
        return "tar"
    return None


def _read_capped(stream) -> Optional[bytes]:
    """Lê no máximo ARCHIVE_MAX_MEMBER_SIZE bytes; None se o item for maior (descarta)."""
    data = stream.read(ARCHIVE_MAX_MEMBER_SIZE + 1)
    return None if len(data) > ARCHIVE_MAX_MEMBER_SIZE else data


def _iter_members(f, kind: str, label: str):
    """Gera (nome, bytes) de cada item de um arquivo compactado, com limites de tamanho."""
    if kind == "zip":
        with zipfile.ZipFile(f) as zf:
            for info in zf.infolist():
                if info.is_dir() or info.flag_bits & 0x1:  # pasta ou criptografado
                    continue
                with zf.open(info) as member:
                    data = _read_capped(member)
                if data is not None:
                    yield info.filename, data
    elif kind == "tar":
        with tarfile.open(fileobj=f, mode="r:") as tf:
            for info in tf:
                if not info.isfile():
                    continue
                data = _read_capped(tf.extractfile(info))
                if data is not None:
                    yield info.name, data
    elif kind == "gz":
        with gzip.GzipFile(fileobj=f) as gz:
            data = _read_capped(gz)
        if data is not None:
            base = label.rsplit("!", 1)[-1].rsplit("/", 1)[-1]
            yield (base[:-3] if base.lower().endswith(".gz") else base) or "conteudo", data


def _scan_archive(f, label: str, compiled, depth: int, budget: _Budget, out: list[Detection]) -> None:
    kind = _archive_kind(f)
    if not kind:
        return
    try:
        for name, data in _iter_members(f, kind, label):
            if not budget.take(len(data)):
                return
            where = f"{label}!{name}"
            out.extend(replace(d, location=where) for d in _scan_bytes(data, compiled))
            if depth < ARCHIVE_MAX_DEPTH:
                _scan_archive(io.BytesIO(data), where, compiled, depth + 1, budget, out)
    except (zipfile.BadZipFile, tarfile.TarError, EOFError, zlib.error, OSError, RuntimeError, NotImplementedError):
        return  # arquivo corrompido ou formato não suportado: ignora o conteúdo interno


def scan_file(path: os.PathLike | str, rules: RuleSet | "yara.Rules", archives: bool = True) -> list[Detection]:
    """Escaneia um arquivo (e, se `archives`, o conteúdo de zip/tar/gz).

    Levanta `yara.Error`/`OSError` se o arquivo não puder ser lido.
    """
    compiled = rules.compiled if isinstance(rules, RuleSet) else rules
    matches = compiled.match(str(path), timeout=MATCH_TIMEOUT_SECONDS)
    found = [_to_detection(m) for m in matches if not INFORMATIONAL_TAGS.intersection(m.tags)]
    if archives:
        inner: list[Detection] = []
        with open(path, "rb") as f:
            _scan_archive(f, str(path), compiled, 1, _Budget(), inner)
        # Um zip "stored" casa por fora e por dentro: mantém só o achado interno.
        inner_rules = {d.rule for d in inner}
        found = [d for d in found if d.rule not in inner_rules] + inner
    return found


def iter_files(directory: os.PathLike | str) -> Iterable[str]:
    """Percorre o diretório (ou devolve o próprio arquivo), sem seguir links simbólicos."""
    directory = str(directory)
    if os.path.isfile(directory):
        yield directory
        return
    for root, _dirs, files in os.walk(directory, followlinks=False):
        for name in files:
            full = os.path.join(root, name)
            if not os.path.islink(full):
                yield full


class Scanner:
    """Executa uma verificação. Pode ser cancelada de outra thread com `cancel()`."""

    def __init__(self, rules: RuleSet, max_file_size: int = DEFAULT_MAX_FILE_SIZE):
        if not rules:
            raise ValueError("Nenhuma regra YARA válida foi carregada.")
        self.rules = rules
        self.max_file_size = max_file_size
        self._cancel = threading.Event()

    def cancel(self) -> None:
        self._cancel.set()

    @property
    def cancelled(self) -> bool:
        return self._cancel.is_set()

    def scan(
        self,
        target: os.PathLike | str,
        on_progress: Optional[Callable[[int, int, str], None]] = None,
        on_detection: Optional[Callable[[FileResult], None]] = None,
        on_counting: Optional[Callable[[int], None]] = None,
    ) -> ScanSummary:
        target = str(target)
        if not os.path.exists(target):
            raise FileNotFoundError(f"Caminho não encontrado: {target}")

        summary = ScanSummary(directory=target, started=datetime.now())

        # Fase 1: contar arquivos (para a barra de progresso ter um total real).
        files: list[str] = []
        for f in iter_files(target):
            if self._cancel.is_set():
                break
            files.append(f)
            if on_counting and len(files) % 500 == 0:
                on_counting(len(files))
        summary.total_files = len(files)

        # Fase 2: escanear.
        for path in files:
            if self._cancel.is_set():
                break
            summary.scanned_files += 1
            try:
                if os.path.getsize(path) > self.max_file_size:
                    summary.skipped_files += 1
                else:
                    detections = scan_file(path, self.rules)
                    if detections:
                        result = FileResult(path, detections)
                        summary.results.append(result)
                        if on_detection:
                            on_detection(result)
            except (OSError, yara.Error):
                summary.error_count += 1
            if on_progress:
                on_progress(summary.scanned_files, summary.total_files, path)

        summary.cancelled = self._cancel.is_set()
        summary.finished = datetime.now()
        return summary


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Qadius Scanner - verificador de malware com regras YARA")
    parser.add_argument("path", help="Arquivo ou pasta a verificar")
    parser.add_argument("--rules", default=str(DEFAULT_RULES_DIR), help="Pasta com as regras YARA")
    parser.add_argument("--no-report", action="store_true", help="Não gerar relatório em PDF")
    args = parser.parse_args(argv)

    try:
        rules = load_rules(args.rules)
    except FileNotFoundError as exc:
        print(exc, file=sys.stderr)
        return 2
    print(f"{len(rules.loaded)} arquivos de regras carregados ({len(rules.skipped)} ignorados).")

    scanner = Scanner(rules)
    started = time.time()
    try:
        summary = scanner.scan(
            args.path,
            on_progress=lambda done, total, _p: print(f"\r{done}/{total}", end="", flush=True),
            on_detection=lambda r: print(f"\n[{r.top_risk}] {r.path}: "
                                         + ", ".join(d.threat_name for d in r.detections)),
        )
    except KeyboardInterrupt:
        scanner.cancel()
        print("\nInterrompido.")
        return 130
    except FileNotFoundError as exc:
        print(exc, file=sys.stderr)
        return 2

    print(f"\nConcluído em {time.time() - started:.1f}s: {summary.scanned_files} arquivos, "
          f"{summary.threat_files} com ameaças, {summary.error_count} erros.")
    if not args.no_report:
        from report import save_report
        print("Relatório:", save_report(summary))
    return 1 if summary.threat_files else 0


if __name__ == "__main__":
    sys.exit(main())
