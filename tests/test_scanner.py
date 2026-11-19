import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from report import save_report  # noqa: E402
from scanner import (  # noqa: E402
    DEFAULT_RULES_DIR,
    RISK_HIGH,
    RISK_LOW,
    RISK_MEDIUM,
    RuleSet,
    Scanner,
    classify_severity,
    iter_files,
    load_rules,
    main,
    scan_file,
)

# Arquivo de teste padrão da indústria antivírus: inofensivo, mas detectado por todos.
EICAR = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


@pytest.fixture(scope="session")
def rules() -> RuleSet:
    return load_rules(DEFAULT_RULES_DIR)


@pytest.fixture
def sample_dir(tmp_path):
    (tmp_path / "limpo.txt").write_text("apenas um texto comum")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "eicar.com").write_text(EICAR)
    (tmp_path / "sub" / "outro_limpo.bin").write_bytes(os.urandom(2048) + b"\x00")
    return tmp_path


# --- regras -----------------------------------------------------------------
def test_load_rules_loads_most_and_skips_broken(rules):
    assert rules
    assert len(rules.loaded) > 600
    # regras que dependem de módulos/campos inexistentes são puladas, sem derrubar o resto
    assert "malrtf.yara" in rules.skipped
    assert "win_geodo.yara" in rules.skipped


def test_load_rules_missing_dir():
    with pytest.raises(FileNotFoundError):
        load_rules("/pasta/que/nao/existe")


def test_load_rules_empty_dir_gives_falsy_ruleset(tmp_path):
    assert not load_rules(tmp_path)


def test_scanner_refuses_empty_ruleset(tmp_path):
    with pytest.raises(ValueError):
        Scanner(load_rules(tmp_path))


def test_load_rules_skips_syntax_errors(tmp_path):
    (tmp_path / "ruim.yar").write_text("rule x { condition: nao_existe }")
    (tmp_path / "bom.yar").write_text('rule ok { strings: $a = "zzz" condition: $a }')
    rs = load_rules(tmp_path)
    assert rs.loaded == ["bom.yar"] and "ruim.yar" in rs.skipped


# --- classificação -----------------------------------------------------------
@pytest.mark.parametrize(
    "sev,risk",
    [(100, RISK_HIGH), (80, RISK_HIGH), (79, RISK_MEDIUM), (50, RISK_MEDIUM),
     (40, RISK_MEDIUM), (39, RISK_LOW), (1, RISK_LOW), (None, RISK_MEDIUM)],
)
def test_classify_severity(sev, risk):
    assert classify_severity(sev) == risk


# --- escaneamento ------------------------------------------------------------
def test_scan_file_detects_eicar(rules, tmp_path):
    f = tmp_path / "eicar.txt"
    f.write_text(EICAR)
    dets = scan_file(f, rules)
    assert dets, "EICAR deveria ser detectado"
    assert dets[0].threat_name == "Multi.EICAR.Not-a-virus"
    assert dets[0].risk == RISK_LOW  # severidade 1 nas regras


def test_scan_file_clean(rules, tmp_path):
    f = tmp_path / "ok.txt"
    f.write_text("nada de mais aqui")
    assert scan_file(f, rules) == []


def test_scan_directory_end_to_end(rules, sample_dir):
    progress, found = [], []
    summary = Scanner(rules).scan(
        sample_dir,
        on_progress=lambda d, t, p: progress.append((d, t)),
        on_detection=found.append,
    )
    assert summary.total_files == 3
    assert summary.scanned_files == 3
    assert summary.threat_files == 1
    assert Path(summary.results[0].path).name == "eicar.com"
    assert progress[-1] == (3, 3)
    assert len(found) == 1
    assert not summary.cancelled and summary.finished


def test_scan_single_file_target(rules, sample_dir):
    summary = Scanner(rules).scan(sample_dir / "sub" / "eicar.com")
    assert summary.total_files == 1 and summary.threat_files == 1


def test_scan_missing_path_raises(rules):
    with pytest.raises(FileNotFoundError):
        Scanner(rules).scan("/nao/existe/mesmo")


def test_cancel_stops_scan(rules, sample_dir):
    scanner = Scanner(rules)
    summary = scanner.scan(sample_dir, on_progress=lambda *_: scanner.cancel())
    assert summary.cancelled
    assert summary.scanned_files == 1  # parou logo após o primeiro


def test_oversized_files_are_skipped(rules, sample_dir):
    summary = Scanner(rules, max_file_size=10).scan(sample_dir)
    assert summary.skipped_files >= 1
    assert summary.threat_files == 0  # eicar.com (68 bytes) também passou do limite


@pytest.mark.skipif(os.name == "nt" or os.geteuid() == 0, reason="permissões POSIX")
def test_unreadable_file_counts_as_error_not_crash(rules, sample_dir):
    secret = sample_dir / "secreto.bin"
    secret.write_text("x")
    secret.chmod(0)
    try:
        summary = Scanner(rules).scan(sample_dir)
    finally:
        secret.chmod(0o600)
    assert summary.error_count == 1
    assert summary.threat_files == 1  # o resto continuou sendo verificado


def test_iter_files_ignores_symlinks(sample_dir):
    (sample_dir / "link").symlink_to(sample_dir / "limpo.txt")
    names = {Path(p).name for p in iter_files(sample_dir)}
    assert "link" not in names and "limpo.txt" in names


# --- relatório / CLI ---------------------------------------------------------
def test_report_with_and_without_threats(rules, sample_dir, tmp_path):
    summary = Scanner(rules).scan(sample_dir)
    pdf = save_report(summary, tmp_path / "out")
    assert pdf.exists() and pdf.read_bytes().startswith(b"%PDF")

    clean = Scanner(rules).scan(sample_dir / "limpo.txt")
    assert save_report(clean, tmp_path / "out").exists()


def test_report_handles_unicode_paths(rules, tmp_path):
    f = tmp_path / "relatório ✓ 日本.txt"
    f.write_text(EICAR)
    summary = Scanner(rules).scan(tmp_path)
    assert save_report(summary, tmp_path / "out").exists()


def test_cli_exit_codes(sample_dir, capsys):
    assert main([str(sample_dir / "limpo.txt"), "--no-report"]) == 0
    assert main([str(sample_dir), "--no-report"]) == 1
    assert main(["/nao/existe", "--no-report"]) == 2


KNOWN_UNLOADABLE = {"malrtf.yara", "win_geodo.yara", "win_plugx.yara"}  # dependem de módulos/campos ausentes


def test_shipped_rules_all_compile_except_known(rules):
    """Atualizar as regras não pode quebrar nenhuma silenciosamente."""
    unexpected = set(rules.skipped) - KNOWN_UNLOADABLE
    assert not unexpected, f"regras que não compilam: {sorted(unexpected)}"
    assert len(rules.loaded) >= 1100


def test_recent_rules_present(rules):
    """O pacote inclui regras recentes (2026) da Elastic, e não só as de 2024."""
    import re
    newest = ""
    for f in rules.loaded:
        m = re.search(r'last_modified = "([\d-]+)"', (DEFAULT_RULES_DIR / f).read_text(errors="ignore"))
        if m and m.group(1) > newest:
            newest = m.group(1)
    assert newest >= "2026-10"


def test_feature_rules_do_not_flag_ordinary_binaries(rules, tmp_path):
    """Regressão: 'obfuscation_singlebyte_mov' casava com 74 arquivos legítimos (jars, dylibs...)."""
    f = tmp_path / "programa_comum.bin"
    f.write_bytes(b"\x00" * 64 + bytes.fromhex("c6450041c6450142c6450243c645") + b"\x00" * 64)
    assert scan_file(f, rules) == []
