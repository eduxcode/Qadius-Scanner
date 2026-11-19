"""Detecção do EICAR em vários formatos.

O EICAR é um texto inerte de 68 bytes, criado para testar antivírus. Nenhum malware real é
usado e nada aqui é executado: os arquivos são gerados em pastas temporárias e só são LIDOS.
"""
import base64
import gzip
import io
import sys
import tarfile
import time
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import scanner  # noqa: E402
from scanner import DEFAULT_RULES_DIR, Scanner, load_rules, scan_file  # noqa: E402

EICAR = rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
THREAT = "Multi.EICAR.Not-a-virus"


@pytest.fixture(scope="module")
def rules():
    return load_rules(DEFAULT_RULES_DIR)


def make_zip(files: dict, compression=zipfile.ZIP_DEFLATED) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression) as zf:
        for name, data in files.items():
            zf.writestr(name, data)
    return buf.getvalue()


def make_tar(files: dict, mode="w") -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode=mode) as tf:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def nested_zip(depth: int) -> bytes:
    data = EICAR
    for i in range(depth):
        data = make_zip({f"nivel{i}.bin" if i else "eicar.com": data})
    return data


def detected(rules, tmp_path, content: bytes, name="amostra.bin"):
    f = tmp_path / name
    f.write_bytes(content)
    return [d for d in scan_file(f, rules) if d.threat_name == THREAT]


# --- formatos simples (devem ser detectados) ---------------------------------
SIMPLE = {
    "puro": EICAR,
    "com_quebra_de_linha_crlf": EICAR + b"\r\n",
    "com_espacos_no_fim": EICAR + b"   \t\n",
    "dentro_de_texto": b"relatorio de teste\n" + EICAR + b"\nfim do arquivo\n",
    "depois_de_lixo_binario": bytes(range(256)) * 20 + b"\n" + EICAR + b"\n",
    "no_comeco_de_arquivo_grande": EICAR + b"\n" + b"A" * 3_000_000,
    "no_fim_de_arquivo_grande": b"A" * 3_000_000 + b"\n" + EICAR,
}


@pytest.mark.parametrize("content", SIMPLE.values(), ids=SIMPLE.keys())
def test_plain_variants(rules, tmp_path, content):
    assert detected(rules, tmp_path, content)


@pytest.mark.parametrize("name", ["eicar.com", "foto.jpg", "planilha.xlsx", "sem_extensao", "EICAR.TXT",
                                  "relatório ✓ 日本.pdf"])
def test_detection_does_not_depend_on_extension(rules, tmp_path, name):
    assert detected(rules, tmp_path, EICAR, name)


def test_detected_deep_in_folder_tree(rules, tmp_path):
    deep = tmp_path.joinpath(*[f"nivel{i}" for i in range(12)])
    deep.mkdir(parents=True)
    (deep / "eicar.com").write_bytes(EICAR)
    summary = Scanner(rules).scan(tmp_path)
    assert summary.threat_files == 1


# --- arquivos compactados -----------------------------------------------------
ARCHIVES = {
    "zip_deflate": make_zip({"eicar.com": EICAR}),
    "zip_stored": make_zip({"eicar.com": EICAR}, zipfile.ZIP_STORED),
    "zip_entre_arquivos_limpos": make_zip({"a.txt": b"oi", "pasta/eicar.com": EICAR, "z.txt": b"fim"}),
    "zip_com_nome_unicode": make_zip({"relatório_日本.com": EICAR}),
    "zip_dentro_de_zip": nested_zip(2),                 # igual ao eicarcom2.zip oficial
    "zip_3_niveis": nested_zip(3),
    "tar": make_tar({"eicar.com": EICAR}),
    "tar_gz": make_tar({"x/eicar.com": EICAR}, "w:gz"),
    "gz": gzip.compress(EICAR),
    "zip_com_tar_gz_dentro": make_zip({"pacote.tgz": make_tar({"eicar.com": EICAR}, "w:gz")}),
}


@pytest.mark.parametrize("content", ARCHIVES.values(), ids=ARCHIVES.keys())
def test_archive_variants(rules, tmp_path, content):
    found = detected(rules, tmp_path, content, "arquivo.dat")  # extensão enganosa de propósito
    assert found, "EICAR dentro do arquivo compactado deveria ser encontrado"


def test_location_inside_archive_is_reported(rules, tmp_path):
    (tmp_path / "pacote.zip").write_bytes(make_zip({"pasta/eicar.com": EICAR}))
    summary = Scanner(rules).scan(tmp_path)
    det = summary.results[0].detections[0]
    assert det.location.endswith("pacote.zip!pasta/eicar.com")


def test_stored_zip_reports_only_inner_finding(rules, tmp_path):
    f = tmp_path / "s.zip"
    f.write_bytes(make_zip({"eicar.com": EICAR}, zipfile.ZIP_STORED))
    dets = scan_file(f, rules)
    assert len(dets) == 1 and dets[0].location


def test_archive_scanning_can_be_disabled(rules, tmp_path):
    f = tmp_path / "z.zip"
    f.write_bytes(make_zip({"eicar.com": EICAR}))
    assert scan_file(f, rules, archives=False) == []


def test_clean_archives_have_no_detections(rules, tmp_path):
    f = tmp_path / "limpo.zip"
    f.write_bytes(make_zip({"a.txt": b"texto normal", "b.bin": bytes(range(256)) * 50}))
    assert scan_file(f, rules) == []


# --- segurança contra arquivos hostis / quebrados -----------------------------
def test_zip_bomb_is_not_expanded(rules, tmp_path, monkeypatch):
    """Item que descompacta para muito mais que o limite é descartado, sem estourar memória."""
    monkeypatch.setattr(scanner, "ARCHIVE_MAX_MEMBER_SIZE", 1024 * 1024)
    f = tmp_path / "bomba.zip"
    f.write_bytes(make_zip({"zeros.bin": b"\0" * (60 * 1024 * 1024)}))  # ~60 KB compactado
    start = time.time()
    assert scan_file(f, rules) == []
    assert time.time() - start < 10


def test_total_budget_stops_extraction(rules, tmp_path, monkeypatch):
    monkeypatch.setattr(scanner, "ARCHIVE_MAX_TOTAL_SIZE", 2000)
    files = {f"f{i}.bin": b"x" * 900 for i in range(5)}
    files["eicar_tarde.com"] = EICAR  # fica depois do orçamento: não é lido
    f = tmp_path / "grande.zip"
    f.write_bytes(make_zip(files))
    assert scan_file(f, rules) == []


def test_member_count_limit(rules, tmp_path, monkeypatch):
    monkeypatch.setattr(scanner, "ARCHIVE_MAX_MEMBERS", 3)
    files = {f"f{i}.txt": b"a" for i in range(10)}
    files["eicar.com"] = EICAR
    f = tmp_path / "muitos.zip"
    f.write_bytes(make_zip(files))
    assert scan_file(f, rules) == []


@pytest.mark.parametrize("cut", [10, 40, 120])
def test_truncated_zip_does_not_crash(rules, tmp_path, cut):
    data = make_zip({"eicar.com": EICAR, "b.txt": b"x" * 500})
    (tmp_path / "quebrado.zip").write_bytes(data[:cut])
    scan_file(tmp_path / "quebrado.zip", rules)  # não pode levantar exceção


def test_corrupt_gzip_and_tar_do_not_crash(rules, tmp_path):
    (tmp_path / "a.gz").write_bytes(b"\x1f\x8b" + b"lixo" * 50)
    (tmp_path / "b.tar").write_bytes(b"\0" * 257 + b"ustar" + b"\xff" * 300)
    Scanner(rules).scan(tmp_path)


def test_empty_and_tiny_files(rules, tmp_path):
    (tmp_path / "vazio").write_bytes(b"")
    (tmp_path / "um").write_bytes(b"x")
    (tmp_path / "pk").write_bytes(b"PK\x03\x04")
    summary = Scanner(rules).scan(tmp_path)
    assert summary.error_count == 0 and summary.threat_files == 0


# --- lacunas conhecidas (documentadas; viram falha se um dia passarem a funcionar) ---
def _encrypted_zip() -> bytes:
    data = bytearray(make_zip({"eicar.com": EICAR}))
    # marca o bit de "criptografado" no cabeçalho local e no diretório central
    data[6] |= 0x01
    cd = data.rfind(b"PK\x01\x02")
    data[cd + 8] |= 0x01
    return bytes(data)


KNOWN_GAPS = {
    "utf16": EICAR.decode().encode("utf-16"),
    "base64": base64.b64encode(EICAR),
    "zip_com_senha": _encrypted_zip(),
    "zip_4_niveis_alem_do_limite": nested_zip(5),
    "bytes_colados_em_letras": b"abc" + EICAR + b"xyz",  # regra exige palavra isolada (fullword)
}


@pytest.mark.parametrize("content", KNOWN_GAPS.values(), ids=KNOWN_GAPS.keys())
@pytest.mark.xfail(strict=True, reason="limitação conhecida: documentada no README")
def test_known_gaps(rules, tmp_path, content):
    assert detected(rules, tmp_path, content)


# --- ponta a ponta -------------------------------------------------------------
def test_mixed_folder_end_to_end(rules, tmp_path):
    (tmp_path / "limpo.txt").write_text("nada aqui")
    (tmp_path / "puro.com").write_bytes(EICAR)
    (tmp_path / "pacote.zip").write_bytes(nested_zip(2))
    (tmp_path / "backup.tar.gz").write_bytes(make_tar({"eicar.com": EICAR}, "w:gz"))
    summary = Scanner(rules).scan(tmp_path)
    assert summary.total_files == 4
    assert summary.threat_files == 3
    assert summary.error_count == 0
