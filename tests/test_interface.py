import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

tk = pytest.importorskip("tkinter")
pytest.importorskip("ttkbootstrap")

import interface  # noqa: E402
from scanner import DEFAULT_RULES_DIR, load_rules  # noqa: E402

EICAR = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


@pytest.fixture(scope="module")
def rules():
    return load_rules(DEFAULT_RULES_DIR)


@pytest.fixture
def app(rules, monkeypatch, tmp_path):
    import ttkbootstrap as ttk

    try:
        root = ttk.Window(themename="darkly")
    except tk.TclError:
        pytest.skip("sem display disponível")
    shown = []
    for name in ("showinfo", "showwarning", "showerror"):
        monkeypatch.setattr(interface.messagebox, name, lambda *a, _n=name, **k: shown.append((_n, a)))
    monkeypatch.setattr(interface, "DEFAULT_REPORTS_DIR", tmp_path / "reports")
    import report
    monkeypatch.setattr(report, "DEFAULT_REPORTS_DIR", tmp_path / "reports")
    monkeypatch.setattr(interface, "save_report", lambda s: report.save_report(s, tmp_path / "reports"))
    application = interface.QadiusApp(root, rules)
    application.shown = shown
    root.withdraw()
    yield application
    root.destroy()


def pump(app, until, timeout=20):
    end = time.time() + timeout
    while time.time() < end:
        app.root.update()
        if until():
            return True
        time.sleep(0.02)
    return False


def test_starts_idle(app):
    assert str(app.start_btn.cget("state")) == "normal"
    assert str(app.stop_btn.cget("state")) == "disabled"
    assert str(app.report_btn.cget("state")) == "disabled"


def test_scan_finds_eicar_and_enables_report(app, tmp_path):
    target = tmp_path / "alvo"
    target.mkdir()
    (target / "ok.txt").write_text("normal")
    (target / "eicar.com").write_text(EICAR)

    app.path_var.set(str(target))
    app.start_scan()
    assert str(app.start_btn.cget("state")) == "disabled"  # bloqueado durante a varredura
    assert pump(app, lambda: str(app.start_btn.cget("state")) == "normal"), "varredura não terminou"

    rows = [app.tree.item(i, "values") for i in app.tree.get_children()]
    assert len(rows) == 1
    assert rows[0][1] == "Multi.EICAR.Not-a-virus" and rows[0][2].endswith("eicar.com")
    full = next(iter(app.rows.values()))
    assert full.path.endswith("eicar.com")  # caminho completo guardado, mesmo se a célula for encurtada
    assert app.threats_var.get() == "1"
    assert app.files_var.get() == "2"
    assert str(app.report_btn.cget("state")) == "normal"
    assert app.last_report.exists()


def test_clean_folder_shows_all_clear(app, tmp_path):
    (tmp_path / "a.txt").write_text("nada")
    app.path_var.set(str(tmp_path))
    app.start_scan()
    assert pump(app, lambda: str(app.start_btn.cget("state")) == "normal")
    assert not app.tree.get_children()
    assert "Nenhuma ameaça" in app.empty_label.cget("text")


def test_invalid_path_warns_and_does_not_start(app):
    app.path_var.set("/caminho/que/nao/existe")
    app.start_scan()
    assert app.shown and app.shown[0][0] == "showwarning"
    assert app.worker is None


def test_stop_cancels(app, tmp_path):
    for i in range(300):
        (tmp_path / f"f{i}.txt").write_text("x" * 50)
    app.path_var.set(str(tmp_path))
    app.start_scan()
    app.stop_scan()
    assert pump(app, lambda: str(app.start_btn.cget("state")) == "normal")
    assert "interrompida" in app.status_var.get() or "Concluído" in app.status_var.get()


def test_fit_keeps_end_of_path_and_fits_width(app):
    app.root.deiconify()
    app.root.update()
    path = "/Users/alguem/uma/pasta/muito/longa/demais/para/caber/na/coluna/relatorio_final.zip"
    short = app._fit(path, 220, keep_end=True)
    assert short.startswith("…") and short.endswith("relatorio_final.zip")
    assert app.tree_font.measure(short) <= 220
    assert app._fit("curto.txt", 220, keep_end=True) == "curto.txt"
    assert app._fit("Multi.EICAR.Not-a-virus (nome enorme) " * 5, 200).endswith("…")


def test_zip_threat_is_clear_and_details_show_full_text(app, tmp_path):
    import io, zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("pasta/eicar.com", EICAR)
    (tmp_path / "pacote_compactado.zip").write_bytes(buf.getvalue())
    app.path_var.set(str(tmp_path))
    app.start_scan()
    assert pump(app, lambda: str(app.start_btn.cget("state")) == "normal")
    iid = app.tree.get_children()[0]
    values = app.tree.item(iid, "values")
    assert values[1] == "Multi.EICAR.Not-a-virus"          # nome da ameaça limpo, sem texto extra
    assert "pasta/eicar.com" in values[2]                  # local dentro do zip na coluna do arquivo
    app.tree.selection_set(iid)
    app.root.update()
    detail = app.detail_label.cget("text")
    assert "pacote_compactado.zip" in detail and "dentro de: pasta/eicar.com" in detail and "O que fazer" in detail


def test_columns_follow_window_width(app, tmp_path):
    app.root.deiconify()
    app.root.geometry("1200x700")
    app.root.update()
    wide = int(app.tree.column("file", "width"))
    app.root.geometry("820x700")
    app.root.update()
    pump(app, lambda: False, timeout=0.3)
    narrow = int(app.tree.column("file", "width"))
    assert narrow < wide
    total = sum(int(app.tree.column(c, "width")) for c in ("risk", "threat", "file"))
    assert total <= app.tree.winfo_width() + 8  # nada passa da borda da tabela


def test_self_test_mode(capsys):
    assert interface.self_test() == 0
    assert "OK" in capsys.readouterr().out


@pytest.mark.parametrize("size", ["960x780", "780x680"])
def test_footer_and_details_always_visible(app, size):
    """Regressão: o rodapé era o primeiro a ser cortado quando a janela ficava baixa."""
    app.root.deiconify()
    app.root.geometry(size)
    app.root.update()
    pump(app, lambda: False, timeout=0.2)
    bottom = app.root.winfo_height()
    for widget in (app.report_btn, app.reveal_btn, app.detail_label):
        y = widget.winfo_rooty() - app.root.winfo_rooty() + widget.winfo_height()
        assert 0 < y <= bottom, f"{widget} cortado em {size}"
    assert app.tree.winfo_height() > 40  # a tabela é quem encolhe, não o rodapé
