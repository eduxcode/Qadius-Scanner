"""Gera o executável com PyInstaller (macOS: Qadius Scanner.app / Windows: Qadius Scanner.exe).

Uso, na raiz do projeto, com as dependências instaladas:
    pip install pyinstaller
    python packaging/build.py

O PyInstaller não faz build cruzado: rode no sistema para o qual quer o executável.
O resultado fica em dist/.
"""
import os
import platform
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
NAME = "Qadius Scanner"


def main() -> int:
    system = platform.system()
    subprocess.run([sys.executable, str(ROOT / "packaging" / "make_icon.py")], check=True)
    icon = ROOT / "packaging" / ("icon.icns" if system == "Darwin" else "icon.ico")

    # Compila numa pasta temporária: pastas sincronizadas (iCloud/OneDrive) interferem na assinatura.
    work = Path(tempfile.mkdtemp(prefix="qadius-build-"))
    cmd = [
        sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean", "--windowed",
        "--name", NAME,
        "--icon", str(icon),
        "--add-data", f"{ROOT / 'rules'}{os.pathsep}rules",
        "--collect-all", "ttkbootstrap",
        "--hidden-import", "yara",
        # O app não usa rede. No macOS o yara-python traz um OpenSSL que conflita com o do Python.
        "--exclude-module", "ssl", "--exclude-module", "_ssl",
        "--distpath", str(work / "dist"), "--workpath", str(work / "work"), "--specpath", str(work),
        str(ROOT / "interface.py"),
    ]
    if system == "Darwin":
        cmd += ["--osx-bundle-identifier", "dev.qadius.scanner"]
    print(" ".join(cmd))
    subprocess.run(cmd, check=True, cwd=ROOT)

    artifact = NAME + (".app" if system == "Darwin" else "")
    built = work / "dist" / artifact
    if system == "Darwin":
        # Em Macs com chip Apple, app sem assinatura não abre: assinatura "ad-hoc" (sem conta de desenvolvedor).
        subprocess.run(["xattr", "-cr", str(built)], check=True)
        subprocess.run(["codesign", "--force", "--deep", "-s", "-", str(built)], check=True)
        subprocess.run(["codesign", "--verify", "--deep", "--strict", str(built)], check=True)
    else:
        built = work / "dist" / NAME  # Windows: pasta com o .exe e as bibliotecas

    final = ROOT / "dist" / built.name
    shutil.rmtree(final, ignore_errors=True)
    final.parent.mkdir(exist_ok=True)
    if system == "Darwin":
        subprocess.run(["ditto", "--noextattr", "--norsrc", str(built), str(final)], check=True)
    else:
        shutil.copytree(built, final)
    shutil.rmtree(work, ignore_errors=True)
    print("\nPronto:", final)
    return 0


if __name__ == "__main__":
    sys.exit(main())
