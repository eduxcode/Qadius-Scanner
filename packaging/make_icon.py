"""Gera o ícone do app (packaging/icon.png, .icns no macOS e .ico). Uso: python packaging/make_icon.py"""
import platform
import shutil
import subprocess
import tempfile
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

HERE = Path(__file__).resolve().parent


def draw(size: int = 1024) -> Image.Image:
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    pad = int(size * 0.06)
    d.rounded_rectangle([pad, pad, size - pad, size - pad], radius=int(size * 0.22), fill=(24, 33, 48, 255))
    # escudo
    cx, top, bottom, half = size // 2, int(size * 0.18), int(size * 0.84), int(size * 0.27)
    shield = [(cx - half, top + int(size * 0.04)), (cx, top), (cx + half, top + int(size * 0.04)),
              (cx + half, int(size * 0.52)), (cx, bottom), (cx - half, int(size * 0.52))]
    d.polygon(shield, fill=(46, 134, 222, 255))
    inner = [(cx - half + 40, top + int(size * 0.08)), (cx, top + 36), (cx + half - 40, top + int(size * 0.08)),
             (cx + half - 40, int(size * 0.51)), (cx, bottom - 56), (cx - half + 40, int(size * 0.51))]
    d.polygon(inner, fill=(24, 33, 48, 255))
    font = None
    for path in ("/System/Library/Fonts/Helvetica.ttc", "C:/Windows/Fonts/arialbd.ttf",
                 "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"):
        try:
            font = ImageFont.truetype(path, int(size * 0.34))
            break
        except OSError:
            continue
    font = font or ImageFont.load_default()
    d.text((cx, int(size * 0.47)), "Q", font=font, fill=(255, 255, 255, 255), anchor="mm")
    return img


def main() -> None:
    img = draw()
    img.save(HERE / "icon.png")
    img.save(HERE / "icon.ico", sizes=[(s, s) for s in (16, 32, 48, 64, 128, 256)])
    if platform.system() == "Darwin" and shutil.which("iconutil"):
        with tempfile.TemporaryDirectory() as tmp:
            iconset = Path(tmp) / "icon.iconset"
            iconset.mkdir()
            for base in (16, 32, 128, 256, 512):
                img.resize((base, base), Image.LANCZOS).save(iconset / f"icon_{base}x{base}.png")
                img.resize((base * 2, base * 2), Image.LANCZOS).save(iconset / f"icon_{base}x{base}@2x.png")
            subprocess.run(["iconutil", "-c", "icns", str(iconset), "-o", str(HERE / "icon.icns")], check=True)
    print("Ícones gerados em", HERE)


if __name__ == "__main__":
    main()
