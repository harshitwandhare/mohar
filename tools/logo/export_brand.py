"""Exports the Mohar brand images from the Blender renders.

    python tools/logo/export_brand.py

Inputs (rendered by seal.py in this folder):
    renders/logo-gold-3q.png        the gold seal, three-quarter view, 2048 px, transparent
    renders/logo-gold-small-512.png the simplified straight-on seal for small sizes
Outputs go to site/assets/brand/ and docs/assets/, and are what every page, the README and the
docs site use. Rerun this after any re-render.
"""
from pathlib import Path

from PIL import Image

ROOT = Path(__file__).resolve().parents[2]
SRC = Path(__file__).resolve().parent / "renders"
OUT = ROOT / "site" / "assets" / "brand"
DOCS = ROOT / "docs" / "assets"


def trimmed(path, pad=0.04):
    """Crop to the visible pixels plus a small margin, on a square canvas."""
    im = Image.open(path).convert("RGBA")
    box = im.getchannel("A").point(lambda a: 255 if a > 8 else 0).getbbox()
    im = im.crop(box)
    side = int(max(im.size) * (1 + 2 * pad))
    sq = Image.new("RGBA", (side, side), (0, 0, 0, 0))
    sq.paste(im, ((side - im.width) // 2, (side - im.height) // 2), im)
    return sq


def save(im, size, name, *dirs):
    out = im.resize((size, size), Image.LANCZOS)
    for d in dirs:
        d.mkdir(parents=True, exist_ok=True)
        out.save(d / name, optimize=True)


seal = trimmed(SRC / "logo-gold-3q.png")
mark = trimmed(SRC / "logo-gold-small-512.png", pad=0.02)

# The full seal: README, docs home, large uses.
save(seal, 1024, "mohar-seal-1024.png", OUT)
save(seal, 512, "mohar-seal-512.png", OUT, DOCS)
# The simplified mark: header wordmark, favicons, app icons.
save(mark, 96, "mohar-mark-96.png", OUT)
save(mark, 192, "icon-192.png", OUT)
save(mark, 512, "icon-512.png", OUT)
save(mark, 32, "favicon-32.png", OUT)
save(mark, 64, "favicon-64.png", DOCS)
# Apple touch icons have no transparency; set the mark on the site's ground.
touch = Image.new("RGBA", (180, 180), (22, 19, 15, 255))
small = mark.resize((150, 150), Image.LANCZOS)
touch.paste(small, (15, 15), small)
touch.convert("RGB").save(OUT / "apple-touch-icon.png", optimize=True)
# favicon.ico at the site root, for browsers and tools that only ask for that.
mark.save(ROOT / "site" / "favicon.ico", sizes=[(16, 16), (32, 32), (48, 48)])
print("wrote", sorted(p.name for p in OUT.iterdir()))
