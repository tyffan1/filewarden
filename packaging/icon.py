"""Generate the FileWarden application icon.

Pure standard library: pixels are painted procedurally and written as a PNG
(a tiny zlib/struct based writer).  The ``.icns`` flavour is produced from the
PNG set with the system ``sips``/``iconutil`` tools (macOS); the ``.ico``
flavour is assembled directly from 32-bit BMP entries (Windows).

    python3 packaging/icon.py build/FileWarden.icns
    python3 packaging/icon.py build/FileWarden.ico
"""

from __future__ import annotations

import math
import shutil
import struct
import subprocess
import sys
import tempfile
import zlib
from pathlib import Path

BG_TOP = (36, 61, 104)      # #243D68
BG_BOTTOM = (13, 20, 36)    # #0D1424
SHIELD_TOP_COLOR = (204, 216, 234)
SHIELD_BOTTOM_COLOR = (248, 251, 255)
CHECK = (61, 220, 132)      # #3DDC84

# Shield geometry, all coordinates are fractions of the icon size.
SHIELD_TOP = 0.210
SHIELD_BOTTOM = 0.830
SHIELD_HALF = 0.252
CORNER_RADIUS = 0.056
TAPER_POWER = 2.8   # sides stay almost straight, then bend to the tip
TAPER_ROOT = 0.9    # ~1 keeps the bottom tip pointy (with a soft rounding)

CHECK_POINTS = ((0.385, 0.545), (0.478, 0.638), (0.645, 0.435))
CHECK_RADIUS = 0.034


def _lerp(a: float, b: float, t: float) -> float:
    return a + (b - a) * t


def _mix(color_a, color_b, t: float):
    return tuple(_lerp(color_a[i], color_b[i], t) for i in range(3))


def _inside_superellipse(x: float, y: float, power: float = 4.2) -> bool:
    """Squircle background, similar to a macOS app icon mask."""
    dx = abs(x - 0.5) * 2.0
    dy = abs(y - 0.5) * 2.0
    return dx**power + dy**power <= 1.0


def _shield_half_width(y: float) -> float:
    if y < SHIELD_TOP or y > SHIELD_BOTTOM:
        return 0.0
    t = (y - SHIELD_TOP) / (SHIELD_BOTTOM - SHIELD_TOP)
    return SHIELD_HALF * (1.0 - t**TAPER_POWER) ** TAPER_ROOT


def _inside_shield(x: float, y: float) -> bool:
    half = _shield_half_width(y)
    if half <= 0.0:
        return False
    if y < SHIELD_TOP + CORNER_RADIUS:  # rounded top corners
        cy = SHIELD_TOP + CORNER_RADIUS
        left = 0.5 - SHIELD_HALF + CORNER_RADIUS
        right = 0.5 + SHIELD_HALF - CORNER_RADIUS
        if x < left:
            return (x - left) ** 2 + (y - cy) ** 2 <= CORNER_RADIUS**2
        if x > right:
            return (x - right) ** 2 + (y - cy) ** 2 <= CORNER_RADIUS**2
    return abs(x - 0.5) <= half


def _distance_to_segment(px: float, py: float, ax: float, ay: float,
                         bx: float, by: float) -> float:
    dx, dy = bx - ax, by - ay
    length_sq = dx * dx + dy * dy
    if length_sq == 0.0:
        return math.hypot(px - ax, py - ay)
    t = max(0.0, min(1.0, ((px - ax) * dx + (py - ay) * dy) / length_sq))
    return math.hypot(px - (ax + t * dx), py - (ay + t * dy))


def _inside_check(x: float, y: float) -> bool:
    radius = CHECK_RADIUS * 0.78
    for (ax, ay), (bx, by) in zip(CHECK_POINTS, CHECK_POINTS[1:]):
        if _distance_to_segment(x, y, ax, ay, bx, by) <= radius:
            return True
    return False


def _sample(x: float, y: float):
    """Return RGBA for one point in the unit square (or None outside)."""
    if not _inside_superellipse(x, y):
        return None
    if _inside_check(x, y):
        return (*CHECK, 255)
    if _inside_shield(x, y):
        shade = (y - SHIELD_TOP) / (SHIELD_BOTTOM - SHIELD_TOP)
        color = _mix(SHIELD_TOP_COLOR, SHIELD_BOTTOM_COLOR, min(1.0, max(0.0, shade)))
        return (*color, 255)
    return (*_mix(BG_TOP, BG_BOTTOM, y), 255)


def render(size: int, supersample: int = 2) -> bytearray:
    pixels = bytearray(size * size * 4)
    step = 1.0 / (size * supersample)
    samples = supersample * supersample
    offset = 0
    for py in range(size):
        for px in range(size):
            red = green = blue = alpha = 0.0
            base_y = py * supersample * step
            base_x = px * supersample * step
            for sy in range(supersample):
                y = base_y + (sy + 0.5) * step
                for sx in range(supersample):
                    x = base_x + (sx + 0.5) * step
                    sample = _sample(x, y)
                    if sample is not None:
                        red += sample[0]
                        green += sample[1]
                        blue += sample[2]
                        alpha += 255.0
            pixels[offset] = int(red / samples)
            pixels[offset + 1] = int(green / samples)
            pixels[offset + 2] = int(blue / samples)
            pixels[offset + 3] = int(alpha / samples)
            offset += 4
    return pixels


def write_png(path: Path, size: int, pixels: bytearray) -> None:
    stride = size * 4
    raw = bytearray()
    for row in range(size):
        raw.append(0)  # no per-row filter
        raw += pixels[row * stride:(row + 1) * stride]

    def chunk(tag: bytes, payload: bytes) -> bytes:
        return (
            struct.pack(">I", len(payload))
            + tag
            + payload
            + struct.pack(">I", zlib.crc32(tag + payload) & 0xFFFFFFFF)
        )

    blob = b"\x89PNG\r\n\x1a\n"
    blob += chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0))
    blob += chunk(b"IDAT", zlib.compress(bytes(raw), 9))
    blob += chunk(b"IEND", b"")
    Path(path).write_bytes(blob)


ICO_SIZES = (16, 24, 32, 48, 64, 128, 256)


def _dib(size: int, pixels: bytearray) -> bytes:
    """One 32-bit BMP/DIB image in the layout classic ``.ico`` files use."""
    header = struct.pack(
        "<IiiHHIIiiII",
        40,               # biSize
        size,             # biWidth
        size * 2,         # biHeight: XOR image plus AND mask
        1,                # biPlanes
        32,               # biBitCount
        0,                # biCompression
        size * size * 4,  # biSizeImage
        0, 0, 0, 0,       # resolution and palette
    )
    body = bytearray()
    stride = size * 4
    for row in range(size - 1, -1, -1):  # DIB rows are stored bottom-up
        start = row * stride
        for pos in range(start, start + stride, 4):
            body += bytes((pixels[pos + 2], pixels[pos + 1], pixels[pos], pixels[pos + 3]))
    mask_stride = ((size + 31) // 32) * 4
    return header + bytes(body) + b"\x00" * (mask_stride * size)


def build_ico(target: Path, sizes: tuple[int, ...] = ICO_SIZES) -> Path:
    """Render the icon as a classic Windows ``.ico`` (BMP entries)."""
    output = Path(target)
    output.parent.mkdir(parents=True, exist_ok=True)
    images = []
    for size in sizes:
        supersample = 4 if size <= 32 else 3 if size <= 64 else 2
        images.append((size, _dib(size, render(size, supersample=supersample))))

    header = struct.pack("<HHH", 0, 1, len(images))  # reserved, type=icon, count
    offset = len(header) + 16 * len(images)
    entries = bytearray()
    payload = bytearray()
    for size, blob in images:
        dimension = 0 if size >= 256 else size  # 0 stands for 256 in the ICO header
        entries += struct.pack("<BBBBHHII", dimension, dimension, 0, 0, 1, 32, len(blob), offset)
        offset += len(blob)
        payload += blob
    output.write_bytes(header + bytes(entries) + bytes(payload))
    return output


ICONSET_SIZES = (16, 32, 64, 128, 256, 512, 1024)


def build_icns(target: Path, png_master: Path | None = None) -> Path:
    """Render the master PNG and convert it to ``.icns`` (macOS only)."""
    output = Path(target)
    output.parent.mkdir(parents=True, exist_ok=True)

    if png_master is None:
        png_master = output.with_suffix(".png")
    master_path = Path(png_master)
    if not master_path.exists():
        write_png(master_path, 1024, render(1024))

    sips = shutil.which("sips")
    iconutil = shutil.which("iconutil")
    if not (sips and iconutil):
        raise RuntimeError("sips/iconutil not found — .icns can only be built on macOS")

    with tempfile.TemporaryDirectory(prefix="filewarden-iconset-") as tmp:
        iconset = Path(tmp) / "FileWarden.iconset"
        iconset.mkdir()
        variants = {
            16: ["icon_16x16.png"],
            32: ["icon_16x16@2x.png", "icon_32x32.png"],
            64: ["icon_32x32@2x.png"],
            128: ["icon_128x128.png"],
            256: ["icon_128x128@2x.png", "icon_256x256.png"],
            512: ["icon_256x256@2x.png", "icon_512x512.png"],
            1024: ["icon_512x512@2x.png"],
        }
        for size, names in variants.items():
            for name in names:
                subprocess.run(
                    [sips, "-z", str(size), str(size), str(master_path),
                     "--out", str(iconset / name)],
                    check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                )
        subprocess.run(
            [iconutil, "-c", "icns", str(iconset), "-o", str(output)],
            check=True, stdout=subprocess.DEVNULL,
        )
    return output


def main(argv: list[str]) -> int:
    target = Path(argv[1]) if len(argv) > 1 else Path("build/FileWarden.icns")
    if len(argv) > 2 and argv[2] == "--png-only":
        png = target if target.suffix == ".png" else target.with_suffix(".png")
        png.parent.mkdir(parents=True, exist_ok=True)
        write_png(png, 1024, render(1024))
        print(f"PNG written: {png}")
        return 0
    if target.suffix.lower() == ".ico":
        ico = build_ico(target)
        print(f"ICO written: {ico} ({ico.stat().st_size} bytes)")
        return 0
    icns = build_icns(target)
    print(f"ICNS written: {icns} ({icns.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
