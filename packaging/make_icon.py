"""
make_icon.py -- draws the Haltline mark: an activity trace that spikes, then flatlines into an amber
halt bar ("Haltline watches behaviour and halts it"). No tile: the mark sits on the taskbar itself.

    python packaging/make_icon.py

Writes, in packaging/:
  haltline.ico             .exe files, installer, Start, desktop: cream trace with a thin ink outline,
                           so it reads on light and dark backgrounds alike (16-256 px)
  haltline-tray-dark.ico   tray on a dark taskbar: cream trace           (16-32 px)
  haltline-tray-light.ico  tray on a light taskbar: ink trace            (16-32 px)
  haltline-tray-off-*.ico  tray while Haltline is stopped: all grey      (16-32 px)
  haltline.png             512 px preview
Small sizes use a simpler trace and heavier strokes so it still reads at 16 px.
"""
import os

from PIL import Image, ImageDraw

AMBER, PAPER, INK, GREY = (242, 178, 58, 255), (246, 241, 227, 255), (24, 27, 31, 255), (128, 128, 124, 255)
APP_SIZES = (16, 20, 24, 32, 40, 48, 64, 96, 128, 256)
TRAY_SIZES = (16, 20, 24, 32)
HERE = os.path.dirname(os.path.abspath(__file__))


def mark(size, trace=PAPER, bar=AMBER, outline=None):
    s = size * 8   # draw large, then downscale: clean anti-aliased edges
    small = size <= 24
    img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    u = lambda v: round(v * s)
    t = 0.12 if small else 0.075
    pts = ([(0.07, 0.5), (0.20, 0.5), (0.33, 0.20), (0.47, 0.80), (0.57, 0.5), (0.66, 0.5)] if small else
           [(0.09, 0.5), (0.22, 0.5), (0.31, 0.22), (0.42, 0.78), (0.51, 0.36), (0.57, 0.5), (0.66, 0.5)])
    w = 0.25 if small else 0.2
    bar_box = (u(0.66), u(0.14 if small else 0.18), u(0.66 + w), u(0.86 if small else 0.82))
    line = [(u(x), u(y)) for x, y in pts]
    if outline:   # a thin ink edge so the cream trace still reads on white
        e = u(0.035)
        d.line(line, fill=outline, width=u(t) + 2 * e, joint="curve")
        for x, y in line[:1]:
            d.ellipse((x - u(t) / 2 - e, y - u(t) / 2 - e, x + u(t) / 2 + e, y + u(t) / 2 + e), fill=outline)
        d.rounded_rectangle((bar_box[0] - e, bar_box[1] - e, bar_box[2] + e, bar_box[3] + e), radius=u(w * 0.25) + e, fill=outline)
    d.line(line, fill=trace, width=u(t), joint="curve")
    x, y = line[0]
    d.ellipse((x - u(t) / 2, y - u(t) / 2, x + u(t) / 2, y + u(t) / 2), fill=trace)   # round start
    d.rounded_rectangle(bar_box, radius=u(w * 0.25), fill=bar)
    return img.resize((size, size), Image.LANCZOS)


def save_ico(name, sizes, **kw):
    frames = [mark(n, **kw) for n in sizes]
    path = os.path.join(HERE, name)
    frames[-1].save(path, sizes=[(n, n) for n in sizes], append_images=frames[:-1])
    with Image.open(path) as ico:   # self-check: every size made it in
        assert set(ico.info["sizes"]) >= {(n, n) for n in sizes}, (name, ico.info["sizes"])


def main():
    save_ico("haltline.ico", APP_SIZES, outline=INK)
    save_ico("haltline-tray-dark.ico", TRAY_SIZES)
    save_ico("haltline-tray-light.ico", TRAY_SIZES, trace=INK)
    save_ico("haltline-tray-off-dark.ico", TRAY_SIZES, trace=GREY, bar=GREY)
    save_ico("haltline-tray-off-light.ico", TRAY_SIZES, trace=GREY, bar=GREY)
    mark(512, outline=INK).save(os.path.join(HERE, "haltline.png"))
    big = mark(256).convert("RGBA")
    assert big.getpixel((5, 5))[3] == 0, "no tile: the corners are transparent"
    assert big.getpixel((int(256 * 0.76), 128))[:3] == AMBER[:3], "the halt bar is amber"
    print("wrote haltline.ico, 4 tray icons and haltline.png")


if __name__ == "__main__":
    main()
