# skills.py brand assets

The mark is a shield with a terminal prompt (`>_`) cut out of it: security plus the command line, in one shape. Everything here is rendered from the source SVGs, so you can re-export any size without quality loss.

## Colors

| Token | Hex | Use |
| --- | --- | --- |
| Background | `#0D1117` | Dark surfaces, icon tile, social cards |
| Green (primary) | `#3FB950` | The mark and the `.py`, on dark |
| Green (on light) | `#2DA44E` | The mark and the `.py`, on white/light |
| Text | `#E6EDF3` | `skills` wordmark on dark |
| Text (on light) | `#1F2328` | `skills` wordmark on light |
| Muted | `#8B949E` | Subtitles, captions |
| Faint | `#586069` | URLs, fine print |

## Type

Monospace. The lockups use the system mono stack (`ui-monospace, SF Mono, Menlo, Consolas`). For pixel-exact re-exports, [JetBrains Mono](https://www.jetbrains.com/lp/mono/) or SF Mono are good substitutes.

## Files

```
assets/
├── brand.md                     this guide
├── banner/
│   ├── hero.svg / hero.png      1280×600 README banner
├── icon/
│   ├── icon.svg / icon.png      transparent green mark (512)
│   ├── icon-mono-white.svg/.png white mark for dark/print
│   ├── icon-mono-black.svg/.png black mark for light/print
│   └── png/icon-{16…1024}.png   size ladder
├── favicon/
│   ├── favicon.svg / .ico       browser favicon
│   ├── favicon-{16,32,48}.png
│   ├── apple-touch-icon.png     180×180
│   ├── web-app-icon-192.png
│   ├── web-app-icon-512.png
│   └── site.webmanifest
├── logo/
│   ├── logo.svg / logo.png      lockup on dark tile
│   ├── logo-on-dark.svg/.png    transparent, for dark backgrounds
│   ├── logo-on-light.svg/.png   transparent, for light backgrounds
│   └── wordmark.svg / .png      type only
└── social/
    ├── github-social.svg/.png   1280×640 GitHub social preview
    └── og.svg / og.png          1200×630 OpenGraph / Twitter card
```

## Do

- Keep clear space around the mark equal to the height of the shield's notch.
- Use `logo-on-light` (darker green) on white; `logo-on-dark` on dark.
- Re-render from SVG when you need a new size.

## Don't

- Don't recolor the mark outside the palette above.
- Don't add gradients, shadows, or a stroke around the wordmark.
- Don't stretch the lockup; scale it uniformly.

## Re-exporting

PNGs were generated with [`rsvg-convert`](https://gitlab.gnome.org/GNOME/librsvg):

```bash
rsvg-convert -w 512 -h 512 icon/icon.svg -o icon/png/icon-512.png
```
