# MNDe Brand Kit

The canonical MNDe logo and usage rules. Use these assets for **all marketing and logo needs**.

## The mark

The mark is a schematic of what MNDe does: **execution flows in (blue) → passes through the authority gate → controlled output flows out (white).** It reads as a firewall / circuit element, not a SaaS glyph — consistent with MNDe being local execution infrastructure.

## Assets

| File | Use |
| --- | --- |
| `mnde-mark.svg` | Primary icon — mark on the dark plate. App icon, social avatar, favicon source. |
| `mnde-mark-mono.svg` | Mark only, transparent. `currentColor` adapts to any surface; blue line stays brand blue. |
| `mnde-wordmark.svg` | Horizontal lockup (mark + “MNDe” + “EXECUTION FIREWALL”). Headers, README, decks, site nav. |
| `favicon.svg` | Simplified mark for ≤32px (browser tabs, small UI). |

All assets are SVG (vector) — infinitely scalable, themeable, and tiny. They are the source of truth; rasterize from these for any PNG/ICO need (e.g. `mnde-mark.svg` → 1024/512/256/128/64 PNG, then `.ico`).

> Raster original: if you need the exact pasted PNG for a context that requires raster, drop it at `brand/mnde-mark.png`. The SVGs above remain canonical.

## Palette

| Token | Hex | Use |
| --- | --- | --- |
| MNDe Blue | `#1D9BF0` | The execution line; one accent only. Never use blue for the gate/output. |
| Ink White | `#FFFFFF` | Gate, output line, wordmark on dark. |
| Plate | `#0E1318` | Logo background plate / dark surfaces. |
| Wordmark on light | `#0E1318` | Set `color:#0E1318` on the mono/wordmark over light backgrounds. |

## Clearspace & sizing

- Keep clearspace ≥ the height of the gate rectangle on all sides.
- Minimum legible size: wordmark ≥ 120px wide; mark ≥ 24px; below that use `favicon.svg`.
- Do not place the white-stroke mono mark on a light background without setting `color` to ink.

## Do / Don't

**Do** — keep the blue strictly on the inbound line; preserve the gate→output direction (blue left, white right); use on `#0E1318` or comparably dark surfaces, or the mono mark with correct `color`.

**Don't** — recolor the gate; add gradients/shadows/glows; rotate or reflect the mark (direction is meaningful); stretch non-uniformly; reintroduce SaaS styling.

## In product

The Authority Console ([../desktop/dashboard.html](../desktop/dashboard.html)) uses the mono mark in its header and `favicon.svg` for the tab. The README uses the wordmark.
