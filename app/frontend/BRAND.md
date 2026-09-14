# Henoyo Design System v1 — docket console

Locked brand language (May 2026): **cream paper, near-black ink, and one green — verdant.** Everything else is supporting. The console uses the **Cream / Editorial** theme (light: ink-on-paper).

---

## Fonts

| Font | Role |
|---|---|
| **Source Serif 4** | Voice. Masthead / headlines, and the wordmark (italic 500 + verdant period). |
| **Inter** | UI and body. Never headlines. |
| **JetBrains Mono** | Eyebrows (uppercase, 0.10em tracking), IDs, code. |

Loaded from Google Fonts:
```
Inter:wght@400;500;600;700
Source Serif 4:ital,opsz,wght@0,8..60,400;0,8..60,600;1,8..60,500
JetBrains Mono:wght@400;500
```

---

## Palette

### Verdant — the only brand hue
| Token | Hex | Use |
|---|---|---|
| verdant-700 | `#2B4A35` | emphasis, hover |
| verdant-600 | `#3B6047` | brand surface, CTA (`--brand`) |
| verdant-500 | `#4F7760` | support, borders |
| verdant-bright | `#4FA776` | wordmark period, "go" accent (`--brand-bright`) |
| verdant-glow | `#6BC78F` | period on dark |
| verdant-200 | `#A8BFAF` | muted text on ink |
| verdant-100 | `#D2DFD6` | soft tints |
| verdant-50 | `#E9EFEB` | pills / chips |

### Ink — text + dark surfaces
| Token | Hex | Use |
|---|---|---|
| ink-900 | `#1A1F1C` | primary text (`--ink`) |
| ink-800 | `#2A302C` | elevated dark |
| ink-700 | `#3F463F` | borders on dark |
| text-secondary | `#5A625B` | captions (`--ink-2`) |
| text-tertiary | `#878F85` | labels, metadata (`--ink-3`) |

### Paper — light surfaces
| Token | Hex | Use |
|---|---|---|
| paper-0 | `#FFFEFB` | cards (`--card`) |
| paper-50 | `#F8F6F1` | page / default (`--page`) |
| paper-100 | `#F0EDE5` | soft fills (`--raised`) |
| paper-200 | `#E3DFD4` | borders (`--line`) |
| paper-300 | `#C9C4B5` | strong borders (`--line-2`) |

### System states only — reds / blues / ambers (contrast-tuned for cream)
| State | Hex |
|---|---|
| critical | `#C0261B` |
| high | `#C2410C` |
| medium | `#A16207` |
| low | `#1D4ED8` |
| info | `#6B7280` |
| ok / success | `#3B6047` (verdant — one green) |

---

## Rules

- Cream is the page, **not white**.
- Letterforms are always **ink-on-paper** (or paper-on-ink on dark canvases).
- Verdant is the **only** brand hue — it lives in accents and the wordmark period.
- Reds / blues / ambers are **system states only**, never decoration.
- Radius: 4 chips, **6 buttons**, **10 cards**, pill for status.
- Spacing scale: 4 / 8 / 12 / 16 / 24 / 32 / 56 / 80.
- Icons: 24×24, 1.5px stroke, round caps (Phosphor / Lucide). Color inherits from text.
- Voice: editorial, not SaaS-catalog. No purple, no glow.

---

## CSS tokens (as shipped in `src/styles.css`)

```css
:root {
  --page: #F8F6F1;   /* paper-50  — page (cream) */
  --card: #FFFEFB;   /* paper-0   — cards */
  --raised: #F0EDE5; /* paper-100 — soft fills */
  --ink: #1A1F1C;    /* ink-900   — primary text */
  --ink-2: #5A625B;  /* text-secondary */
  --ink-3: #878F85;  /* text-tertiary */
  --line: #E3DFD4;   /* paper-200 — borders */
  --line-2: #C9C4B5; /* paper-300 — strong borders */

  --brand: #3B6047;        /* verdant-600 — CTA */
  --brand-hover: #2B4A35;  /* verdant-700 */
  --brand-ink: #FFFEFB;    /* paper-on-verdant */
  --brand-bright: #4FA776; /* verdant-bright — accent / period */

  --crit: #C0261B; --high: #C2410C; --med: #A16207;
  --low: #1D4ED8;  --info: #6B7280; --ok: #3B6047;

  --sans:  "Inter", ui-sans-serif, system-ui, sans-serif;
  --serif: "Source Serif 4", Georgia, serif;
  --mono:  "JetBrains Mono", ui-monospace, Menlo, monospace;
  --r: 10px;    /* cards */
  --r-sm: 6px;  /* buttons */
}
```

_Canonical source: `henoyo-commercials/brand/Henoyo-wordmark-2/Henoyo Design System.html`; product UI tokens: `henoyo-design/theme/tokens.css`._
