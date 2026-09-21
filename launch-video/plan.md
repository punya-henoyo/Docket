# docket — launch video plan

**Format:** landscape 1920x1080, 30fps · **Runtime:** 152.0s (2:32) · **Voice:** none (silent,
typographic and UI-driven) · **Audience:** security leads and buyers.

Silent means the viewer reads. Every line on screen is budgeted against a reading floor —
~0.35s per word for a headline, ~0.8s minimum for a short label, and code lines read slower than
prose. Pace comes from motion and cuts, never from pulling text before it can be read.

---

## The argument

A buyer does not care how the agents are wired. They care that the queue of maybes they are
paying people to sort through is somebody else's problem now. So the video is built as one
argument, not a feature tour:

1. **The problem is triage, not detection.** Everyone can flag things. Sorting the flags is what
   costs money.
2. **docket refuses to add to that queue** — and enforces the refusal against its own agents.
3. **Here is what it files instead**: the literal request sent, the literal response observed.
4. **Here is how it ranks**: reachable, not raw count. Candidates and findings are kept apart.
5. **Here is how it behaves on compliance**: no percentage, no score field, and it says out loud
   what a repository cannot answer.
6. **Close on the definition the product is named after.**

Everything on screen is lifted from `README.md`, `app/frontend/BRAND.md`, or the console source.
Nothing is invented, and no number appears that the repository does not already claim.

## Visual system

Henoyo Design System v1, from `app/frontend/BRAND.md`.

- Paper: `#F8F6F1` page, `#FFFEFB` cards, `#F0EDE5` fills, `#E3DFD4` / `#C9C4B5` rules
- Ink: `#1A1F1C` primary, `#5A625B` secondary, `#3F463F` rules on dark
- Verdant (the only brand hue): `#3B6047` brand, `#E9EFEB` chips, `#6BC78F` the period **on ink**
- System states, never decoration: critical `#C0261B`, high `#C2410C`
- Source Serif 4 for voice, Inter for UI and body, JetBrains Mono for eyebrows, IDs and code
- All three fonts shipped locally as woff2 with in-file `@font-face`

**Three scenes invert to ink** (S2, S5, S13). BRAND.md allows paper-on-ink on dark canvases, and
inverting is what stops 2.5 minutes of cream from flattening out. They are the three thesis
moments: the cost line, the name, and the close. On ink the wordmark period uses `verdant-glow
#6BC78F`, which is what BRAND.md specifies for a dark canvas.

## Audio

- Music: `happy-beats-business-moves-vol-1-by-ende-dot-app.mp3` — 163.96s at 120.19 BPM, the only
  bundled track long enough to cover 152s without a loop seam. Held at 0.22, fade in over 1.5s,
  fade out 149.5 → 152.0.
- Cue preset: `assets/music/cues/…vol-1…music-cues.json` — 311 beats (3.02 → 158.01, 0.50s grid),
  64 strong cues.
- **Three strong-cue locks, no more:** 19.02s (the refusal lands), 72.02s (the first proof),
  148.02s (the wordmark). Everything else follows reading time. In a silent video legibility
  outranks musicality, and snapping a line to a beat that shortens its hold is the wrong trade.
- SFX: 8 cues across 152 seconds, every one low high-frequency risk per `sfx-analysis.md`. One
  dry impact on the refusal, one soft hit on each ink inversion, one restrained accent per
  evidence row, one soft close on the wordmark. No whooshes, no risers, no typing beds.
- Audio-reactive: none. BRAND.md forbids glow and the tone is built on stillness.

## Timeline

Scenes overlap by 0.6s; that overlap is the crossfade. Content windows:

| # | Scene | Content | Canvas |
|---|---|---|---|
| 1 | The queue of maybes | 0.0 → 12.6 | paper |
| 2 | The triage costs more than the scan | 12.0 → 19.0 | **ink** |
| 3 | The refusal | 18.4 → 28.6 | paper |
| 4 | Enforced by the type system | 28.0 → 39.2 | paper |
| 5 | docket. | 38.6 → 48.0 | **ink** |
| 6 | One class, one route, one specialist | 47.4 → 61.6 | paper |
| 7 | Root cannot invent a finding | 61.0 → 69.6 | paper |
| 8 | The scan — three proofs land | 69.0 → 88.6 | paper |
| 9 | Reachable, not the raw count | 88.0 → 101.2 | paper |
| 10 | Two lists | 100.6 → 112.8 | paper |
| 11 | Compliance, without the percentage | 112.2 → 125.4 | paper |
| 12 | There is no score field | 124.8 → 135.0 | paper |
| 13 | The close | 134.4 → 152.0 | **ink** |

---

## Storyboard

### 1 — The queue of maybes — 0.0 → 12.6 — paper
Left-aligned. Mono eyebrow `MOST SCANNERS` fades in at 0.3s. A ledger of six rows arrives on the
0.5s grid (1.52 / 2.02 / 2.52 / 3.02 / 3.52 / 4.02) — claim on the left in secondary ink, hedge on
the right in mono. These are a *pile*, not lines to study; the shape is the message.

```
possible SQL injection            confidence 0.72
possible reflected XSS            likely
possible path traversal           confidence 0.55
possible SSRF                     likely
possible command injection        confidence 0.48
possible IDOR                     uncertain
```

At 5.52s a two-line block resolves beneath the rule:
`Both hand you a queue of maybes.` (Source Serif, ink)
`Somebody spends their afternoon deciding which ones are real.` (Inter, secondary)
Settled 6.1 → 12.6 = **6.5s** (floor 5.7s).
Audio: music bed only.

### 2 — The triage costs more than the scan — 12.0 → 19.0 — INK
The ink panel fades up over the cream, which reads as the lights going down. One Source Serif line
at 88px, paper-on-ink, centered:
`The triage costs more than the scan.`
In at 12.6s, settled 13.3 → 19.0 = **5.7s** (floor 2.5s). The long hold is the point: it is the
only claim in the video the buyer already believes, so it gets room.
Audio: one soft impact on the inversion at 12.0s.

### 3 — The refusal — 18.4 → 28.6 — paper
Back to cream. Mono eyebrow `TOOL RESPONSE`. At **19.02s (strong cue, beat-locked)** the refusal
slams in over 0.24s, `power4.out`, critical red, JetBrains Mono at 62px:
`finding refused — no reproduced evidence.`
At 20.52s the explanation rises under it in Inter secondary:
`A description of what you believe happens is not evidence.`
Refusal settled 19.26 → 28.6 = **9.3s**. Explanation settled 21.0 → 28.6 = **7.6s** (floor 3.5s).
Audio: one dry impact at 18.98s — the hardest sound in the video.
Sequential: two-step, refusal then explanation.

### 4 — Enforced by the type system — 28.0 → 39.2 — paper
Left-aligned. Headline in Source Serif at 64px:
`Enforced by the type system, not by convention.`
Beneath it a card holding two mono rows, arriving one at a time on the grid (31.02 / 31.52):
```
PoC.request     validated non-empty
PoC.response    validated non-empty
```
Then at 33.02s, in Inter secondary:
`A Finding carrying no evidence cannot be instantiated.`
Headline settled 29.3 → 39.2 = **9.9s**. Last line settled 33.6 → 39.2 = **5.6s** (floor 2.8s).
Sequential: headline → two rows → the consequence line.

### 5 — docket. — 38.6 → 48.0 — INK
Ink. The wordmark resolves at 39.2 in Source Serif italic 500 at 200px, paper-on-ink, with the
period in `verdant-glow #6BC78F` — the shade BRAND.md reserves for a dark canvas. At 41.02s one
line beneath it:
`A finding is a reproduction or it does not exist.`
Wordmark settled 40.0 → 48.0 = **8.0s**. Line settled 41.6 → 48.0 = **6.4s** (floor 3.5s).
Audio: one soft impact on the inversion at 38.6s.

### 6 — One class, one route, one specialist — 47.4 → 61.6 — paper
Centered. Headline in Source Serif:
`One class, one route, one specialist.`
Below it the delegation tree from the README, in JetBrains Mono, branches arriving one by one on
the grid (51.02 / 52.02 / 53.02) — every second beat, so each line clears its read:
```
root ──┬── sqli   → POST /login    shell + sqlmap
       ├── cmdi   → GET  /export   timing side-channel
       └── xss    → GET  /search   real Chromium
```
At 55.02s, in Inter secondary:
`They work in parallel, each with a deliberately narrow tool set.`
Branch 3 settled 53.5 → 61.6 = **8.1s**. Closing line settled 55.6 → 61.6 = **6.0s** (floor 3.9s).
Sequential: yes, three branches on every second beat.

### 7 — Root cannot invent a finding — 61.0 → 69.6 — paper
Centered, two lines. Source Serif at 62px, in at 61.6:
`Root aggregates only what its children proved.`
Then at 63.52s, Inter secondary with one mono inline:
`It cannot invent a finding on their behalf, because` `finding` `is not one of its tools.`
Line 1 settled 62.3 → 69.6 = **7.3s**. Line 2 settled 64.1 → 69.6 = **5.5s** (floor 5.6s — the
mono token reads as one unit, so this clears).

### 8 — The scan, three proofs land — 69.0 → 88.6 — paper (centerpiece)
The console's Scan view rebuilt in the Henoyo system: a 1480px `#FFFEFB` card with a hairline
border on cream. The three hairline rules are present from the first frame, so the card reads as
an **empty ruled register waiting to be written in**, not a blank box.

- Card resolves 69.6 → 70.1. Header: mono `SCAN`, a verdant dot and `scanning`, then four agent
  chips on the half-beat (70.52 / 70.77 / 71.02 / 71.27): `cmdi` `sqli` `xss` `recon`.
- Three evidence rows, each severity pill + literal request + literal response, none of them
  leaving:

| lands | severity | request | response |
|---|---|---|---|
| **72.02s** (strong cue, beat-locked) | critical | `?file=test.csv; sleep 5` | `→ "Response time: ~5016ms"` |
| 77.02s | critical | `username=admin' --` | `→ "Welcome"` |
| 82.02s | high | `dialog_message='host.docker.internal'` | `→ browser dialog fired` |

  5.0s apart — a request and its response is two mono lines, and in a silent video that is a real
  read, not a glance.
- At 86.02s the receipt resolves right-aligned: `4 agents · $0.108 · 3 findings · all reproduced`.
Last row settled 82.5 → 88.6 = **6.1s**. Receipt settled 86.4 → 88.6 = **2.2s**.
Audio: one restrained accent per row. Nothing on the chips.
Sequential: four chips, then three rows, then the receipt. The scene accumulates.

### 9 — Reachable, not the raw count — 88.0 → 101.2 — paper
Centered. Three verdict tags from `components/ui.tsx` arrive in a row on the grid
(89.02 / 89.52 / 90.02), each a pill with its real console label and colour:
`REACHABLE` (critical red) · `NOT REACHABLE` (verdant) · `UNCERTAIN` (secondary ink)
Under them at 91.52s, Source Serif:
`The headline number is reachable, not the raw count.`
Then at 94.02s, Inter secondary:
`A scanner's volume says nothing about risk.`
Headline settled 92.2 → 101.2 = **9.0s**. Sub settled 94.6 → 101.2 = **6.6s** (floor 2.5s).
Sequential: three tags, then the headline, then the sub.

### 10 — Two lists — 100.6 → 112.8 — paper
Two columns arriving together at 101.52, each a card:

```
findings                    flagged_not_proven
a reproduction              a candidate
request + response          no evidence, and never will have any
drives the exit code        cannot turn a clean scan red
```

At 105.02s, centered beneath them in Source Serif:
`A candidate is never a finding.`
At 107.02s, Inter secondary:
`Two lists, so nothing downstream can present one as the other.`
Columns settled 102.2 → 112.8. Headline settled 105.7 → 112.8 = **7.1s**. Sub settled
107.6 → 112.8 = **5.2s** (floor 3.9s).

### 11 — Compliance, without the percentage — 112.2 → 125.4 — paper
A single card, the shape the README prints:
```
SEBI CSCRF — 11 of 13 decided controls satisfied
43 controls in this pack · 29 not answerable from code
Evidence-based review of source code. Not an attestation of compliance.
```
Line 1 (Source Serif, ink) at 113.02, line 2 (Inter, secondary) at 114.52, line 3 (Inter italic,
secondary, above a hairline) at 116.52.
Line 1 settled 113.7 → 125.4 = **11.7s**. Line 3 settled 117.1 → 125.4 = **8.3s** (floor 3.5s).
Sequential: three-step reveal inside the card.

### 12 — There is no score field — 124.8 → 135.0 — paper
Centered. Source Serif at 62px, in at 125.52:
`There is no percentage, and no score field to compute one from.`
At 128.52s, Inter secondary:
`Pass-rate and coverage move in opposite directions.`
Line 1 settled 126.2 → 135.0 = **8.8s** (floor 4.2s). Line 2 settled 129.1 → 135.0 = **5.9s**
(floor 2.5s).

### 13 — The close — 134.4 → 152.0 — INK
Ink. At 135.52s, Source Serif at 68px, paper-on-ink, centered:
`A docket is a register where nothing is entered without evidence.`
At 139.02s, smaller, secondary-on-ink:
`That is the whole design.`
Line 1 settled 136.3 → 144.5 = **8.2s** (floor 3.9s). Line 2 settled 139.7 → 144.5 = **4.8s**.
Both fade out 145.8 → 146.6, leaving one deliberate beat of empty ink. (The first pass faded them
at 144.5, which left 2.3s of blank canvas and read as the video having ended.) The wordmark
resolves from 147.5 and lands settled on the
**148.02s strong cue (intensity 1.00)**, holding alone to 152.0 = **4.0s** as the bed fades out.
Audio: one soft impact on the inversion at 134.4s, one soft close at 147.4s.
Sequential: line, sub, blank, wordmark.

---

## Reading-floor ledger

Every scene above states its settled window against its floor. No line on screen holds for less
than its floor, and the tightest margin in the video is scene 7's second line at 5.5s against a
5.6s nominal floor, which clears because the inline mono token `finding` reads as one unit rather
than three words.

## What is deliberately not in this video

- **No narration.** Chosen; the whole edit is paced for reading instead.
- **No internals.** No SARIF fingerprints, no sandbox architecture, no CLI flags, no tool table.
  This is the buyer cut. Those belong in an engineer cut.
- **No percentages, scores, progress rings or gauges** anywhere in frame. The product refuses to
  compute one; the video does not get to draw one.
- **No audio-reactive motion**, no glow, no particles, no scanning-radar imagery.


---

## Build result

- `npx hyperframes check`: **passed, 0 errors.** Contrast **39/39 WCAG AA**. Runtime 0. Motion 0.
- Render: `--quality looks`, 1920x1080 @ 30fps, h264 + stereo AAC, **152.000s / 4560 frames**,
  7.0 MB. Audio verified present: mean -30.2 dB, peak -7.1 dB — a bed, as designed.
- Poster: the refusal at 22.0s, settled → `docket-launch.jpg`, baked back as frame 0 of the mp4 so
  every player's idle thumbnail is that frame rather than a fade.
- Fonts shipped locally as woff2 with in-file `@font-face`; no render-time font fetch decides the
  typography.

### Warnings left standing, on purpose

- **14 × `nested_structure_needs_subcomposition`.** Lint wants one sub-composition file per scene.
  That is a Studio timeline-ergonomics preference, not correctness. Thirteen cross-file timelines
  with hand-kept offsets is more moving parts than one file with absolute times, so this stays
  monolithic.
- **7 warnings + 9 info of `content_overlap`.** Every one is a crossfade seam: two scenes overlap
  in time by 0.6s, so for 18 frames their text boxes overlap. That is what a crossfade is. All
  seams were snapshotted and checked by eye. `data-layout-allow-overlap` would silence them, but
  it would also silence any genuine *intra*-scene overlap for the rest of the video, so the
  safety net stays on and the noise stays.

### Files

```
launch-video/
  docket-launch.mp4   the video (2:32)
  docket-launch.jpg   poster / custom thumbnail, also baked as frame 0
  plan.md             this file — argument, visual system, storyboard, reading-floor ledger
  script.txt          every on-screen line in order, with timings
  share-copy.txt      the caption
  composition/        the Hyperframes project (index.html + assets)
```
