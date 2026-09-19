# Hyperframes Composition Brief: docket

## Objective
Create a short launch-style brag video for **docket** — autonomous pentesting agents that file a
vulnerability only once they have reproduced it.

## Output
- Composition directory: `brag-output/composition/`
- Rendered video: `brag-output/brag.mp4`
- Format: landscape — 1920x1080
- Duration: 24.2 seconds (as rendered)

## Source Material
- Project root: `/Users/sarthakgarg/Docket`
- Primary files read: `README.md`, `app/frontend/BRAND.md`, `app/frontend/index.html`,
  `app/frontend/src/styles.css`, `app/frontend/src/App.tsx`,
  `app/frontend/src/views/{Overview,Scan}.tsx`, `app/frontend/src/components/{ui,AgentActivity}.tsx`,
  `docket_runs/*/report.json`
- Product name: **docket** (wordmark is lowercase, Source Serif 4 italic 500, verdant period)
- Tagline / strongest claim: *"A finding is a reproduction or it does not exist."*
- Key UI moment to recreate: the **Scan view** — the agent roster filling with four parallel
  specialists, then findings arriving as evidence rows carrying the literal request sent and the
  literal response observed (`app/frontend/src/views/Scan.tsx`,
  `app/frontend/src/components/FindingsTable.tsx`).

### Copy that must appear verbatim
Every line below is lifted from the repository. Do not paraphrase, do not invent new claims, do not
add a line that is not here.

- `finding refused — no reproduced evidence.` (README.md, the tool's refusal message)
- `A description of what you believe happens is not evidence.` (README.md, same message)
- `Only files what it has already exploited.` (condensed from README "Why docket")
- `scanning` (console status label, `views/Scan.tsx` → `STATUS_LABEL`)
- `cmdi` `sqli` `xss` `recon` (agent roles, from the verified run and `AgentActivity.tsx`)
- `?file=test.csv; sleep 5` → `"Response time: ~5016ms"` (README "Verified live")
- `username=admin' --` → `"Welcome"` (README "Verified live")
- `dialog_message='host.docker.internal'` → `browser dialog fired` (README "Verified live")
- `4 agents · $0.108 · 3 findings · all reproduced` (README "Verified live" run stats)
- `Nothing is entered without evidence.` (condensed from README's opening definition of a docket)
- `docket.` (wordmark)

## Creative Direction
- Tone preset: `polished`
- Creative direction: an editorial ink-on-paper product film — a register being written in, not a
  dashboard being sold.
- Interpretation: restraint is the argument. Large serif type, small confident motion, long holds.
  Nothing glows, nothing bounces, nothing slides in from off-frame except where the plan says so.
  The only abrupt motion in the whole video is the refusal in Scene 1, because refusing should feel
  abrupt.
- Angle: every scanner hands you a queue of maybes. The one thing docket does that no other scanner
  does is **say no to itself** — the refusal is a real string in the codebase, enforced by the type
  system against docket's own agents. The video spends its hook on that refusal, then earns it back
  with three real payloads and the real responses they produced.
- Hook (0.0–3.4s): the refusal message lands alone on cream paper, in critical red.
- Outro / punchline: `Nothing is entered without evidence.` → the `docket.` wordmark.
- Avoid:
  - Generic SaaS language ("streamline", "supercharge", "next-generation")
  - Abstract filler visuals, particle fields, scanning-radar clichés, matrix-green terminals
  - Any unrelated visual redesign — the Henoyo tokens below are the design, not a starting point
  - Percentages, scores, or progress rings anywhere in the frame (the product refuses to compute one)
  - Red, blue or amber as decoration — those are **system-state colors only** per BRAND.md

## Visual Identity
Source of truth: `app/frontend/BRAND.md` (Henoyo Design System v1) and `src/styles.css`.
- Background: `#F8F6F1` (paper-50, cream — **not white**)
- Card surface: `#FFFEFB` (paper-0); soft fill `#F0EDE5` (paper-100)
- Text: `#1A1F1C` (ink-900); secondary `#5A625B`; tertiary `#878F85`
- Borders: `#E3DFD4` (line); strong `#C9C4B5` (line-2)
- Accent: `#3B6047` (verdant-600, the **only** brand hue); bright `#4FA776` (the wordmark period);
  soft chip fill `#E9EFEB` (verdant-50)
- System states (used only as states): critical `#C0261B`, high `#C2410C`
- Display font: **Source Serif 4** (shipped locally: `assets/fonts/SourceSerif4.woff2`,
  `SourceSerif4-Italic.woff2`) — the wordmark is italic 500
- Body font: **Inter** (`assets/fonts/Inter.woff2`)
- Code / eyebrow font: **JetBrains Mono** (`assets/fonts/JetBrainsMono.woff2`), eyebrows uppercase
  at 0.10em tracking
- Radius: 10px cards, 6px buttons, pill for status tags. Spacing scale 4/8/12/16/24/32/56/80.
- Visual references from the project:
  - The evidence row — mono request above mono response, hairline rule below, severity pill left
  - The agent chips — pill, `#E9EFEB` fill, verdant text, mono label
  - The wordmark — `docket` in Source Serif 4 italic 500 with a `#4FA776` period
  - Generous cream margin; the card floats on paper, it does not fill the frame

## Storyboard
`brag-output/brag-plan.md` is the creative contract. Scene summary:

1. **The refusal** — 0.0 → 5.3 — the refusal line slams in critical red, then the quieter
   explanation line rises under it.
2. **The wordmark** — 4.8 → 9.1 — `docket.` resolving, with `Only files what it has already exploited.`
3. **The scan (centerpiece)** — 8.6 → 19.6 — console card: four agent chips arrive one by one onto
   an empty ruled register, then three evidence rows land one per beat and accumulate, then the
   run receipt.
4. **Outro** — 19.1 → 24.2 — `Nothing is entered without evidence.` then the wordmark alone.

A fifth scene on the no-percentage compliance report was planned and **cut in the build** — its
three lines could not clear their reading floors inside the 25s ceiling. Rationale in
`brag-plan.md` → "Plan vs build".

## Audio
- Audio role: sparse professional accents over a low music bed. Sound supports the paper; it does
  not sell the product.
- Audio arc: near-silence → one dry impact on the refusal → a low steady bed → three restrained
  accents as the proofs land → fade to silence under the wordmark.
- Music: `assets/music/happy-beats-business-moves-vol-12-by-ende-dot-app.mp3` (109.96 BPM — the
  calmest bundled track, and the one the brag audio reference recommends for `polished`).
- Music treatment: starts at 0.0s, held low (volume ≈ 0.20, below the 0.3–0.4 normal bed because
  this tone is restraint-heavy), fade in over ~0.8s, fade out over the last ~1.4s so the wordmark
  lands in near-silence. It must never be the loudest thing on screen.
- Music cue guidance: bundled preset, copied to
  `assets/music/cues/happy-beats-business-moves-vol-12-by-ende-dot-app.music-cues.json` (and `.md`).
  Tempo 109.96 BPM. **Strong-cue locks to target (3 max):** 8.74s (first evidence row), 13.11s
  (third evidence row), 22.93s (wordmark). Secondary strong cue available at 17.47s (compliance
  headline). Beat-grid window for the four sequential agent chips: 7.09 / 7.64 / 8.19 (+ one just
  before 8.74). Beat grid for the three evidence rows: 8.74 / 10.93 / 13.11 — deliberately every
  fourth beat (~2.2s apart), because these are lines the viewer must read and the raw grid at
  ~0.55s would outrun reading.
- Audio-reactive treatment: **none — a deliberate creative decision, not an extraction failure.**
  BRAND.md forbids glow ("no purple, no glow") and this tone is built on stillness; a breathing
  hero or pulsing card would contradict both. The extraction helper is available and was not used.
- Audio-coupled moments:
  - Scene 1, the refusal slam — one dry impact, the single hardest sound in the video
  - Scene 3, each evidence row arrival — one restrained accent per row, on the row's strong cue
  - Scene 5, the wordmark — one very soft close, or silence
- SFX selection guidance: at most five cues in the entire video. All picks must be **low
  high-frequency risk** per `sfx-analysis.md` — this is a polished tone with repeated accents. No
  whooshes, no risers, no stingers, no typing bed. Sound lands at the **start** of each animation.
  If a cue makes the video feel like an ad, cut it; silence is an acceptable answer for any cue here.
- SFX analysis guidance: `~/.claude/plugins/cache/brag/brag/0.2.2/skills/brag/assets/sfx/sfx-analysis.md`.
  Copied low-risk picks already staged in the project:
  - `assets/sfx/impact/impactSoft_medium_001.ogg` (0.18s, warm, low risk, transient — major reveal)
  - `assets/sfx/interface/bong_001.ogg` (0.12s, warm, low risk, textured — general accent)
  - `assets/sfx/impact/impactSoft_medium_000.ogg` (0.12s, warm, low risk, textured — soft close)
- Exact SFX choice: Hyperframes chooses filenames, timestamps, density, and volume against the
  implemented animation. Music at ≈0.20; SFX at 0.25–0.55 (the low end of the polished range).
- Audio files: all staged under `brag-output/composition/assets/` with relative paths.

## Hyperframes Instructions
Built with the current Hyperframes domain skills — `hyperframes-core` (composition contract and
`data-*` timing), `hyperframes-animation` (motion), `hyperframes-creative` (design direction),
`hyperframes-keyframes` (seek-safe keyframes), `hyperframes-cli` (lint / check / render). This is
the `/brag` workflow — not the `hyperframes` entry-point interview and not the generic
product-launch-video workflow. Native Hyperframes conventions win over anything in `/brag`.

Requirements:
- Show at least one real UI element from the project — Scene 3 recreates the console's Scan view.
- All text readable in the final render: short labels hold ≥0.8s settled, sentences ≥0.3s/word.
- Total duration 23.9s (inside the 15–25s window).
- Include the music bed and the five SFX cues above.
- Treat the audio notes as guidance, not a fixed cue sheet; choose exact SFX after the animation exists.
- Treat cue metadata as optional timing hints; lock at most three strong cues; ignore any cue that
  hurts readability or pacing.
- Fonts are shipped locally with in-file `@font-face` (lint rule `font_family_without_font_face`).
- Use only relative asset paths.
- `npx hyperframes check` must pass before render — the single gate.

## Build result
- `npx hyperframes check`: **passed** — 0 errors. Layout 0 issues / 9 samples, runtime 0, motion 0,
  contrast **31/31 pass WCAG AA**. Four `nested_structure_needs_subcomposition` warnings remain:
  they ask for one sub-composition file per scene, which is a Studio timeline-ergonomics
  preference, not a render or correctness issue. Kept monolithic — `hyperframes-core` supports
  both, and four cross-file timelines buy nothing here.
- Render: `--quality looks` → `brag-output/brag.mp4`, 1920x1080 @ 30fps, h264 + stereo AAC,
  24.2s, 726 frames. Audio verified present: mean -30.9 dB, peak -6.8 dB.
- Fonts are shipped locally (`assets/fonts/*.woff2`, Google's latin variable cuts) with in-file
  `@font-face`, so no render-time font fetch decides the typography.
- Poster: frame at 2.6s (the refusal, settled) → `brag.jpg`, baked back as frame 0 of `brag.mp4`.
