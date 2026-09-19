# Brag Plan: docket

## What is this app?
Autonomous pentesting agents that file a vulnerability only after they have reproduced it — the
refusal is enforced by the type system, against docket's own agents, not by convention.

## The angle
Every scanner hands you a queue of maybes. The one thing docket does that no other scanner does
is **say no to itself**. The hero moment is not a finding — it is the tool refusing a finding.
That refusal is a real string in the codebase, and it is the most specific, least generic 2
seconds this product owns. The video spends its hook on the refusal, then earns it back with
three real payloads and the real responses they produced.

Everything on screen is verbatim from the repo: the refusal text, the three exploit lines from
the "Verified live" run, the run stats, the SEBI CSCRF report shape. Nothing invented.

## Hook (first 2-3 seconds)
Cream paper. Silence under a low bed. A single mono line lands in critical red, hard-in, then
holds:

```
finding refused — no reproduced evidence.
```

A security tool whose first word is *no* is the whole pitch in one frame.

## Key moments (the middle)
- **The fan-out.** Four agent chips arrive one by one along the top of the console —
  `cmdi` `sqli` `xss` `recon` — each a narrow tool set, working in parallel.
- **Three proofs land, one per beat.** Each is a two-line evidence row: the literal request
  the model chose, and the literal response it got back. Verbatim from the verified run:
  - `?file=test.csv; sleep 5` → `Response time: ~5016ms`
  - `username=admin' --` → `Welcome`
  - `dialog_message='host.docker.internal'` → browser dialog fired
- **The receipt.** A single mono footer: `4 agents · $0.108 · 3 findings · all reproduced`.
- **The counterpoint.** The compliance card with no score on it — and the line that there is no
  `score` field to compute one from.

## Outro / punchline
`Nothing is entered without evidence.` → the wordmark `docket.` with its verdant period.

## User flow worth showing
Entry → key action → result, pulled from the console (`app/frontend/src/views/`):
1. **Entry** — a run starts; the Scan view shows status `scanning` and the agent roster fills.
2. **Key action** — four specialists work one vulnerability class each, in parallel, each sending
   a real payload at the target.
3. **Result** — findings arrive in the table as evidence rows (request + response + severity +
   CWE), and the run reports its cost.

The centerpiece scene (Scene 3) is this flow, not the README's feature list.

## Tone
- Preset: `polished`
- Creative direction: an editorial ink-on-paper product film — a register being written in, not a
  dashboard being sold.
- Interpretation: restraint is the argument. Type is large and serifed, motion is small and
  confident, holds are long. Nothing glows, nothing bounces. The only fast thing in the video is
  the refusal in Scene 1, because refusing should feel abrupt.

## Format: landscape — 1920x1080
## Duration: 23.9s

## Visual identity (from the project)
Source: `app/frontend/BRAND.md`, `app/frontend/src/styles.css` (Henoyo Design System v1).
- Background: `#F8F6F1` (paper-50, cream — **not white**)
- Card surface: `#FFFEFB` (paper-0)
- Text: `#1A1F1C` (ink-900); secondary `#5A625B`; tertiary `#878F85`
- Borders: `#E3DFD4` (line), `#C9C4B5` (line-2)
- Accent: `#3B6047` (verdant-600, the only brand hue); bright `#4FA776` (the wordmark period)
- System state (refusal / critical only): `#C0261B`
- Display font: **Source Serif 4** (wordmark is italic 500)
- Body font: **Inter**
- Code / eyebrow font: **JetBrains Mono** (uppercase eyebrows at 0.10em tracking)
- Radius: 10px cards, 6px buttons, pill for status tags
- Strongest visual element: the evidence row — mono request above mono response, hairline rule
  between, verdant `REACHABLE` pill on the right. Second strongest: `docket.` in serif italic
  with the verdant-bright period.
- Hard rule from BRAND.md: reds/blues/ambers are **system states only, never decoration**. The
  only red in this video is the refusal and the `critical` severity tag.

## Share copy (draft)
Every scanner hands you maybes. docket refuses to file a finding it hasn't already exploited —
and enforces that against its own agents. One run: 4 agents, $0.108, 3 reproductions.

## Audio direction
- Role: sparse professional accents over a low music bed. Sound supports the paper, it does not
  sell the product.
- Music: `happy-beats-business-moves-vol-12-by-ende-dot-app.mp3` (109.96 BPM — the calmest and
  longest bundled track, the only one that survives a restrained edit).
- Music treatment: start at 0.0s, held low (roughly -18 to -20 dB under the bed), 0.6s fade-in,
  1.2s fade-out over the outro. It must never be the loudest thing on screen.
- Music cue guidance: preset read from
  `assets/music/cues/happy-beats-business-moves-vol-12-by-ende-dot-app.music-cues.md`.
  Target strong cues: **8.74s** (first proof), **13.11s** (third proof), **17.47s** (compliance
  headline), **22.93s** (wordmark). Beat-grid window for the sequential agent chips:
  7.09 / 7.64 / 8.19. Beat grid for sequential proof rows: 8.74 / 10.93 / 13.11 (every fourth
  beat, ~2.2s apart — deliberately slower than the grid so each line is readable).
- Audio-reactive treatment: **none**. This tone does not breathe with the music.
- SFX posture: sparse. At most five cues in the whole video — one dry refusal hit, three light
  interface ticks for the proof rows, one soft close on the wordmark. No whooshes.
- Audio-coupled moments: the refusal line (one dry impact on its slam-in); the four agent chips
  (very light, near-inaudible interface ticks); each proof row arrival (one restrained tick);
  the wordmark period (a soft dot, or silence — Hyperframes' call).
- Restraint rule: no risers, no whooshes, no stingers, no keyboard-typing bed. If a cue makes the
  video feel like an ad, cut it. Silence is an acceptable answer for any cue here.

## Storyboard

### Scene 1 — The refusal — 0.0 → 3.4s (3.4s)
Full cream field, generous margin. A JetBrains Mono eyebrow at top-left in tertiary ink:
`TOOL RESPONSE`. Then the refusal lands hard (0.25s in, no ease-out softness) at ~0.9s in
critical red `#C0261B`, mono, large:

```
finding refused — no reproduced evidence.
```

Holds settled to ~2.6s (5 words + fragment ≈ 1.8s floor, given 1.7s). Beneath it, at ~2.0s, a
single Inter line in secondary ink, quieter and smaller:
`A description of what you believe happens is not evidence.`
(verbatim from README.md). Holds to scene end.
Sequential/interaction: yes — two-step reveal, refusal first, then the explanation line.
Audio intent: one dry, low impact on the refusal. Music barely present yet.
Audio-coupled idea: the refusal slam gets the single impact cue of the video.
Music: low bed, fading in from 0.0s.
Transition mood: soft crossfade (0.7s) → Scene 2

### Scene 2 — The wordmark — 3.4 → 6.9s (3.5s)
Cream field. Centered: `docket.` in Source Serif 4 italic 500 at large scale, ink-900, with the
final period in verdant-bright `#4FA776`. It does not animate in — it resolves (a 0.8s opacity
and 2% scale settle). At ~4.6s, one line below it in Inter, secondary ink, letter-spaced:
`Only files what it has already exploited.`
Holds to scene end (7 words ≈ 2.1s floor, given 2.3s).
Sequential/interaction: none — this scene is a held image, on purpose.
Audio intent: the bed opens up slightly. No accent. Let the name sit.
Audio-coupled idea: none.
Music: bed, still low.
Transition mood: soft crossfade (0.6s) → Scene 3

### Scene 3 — The scan (centerpiece) — 6.9 → 16.4s (9.5s)
The console, recreated in the Henoyo system: cream page, one `#FFFEFB` card with a `#E3DFD4`
hairline border and 10px radius, sitting on the paper with real margin.

**Beat A — the fan-out (6.9 → 8.7s).** Card header: mono eyebrow `SCAN` on the left, and a
status line in verdant `scanning`. Four agent chips arrive one by one along the header row on
beats 7.09 / 7.64 / 8.19 / and one just before 8.74 — `cmdi` `sqli` `xss` `recon` — pill-shaped,
`#E9EFEB` fill, verdant text. Small, quiet, fast. These are labels, not lines to read.

**Beat B — three proofs land (8.74 → 15.3s).** Three evidence rows enter one at a time, each on
a strong cue: **8.74s**, **10.93s**, **13.11s**. Each holds ≥2.2s and none exit — by 13.1s all
three are on screen together. Each row is: a `critical`/`high` severity pill, then the request in
JetBrains Mono on line one, then an arrow and the response in mono on line two in secondary ink,
with a hairline `#E3DFD4` rule below. Verbatim content:

```
critical   ?file=test.csv; sleep 5
           → "Response time: ~5016ms"

critical   username=admin' --
           → "Welcome"

high       dialog_message='host.docker.internal'
           → browser dialog fired
```

**Beat C — the receipt (15.3 → 16.4s).** A single mono footer line resolves under the card in
tertiary ink, right-aligned to the card edge:
`4 agents · $0.108 · 3 findings · all reproduced`
Holds ~1.1s (short mono stat line, reads as one unit).
Sequential/interaction: yes — four chips appear one by one, then three evidence rows appear one
by one on the beat grid at ~2.2s spacing, then the footer. Nothing exits early; the scene
accumulates.
Audio intent: quiet, procedural, inevitable. Three restrained interface ticks, one per row. The
chips get near-inaudible ticks or nothing at all.
Audio-coupled idea: each evidence row arrival takes one light interface tick on its strong cue.
Music: bed continues, slightly more present under Beat B.
Transition mood: soft crossfade (0.6s) → Scene 4

### Scene 4 — No percentage — 16.4 → 20.2s (3.8s)
Cream field, one narrow card. At the **17.47s** strong cue, the compliance headline resolves in
Source Serif 4, ink-900:
`SEBI CSCRF — 11 of 13 decided controls satisfied`
Beneath it, in Inter tertiary ink, smaller, at ~18.2s:
`43 controls in this pack · 29 not answerable from code`
At the **18.56s** strong cue, one short line in mono, verdant, sits apart from the card:
`there is no score field`
All three hold to scene end (headline 8 words ≈ 2.4s, given 2.7s).
Sequential/interaction: yes — three-step reveal, headline → context → the mono line.
Audio intent: no accent. The bed carries it. This scene is a statement, not a hit.
Audio-coupled idea: none — deliberate. The restraint is the point of the scene.
Music: bed, unchanged.
Transition mood: soft crossfade (0.7s) → Scene 5

### Scene 5 — Outro — 20.2 → 23.9s (3.7s)
Cream field, empty. At ~20.75s one Source Serif 4 line, ink-900, centered:
`Nothing is entered without evidence.`
Holds to ~22.6s (5 words ≈ 1.5s floor, given 1.9s). It then fades and the wordmark `docket.`
resolves alone at the **22.93s** strong cue — serif italic 500, verdant-bright period — and holds
to 23.9s in near-silence as the bed fades out.
Sequential/interaction: yes — line first, then wordmark alone.
Audio intent: the bed fades to nothing under the wordmark. A soft close cue on the period is
optional; silence is equally correct.
Audio-coupled idea: the verdant period may take one very soft dot, or nothing.
Music: 1.2s fade-out ending at 23.9s.
Transition mood: end.

**Music mood for this video:** restrained / low — a bed, not a soundtrack.
**Audio summary:** One dry impact on the refusal, a long quiet bed under the paper, three light
interface ticks as the proofs land, and a fade to silence on the wordmark — the audio stays under
the type from the first frame to the last.

## Scene duration check
3.4 + 3.5 + 9.5 + 3.8 + 3.7 = **23.9s** ✓ (15-25s)
