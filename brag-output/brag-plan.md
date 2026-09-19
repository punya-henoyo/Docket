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
- **Cut in the build:** a fifth scene showing the compliance card (`SEBI CSCRF — 11 of 13 decided
  controls satisfied` / `there is no score field`). See "Plan vs build" at the end.

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
## Duration: 24.2s

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
  `assets/music/cues/happy-beats-business-moves-vol-12-by-ende-dot-app.music-cues.md` (109.96 BPM).
  **Strong-cue locks (3, as built):** 10.93s (first proof), 13.11s (second proof), 22.37→22.93s
  (the wordmark, on the 1.00-intensity hit). Beat-grid alignments: agent chips at
  9.56 / 9.83 / 10.10 / 10.37 (half-beat), third proof 15.29s, run receipt 17.47s, outro line
  19.66s. Proof rows sit ~2.18s apart — every fourth beat, deliberately slower than the raw grid,
  because these are lines the viewer has to read.
- Audio-reactive treatment: **none**. This tone does not breathe with the music.
- SFX posture: sparse. At most five cues in the whole video — one dry refusal hit, three light
  interface ticks for the proof rows, one soft close on the wordmark. No whooshes.
- Audio-coupled moments: the refusal line (one dry impact on its slam-in); the four agent chips
  (very light, near-inaudible interface ticks); each proof row arrival (one restrained tick);
  the wordmark period (a soft dot, or silence — Hyperframes' call).
- Restraint rule: no risers, no whooshes, no stingers, no keyboard-typing bed. If a cue makes the
  video feel like an ad, cut it. Silence is an acceptable answer for any cue here.

## Storyboard (as built)

All times are absolute composition seconds. Scenes overlap by 0.5s; that overlap is the crossfade,
and the cream paper underneath never blinks. Root duration **24.2s**.

### Scene 1 — The refusal — content 0.0 → 4.8, fades out by 5.3
Full cream field, left-aligned block on a 160px margin. Mono eyebrow `TOOL RESPONSE` in secondary
ink fades in at 0.15s. At **0.56s** (beat) the refusal lands hard — 0.24s, `power4.out`, no soft
landing — in critical red `#C0261B`, JetBrains Mono 500 at 62px:

```
finding refused — no reproduced evidence.
```

At 1.35s the explanation rises under it in Inter 34px secondary ink:
`A description of what you believe happens is not evidence.`
Refusal settled 0.80 → 4.8 (**4.0s**, floor 1.8s). Explanation settled 1.80 → 4.8 (**3.0s**, floor 3.0s).
Sequential/interaction: yes — two-step reveal, refusal first, then the explanation.
Audio intent: one dry impact on the slam. Music still fading up.
Music: bed fading in from 0.0s.
Transition mood: soft crossfade (0.5s) → Scene 2

### Scene 2 — The wordmark — content 4.8 → 8.6, fades out by 9.1
Centered. `docket.` in Source Serif 4 italic 500 at 184px, ink-900, verdant period. It resolves
rather than arrives: opacity plus a 1.5% settle over 0.7s from 5.3s. At **6.00s** (beat) one Inter
line rises beneath it: `Only files what it has already exploited.`
Wordmark settled 6.0 → 8.6 (**2.6s**). Tagline settled 6.50 → 8.6 (**2.1s**, floor 2.1s).
Sequential/interaction: none — this scene is a held image, on purpose.
Audio intent: the bed opens up slightly. No accent. Let the name sit.
Transition mood: soft crossfade (0.5s) → Scene 3

### Scene 3 — The scan (centerpiece) — content 8.6 → 19.1, fades out by 19.6
The console's Scan view rebuilt in the Henoyo system: a 1400px `#FFFEFB` card with a `#E3DFD4`
hairline border and 10px radius, floating on cream with real margin.

**Beat A — the fan-out (9.1 → 10.65s).** The card resolves at 9.1s. Header: mono eyebrow `SCAN`,
a verdant dot and `scanning` (the console's own `STATUS_LABEL`), and four agent chips arriving one
by one at 9.56 / 9.83 / 10.10 / 10.37 — `cmdi` `sqli` `xss` `recon`, verdant on `#E9EFEB` pills.

**Beat B — three proofs land (10.93 → 15.74s).** The card's three hairline rules are present from
the first frame, so what the viewer sees during Beat A is an **empty ruled register waiting to be
written in** — not a blank box. Then the entries arrive, one per lock, and none of them leave:

| lands at | severity | request | response |
|---|---|---|---|
| **10.93s** (strong cue 0.97) | critical | `?file=test.csv; sleep 5` | `→ "Response time: ~5016ms"` |
| **13.11s** (strong cue 0.98) | critical | `username=admin' --` | `→ "Welcome"` |
| **15.29s** (beat) | high | `dialog_message='host.docker.internal'` | `→ browser dialog fired` |

By 15.74s all three are on screen together. Last row settled 15.74 → 19.1 (**3.4s**).

**Beat C — the receipt (17.47 → 19.1s).** One mono line resolves under the ledger, right-aligned:
`4 agents · $0.108 · 3 findings · all reproduced`. Settled 17.87 → 19.1 (**1.2s**).
Sequential/interaction: yes — four chips one by one, then three evidence rows one by one on the
beat grid at ~2.18s spacing, then the receipt. Nothing exits early; the scene accumulates.
Audio intent: quiet, procedural, inevitable. One restrained accent per row, nothing on the chips.
Transition mood: soft crossfade (0.5s) → Scene 4

### Scene 4 — Outro — content 19.1 → 24.2
Cream field, empty. At **19.66s** one Source Serif 4 line, 68px, centered:
`Nothing is entered without evidence.` Settled 20.16 → 21.84 (**1.7s**, floor 1.5s). It fades out
over 21.84 → 22.30, and the wordmark resolves alone from **22.37s**, landing settled on the
**22.93s** strong cue (intensity 1.00) and holding to 24.2 (**1.3s**) as the bed fades to nothing.
Sequential/interaction: yes — line first, then the wordmark alone.
Audio intent: one very soft close under the wordmark, then silence.
Music: fades out 22.6 → 24.2.
Transition mood: end.

**Music mood for this video:** restrained / low — a bed, not a soundtrack.
**Audio summary:** One dry impact on the refusal, a long quiet bed under the paper, three light
accents as the proofs land, and a fade to silence on the wordmark — the audio stays under the type
from the first frame to the last. Measured on the render: mean -30.9 dB, peak -6.8 dB.

## Scene duration check
4.8 + 3.8 + 10.5 + 5.1 = **24.2s** ✓ (15-25s)

## Plan vs build

**Cut: the compliance scene.** The first draft had a fifth scene on the no-percentage compliance
report (`SEBI CSCRF — 11 of 13 decided controls satisfied` / `43 controls in this pack · 29 not
answerable from code` / `there is no score field`). Costing the reading floors killed it: those
three lines need ~7s of settled time between them, which pushed the video to roughly 26.6s — past
the 25s ceiling — and squeezing them into 3.5s would have been exactly the "too much text for the
scene length" failure the reading rule exists to prevent. Cutting it also lands the video on the
3-4 scene shape the `polished` tone prescribes. The exploit proof already carries the argument;
compliance is the second-best differentiator, not the first.

**Changed: the wordmark period colour.** BRAND.md assigns the period `verdant-bright #4FA776`. At
164-184px on cream that measures 2.73:1 and fails the WCAG audit, so it renders as `verdant-600
#3B6047` — the same hue, an actual BRAND.md token, and comfortably above threshold. BRAND.md itself
pairs the bright variant with dark canvases (`verdant-glow` is "period on dark"), so this is the
light-theme reading of the same rule.

**Kept, deliberately: no audio-reactive treatment.** Not an extraction failure — the helper is
available. BRAND.md forbids glow and this tone is built on stillness; a breathing hero would
contradict both.
