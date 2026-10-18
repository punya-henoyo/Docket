// Shared bits for the Docket elements: the origin chip (Henoyo-native vs third-party),
// the lamp vocabulary, and a few extra glyphs the kit does not ship. Everything here
// reads the kit's --k-* variables, so the Docket elements look like the rest of the family.

import { esc } from './henoyoKit';

export type Origin = 'henoyo' | 'third_party';
export type Level = 'action' | 'attention' | 'clear' | 'unknown';

/** 24x24 stroke glyphs, lucide-style, for the shapes the kit set lacks. */
const EXTRA: Record<string, string> = {
  shield: '<path d="M12 3 4 6v6c0 4.5 3.2 7.6 8 9 4.8-1.4 8-4.5 8-9V6l-8-3z"/>',
  'shield-alert':
    '<path d="M12 3 4 6v6c0 4.5 3.2 7.6 8 9 4.8-1.4 8-4.5 8-9V6l-8-3z"/><path d="M12 8v4"/><path d="M12 15.5h.01"/>',
  crosshair:
    '<circle cx="12" cy="12" r="8"/><path d="M12 2v5M12 17v5M2 12h5M17 12h5"/>',
  'git-branch':
    '<circle cx="6" cy="5" r="2"/><circle cx="6" cy="19" r="2"/><circle cx="18" cy="8" r="2"/><path d="M6 7v10"/><path d="M18 10c0 4-6 3-12 7"/>',
  wrench:
    '<path d="M14.7 6.3a4 4 0 0 0-5.4 5.4L3 18l3 3 6.3-6.3a4 4 0 0 0 5.4-5.4l-2.6 2.6-2.4-.6-.6-2.4 2.6-2.6z"/>',
  scan: '<path d="M4 8V5a1 1 0 0 1 1-1h3M16 4h3a1 1 0 0 1 1 1v3M20 16v3a1 1 0 0 1-1 1h-3M8 20H5a1 1 0 0 1-1-1v-3"/><path d="M4 12h16"/>',
  'file-code':
    '<path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/><path d="M14 3v5h5"/><path d="m10 13-2 2 2 2M14 13l2 2-2 2"/>',
  package:
    '<path d="m12 3 8 4.5v9L12 21l-8-4.5v-9z"/><path d="M12 12 4 7.5M12 12l8-4.5M12 12v9"/>',
  'key-square': '<circle cx="8" cy="15" r="4"/><path d="m11 12 8-8M16 7l3 3"/>',
  radar:
    '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="5"/><path d="M12 12 18 6"/>',
  brain:
    '<path d="M9 4a3 3 0 0 0-3 3 3 3 0 0 0-2 5 3 3 0 0 0 2 5 3 3 0 0 0 6 1V4a3 3 0 0 0-3 0z"/><path d="M15 4a3 3 0 0 1 3 3 3 3 0 0 1 2 5 3 3 0 0 1-2 5 3 3 0 0 1-6 1"/>',
  'scroll-text':
    '<path d="M8 21h10a2 2 0 0 0 2-2v-1H10v1a2 2 0 0 1-2 2zm0 0a2 2 0 0 1-2-2V5a2 2 0 0 0-2-2h14a2 2 0 0 1 2 2v13"/><path d="M10 8h6M10 12h6"/>',
  check: '<path d="m5 12 5 5 9-10"/>',
  x: '<path d="M6 6l12 12M18 6 6 18"/>',
  minus: '<path d="M6 12h12"/>',
  clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
  alert: '<path d="M12 3 2 20h20z"/><path d="M12 10v4"/><path d="M12 17h.01"/>',
  lock: '<rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/>',
  link: '<path d="M10 14a4 4 0 0 0 5.7 0l3-3a4 4 0 0 0-5.7-5.7l-1 1"/><path d="M14 10a4 4 0 0 0-5.7 0l-3 3a4 4 0 0 0 5.7 5.7l1-1"/>',
  gantt: '<path d="M4 6h8M8 12h10M6 18h7"/>',
};

export function dg(name: string, size = 14, cls = 'g'): string {
  const body = EXTRA[name] ?? EXTRA['shield'];
  return `<svg class="${cls}" width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${body}</svg>`;
}

/** "Henoyo" (verdant, a tick) or the tool's own name (neutral). Always a word, never colour alone. */
export function originChip(origin: Origin, tool?: string): string {
  return origin === 'henoyo'
    ? `<span class="origin h" title="Built and run by Henoyo">${dg('shield-alert', 11, 'g')}Henoyo</span>`
    : `<span class="origin t" title="Third-party tool, run by Docket">${esc(tool ?? 'Third-party')}</span>`;
}

export const LEVEL_WORD: Record<Level, { word: string; answer: string }> = {
  action: { word: 'Act today', answer: 'Yes. Needs someone today.' },
  attention: { word: 'Watch', answer: 'Not today. Look this week.' },
  clear: { word: 'Clear', answer: 'No. Nothing to do.' },
  unknown: { word: 'Unknown', answer: 'Cannot tell. Not enough scans.' },
};

/** Shared CSS: origin chips, lamps, hatch pattern, tooltips. Appended after KIT_STYLE by each element. */
export const DOCKET_STYLE = `
.origin { display:inline-flex; align-items:center; gap:4px; height:18px; padding:0 7px; border-radius:999px; font-size:10.5px; font-weight:600; letter-spacing:.02em; white-space:nowrap; }
.origin.h { background:rgb(var(--h-verdant-50, 233 239 235)); color:rgb(var(--h-verdant-700, 43 74 53)); border:1px solid rgb(var(--h-verdant-200, 168 191 175)); }
.origin.t { background:var(--k-surface-2); color:var(--k-text-2); border:1px solid var(--k-hairline-2); }
.lamp { display:inline-block; width:10px; height:10px; border-radius:999px; flex:none; box-shadow:0 0 0 2px var(--k-surface), 0 0 0 3px var(--k-hairline-2); }
.lamp.ok { background:var(--k-ok); } .lamp.warn { background:rgb(var(--h-sev-high, 217 122 26)); } .lamp.bad { background:var(--k-sev-critical); }
.lamp.off { background:var(--k-hairline-2); } .lamp.info { background:var(--k-info); }
.hatch { background-image:repeating-linear-gradient(135deg, rgb(var(--h-sev-high, 217 122 26) / .55) 0 2px, transparent 2px 7px); }
button.row-btn { all:unset; box-sizing:border-box; cursor:pointer; display:contents; }
.tt { position:relative; }
.tt:hover > .tipbox, .tt:focus-within > .tipbox { display:block; }
.tipbox { display:none; position:absolute; z-index:6; left:0; top:calc(100% + 4px); min-width:200px; max-width:300px; padding:8px 10px; border-radius:8px; background:var(--k-text); color:var(--k-surface);
  font-size:12px; line-height:1.45; font-weight:400; letter-spacing:0; text-transform:none; white-space:normal; pointer-events:none; box-shadow:0 8px 24px rgb(26 31 28 / .18); }
.tipbox b { font-weight:600; }
`;
