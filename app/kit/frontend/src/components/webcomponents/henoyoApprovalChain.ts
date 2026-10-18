// <henoyo-approval-chain>: maker-checker approvals and sign-offs for one record.

import {
  HenoyoElement,
  chip,
  defineElement,
  downloadCsv,
  emit,
  esc,
  fmtDate,
  fmtDateTime,
  glyph,
  initials,
  isMaterial,
  ms,
  span,
  type KitStat,
  type Material,
} from './henoyoKit';

export type ApprovalStatus =
  | 'pending'
  | 'approved'
  | 'rejected'
  | 'skipped'
  | 'not_required'
  | 'unknown';

export interface HenoyoApprovalSlot {
  id: string;
  role: string;
  actor?: string;
  /** Shown in place of the identifier; the identifier stays in the tooltip. */
  actorName?: string;
  status: ApprovalStatus;
  decidedAt?: string;
  note?: string;
  /** An earlier, superseded decision for the same function (history). */
  previous?: { status: ApprovalStatus; decidedAt?: string };
  board?: boolean;
}

export interface HenoyoApprovalRequester {
  actor: string;
  actorName?: string;
  at?: string;
  label?: string;
}

export interface HenoyoApprovalLabels {
  separation?: string;
  board?: string;
  requestedBy?: string;
  allMustSign?: string;
  next?: string;
}

type Outcome = 'approved' | 'rejected' | 'progress' | 'review';

const STATUS_LABEL: Record<ApprovalStatus, string> = {
  pending: 'Pending',
  approved: 'Approved',
  rejected: 'Rejected',
  skipped: 'Skipped',
  not_required: 'Not required',
  unknown: 'Unknown',
};

const STATUS_TONE: Record<ApprovalStatus, string> = {
  pending: 'warn',
  approved: 'ok',
  rejected: 'bad',
  skipped: 'neutral',
  not_required: 'neutral',
  unknown: 'neutral',
};

const ACRONYMS = new Set([
  'ceo',
  'cfo',
  'coo',
  'cto',
  'cio',
  'ciso',
  'cro',
  'cco',
  'cdo',
  'dpo',
  'cpo',
  'vp',
  'svp',
  'evp',
  'it',
  'hr',
  'grc',
  'qa',
  'ai',
  'pmo',
  'sox',
  'soc',
  'dpia',
  'gdpr',
  'dpdp',
  'iso',
  'us',
  'uk',
  'eu',
]);

/**
 * "jane.doe@acme.com" reads as "Jane Doe"; a display name is left as it is. Role mailboxes keep
 * known acronyms upper case: "cto@acme.com" is "CTO", "ciso.office@acme.com" is "CISO office".
 */
export function personName(actor: string, name?: string): string {
  if (name !== undefined && name.trim() !== '') return name.trim();
  const local = actor.includes('@') ? (actor.split('@')[0] ?? actor) : actor;
  const words = local.split(/[._\-\s]+/).filter(Boolean);
  if (words.length === 0) return actor;
  if (!actor.includes('@') && words.length === 1 && !ACRONYMS.has(words[0]!.toLowerCase()))
    return actor;
  const hasAcronym = words.some((w) => ACRONYMS.has(w.toLowerCase()));
  return words
    .map((w, i) => {
      const lower = w.toLowerCase();
      if (ACRONYMS.has(lower)) return lower.toUpperCase();
      if (hasAcronym && i > 0) return lower;
      return w.charAt(0).toUpperCase() + w.slice(1);
    })
    .join(' ');
}

/** A slot role such as "Cto" or "ciso office" reads "CTO" / "CISO office"; other roles are left alone. */
export function roleLabel(role: string): string {
  const words = role.split(/[._\-\s]+/).filter(Boolean);
  return words.some((w) => ACRONYMS.has(w.toLowerCase())) ? personName(role) : role;
}

function prevNote(s: HenoyoApprovalSlot): string {
  const p = s.previous;
  if (p === undefined || (p.status !== 'rejected' && p.status !== 'approved')) return '';
  const t = ms(p.decidedAt);
  const word = p.status === 'rejected' ? 'declined' : 'approved';
  const text = `Previously ${word}${t !== null ? ` ${fmtDate(t)}` : ''}`;
  return `<span class="note" style="display:block" title="${esc(text)}">${esc(text)}</span>`;
}

const list = (names: readonly string[]): string =>
  names.length <= 2 ? names.join(' and ') : `${names[0]}, ${names[1]} and ${names.length - 2} more`;

/** The finding: who the chain is waiting on, and since when. */
export function approvalFinding(
  outcome: Outcome,
  waiting: readonly string[],
  since: number | null,
  decided: number | null,
): string {
  if (outcome === 'approved') return decided === null ? 'Approved' : `Approved ${fmtDate(decided)}`;
  if (outcome === 'rejected') return 'Rejected';
  if (outcome === 'review') return 'Needs review';
  if (waiting.length === 0) return 'In progress';
  return `Waiting on ${list(waiting)}${since === null ? '' : ` since ${fmtDate(since)}`}`;
}

function actorOf(v: unknown): string | null {
  return typeof v === 'string' && v.trim() ? v.trim() : null;
}

export class HenoyoApprovalChain extends HenoyoElement {
  private _heading: string | undefined;
  private _mode: 'sequential' | 'parallel' = 'sequential';
  private _requester: HenoyoApprovalRequester | undefined;
  private _slots: HenoyoApprovalSlot[] = [];
  private _requireSeparation = true;
  private _material: Material = 'brass';
  private _glyphName = 'gavel';
  private _exportEnabled: boolean | undefined;
  private _labels: HenoyoApprovalLabels = {};

  constructor() {
    super();
    this.root.addEventListener('click', (e) => {
      const target = (e.target as HTMLElement).closest<HTMLElement>('[data-act]');
      if (!target) return;
      if (target.dataset.act === 'select' && target.dataset.arg !== undefined)
        emit(this, 'henoyo:approver-selected', { id: target.dataset.arg });
      else if (target.dataset.act === 'export') this.exportCsv();
    });
  }

  get heading(): string | undefined {
    return this._heading;
  }
  set heading(v: string | undefined) {
    this._heading = v;
    this.invalidate();
  }
  get mode(): 'sequential' | 'parallel' {
    return this._mode;
  }
  set mode(v: 'sequential' | 'parallel') {
    this._mode = v === 'parallel' ? 'parallel' : 'sequential';
    this.invalidate();
  }
  get requester(): HenoyoApprovalRequester | undefined {
    return this._requester;
  }
  set requester(v: HenoyoApprovalRequester | undefined) {
    this._requester = v;
    this.invalidate();
  }
  get slots(): HenoyoApprovalSlot[] {
    return this._slots;
  }
  set slots(v: HenoyoApprovalSlot[]) {
    this._slots = Array.isArray(v) ? v.filter((s) => s && typeof s === 'object') : [];
    this.invalidate();
  }
  get requireSeparation(): boolean {
    return this._requireSeparation;
  }
  set requireSeparation(v: boolean | undefined) {
    this._requireSeparation = v !== false;
    this.invalidate();
  }
  get material(): Material {
    return this._material;
  }
  set material(v: Material | undefined) {
    this._material = isMaterial(v) ? v : 'brass';
    this.invalidate();
  }
  get glyphName(): string {
    return this._glyphName;
  }
  set glyphName(v: string | undefined) {
    this._glyphName = v || 'gavel';
    this.invalidate();
  }
  get labels(): HenoyoApprovalLabels {
    return this._labels;
  }
  set labels(v: HenoyoApprovalLabels | undefined) {
    this._labels = v && typeof v === 'object' ? v : {};
    this.invalidate();
  }
  get exportEnabled(): boolean | undefined {
    return this._exportEnabled;
  }
  set exportEnabled(v: boolean | undefined) {
    this._exportEnabled = v;
    this.invalidate();
  }

  private outcome(): Outcome {
    if (this._slots.some((s) => s.status === 'rejected')) return 'rejected';
    if (this._slots.some((s) => s.status === 'unknown')) return 'review';
    const required = this._slots.filter(
      (s) => s.status !== 'skipped' && s.status !== 'not_required',
    );
    if (required.length > 0 && required.every((s) => s.status === 'approved')) return 'approved';
    return 'progress';
  }

  private nextIds(): Set<string> {
    const next = new Set<string>();
    if (this.outcome() !== 'progress') return next;
    for (const s of this._slots) {
      if (s.status === 'skipped' || s.status === 'not_required') continue;
      if (s.status === 'pending') {
        next.add(s.id);
        if (this._mode === 'sequential') break;
      } else if (s.status !== 'approved') break;
    }
    return next;
  }

  private conflicts(): Set<string> {
    const out = new Set<string>();
    const who = actorOf(this._requester?.actor);
    if (!who) return out;
    for (const s of this._slots)
      if (actorOf(s.actor)?.toLowerCase() === who.toLowerCase()) out.add(s.id);
    return out;
  }

  private elapsed(index: number): string {
    const at = ms(this._slots[index]?.decidedAt);
    if (at === null) return '';
    let base = ms(this._requester?.at);
    let label = 'after request';
    if (this._mode === 'sequential') {
      for (let i = index - 1; i >= 0; i--) {
        const prev = ms(this._slots[i]?.decidedAt);
        if (prev !== null) {
          base = prev;
          label = 'after previous decision';
          break;
        }
      }
    }
    if (base === null || at < base) return '';
    return `${span((at - base) / 86_400_000)} ${label}`;
  }

  private exportCsv(): void {
    downloadCsv(
      this,
      'approvals',
      ['order', 'role', 'actor', 'status', 'decided_utc', 'note'],
      this._slots.map((s, i) => {
        const t = ms(s.decidedAt);
        return [
          i + 1,
          s.role,
          s.actor,
          s.status,
          t === null ? '' : new Date(t).toISOString(),
          s.note,
        ];
      }),
    );
  }

  protected styles(): string {
    return `
.req { display:flex; align-items:center; flex-wrap:wrap; gap:8px; padding:8px 0 12px; font-size:13px; color:var(--k-text-2); }
.req b { color:var(--k-text); font-weight:600; }
.who { display:inline-flex; align-items:center; gap:8px; min-width:0; max-width:100%; }
.nm { min-width:0; overflow-wrap:break-word; }
.steps { list-style:none; margin:0; padding:0; }
.steps.par { display:grid; grid-template-columns:repeat(auto-fit,minmax(220px,1fr)); gap:var(--h-kit-row-py, 10px); }
.step { position:relative; display:flex; gap:12px; }
.seq .step { padding-bottom:var(--h-kit-row-px, 14px); }
.seq .step:not(:last-child)::before { content:""; position:absolute; left:13px; top:28px; bottom:0; width:2px; background:var(--k-hairline-2); }
.node { flex:none; width:28px; height:28px; border-radius:999px; display:grid; place-items:center; font-size:12px; font-weight:700;
  background:var(--k-surface-2); border:1px solid var(--k-hairline-2); color:var(--k-text-2); }
.node.ok { background:var(--k-ok-soft); color:var(--k-ok); border-color:transparent; }
.node.bad { background:var(--k-bad-soft); color:var(--k-bad); border-color:transparent; }
.node.warn { background:var(--k-warn-soft); color:var(--k-warn); border-color:transparent; }
.card-step { flex:1; min-width:0; text-align:left; display:block; width:100%; background:none; border:0; padding:2px 6px; margin:-2px -6px; border-radius:8px; cursor:pointer; min-height:24px; }
.card-step:hover .role { text-decoration:underline; }
.card-step:focus { outline:none; }
.card-step:focus-visible { outline:2px solid var(--k-brand); outline-offset:2px; }
.par .step { align-items:stretch; border:1px solid var(--k-hairline); border-radius:10px; padding:var(--h-kit-gap, 12px); background:var(--k-surface); }
.par .step.next { border-color:var(--k-warn); }
.line1 { display:flex; flex-wrap:nowrap; align-items:center; gap:6px 8px; }
.head { display:flex; flex-wrap:wrap; flex:0 1 auto; align-items:center; gap:8px; min-width:0; }
.role { font-weight:700; font-size:14px; min-width:0; overflow-wrap:anywhere; }
.head .pill, .line1 .tag { flex:none; white-space:nowrap; }
.pill.ok { background:var(--k-ok-soft); color:var(--k-ok); }
.pill.bad { background:var(--k-bad-soft); color:var(--k-bad); }
.pill.warn { background:var(--k-warn-soft); color:var(--k-warn); }
.pill.neutral { background:var(--k-neutral-soft); color:var(--k-neutral); }
.tag { font-size:11px; font-weight:600; padding:1px 7px; border-radius:999px; border:1px solid var(--k-hairline-2); color:var(--k-text-2); }
.tag.next { background:var(--k-warn-soft); color:var(--k-warn); border-color:transparent; }
.row2 { display:flex; align-items:center; gap:8px; margin-top:6px; font-size:13px; overflow-wrap:anywhere; }
.when { margin-top:4px; font-size:12px; color:var(--k-text-3); }
.note { margin-top:4px; font-size:12.5px; color:var(--k-text-3); overflow-wrap:anywhere; }
.conflict { margin-top:6px; display:flex; gap:6px; align-items:flex-start; font-size:12.5px; font-weight:600; color:var(--k-bad); }
.step-body { flex:1; min-width:0; }
.glyph { font-weight:700; margin-right:4px; }
.sod-ok { color:var(--k-ok); font-weight:600; }
`;
  }

  protected view(): string {
    const L = this._labels;
    const lSep = L.separation || 'Separation of duties';
    const lBoard = L.board || 'Board';
    const lReq = L.requestedBy || 'Requested by';
    const lAll = L.allMustSign || 'All must sign.';
    const lNext = L.next || 'Next';
    const slots = this._slots;
    const out = this.outcome();
    const next = this.nextIds();
    const bad = this.conflicts();
    const outLabel =
      out === 'approved'
        ? 'Approved'
        : out === 'rejected'
          ? 'Rejected'
          : out === 'review'
            ? 'Needs review'
            : 'In progress';
    const outTone: KitStat['tone'] =
      out === 'approved'
        ? 'ok'
        : out === 'rejected'
          ? 'bad'
          : out === 'review'
            ? 'neutral'
            : 'warn';
    const decided = slots.flatMap((s) => (ms(s.decidedAt) === null ? [] : [ms(s.decidedAt)!]));
    const waiting = slots.filter((s) => next.has(s.id)).map((s) => roleLabel(s.role));
    const since = decided.length > 0 ? Math.max(...decided) : ms(this._requester?.at);
    const stats: KitStat[] = [
      ...(this._requireSeparation && bad.size > 0
        ? [{ tone: 'bad' as const, icon: 'lock', text: `${lSep} conflict` }]
        : []),
      { tone: outTone, text: outLabel, data: { outcome: out } },
    ];
    const conflictNote =
      this._requireSeparation && bad.size > 0
        ? `<span class="sr" role="status">${esc(lSep)}: ${bad.size} conflict${bad.size === 1 ? '' : 's'}</span>`
        : '';
    const exportBtn =
      this._exportEnabled !== false && slots.length > 0
        ? `<button class="btn" type="button" data-act="export">${glyph('download', 14)}Export CSV</button>`
        : '';
    const header = this.head(
      this._heading ?? 'Approvals',
      approvalFinding(out, waiting, since, decided.length > 0 ? Math.max(...decided) : null),
      {
        lead: chip(this._material, this._glyphName, true),
        stats,
        actions: conflictNote + exportBtn,
      },
    );
    if (slots.length === 0)
      return `<div class="card">${header}<div class="empty">No approvals required.</div>${this.foot()}</div>`;

    const req = this._requester;
    const reqActor = actorOf(req?.actor);
    const reqAt = ms(req?.at);
    const requester = req
      ? `<div class="req"><span>${esc(req.label ?? lReq)}</span><span class="who">${reqActor ? `<span class="av" aria-hidden="true">${esc(initials(personName(reqActor, req.actorName)))}</span><b title="${esc(reqActor)}">${esc(personName(reqActor, req.actorName))}</b>` : '<b>Unassigned</b>'}</span>${reqAt !== null ? `<span class="muted">${esc(fmtDateTime(reqAt))}</span>` : ''}</div>`
      : '';

    const steps = slots
      .map((s, i) => {
        const tone = STATUS_TONE[s.status] ?? 'neutral';
        const isNext = next.has(s.id);
        const conflict = this._requireSeparation && bad.has(s.id);
        const t = ms(s.decidedAt);
        const el = this.elapsed(i);
        const nodeMark =
          s.status === 'approved'
            ? glyph('check', 14)
            : s.status === 'rejected'
              ? glyph('circle-alert', 14)
              : s.status === 'skipped' || s.status === 'not_required'
                ? '–'
                : isNext
                  ? glyph('hourglass', 14)
                  : String(i + 1);
        const who = actorOf(s.actor);
        const shown = who ? personName(who, s.actorName) : '';
        const actor = who
          ? `<span class="av" aria-hidden="true">${esc(initials(shown))}</span><span class="nm" title="${esc(who)}">${esc(shown)}</span>`
          : '<span class="muted">Unassigned</span>';
        const mark =
          s.status === 'approved'
            ? glyph('check', 12)
            : s.status === 'rejected'
              ? '✕'
              : s.status === 'unknown'
                ? '?'
                : s.status === 'skipped' || s.status === 'not_required'
                  ? '–'
                  : isNext
                    ? glyph('hourglass', 12)
                    : '';
        return `<li class="step${isNext ? ' next' : ''}">
          ${this._mode === 'sequential' ? `<span class="node ${tone === 'neutral' ? '' : tone}" aria-hidden="true">${nodeMark}</span>` : ''}
          <div class="step-body"><button class="card-step" type="button" data-act="select" data-arg="${esc(s.id)}" data-step="${esc(s.id)}" aria-label="${esc(`${roleLabel(s.role)}: ${STATUS_LABEL[s.status] ?? s.status}${who ? `, ${shown}` : ', unassigned'}`)}">
            <span class="line1"><span class="head"><span class="role">${esc(roleLabel(s.role))}</span>
              <span class="pill ${tone}">${mark ? `<span class="glyph" aria-hidden="true">${mark}</span>` : ''}${esc(STATUS_LABEL[s.status] ?? s.status)}</span></span>
              ${isNext ? `<span class="tag next">${esc(lNext)}</span>` : ''}
              ${s.board ? `<span class="tag">${esc(lBoard)}</span>` : ''}</span>
            <span class="row2">${actor}</span>
            ${t !== null ? `<span class="when" style="display:block">${esc(fmtDateTime(t))}${el ? ` · ${esc(el)}` : ''}</span>` : ''}
            ${s.note ? `<span class="note" style="display:block">${esc(s.note)}</span>` : ''}
            ${prevNote(s)}
          </button>
          ${conflict ? `<div class="conflict" role="alert">${glyph('lock', 14)}<span>Approver is also the requester (${esc(shown)}). Assign a different person.</span></div>` : ''}
        </div></li>`;
      })
      .join('');

    const list =
      this._mode === 'parallel'
        ? `<div class="sub" style="margin:0 0 8px">${esc(lAll)}</div><ul class="steps par">${steps}</ul>`
        : `<ul class="steps seq">${steps}</ul>`;
    const sod =
      this._requireSeparation && bad.size === 0 && req
        ? `<span class="sod-ok">${esc(lSep)}: met</span>`
        : '';
    return `<div class="card">${header}<div class="body">${requester}${list}</div>${this.foot(sod)}</div>`;
  }
}

defineElement('henoyo-approval-chain', HenoyoApprovalChain);

declare global {
  interface HTMLElementTagNameMap {
    'henoyo-approval-chain': HenoyoApprovalChain;
  }
}
