/* Policies mockup (spec 5.3). The flow, the policy-against-reality matrix and the stations are the
   real Docket elements from the kit bundle; the rest is page chrome. Every number in the "If you save"
   panel is recomputed here from the sample matrix (policies-sample.js) so the interaction feels real.
   Nothing is saved anywhere: Save only moves the draft into the in-page library. */
(function () {
  const P = window.P, S = window.S;
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => [...r.querySelectorAll(s)];
  const esc = (v) => String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const clone = (o) => JSON.parse(JSON.stringify(o));
  const K = (tag, props) => { const e = document.createElement(tag); Object.assign(e, props); return e; };
  const help = (t) => `<button type="button" class="help" aria-label="About this section" data-tip="${esc(t)}">i</button>`;
  const slotOf = (id) => P.slots.find((s) => s.id === id);
  const packOf = (id) => P.guidelines.find((g) => g.id === id);
  const appOf = (id) => P.apps.find((a) => a.id === id);
  const AW = { runs: 'Runs in Docket', imports: 'Imports SARIF', planned: 'Planned' };
  const avl = (a) => `<span class="avl ${a}">${AW[a]}</span>`;
  const origin = (o, name) => o === 'henoyo' ? '<span class="origin h">Henoyo</span>' : `<span class="origin t">${esc(name || 'Third party')}</span>`;
  const ICO = {
    package: '<path d="m12 3 8 4.5v9L12 21l-8-4.5v-9z"/><path d="M12 12 4 7.5M12 12l8-4.5M12 12v9"/>',
    'file-code': '<path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/><path d="M14 3v5h5"/><path d="m10 13-2 2 2 2M14 13l2 2-2 2"/>',
    radar: '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="5"/><path d="M12 12 18 6"/>',
    'shield-alert': '<path d="M12 3 4 6v6c0 4.5 3.2 7.6 8 9 4.8-1.4 8-4.5 8-9V6l-8-3z"/><path d="M12 8v4M12 15.5h.01"/>',
    crosshair: '<circle cx="12" cy="12" r="8"/><path d="M12 2v5M12 17v5M2 12h5M17 12h5"/>',
    brain: '<path d="M9 4a3 3 0 0 0-3 3 3 3 0 0 0-2 5 3 3 0 0 0 2 5 3 3 0 0 0 6 1V4a3 3 0 0 0-3 0z"/><path d="M15 4a3 3 0 0 1 3 3 3 3 0 0 1 2 5 3 3 0 0 1-2 5 3 3 0 0 1-6 1"/>',
    'scroll-text': '<path d="M8 21h10a2 2 0 0 0 2-2v-1H10v1a2 2 0 0 1-2 2zm0 0a2 2 0 0 1-2-2V5a2 2 0 0 0-2-2h14a2 2 0 0 1 2 2v13"/><path d="M10 8h6M10 12h6"/>',
    wrench: '<path d="M14.7 6.3a4 4 0 0 0-5.4 5.4L3 18l3 3 6.3-6.3a4 4 0 0 0 5.4-5.4l-2.6 2.6-2.4-.6-.6-2.4 2.6-2.6z"/>',
  };
  const ico = (n) => `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${ICO[n] || ICO.package}</svg>`;
  const FIELDS = [['category', 'Category'], ['exposure', 'Exposure'], ['stack', 'Stack'], ['tier', 'Tier']];

  // ---- state --------------------------------------------------------------------------------
  const st = {
    saved: clone(P.policies),          // what docket_policy.json holds
    work: {},                          // working copies by id (unsaved edits and new drafts)
    sel: 'banking-customer',
    selStep: null,
    appId: null,
    runTab: 'plan',
    flash: null,
    n: 0,
  };
  const savedOf = (id) => st.saved.find((p) => p.id === id);
  const draft = () => (st.work[st.sel] ||= clone(savedOf(st.sel)));
  const isDirty = (id) => !!st.work[id] && (!savedOf(id) || JSON.stringify(st.work[id]) !== JSON.stringify(savedOf(id)));
  const libIds = () => [...st.saved.map((p) => p.id), ...Object.keys(st.work).filter((id) => !savedOf(id))];
  const policyById = (id) => st.work[id] && isDirty(id) ? st.work[id] : savedOf(id);

  // ---- policy logic (mirrors the spec: assignment, floor, coverage) -----------------------------
  const matches = (w, a) => FIELDS.every(([f]) => !w[f].length || w[f].includes(a[f]));
  const spec = (w) => FIELDS.filter(([f]) => w[f].length).length;
  /** world: array of policies in force. Returns {policy, tie:[policies]} for an application. */
  function assign(world, a) {
    const cands = world.filter((p) => matches(p.applies_when, a));
    if (!cands.length) return { policy: P.DEFAULT_POLICY, tie: [] };
    const top = Math.max(...cands.map((p) => spec(p.applies_when)));
    const best = cands.filter((p) => spec(p.applies_when) === top);
    return { policy: best[0], tie: best.length > 1 ? best : [] };
  }
  function outcome(p, a) {
    const lack = [];
    for (const s of p.steps.filter((x) => x.required)) {
      const d = a.ran[s.id];
      const sl = slotOf(s.id);
      if (d === null || d === undefined) lack.push(`${sl.label} has never run`);
      else if (d > p.cadence_days) lack.push(`${sl.label} last ran ${d} days ago; the window is ${p.cadence_days}`);
    }
    return { meets: lack.length === 0, lack };
  }
  function floor(p) {
    const w = p.applies_when, req = (id) => p.steps.some((s) => s.id === id && s.required);
    const cf = !w.exposure.length || w.exposure.includes('Customer-facing');
    if (!cf) return [];
    const need = ['trivy', 'semgrep', 'triage'];
    const bank = w.category.includes('Banking');
    if (bank) need.push('swarm');
    const miss = need.filter((id) => !req(id)).map((id) => slotOf(id).label);
    if (!miss.length) return [];
    return [`${bank ? 'Banking customer-facing' : 'customer-facing'} applications: ${miss.join(', ')} should be required`];
  }
  const worldWith = (p) => [...st.saved.filter((x) => x.id !== p.id), p];
  /** Preview, the same shape as POST /api/policy/preview but computed here. */
  function preview(d) {
    const before = st.saved, after = worldWith(d);
    const errors = [];
    if (!d.name.trim()) errors.push('Give the policy a name.');
    if (!d.steps.some((s) => s.required)) errors.push('A policy with nothing required is refused: it would put every application on the right.');
    const mine = [], changes = [], tiesOut = [], overridden = [];
    for (const a of P.apps) {
      const b = assign(before, a), n = assign(after, a);
      if (n.tie.length) tiesOut.push(`${a.label}: ties with ${n.tie.filter((p) => p.id !== d.id).map((p) => `"${p.name}"`).join(', ')}`);
      if (matches(d.applies_when, a) && n.policy.id !== d.id) overridden.push({ a, by: n.policy });
      const nOut = outcome(n.policy, a), bOut = outcome(b.policy, a);
      if (n.policy.id === d.id) mine.push({ a, out: nOut });
      const moved = b.policy.id !== n.policy.id;
      if (moved || bOut.meets !== nOut.meets || bOut.lack.join() !== nOut.lack.join())
        changes.push({ a, before: { policy: b.policy, out: bOut }, after: { policy: n.policy, out: nOut } });
    }
    if (tiesOut.length) errors.push('Two policies are equally specific for the same application. Narrow one of them. ' + tiesOut[0] + (tiesOut.length > 1 ? ` (and ${tiesOut.length - 1} more)` : ''));
    return { mine, changes, overridden, errors, meet: mine.filter((m) => m.out.meets).length, lack: mine.filter((m) => !m.out.meets).length };
  }

  // ---- hydrate a policy for <docket-policy-flow> -------------------------------------------------
  function toolOf(step) { const sl = slotOf(step.id); return sl.tools.find((t) => t.id === (step.tool || sl.tools.find((x) => x.default).id)); }
  function hydrate(d) {
    return {
      id: d.id, name: d.name || 'Untitled policy', cadence_days: d.cadence_days, guidelines: d.guidelines,
      applies: appliesText(d.applies_when),
      steps: P.slots.filter((sl) => d.steps.some((s) => s.id === sl.id)).map((sl) => {
        const s = d.steps.find((x) => x.id === sl.id), t = toolOf(s);
        const cad = sl.cadence.includes('window') ? (s.required ? sl.cadence.replace('window', `${d.cadence_days} days`) : 'Judged only when it runs') : sl.cadence;
        return { id: sl.id, label: sl.label, tool: t.name, origin: t.origin, availability: t.availability, required: !!s.required, cadence: cad, what: sl.what, produces: sl.produces, command: sl.command, icon: sl.icon };
      }),
    };
  }
  function appliesText(w) {
    const bits = FIELDS.map(([f]) => w[f].join(' or ')).filter(Boolean);
    return bits.length ? bits.join(', ') + ' applications' : 'Every application not covered by a more specific policy';
  }
  const hydratedPacks = (d) => d.guidelines.map(packOf).filter(Boolean);

  // ---- shell: tabs ------------------------------------------------------------------------------
  const NAV = [['home', 'Home'], ['apps', 'Applications'], ['scans', 'Scans'], ['findings', 'Findings'], ['compliance', 'Compliance']];
  $('#tabs').innerHTML = `<span class="app">Code Security</span>` + NAV.map(([k, l]) => `<a href="index.html#${k}">${l}</a>`).join('') + `<a href="policies.html" aria-current="page">Policies</a>`;

  // ---- page skeleton ------------------------------------------------------------------------------
  $('#main').innerHTML = `
    <div class="pagehead"><div class="grow"><div class="eyebrow">Code Security</div><h1>Policies</h1>
      <p class="sub">A policy says which checks an application must have had, from any vendor, how recently, and what a gap means. Docket runs one fixed pipeline; the policy judges it.</p></div>
      <div class="libbar"><button class="btn" id="tplBtn" aria-haspopup="true" aria-expanded="false">Start from a template</button><button class="btn primary" id="newBtn">New policy</button>
        <div class="menu" id="tplMenu" role="menu"></div></div></div>
    <div class="lib" id="lib"></div>
    <div class="stack">
      <div id="flowHost"></div>
      <div class="bgrid">
        <div class="stack" id="builder"></div>
        <div class="stickycol" id="side"></div>
      </div>
      <section class="hc" id="runCard"></section>
      <div id="matrixHost"></div>
    </div>`;

  const flow = K('docket-policy-flow', {
    starts: P.starts, gate: P.gate, mode: 'design',
    helpText: 'The whole policy as one picture, left to right: how a run starts, the scanners from any vendor, the Docket agents, the guidelines that advise, the gate, and what people get. Select a station to edit it.',
    source: { label: 'docket_policy.json' },
  });
  $('#flowHost').appendChild(flow);
  const runFlow = K('docket-policy-flow', { starts: P.starts, gate: P.gate, mode: 'run', helpText: 'The same flow, drawn from the recorded evidence of one real run. A dashed slot is a step the policy requires that did not run. Nothing here is projected.' });
  const matrix = K('docket-policy-matrix', { heading: 'Policy against reality', helpText: 'Each cell asks: did this required check finish inside the policy window for this application? The last column says what that adds up to: a stale check flags, a reproduced exploit blocks.', source: { label: 'Docket scans' } });
  $('#matrixHost').appendChild(matrix);

  // ---- library ---------------------------------------------------------------------------------------
  function drawLibrary() {
    const cards = libIds().map((id) => {
      const p = policyById(id), sv = savedOf(id);
      const apps = P.apps.filter((a) => assign(st.saved, a).policy.id === id);
      const meet = apps.filter((a) => outcome(sv || p, a).meets).length;
      const when = FIELDS.flatMap(([f]) => p.applies_when[f]).map((x) => `<span class="chip neutral">${esc(x)}</span>`).join('') || '<span class="chip neutral">Every other application</span>';
      const dots = ['pre', 'agents'].map((ph) => P.slots.filter((sl) => (sl.phase === ph) && p.steps.some((s) => s.id === sl.id)).map((sl) => {
        const s = p.steps.find((x) => x.id === sl.id);
        return `<i class="${s.required ? '' : 'o'}" title="${esc(sl.label)}: ${s.required ? 'Required' : 'Optional'}"></i>`;
      }).join('')).filter(Boolean).join('<span class="sep"></span>');
      const req = p.steps.filter((s) => s.required).length;
      const warn = floor(p).length ? `<span class="chip warn" title="${esc(floor(p)[0])}">Thinner than the baseline</span>` : '';
      return `<button type="button" class="pcard" data-id="${esc(id)}" aria-pressed="${id === st.sel}">
        <div style="display:flex;gap:8px;align-items:flex-start;justify-content:space-between"><h3>${esc(p.name || 'Untitled policy')}</h3><span style="display:flex;gap:4px;flex-wrap:wrap;justify-content:flex-end">${!sv ? '<span class="chip neutral">Draft</span>' : ''}${isDirty(id) && sv ? '<span class="chip info" style="background:rgb(var(--h-status-info-soft));color:rgb(var(--h-status-info))">Unsaved changes</span>' : ''}</span></div>
        <div class="when">${when}</div>
        <div class="minif" role="img" aria-label="${req} required steps, ${p.steps.length - req} optional">${dots}<small>${req} required, ${p.steps.length - req} optional</small></div>
        <div class="cnt"><span><b>${apps.length}</b> application${apps.length === 1 ? '' : 's'}</span><span>${sv ? `${meet} of ${apps.length} have every required check current` : 'Not saved yet'}</span></div>
        ${warn ? `<div>${warn}</div>` : ''}</button>`;
    }).join('');
    $('#lib').innerHTML = cards;
    $$('.pcard', $('#lib')).forEach((b) => b.addEventListener('click', () => { st.sel = b.dataset.id; st.selStep = null; st.appId = null; drawAll(); }));
  }
  const tpl = () => {
    const m = $('#tplMenu');
    m.innerHTML = [...st.saved.map((p) => `<button role="menuitem" data-t="${esc(p.id)}">${esc(p.name)}<small>${esc(appliesText(p.applies_when))}</small></button>`), '<button role="menuitem" data-t="blank">Blank policy<small>Trivy and Semgrep required, nothing else</small></button>'].join('');
    $$('button', m).forEach((b) => b.addEventListener('click', () => { newPolicy(b.dataset.t === 'blank' ? null : b.dataset.t); m.classList.remove('open'); $('#tplBtn').setAttribute('aria-expanded', 'false'); }));
  };
  function newPolicy(fromId) {
    st.n += 1;
    const base = fromId ? clone(savedOf(fromId)) : { applies_when: { category: [], exposure: [], stack: [], tier: [] }, cadence_days: 7, steps: [{ id: 'trivy', required: true, tool: null }, { id: 'semgrep', required: true, tool: null }], guidelines: [] };
    const id = `new-policy-${st.n}`;
    st.work[id] = { ...base, id, name: fromId ? `Copy of ${savedOf(fromId).name}` : 'New policy', version: 0, status: 'draft', default: false };
    st.sel = id; st.selStep = null; st.appId = null; drawAll();
    document.getElementById('flowHost').scrollIntoView({ behavior: 'smooth', block: 'start' });
  }
  $('#newBtn').addEventListener('click', () => newPolicy(null));
  $('#tplBtn').addEventListener('click', (e) => { tpl(); const m = $('#tplMenu'); const o = m.classList.toggle('open'); e.currentTarget.setAttribute('aria-expanded', String(o)); });
  document.addEventListener('click', (e) => { if (!e.target.closest('.libbar')) $('#tplMenu').classList.remove('open'); });

  // ---- flow (hero) -----------------------------------------------------------------------------------
  function drawFlow() {
    const d = draft();
    flow.policy = hydrate(d);
    flow.guidelines = hydratedPacks(d);
    flow.warnings = floor(d);
    flow.selected = st.selStep || undefined;
  }
  flow.addEventListener('docket:station', (e) => { st.selStep = st.selStep === e.detail.id ? null : e.detail.id; drawFlow(); drawBuilder(); const r = $(`[data-step="${st.selStep}"]`); if (r) r.scrollIntoView({ behavior: 'smooth', block: 'center' }); });
  flow.addEventListener('docket:add-station', (e) => { st.flash = e.detail.group; drawBuilder(); const p = $('#palette'); p.scrollIntoView({ behavior: 'smooth', block: 'center' }); setTimeout(() => { st.flash = null; $$('.slot.flash').forEach((x) => x.classList.remove('flash')); }, 1800); });
  flow.addEventListener('docket:add-guideline', () => { const g = $('#guidelines'); g.scrollIntoView({ behavior: 'smooth', block: 'center' }); $$('.pk', g).forEach((x) => x.classList.add('flash')); setTimeout(() => $$('.pk.flash').forEach((x) => x.classList.remove('flash')), 1500); });

  // ---- builder ----------------------------------------------------------------------------------------
  const card = (title, body, { sub = '', tip = '', id = '' } = {}) => `<section class="hc" ${id ? `id="${id}"` : ''}><header><div class="grow"><h3>${esc(title)}${tip ? help(tip) : ''}</h3>${sub ? `<p>${sub}</p>` : ''}</div></header><div class="pad">${body}</div></section>`;
  let lastFocus = null;
  document.addEventListener('focusin', (e) => { lastFocus = e.target.dataset && e.target.dataset.k ? e.target.dataset.k : null; });

  function drawBuilder() {
    const d = draft(), w = d.applies_when, pv = preview(d);
    const profile = `<div class="fld"><div class="lbl">Name</div><input class="nm-in" data-k="name" value="${esc(d.name)}" aria-label="Policy name"></div>
      <div class="fld"><div class="lbl">Applies when${help('An application gets this policy when its profile matches every field you choose. A field you leave empty does not constrain it. The most specific matching policy wins; an application with no match gets the built-in baseline.')}<span class="chip neutral" style="margin-left:auto">Matching</span></div>
      ${FIELDS.map(([f, l]) => `<div class="pf"><span>${l}</span><div class="toggles">${P.profile[f].map((v) => `<button type="button" class="tg" data-k="tg-${f}-${v}" data-f="${f}" data-v="${esc(v)}" aria-pressed="${w[f].includes(v)}">${esc(v)}</button>`).join('')}</div></div>`).join('')}
      <div class="matchline" aria-live="polite"><b>Matches ${pv.mine.length} application${pv.mine.length === 1 ? '' : 's'}</b>
        <div class="chips">${pv.mine.map((m) => `<span class="chip neutral" title="${esc(m.a.category)} · ${esc(m.a.exposure)} · ${esc(m.a.stack)}">${esc(m.a.label)} · ${esc(m.a.tier)}</span>`).join('') || '<span class="sub2">No application has this profile.</span>'}</div>
        ${pv.overridden.length ? `<div class="sub2" style="margin-top:7px">${pv.overridden.length} more fit${pv.overridden.length === 1 ? 's' : ''} the profile but use${pv.overridden.length === 1 ? 's' : ''} a more specific policy: ${pv.overridden.map((o) => esc(o.a.label) + ' (' + esc(o.by.name) + ')').join(', ')}.</div>` : ''}</div></div>
      <div class="fld"><label for="cad">Cadence${help('The window a required check is judged against: it counts as current if it finished within this many days. Docket does not start scans on a schedule yet; it judges how recent the last one was.')}<span class="chip sec" style="margin-left:6px">Required</span></label>
        <div style="display:flex;align-items:center;gap:8px"><input id="cad" class="num" type="number" min="1" max="90" value="${d.cadence_days}" data-k="cad"> <span class="sub2">days. Judged, not started.</span></div></div>`;
    const stepRows = P.slots.filter((sl) => d.steps.some((s) => s.id === sl.id)).map((sl) => {
      const s = d.steps.find((x) => x.id === sl.id), t = toolOf(s), sel = st.selStep === sl.id;
      const tool = sl.tools.length > 1
        ? `<select class="sel" data-k="tool-${sl.id}" data-tool="${sl.id}" aria-label="Tool for ${esc(sl.label)}">${sl.tools.map((x) => `<option value="${x.id}" ${x.id === t.id ? 'selected' : ''} ${x.availability === 'planned' ? 'disabled' : ''} title="${x.availability === 'planned' ? 'Planned: not available yet' : ''}">${esc(x.name)}${x.availability === 'planned' ? ' (Planned)' : x.availability === 'imports' ? ' (imports SARIF)' : ''}</option>`).join('')}</select>`
        : `<span>${esc(t.name)}</span>`;
      const locked = sl.locked;
      const sw = locked
        ? `<button type="button" class="sw" role="switch" aria-checked="false" aria-disabled="true" title="Guidelines advise only, so the reader is always optional"><span class="tr"></span>Optional, locked</button>`
        : `<button type="button" class="sw" role="switch" aria-checked="${!!s.required}" data-k="req-${sl.id}" data-req="${sl.id}"><span class="tr"></span>${s.required ? 'Required' : 'Optional'}</button>`;
      const cantRemove = locked && d.guidelines.length;
      return `<div class="srow ${s.required ? '' : 'opt'} ${sel ? 'sel-row' : ''}" data-step="${sl.id}">
        <div class="nm"><span class="ic ${sl.origin === 'henoyo' ? 'h' : ''}">${ico(sl.icon)}</span><button type="button" class="linkish" data-sel="${sl.id}" style="all:unset;cursor:pointer;font:inherit">${esc(sl.label)}</button></div>
        <div class="tl">${tool}${t.origin === 'henoyo' ? origin('henoyo') : ''}${avl(t.availability)}</div>
        <div>${sw}</div>
        <button type="button" class="xbtn" data-rm="${sl.id}" aria-label="Remove ${esc(sl.label)}" aria-disabled="${!!cantRemove}" title="${cantRemove ? 'Needed while a guideline is selected' : 'Remove from the policy'}"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M6 6l12 12M18 6 6 18"/></svg></button>
        ${sel ? `<div class="srow-d"><div>${esc(sl.what)}</div><div><b>Reads:</b> ${esc(sl.reads)}. <b>Produces:</b> ${esc(sl.produces)}.</div>${sl.command ? `<div><code>${esc(sl.command)}</code></div>` : '<div>Runs as a Docket agent, inside the sandbox.</div>'}<div><b>Detection written by:</b> ${t.origin === 'henoyo' ? 'Henoyo' : esc(t.name)}</div></div>` : ''}
      </div>`;
    }).join('');
    const group = (ph, title) => `<div class="palh">${title}</div><div class="pal">${P.slots.filter((sl) => sl.phase === ph).map((sl) => {
      const inP = d.steps.some((s) => s.id === sl.id);
      const opts = sl.locked ? '<p>Added when you choose a guideline below.</p>'
        : inP ? '<p>In this policy.</p>'
        : `<div class="opts">${sl.tools.map((t) => t.availability === 'planned'
          ? `<span class="vend" aria-disabled="true" title="Planned: ${esc(t.name)} is not available yet, so a policy cannot use it.">${esc(t.name)}${avl('planned')}</span>`
          : `<button type="button" class="vend" data-add="${sl.id}" data-tool="${t.id}" aria-label="Add ${esc(sl.label)} using ${esc(t.name)}">${esc(t.name)}${avl(t.availability)}</button>`).join('')}</div>`;
      return `<div class="slot ${inP ? 'in' : ''} ${st.flash === ph ? 'flash' : ''}"><b>${esc(sl.label)}</b><p>${esc(sl.what)}</p>${opts}</div>`;
    }).join('')}</div>`;
    const steps = `<p class="sub2" style="margin:0 0 10px">Steps sit in the order Docket runs them. There is nothing to reorder: the policy decides what must have run, not the order.</p>
      <div class="srows">${stepRows}</div>
      <div id="palette"><div style="display:flex;align-items:center;gap:6px;margin-top:18px"><b style="font-size:13px">Add a step</b>${help('Pick a vendor to fill a capability. Docket runs the tools marked Runs in Docket. Tools marked Imports SARIF are run by you; Docket reads their SARIF file and records that the step ran. Planned tools are shown so you can see what is coming, but cannot be chosen.')}</div>
      ${group('pre', 'Before the agents')}${group('agents', 'Docket agents')}</div>`;
    const packs = `<div class="packs">${P.guidelines.map((g) => {
      const on = d.guidelines.includes(g.id);
      return `<button type="button" class="pk" role="checkbox" aria-checked="${on}" data-pack="${g.id}" data-k="pk-${g.id}"><span class="bx"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3.2" stroke-linecap="round"><path d="m5 12 5 5 9-10"/></svg></span><span><span class="t"><span class="chip reg">${esc(g.authority)}</span>${esc(g.title)}</span><span class="c" style="display:block">${g.controls} controls, ${g.observable} readable from code. The others need a person to answer.</span></span></button>`;
    }).join('')}</div><p class="note">Guidelines advise only. Selecting one adds the Compliance reader as an optional step. It annotates a pull request at notice level and never blocks.</p>`;
    $('#builder').innerHTML =
      card('Who and when', profile, { sub: 'Which applications this policy covers, and how fresh a required check must be.', id: 'who' }) +
      card('Steps', steps, { sub: 'What must have run. Required steps decide whether an application meets the policy.', tip: 'A required step that has not finished inside the window means the application lacks a check; the gate flags it. An optional step is judged only when it runs.', id: 'steps' }) +
      card('Guidelines', packs, { sub: 'Regulatory and framework packs the Compliance reader checks the code against.', id: 'guidelines' });
    wireBuilder();
    if (lastFocus) { const el = $(`[data-k="${lastFocus}"]`); if (el && el !== document.activeElement) el.focus({ preventScroll: true }); }
  }
  function touch() { drawLibrary(); drawFlow(); drawSide(); drawRun(); drawMatrix(); }
  function wireBuilder() {
    const d = draft();
    $$('[data-k="name"]').forEach((i) => i.addEventListener('input', () => { d.name = i.value; touch(); }));
    $$('.tg').forEach((b) => b.addEventListener('click', () => { const w = d.applies_when[b.dataset.f]; const i = w.indexOf(b.dataset.v); i < 0 ? w.push(b.dataset.v) : w.splice(i, 1); drawBuilder(); touch(); }));
    $('#cad').addEventListener('input', (e) => { const n = Math.max(1, Math.min(90, +e.target.value || 1)); d.cadence_days = n; touch(); });
    $$('[data-req]').forEach((b) => b.addEventListener('click', () => { const s = d.steps.find((x) => x.id === b.dataset.req); s.required = !s.required; drawBuilder(); touch(); }));
    $$('[data-tool]').forEach((sel) => sel.addEventListener('change', () => { const s = d.steps.find((x) => x.id === sel.dataset.tool); const df = slotOf(s.id).tools.find((t) => t.default).id; s.tool = sel.value === df ? null : sel.value; drawBuilder(); touch(); }));
    $$('[data-sel]').forEach((b) => b.addEventListener('click', () => { st.selStep = st.selStep === b.dataset.sel ? null : b.dataset.sel; drawBuilder(); drawFlow(); }));
    $$('[data-rm]').forEach((b) => b.addEventListener('click', () => { if (b.getAttribute('aria-disabled') === 'true') return; d.steps = d.steps.filter((s) => s.id !== b.dataset.rm); if (st.selStep === b.dataset.rm) st.selStep = null; drawBuilder(); touch(); }));
    $$('[data-add]').forEach((b) => b.addEventListener('click', () => { const sl = slotOf(b.dataset.add); const df = sl.tools.find((t) => t.default).id; d.steps.push({ id: sl.id, required: sl.id === 'trivy' || sl.id === 'semgrep' || sl.id === 'triage' || sl.id === 'swarm', tool: b.dataset.tool === df ? null : b.dataset.tool }); st.selStep = sl.id; drawBuilder(); touch(); }));
    $$('[data-pack]').forEach((b) => b.addEventListener('click', () => {
      const i = d.guidelines.indexOf(b.dataset.pack);
      if (i < 0) { d.guidelines.push(b.dataset.pack); if (!d.steps.some((s) => s.id === 'compliance')) d.steps.push({ id: 'compliance', required: false, tool: null }); } else d.guidelines.splice(i, 1);
      drawBuilder(); touch();
    }));
  }

  // ---- side: gate + "If you save" -------------------------------------------------------------------------
  const EFF = { blocks: ['bad', 'Blocks'], flags: ['warn', 'Flags'], advises: ['neutral', 'Advises'] };
  function drawSide() {
    const d = draft(), pv = preview(d), sv = savedOf(d.id), dirty = isDirty(d.id), w = floor(d);
    const unchanged = P.apps.length - pv.changes.length;
    const state = (x, pol) => x.out.meets ? `<span class="chip ok">Current</span>` : `<span class="chip warn" title="${esc(x.out.lack.join('; '))}">Lacks ${x.out.lack.length} check${x.out.lack.length === 1 ? '' : 's'}</span>`;
    const rows = pv.changes.map((c) => {
      const moved = c.before.policy.id !== c.after.policy.id;
      const why = moved ? (c.after.policy.id === d.id ? `Now uses this policy (was ${esc(c.before.policy.name)}). ` : `Falls to ${esc(c.after.policy.name)}. `) : '';
      const reason = (c.after.out.lack[0] || (c.after.out.meets ? 'Every required check is inside the window' : ''));
      return `<tr><td data-v="${esc(c.a.label)}"><b>${esc(c.a.label)}</b></td><td data-v="${esc(c.a.tier)}">${esc(c.a.tier)}</td><td data-v="${c.before.out.meets ? 0 : 1}">${state(c.before)}</td><td data-v="${c.after.out.meets ? 0 : 1}">${state(c.after)}</td><td class="sub2">${why}${esc(reason)}</td></tr>`;
    }).join('');
    const changes = pv.changes.length
      ? `<table class="lv sortable"><thead><tr><th data-sort>Application</th><th data-sort>Tier</th><th data-sort>Now</th><th data-sort>If you save</th><th>Why</th></tr></thead><tbody>${rows}</tbody></table><p class="sub2" style="margin:8px 0 0">${unchanged} other application${unchanged === 1 ? '' : 's'} would not change.</p>`
      : `<p class="sub2" style="margin:0">Nothing changes for any application.</p>`;
    const msg = pv.errors.map((e) => `<div class="err" role="alert">${esc(e)}</div>`).join('');
    const warn = w.map((x) => `<span class="chip warn">Thinner than the baseline for ${esc(x)}</span>`).join('');
    $('#side').innerHTML = `
      <section class="hc"><header><div class="grow"><h3>If you save${help('Computed from the latest runs of every application, with nothing sent anywhere. It compares what each application gets today with what it would get if this draft were saved.')}${dirty ? '<span class="chip warn dirty">Unsaved changes</span>' : ''}</h3><p>${dirty || !sv ? 'The effect of this draft on every application.' : 'No unsaved changes. This is the saved policy.'}</p></div></header>
        <div class="pad sv">
          <div class="big"><div><b>${pv.mine.length}</b><span>Matches</span></div><div><b>${pv.meet}</b><span>Would be current</span></div><div class="lack"><b>${pv.lack}</b><span>Would lack a check</span></div></div>
          ${warn ? `<div style="display:flex;gap:6px;flex-wrap:wrap">${warn}</div>` : ''}${msg}
          ${changes}
          <div class="btnrow"><button class="btn primary" id="saveBtn" ${(!dirty || pv.errors.length) ? 'disabled' : ''}>Save</button><button class="btn" id="discBtn" ${dirty ? '' : 'disabled'}>Discard</button><span style="flex:1"></span><button class="btn danger" id="delBtn" ${sv ? '' : 'disabled'} title="${sv ? 'Remove this policy' : 'Not saved yet'}">Delete</button></div>
          <p class="sub2" style="margin:0">Save only writes the policy file. It does not start a scan. Approval is not editable until an audit trail exists.</p>
        </div></section>
      <section class="hc"><header><div class="grow"><h3>The gate${help('What a run concludes is fixed by Docket. A policy cannot change it: it only decides which checks must have run.')}<span class="chip neutral" style="margin-left:8px">Read-only</span></h3><p>Fixed for every policy.</p></div></header>
        <div class="pad"><div class="gate">${P.gate.map((g) => `<div><span class="chip ${EFF[g.effect][0]}">${EFF[g.effect][1]}</span> ${esc(g.text)}</div>`).join('')}</div></div></section>`;
    sortable($('#side'));
    $('#saveBtn').addEventListener('click', save);
    $('#discBtn').addEventListener('click', () => { delete st.work[d.id]; if (!savedOf(d.id)) { st.sel = st.saved[0].id; } st.selStep = null; drawAll(); });
    $('#delBtn').addEventListener('click', confirmDelete);
  }
  function save() {
    const d = draft(), pv = preview(d);
    if (pv.errors.length) return;
    const out = clone(d);
    if (out.id.startsWith('new-policy')) { out.id = out.name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || out.id; }
    out.version = (savedOf(d.id)?.version || 0) + 1; out.status = 'saved';
    delete st.work[d.id];
    const i = st.saved.findIndex((p) => p.id === d.id);
    if (i >= 0) st.saved[i] = out; else st.saved.push(out);
    st.sel = out.id; drawAll(); toast(`Saved "${out.name}". Only the policy file was written.`);
  }
  function confirmDelete() {
    const d = draft(), rest = st.saved.filter((p) => p.id !== d.id);
    const fall = P.apps.filter((a) => assign(st.saved, a).policy.id === d.id).map((a) => ({ a, to: assign(rest, a).policy }));
    $('#modal').innerHTML = `<div class="box"><h3 id="mt">Delete "${esc(d.name)}"?</h3><p style="margin:0">${fall.length ? `${fall.length} application${fall.length === 1 ? '' : 's'} would fall to another policy, and may start to lack checks.` : 'No application uses this policy.'}</p>
      ${fall.length ? `<ul>${fall.map((f) => `<li><b>${esc(f.a.label)}</b> would use ${esc(f.to.name)}${f.to.default ? '' : ''}</li>`).join('')}</ul>` : ''}
      <div class="btnrow" style="justify-content:flex-end"><button class="btn" id="mNo">Keep it</button><button class="btn danger" id="mYes">Delete policy</button></div></div>`;
    $('#modal').classList.add('open'); $('#mNo').focus();
    $('#mNo').addEventListener('click', () => $('#modal').classList.remove('open'));
    $('#mYes').addEventListener('click', () => { st.saved = rest; delete st.work[d.id]; st.sel = st.saved[0].id; $('#modal').classList.remove('open'); drawAll(); toast(`Deleted "${d.name}".`); });
  }
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape') { $('#modal').classList.remove('open'); closeDrawer(); } });
  let tt;
  function toast(t) { const el = $('#toast'); el.textContent = t; el.classList.add('open'); clearTimeout(tt); tt = setTimeout(() => el.classList.remove('open'), 3200); }

  // ---- sortable tables ------------------------------------------------------------------------------------------
  function sortable(root) {
    $$('table.sortable', root).forEach((t) => {
      $$('th[data-sort]', t).forEach((th) => {
        th.tabIndex = 0; th.setAttribute('role', 'columnheader');
        const go = () => {
          const dir = th.dataset.dir === 'asc' ? 'desc' : 'asc';
          $$('th', t).forEach((x) => { delete x.dataset.dir; x.removeAttribute('aria-sort'); });
          th.dataset.dir = dir; th.setAttribute('aria-sort', dir === 'asc' ? 'ascending' : 'descending');
          const idx = [...th.parentNode.children].indexOf(th);
          const rows = [...t.tBodies[0].rows];
          const val = (r) => { const c = r.cells[idx]; return c.dataset.v ?? c.textContent.trim(); };
          rows.sort((a, b) => { const x = val(a), y = val(b); const n = !isNaN(+x) && !isNaN(+y) && x !== '' ? +x - +y : String(x).localeCompare(String(y)); return dir === 'asc' ? n : -n; });
          rows.forEach((r) => t.tBodies[0].appendChild(r)); th.focus();
        };
        th.addEventListener('click', go);
        th.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); go(); } });
      });
    });
  }

  // ---- run it ------------------------------------------------------------------------------------------------------
  const assigned = () => { const d = draft(), world = worldWith(d); return P.apps.filter((a) => assign(world, a).policy.id === d.id); };
  function drawRun() {
    const d = draft(), list = assigned();
    if (!list.some((a) => a.id === st.appId)) st.appId = (list.find((a) => P.lastRuns[a.id]) || list[0] || {}).id || null;
    const a = st.appId ? appOf(st.appId) : null, hp = hydrate(d);
    const head = `<header><div class="grow"><h3>Run it${help('See what this policy would do for one application, then what the last real run did. A preview is a plan: it never shows results. Results come only from a recorded run.')}</h3><p>Pick an application. Preview the plan, or read the evidence of its last run.</p></div></header>`;
    if (!a) { $('#runCard').innerHTML = head + `<div class="pad"><p class="note">No application matches this policy yet. Choose who it applies to above.</p></div>`; return; }
    const bar = `<div class="runbar"><label class="sub2" for="appSel" style="display:flex;gap:8px;align-items:center">Application <select class="sel" id="appSel" data-k="appsel">${list.map((x) => `<option value="${x.id}" ${x.id === a.id ? 'selected' : ''}>${esc(x.label)} (${esc(x.tier)})</option>`).join('')}</select></label>
      <div class="seg" role="group" aria-label="What to show"><button type="button" data-rt="plan" aria-pressed="${st.runTab === 'plan'}">Preview a run</button><button type="button" data-rt="last" aria-pressed="${st.runTab === 'last'}">Last run</button></div>
      <span style="flex:1"></span><button class="btn primary" id="runNow">Run now</button></div>
      <p class="sub2" style="margin:0 0 12px">${a.repo ? 'Run now uses the existing scan launcher, from the Scans tab.' : `No repository is connected to ${esc(a.label)}, so Run now cannot start. From the command line: <code class="mono">docket --target https://staging.example.com --source ./${esc(a.id)} -n</code>`}</p>`;
    let body = '';
    if (st.runTab === 'plan') {
      const rows = hp.steps.map((s, i) => {
        const sl = slotOf(s.id), t = toolOf(d.steps.find((x) => x.id === s.id));
        return `<tr><td data-v="${i}"><b>${esc(s.label)}</b><div style="margin-top:4px;display:flex;gap:5px;flex-wrap:wrap">${origin(s.origin, s.tool)}${avl(s.availability)}<span class="chip ${s.required ? 'sec' : 'neutral'}">${s.required ? 'Required' : 'Optional'}</span></div></td>
          <td>${t.availability === 'imports' ? `Run ${esc(t.name)} in your own pipeline, then pass its results: <code>docket --sarif ${esc(t.id)}.sarif</code>` : sl.command ? `<code>${esc(sl.command)}</code>` : 'A Docket agent, in the sandbox'}</td><td>${esc(sl.reads)}</td><td>${esc(sl.produces)}</td><td>${t.origin === 'henoyo' ? 'Henoyo' : esc(t.name)}</td></tr>`;
      }).join('');
      body = `<div class="eyebrow" style="margin-bottom:8px">Plan for ${esc(a.label)}. Nothing has run.</div>
        <table class="lv sortable plan"><thead><tr><th data-sort>Step</th><th data-sort>How it runs</th><th data-sort>What it reads</th><th data-sort>What it produces</th><th data-sort>Detection written by</th></tr></thead><tbody>${rows}</tbody></table>
        <p class="note">This is a plan, not a result. A step marked Imports SARIF is run by your own pipeline: Docket reads its file and records that the step ran.</p>`;
    } else {
      const lr = P.lastRuns[a.id];
      body = lr ? '<div id="runFlowHost"></div>' : `<div class="empty" style="padding:22px"><b>No run is recorded for ${esc(a.label)}.</b><p style="margin:6px 0 0">Use Run now. Docket never shows an outcome that did not happen.</p></div>`;
    }
    $('#runCard').innerHTML = head + `<div class="pad">${bar}${body}</div>`;
    sortable($('#runCard'));
    if (st.runTab === 'last' && P.lastRuns[a.id]) {
      const lr = P.lastRuns[a.id];
      runFlow.policy = hp; runFlow.guidelines = hydratedPacks(d); runFlow.runLanes = lr.lanes; runFlow.gateResult = lr.gateResult; runFlow.runLabel = lr.label;
      $('#runFlowHost').appendChild(runFlow);
    }
    $('#appSel').addEventListener('change', (e) => { st.appId = e.target.value; drawRun(); });
    $$('[data-rt]').forEach((b) => b.addEventListener('click', () => { st.runTab = b.dataset.rt; drawRun(); }));
    $('#runNow').addEventListener('click', () => { if (a.repo) location.href = 'index.html#scans'; else toast('Connect a repository first, or use the command line shown.'); });
  }
  runFlow.addEventListener('docket:lane', (e) => {
    const a = appOf(st.appId), lr = P.lastRuns[a.id]; const l = lr.lanes.find((x) => x.id === e.detail.id), ev = lr.evidence[e.detail.id] || {};
    const step = hydrate(draft()).steps.find((s) => s.id === e.detail.id) || {};
    openDrawer(`<header><button class="x" aria-label="Close">×</button><div class="eyebrow">Run evidence</div><h3 style="font-size:1.3rem;margin-top:4px">${esc(step.label || (l && l.label) || e.detail.id)}</h3><div style="margin-top:10px;display:flex;gap:8px;flex-wrap:wrap">${l ? origin(l.origin, l.tool) : ''}${step.required ? '<span class="chip sec">Required by this policy</span>' : ''}</div></header>
      <div class="body"><dl class="kv" style="margin-top:14px"><dt>State</dt><dd>${l ? esc(l.state.replace('_', ' ')) : 'Did not run'}</dd><dt>Result</dt><dd>${esc((l && l.summary) || 'Nothing to report')}</dd>
      ${ev.tool ? `<dt>Tool</dt><dd>${esc(ev.tool)} ${esc(ev.version || '')}</dd>` : ''}${ev.commit ? `<dt>Source commit</dt><dd class="mono">${esc(ev.commit)}</dd>` : ''}${ev.sarif_at ? `<dt>SARIF time</dt><dd>${esc(ev.sarif_at)}</dd>` : ''}</dl>
      ${ev.note ? `<p class="note">${esc(ev.note)}</p>` : ''}${!l ? '<p class="note">The policy requires this step, but no record shows it ran.</p>' : ''}</div>`);
  });
  function openDrawer(html) { $('#drawer').innerHTML = html; $('#drawer').classList.add('open'); $('#scrim').classList.add('open'); $('#drawer .x').addEventListener('click', closeDrawer); }
  function closeDrawer() { $('#drawer').classList.remove('open'); $('#scrim').classList.remove('open'); }
  $('#scrim').addEventListener('click', closeDrawer);

  // ---- matrix ----------------------------------------------------------------------------------------------------------
  function drawMatrix() {
    const d = draft(), hp = hydrate(d), req = hp.steps.filter((s) => s.required), list = assigned();
    matrix.heading = `Policy against reality: ${d.name || 'Untitled policy'}`;
    matrix.windowDays = d.cadence_days;
    matrix.scanners = req.map((s) => ({ id: s.id, label: s.label, tool: s.tool, origin: s.origin, icon: s.icon }));
    matrix.rows = list.map((a) => {
      const cells = {}; const late = [];
      for (const s of req) { const days = a.ran[s.id]; const state = days === null || days === undefined ? 'missing' : days <= d.cadence_days ? 'ok' : 'stale'; cells[s.id] = { state, ago: state === 'missing' ? 'never' : `${days} d` }; if (state !== 'ok') late.push(`${s.label} ${state === 'missing' ? 'has never run' : `is ${days} days old`}`); }
      const consequence = a.proven ? { effect: 'blocks', text: `${a.proven} reproduced exploit${a.proven === 1 ? '' : 's'} open` } : late.length ? { effect: 'flags', text: late[0] + (late.length > 1 ? ` (and ${late.length - 1} more)` : '') } : null;
      return { id: a.id, label: a.label, tier: a.tier, cells, consequence };
    });
  }
  document.addEventListener('docket:open-app', (e) => { st.appId = e.detail.id; st.runTab = 'last'; drawRun(); $('#runCard').scrollIntoView({ behavior: 'smooth', block: 'start' }); });

  // ---- go ------------------------------------------------------------------------------------------------------------------
  function drawAll() { drawLibrary(); drawFlow(); drawBuilder(); drawSide(); drawRun(); drawMatrix(); }
  // Deep link for review and screenshots: policies.html#policy=non-banking-web&step=triage&run=last&app=loan-origination
  const q = new URLSearchParams(location.hash.slice(1));
  if (q.get('policy') && savedOf(q.get('policy'))) st.sel = q.get('policy');
  if (q.get('step')) st.selStep = q.get('step');
  if (q.get('run')) st.runTab = q.get('run');
  if (q.get('app')) st.appId = q.get('app');
  if (q.get('edit') === 'swarm-optional') draft().steps.find((s) => s.id === 'swarm').required = false;
  if (q.get('edit') === 'cad3') draft().cadence_days = 3;
  drawAll();
})();
