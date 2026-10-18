/* Mockup renderer. Pages are template strings with <div data-mount="id"> holes that are
   filled with real Visual Kit and Docket elements, so what you see is the actual
   component output, not a drawing of it. */
(function () {
  const { apps, findings, lanes, groups, health, proof, policy, matrix, rbi, trend, NOW, iso } = window.S;
  const $ = (s, r = document) => r.querySelector(s);
  const esc = (v) => String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const appById = (id) => apps.find((a) => a.id === id);
  const K = (tag, props) => { const e = document.createElement(tag); Object.assign(e, props); return e; };
  const origin = (o, name) => o === 'henoyo' ? '<span class="origin h">Henoyo</span>' : `<span class="origin t">${esc(name || 'Third-party')}</span>`;
  const sevChip = (s) => `<span class="chip ${window.S.sev(s)}">${s[0].toUpperCase() + s.slice(1)}</span>`;
  const help = (t) => `<button type="button" class="help" aria-label="About this section" data-tip="${esc(t)}">i</button>`;
  const LV = { action: ['Act today', 'bad'], attention: ['Watch', 'warn'], clear: ['Clear', 'ok'], unknown: ['Not scanned', 'off'] };
  const lamp = (lv) => `<span class="lamp ${LV[lv][1]}"></span>`;
  const objIcon = (bg, fg, svg) => `<span class="objicon" style="background:${bg};color:${fg}">${svg}</span>`;
  const IC = {
    shield: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3 4 6v6c0 4.5 3.2 7.6 8 9 4.8-1.4 8-4.5 8-9V6l-8-3z"/></svg>',
    code: '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m8 7-5 5 5 5M16 7l5 5-5 5M14 4l-4 16"/></svg>',
  };
  let TAB = 'overview', VIEW = 'proven', PACK = 'rbi-csf', CFILTER = 'all';

  // ---- navigation ---------------------------------------------------------------
  const NAV = [['home', 'Home'], ['apps', 'Applications'], ['scans', 'Scans'], ['findings', 'Findings'], ['compliance', 'Compliance'], ['policy', 'Policy']];
  function route() {
    const [r, id] = (location.hash.replace('#', '') || 'home').split('/');
    return { r, id };
  }
  function drawTabs(cur) {
    const base = cur === 'app' ? 'apps' : cur === 'scan' ? 'scans' : cur;
    $('#tabs').innerHTML = `<span class="app">Code Security</span>` + NAV.map(([k, l]) => `<a href="#${k}" ${k === base ? 'aria-current="page"' : ''}>${l}</a>`).join('');
  }
  function fill(root, mounts) {
    for (const [id, el] of Object.entries(mounts)) { const slot = root.querySelector(`[data-mount="${id}"]`); if (slot) slot.replaceWith(el); }
  }
  function go(html, mounts = {}) { const m = $('#main'); m.innerHTML = html; fill(m, mounts); window.scrollTo(0, 0); }
  document.addEventListener('docket:open-app', (e) => { location.hash = '#app/' + e.detail.id; });
  document.addEventListener('docket:open-scan', () => { location.hash = '#scan/2184'; });
  document.addEventListener('docket:lane', (e) => { const l = lanes.find((x) => x.id === e.detail.id); if (l) laneDrawer(l); });

  // ---- shared bits ---------------------------------------------------------------
  const head = (eyebrow, title, sub, actions = '') => `<div class="pagehead"><div class="grow"><div class="eyebrow">${esc(eyebrow)}</div><h1>${esc(title)}</h1>${sub ? `<p class="sub">${sub}</p>` : ''}</div>${actions}</div>`;
  const card = (title, body, { sub = '', tip = '', actions = '', flush = false } = {}) => `<section class="hc"><header><div class="grow"><h3>${esc(title)}${tip ? help(tip) : ''}</h3>${sub ? `<p>${sub}</p>` : ''}</div>${actions}</header><div class="${flush ? 'flush' : 'pad'}">${body}</div></section>`;

  // ---- HOME ----------------------------------------------------------------------
  function home() {
    const act = apps.filter((a) => a.level === 'action'), att = apps.filter((a) => a.level === 'attention');
    const clear = apps.filter((a) => a.level === 'clear'), unk = apps.filter((a) => a.level === 'unknown');
    const row = (a) => `<li data-app="${a.id}"><div>${lamp(a.level)}</div><div><div class="t">${esc(a.label)} <span class="chip neutral" style="margin-left:6px">${esc(a.tier)}</span></div><div class="r">${esc(a.reason)}</div></div><div class="age">${a.age ? esc(a.age) + ' open' : ''}<br><span style="color:rgb(var(--h-text-link));font-weight:600">${a.level === 'unknown' ? 'Connect repo' : 'Open'} →</span></div></li>`;
    const grp = (title, list) => list.length ? `<li class="wqh">${title}<b>${list.length}</b></li>` + list.map(row).join('') : '';
    const sentence = `<span style="font:500 1.45rem/1.35 'Source Serif 4',Georgia,serif;letter-spacing:-.01em"><b style="color:rgb(var(--h-sev-critical))">${act.length} of ${apps.length} applications need action today.</b> Both have an exploit that Docket reproduced against staging. ${att.length} more need a look this week, ${unk.length} has never been scanned, and ${clear.length} are clear.</span>`;
    const q = `<ul class="wq">${grp('Act today', act)}${grp('Watch this week', att)}${grp('Not scanned', unk)}</ul>`;
    const ring = K('henoyo-ring', { heading: 'Application health', showPercent: false, finding: `${act.length} need action, ${att.length} need a look`, centerLabel: 'applications', helpText: 'Every application is in one state. Act today means a reproduced exploit, a secret in code, or a broken policy. Watch means something to look at this week.', parts: [{ label: 'Act today', count: act.length, tone: 'bad' }, { label: 'Watch', count: att.length, tone: 'warn' }, { label: 'Clear', count: clear.length, tone: 'ok' }, { label: 'Not scanned', count: unk.length, tone: 'neutral' }], source: { label: 'Docket scans' }, asOf: iso(0) });
    const req = policy.steps.filter((x) => x.required);
    const covRows = req.map((st) => { const n = matrix.filter((m) => m[1][st.id] && m[1][st.id][0] === 'ok').length; return `<div class="covrow"><div class="cl">${origin(st.origin, st.tool)}<span class="cn">${esc(st.label)}</span></div><div class="cbar" role="img" aria-label="${n} of ${matrix.length} applications ran ${esc(st.label)} inside 7 days"><span class="${st.origin === 'henoyo' ? 'h' : 't'}" style="width:${(n / matrix.length) * 100}%"></span></div><div class="cc">${n} of ${matrix.length}</div></div>`; }).join('');
    const who = card('Required scanners, this week', covRows + '<p class="note" style="margin-top:12px">Tier 1 applications that ran each required scanner inside the 7-day window. Verdant is a Henoyo-built scanner; grey is a third-party tool Docket runs for you.</p>', { tip: 'One required-scanner list: the same one the policy, the pipeline and each health card use.', sub: 'Tier 1 payments baseline' });
    const cont = K('docket-continuum', { heading: 'Scan continuum', rows: [...apps].sort((a, b) => ['action', 'attention', 'unknown', 'clear'].indexOf(a.level) - ['action', 'attention', 'unknown', 'clear'].indexOf(b.level)).map((a) => ({ id: a.id, label: a.label, sub: a.tier, level: a.level, events: a.events })), from: iso(28), to: iso(0), cadenceDays: 7, helpText: 'Every scan of every application. A red diamond is a scan that proved an exploit. Amber hatching is time beyond the policy cadence with no scan.', source: { label: 'Docket scans' }, asOf: iso(0) });
    const dt = K('henoyo-discovery-trend', { heading: 'Proven and likely findings by week', helpText: 'New findings first seen each week, by severity.', periods: trend.periods, series: trend.series.map((s) => ({ ...s, ...HenoyoKit.paint(s.key) })), source: { label: 'Findings' }, asOf: iso(0) });
    const sa = K('henoyo-severity-age', { heading: 'Open findings by severity and age', oldCritical: 3, oldAge: '14 days', rows: ['critical', 'high', 'medium', 'low'].map((s) => ({ id: s, label: s[0].toUpperCase() + s.slice(1), tone: s })), columns: ['0-30', '31-90', '91-180', '181+'].map((c) => ({ id: c, label: c.replace('-', ' to ') + (c === '181+' ? ' days' : ' days'), tone: '' })), cells: [['critical', '0-30', 3], ['critical', '31-90', 2], ['high', '0-30', 6], ['high', '31-90', 4], ['high', '91-180', 1], ['medium', '0-30', 11], ['medium', '31-90', 9], ['medium', '91-180', 3], ['low', '0-30', 7], ['low', '31-90', 5]].map(([row, col, value]) => ({ row, col, value })), helpText: 'How many open findings sit in each severity and age band. Old criticals are the ones to chase.', source: { label: 'Findings' }, asOf: iso(0) });
    go(`${head('Code Security', 'Posture', sentence, '<button class="btn">Policy</button><button class="btn primary">Run a scan</button>')}
      <div class="stack">
        <div class="cols">${card('Needs you', q, { flush: true, tip: 'Applications that are not clear, grouped by urgency. Each line says why in one sentence.', sub: 'Worst first. Only the first group needs someone today.' })}<div class="stack"><div data-mount="ring"></div>${who}</div></div>
        <div data-mount="cont"></div>
        <div class="cols2"><div data-mount="dt"></div><div data-mount="sa"></div></div>
      </div>`, { ring, cont, dt, sa });
    $('#main').querySelectorAll('.wq li').forEach((li) => li.addEventListener('click', () => (location.hash = '#app/' + li.dataset.app)));
  }

  // ---- APPLICATIONS (list view) --------------------------------------------------
  function appsList() {
    const rows = [...apps].sort((a, b) => ['action', 'attention', 'unknown', 'clear'].indexOf(a.level) - ['action', 'attention', 'unknown', 'clear'].indexOf(b.level)).map((a) => {
      const last = a.events.length ? a.events[a.events.length - 1] : null;
      const proven = a.events.reduce((n, e) => n + (e === last ? e.proven : 0), 0);
      return `<tr data-app="${a.id}"><td>${lamp(a.level)} <b style="margin-left:8px">${LV[a.level][0]}</b></td><td><div class="tt">${esc(a.label)}</div><div class="ms mono">${esc(a.repo)} · ${esc(a.lang)}</div></td><td>${esc(a.tier)}</td><td>${proven ? `<span class="proof y">◆ ${proven} proven</span>` : '<span class="proof n">None proven</span>'}</td><td>${last ? esc(a.age || '1 d') + ' ago' : 'Never'}</td><td>${esc(a.reason)}</td><td>${esc(a.owner)}</td></tr>`;
    }).join('');
    go(`${head('Code Security', 'Applications', 'Every application the policy covers, worst first. Open one for its health report, scan pipeline and findings.', '<button class="btn primary">Add application</button>')}
      ${card('All applications', `<table class="lv"><thead><tr><th>Health</th><th>Application</th><th>Tier</th><th>Proof</th><th>Last scan</th><th>Why</th><th>Owner</th></tr></thead><tbody>${rows}</tbody></table>`, { flush: true })}`);
    $('#main').querySelectorAll('tbody tr').forEach((tr) => tr.addEventListener('click', () => (location.hash = '#app/' + tr.dataset.app)));
  }

  // ---- APPLICATION record ---------------------------------------------------------
  function healthFor(a) {
    if (a.id === 'card-payments') return health;
    const lvl = a.level;
    return {
      level: lvl, verdict: '', reasons: [a.reason + '.'],
      annunciators: [
        { key: 'p', label: 'Proven exploits', state: lvl === 'action' ? 'bad' : lvl === 'unknown' ? 'off' : 'ok', value: lvl === 'action' ? '1' : lvl === 'unknown' ? 'n/a' : '0', hint: lvl === 'unknown' ? 'never scanned' : 'reproduced, still open' },
        { key: 's', label: 'Secrets in code', state: a.id === 'upi-adapter' ? 'warn' : lvl === 'unknown' ? 'off' : 'ok', value: a.id === 'upi-adapter' ? '2 unsure' : lvl === 'unknown' ? 'n/a' : '0', hint: '' },
        { key: 'c', label: 'Critical CVEs', state: a.id === 'kyc-gateway' ? 'warn' : lvl === 'unknown' ? 'off' : 'ok', value: a.id === 'kyc-gateway' ? '1' : lvl === 'unknown' ? 'n/a' : '0', hint: a.id === 'kyc-gateway' ? 'reachable' : '' },
        { key: 'r', label: 'Required scanners', state: a.id === 'admin-ledger' ? 'warn' : lvl === 'unknown' ? 'off' : 'ok', value: a.id === 'admin-ledger' ? '3 of 4' : lvl === 'unknown' ? '0 of 4' : '4 of 4', hint: a.id === 'admin-ledger' ? 'Nuclei skipped' : '' },
        { key: 'f', label: 'Last scan', state: ['kyc-gateway', 'loan-origination'].includes(a.id) ? 'warn' : lvl === 'unknown' ? 'off' : 'ok', value: a.age || 'never', hint: '7-day window' },
      ],
      analytes: lvl === 'unknown' ? [] : health.analytes.map((x) => ({ ...x, value: 0, display: lvl === 'unknown' ? 'No data' : '0', flag: lvl === 'unknown' ? 'unknown' : 'ok', flagWord: lvl === 'unknown' ? 'Not scanned' : 'In range', trend: lvl === 'unknown' ? undefined : [0, 0, 0, 0, 0, 0, 0, 0], previous: lvl === 'unknown' ? '' : '0' })),
    };
  }
  function lanesFor(a) {
    if (a.id === 'card-payments') return lanes;
    if (a.level === 'unknown') return lanes.map((l) => ({ ...l, state: 'not_run', start: undefined, end: undefined, proven: 0, candidates: 0, summary: '', cost: 0 })).filter((l) => l.required);
    return lanes.map((l) => ({ ...l, proven: a.level === 'action' && l.id === 'swarm' ? 1 : 0, state: a.id === 'admin-ledger' && l.id === 'nuclei' ? 'skipped' : l.id === 'apisec' ? 'done' : l.state, summary: l.id === 'swarm' && a.level !== 'action' ? '3 specialists, nothing reproduced' : l.summary }));
  }
  function appPage(id) {
    const a = appById(id) || apps[0];
    const hc = K('docket-health-card', { heading: 'Health report', subject: a.label, ...healthFor(a), helpText: 'The verdict, then what is lit, then every measure against its reference range. Reference ranges come from the security policy that covers this application.', source: { label: 'Last scan' }, asOf: iso(a.events.length ? 1 : 0) });
    const pipe = K('docket-pipeline', { heading: 'Latest scan pipeline', lanes: a.level === 'unknown' ? [] : lanesFor(a), groups, policy: 'Tier 1 payments baseline', helpText: 'Each bar is a scanner or agent, from when it started to when it finished. Verdant bars are built by Henoyo; grey bars are third-party tools. A dashed amber bar is a scanner the policy requires that did not run.', source: { label: 'Scan #2184', href: '#scan/2184' }, asOf: iso(1) });
    const sp = K('henoyo-status-path', { variant: 'bar', editable: false, values: [{ value: 'onboarded', label: 'Onboarded' }, { value: 'scanned', label: 'Scanned' }, { value: 'proven', label: 'Exploit open' }, { value: 'fix_proposed', label: 'Fix in review' }, { value: 'fix_merged', label: 'Fix merged' }, { value: 'verified', label: 'Re-verified' }], current: a.level === 'unknown' ? 'onboarded' : a.level === 'action' ? 'fix_proposed' : a.level === 'attention' ? 'scanned' : 'verified', since: iso(3), owner: a.owner, ownerLabel: 'Owner' });
    const banner = K('henoyo-record-banner', { rows: a.id === 'card-payments' ? [
      { id: 'b1', level: 'danger', word: 'Exploit proven', message: '2 reproduced exploits are open. The SQL injection in POST /payments/refund has been open 3 days.', reason: 'Policy: a reproduced exploit blocks the release', actionLabel: 'Review proof', href: '#findings' },
      { id: 'b2', level: 'warning', word: 'Out of policy', message: 'The API Security engine has not run for 9 days.', reason: 'Tier 1 baseline requires it every 7 days', actionLabel: 'Run it now', href: '#policy' },
      { id: 'b3', level: 'info', message: 'Fix pull request #482 is waiting for review.', reason: 'Docket proposed it after the exploit was proven' }] : a.level === 'unknown' ? [{ id: 'b0', level: 'warning', message: 'This application has never been scanned.', reason: 'No repository is connected', actionLabel: 'Connect repository' }] : [{ id: 'bx', level: a.level === 'clear' ? 'success' : 'warning', message: a.reason + '.' }] });
    const fl = findings.filter((f) => f.app === a.id);
    const frows = fl.length ? fl.map((f) => `<tr data-f="${f.id}"><td>${sevChip(f.sev)}</td><td><div class="tt">${esc(f.title)}</div><div class="ms">${esc(f.sub)}</div></td><td>${proofCell(f)}</td><td>${origin(f.by.origin, f.by.name)}</td><td>${esc(f.age)}</td></tr>`).join('') : '<tr><td colspan="5" class="empty">Nothing open. The last scan found no open finding here.</td></tr>';
    const scans = a.events.slice().reverse().map((e) => `<tr data-scan="1"><td><b>#${2184 - a.events.indexOf(e) * 3}</b> <span class="ms">${e.kind === 'pr' ? 'Pull request' : 'Full scan'}</span></td><td>${new Date(e.at).toLocaleDateString('en-GB', { day: 'numeric', month: 'short' })}</td><td>${e.coverage === 'full' ? '<span class="chip ok">4 of 4 required</span>' : '<span class="chip warn">3 of 4 required</span>'}</td><td>${e.proven ? `<span class="proof y">◆ ${e.proven} proven</span>` : '<span class="proof n">None</span>'}</td><td>${e.candidates} candidates</td></tr>`).join('') || '<tr><td colspan="5" class="empty">No scans yet.</td></tr>';
    const trs = ['overview', 'related', 'details'];
    const body = TAB === 'overview' ? `<div class="stack"><div data-mount="hc"></div><div data-mount="pipe"></div>
        <div class="cols">${card('Open findings', `<table class="lv"><thead><tr><th>Severity</th><th>Finding</th><th>Proof</th><th>Found by</th><th>Age</th></tr></thead><tbody>${frows}</tbody></table>`, { flush: true, sub: 'Proven first', tip: 'Findings related to this application. Reproduced exploits sort above candidates.' })}
        ${card('Scan history', `<table class="lv"><thead><tr><th>Scan</th><th>When</th><th>Coverage</th><th>Result</th><th></th></tr></thead><tbody>${scans}</tbody></table>`, { flush: true, sub: 'Newest first' })}</div></div>`
      : TAB === 'related' ? `<div class="stack">${card('Findings', `<table class="lv"><tbody>${frows}</tbody></table>`, { flush: true })}${card('Scans', `<table class="lv"><tbody>${scans}</tbody></table>`, { flush: true })}${card('Fix pull requests', `<table class="lv"><thead><tr><th>PR</th><th>Fixes</th><th>Status</th><th>Opened</th></tr></thead><tbody>${a.id === 'card-payments' ? '<tr><td class="tt">#482 Parameterise refund lookup</td><td>SQL injection</td><td><span class="chip warn">Review requested</span></td><td>3 d ago</td></tr>' : '<tr><td colspan="4" class="empty">No fix pull request.</td></tr>'}</tbody></table>`, { flush: true })}${card('Compliance results', `<p style="margin:0">RBI Cyber Security Framework: 6 met, 5 not met, 3 could not be told from code. <a href="#compliance">Open the baseline</a></p>`)}</div>`
      : `${card('Details', `<dl class="kv"><dt>Repository</dt><dd class="mono">${esc(a.repo)}</dd><dt>Language</dt><dd>${esc(a.lang)}</dd><dt>Tier</dt><dd>${esc(a.tier)}</dd><dt>Owner</dt><dd>${esc(a.owner)}</dd><dt>Policy</dt><dd>Tier 1 payments baseline</dd><dt>Henoyo record</dt><dd><a href="#">sec__application</a> · 3 linked assets</dd></dl>`)}`;
    go(`<div class="rh">${objIcon('rgb(var(--h-verdant-100))', 'rgb(var(--h-verdant-700))', IC.code)}<div><div class="eyebrow">Application</div><h1>${esc(a.label)}</h1><div class="meta">${lamp(a.level)}<b>${LV[a.level][0]}</b><span>·</span><span class="mono">${esc(a.repo)}</span><span>·</span><span>${esc(a.tier)}</span><span>·</span><span>Owner ${esc(a.owner)}</span></div></div><div class="grow" style="flex:1"></div><button class="btn">Edit</button><button class="btn primary">Run scan</button></div>
      <div class="stack"><div data-mount="banner"></div><div data-mount="sp"></div></div>
      <div class="rtabs" role="tablist">${trs.map((t) => `<button role="tab" aria-selected="${TAB === t}" data-tab="${t}">${t[0].toUpperCase() + t.slice(1)}</button>`).join('')}</div>${body}`, { hc, pipe, sp, banner });
    $('#main').querySelectorAll('[data-tab]').forEach((b) => b.addEventListener('click', () => { TAB = b.dataset.tab; appPage(id); }));
    $('#main').querySelectorAll('tr[data-f]').forEach((tr) => tr.addEventListener('click', () => findingDrawer(tr.dataset.f)));
    $('#main').querySelectorAll('tr[data-scan]').forEach((tr) => tr.addEventListener('click', () => (location.hash = '#scan/2184')));
  }
  const proofCell = (f) => ({ reproduced: '<span class="proof y">◆ Reproduced</span>', deterministic: '<span class="proof y">● Deterministic</span>', candidate: `<span class="proof m">◇ Candidate${f.reach ? ' · ' + f.reach : ''}</span>`, not_reachable: '<span class="proof n">○ Not reachable</span>' }[f.proof]);

  // ---- SCAN run -------------------------------------------------------------------
  function scanPage() {
    const pipe = K('docket-pipeline', { heading: 'Scan #2184 pipeline', lanes, groups, policy: 'Tier 1 payments baseline', helpText: 'Click a bar for what that stage did. The time axis is minutes and seconds from the start of the scan.', source: { label: 'Card Payments API', href: '#app/card-payments' }, asOf: iso(1) });
    const cost = [['Total cost', '$1.84'], ['Agents spawned', '6'], ['Tokens', '41.2k in, 9.8k out'], ['Commit', 'a91f3c2 on main']];
    go(`${head('Scan', '#2184 · Card Payments API', 'A full scan of main at a91f3c2, started yesterday at 09:12. Three third-party scanners ran, then Docket’s agents tried to exploit what they found.', '<button class="btn">Download SARIF</button><button class="btn primary">Run again</button>')}
      <div class="stack"><div class="res">${cost.map(([k, v]) => `<div class="count"><b style="font-size:20px">${v}</b><span>${k}</span></div>`).join('')}</div><div data-mount="pipe"></div>
      ${card('Findings from this scan', `<table class="lv"><tbody>${findings.filter((f) => f.app === 'card-payments').map((f) => `<tr data-f="${f.id}"><td>${sevChip(f.sev)}</td><td><div class="tt">${esc(f.title)}</div><div class="ms">${esc(f.sub)}</div></td><td>${proofCell(f)}</td><td>${origin(f.by.origin, f.by.name)}</td></tr>`).join('')}</tbody></table>`, { flush: true, sub: 'Click one to see the proof' })}</div>`, { pipe });
    $('#main').querySelectorAll('tr[data-f]').forEach((tr) => tr.addEventListener('click', () => findingDrawer(tr.dataset.f)));
  }
  function scansList() {
    const rows = apps.flatMap((a) => a.events.map((e) => ({ a, e }))).sort((x, y) => Date.parse(y.e.at) - Date.parse(x.e.at)).slice(0, 14).map(({ a, e }, i) => `<tr data-scan="1"><td><b>#${2184 - i * 2}</b></td><td><div class="tt">${esc(a.label)}</div></td><td>${e.kind === 'pr' ? 'Pull request' : 'Full scan'}</td><td>${new Date(e.at).toLocaleDateString('en-GB', { day: 'numeric', month: 'short' })}</td><td>${e.coverage === 'full' ? '<span class="chip ok">All required ran</span>' : '<span class="chip warn">Partial</span>'}</td><td>${e.proven ? `<span class="proof y">◆ ${e.proven} proven</span>` : '<span class="proof n">None proven</span>'}</td></tr>`).join('');
    go(`${head('Code Security', 'Scans', 'Every scan across the portfolio, newest first.')}${card('Recent scans', `<table class="lv"><thead><tr><th>Scan</th><th>Application</th><th>Kind</th><th>When</th><th>Coverage</th><th>Result</th></tr></thead><tbody>${rows}</tbody></table>`, { flush: true })}`);
    $('#main').querySelectorAll('tr[data-scan]').forEach((tr) => tr.addEventListener('click', () => (location.hash = '#scan/2184')));
  }

  // ---- FINDINGS --------------------------------------------------------------------
  const VIEWS = { proven: ['Proven exploitable', (f) => f.proof === 'reproduced'], reach: ['Reachable, unproven', (f) => f.proof === 'candidate' && f.reach === 'Reachable'], secrets: ['Secrets', (f) => /secret|key|credential/i.test(f.title)], all: ['All open', (f) => f.proof !== 'not_reachable'] };
  function findingsPage() {
    const sel = findings.filter(VIEWS[VIEW][1]);
    const rows = sel.map((f) => `<tr data-f="${f.id}"><td>${sevChip(f.sev)}</td><td><div class="tt">${esc(f.title)}</div><div class="ms">${esc(f.sub)}</div></td><td>${esc(appById(f.app).label)}</td><td>${proofCell(f)}</td><td>${origin(f.by.origin, f.by.name)}</td><td>${esc(f.age)}</td><td>${esc(f.status)}</td></tr>`).join('') || '<tr><td colspan="7" class="empty">Nothing here.</td></tr>';
    go(`${head('Code Security', 'Findings', 'A finding that blocks a release has a reproduced proof. Everything else is a lead for a person to judge.', '<button class="btn">Export SARIF</button>')}
      ${card('', `<div class="views">${Object.entries(VIEWS).map(([k, [l, fn]]) => `<button class="view" aria-pressed="${VIEW === k}" data-v="${k}">${l}<b>${findings.filter(fn).length}</b></button>`).join('')}</div>
      <table class="lv"><thead><tr><th>Severity</th><th>Finding</th><th>Application</th><th>Proof</th><th>Found by</th><th>Age</th><th>Status</th></tr></thead><tbody>${rows}</tbody></table>`, { flush: true })}`);
    $('#main').querySelectorAll('.hc>header').forEach((h) => h.remove());
    $('#main').querySelectorAll('[data-v]').forEach((b) => b.addEventListener('click', () => { VIEW = b.dataset.v; findingsPage(); }));
    $('#main').querySelectorAll('tr[data-f]').forEach((tr) => tr.addEventListener('click', () => findingDrawer(tr.dataset.f)));
  }
  function openDrawer(html) { $('#drawer').innerHTML = html; $('#drawer').classList.add('open'); $('#scrim').classList.add('open'); $('#drawer .x').addEventListener('click', closeDrawer); }
  function closeDrawer() { $('#drawer').classList.remove('open'); $('#scrim').classList.remove('open'); }
  $('#scrim').addEventListener('click', closeDrawer);
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeDrawer(); });
  function findingDrawer(id) {
    const f = findings.find((x) => x.id === id);
    const p = id === 'f1' ? proof : { request: 'GET /cards/1002 HTTP/1.1\nHost: staging.card-payments.ibank.example\nAuthorization: Bearer <redacted: user B>', response: 'HTTP/1.1 200 OK\n\n{"id":1002,"owner":"user-A","pan_last4":"9023","limit":150000}', notes: 'Signed in as user B, requested user A’s card. The handler returned it.', triage: 'EXPLOITABLE: cards/routes.py:44 loads the card by id and never compares owner to the caller.', fix: '' };
    const body = f.proof === 'reproduced' ? `<h4>Proof <span class="chip crit" style="margin-left:6px">Reproduced</span></h4><p class="note">Docket only reports an exploit after it reproduces it. This request and response were captured from a live run against staging and stored as Henoyo evidence <span class="mono">ev-7f3a…c91</span> (SHA-256 recorded).</p>
        <div class="eyebrow" style="margin:12px 0 6px">Request</div><pre class="code">${esc(p.request)}</pre><div class="eyebrow" style="margin:12px 0 6px">Response</div><pre class="code">${esc(p.response)}</pre><p>${esc(p.notes)}</p>
        <h4>Why triage agrees</h4><p>${esc(p.triage)}</p>${p.fix ? `<h4>Proposed fix <span class="chip warn" style="margin-left:6px">PR #482 awaiting review</span></h4><pre class="code">${esc(p.fix)}</pre>` : ''}`
      : `<h4>Why this is not a proven finding</h4><p class="note">${f.proof === 'deterministic' ? 'A secret in source is a deterministic rule: it blocks without an exploit.' : 'A scanner matched a pattern. No exploit has been reproduced, so this is a lead, not a verdict.'}</p>${f.reach ? `<dl class="kv"><dt>Reachability</dt><dd>${esc(f.reach)}</dd></dl>` : ''}`;
    openDrawer(`<header><button class="x" aria-label="Close">×</button><div class="eyebrow">Finding · ${esc(appById(f.app).label)}</div><h3 style="font-size:1.3rem;margin-top:4px">${esc(f.title)}</h3><div style="display:flex;gap:8px;margin-top:10px;flex-wrap:wrap;align-items:center">${sevChip(f.sev)}${proofCell(f)}${origin(f.by.origin, f.by.name)}<span class="chip neutral">${esc(f.status)}</span></div></header><div class="body">${body}<h4>Next</h4><div style="display:flex;gap:8px;flex-wrap:wrap"><button class="btn primary">Open fix pull request</button><button class="btn">Raise exception in IRM</button><button class="btn">Mark accepted risk</button></div></div>`);
  }
  function laneDrawer(l) {
    openDrawer(`<header><button class="x" aria-label="Close">×</button><div class="eyebrow">Pipeline stage</div><h3 style="font-size:1.3rem;margin-top:4px">${esc(l.label)}</h3><div style="margin-top:10px;display:flex;gap:8px">${origin(l.origin, l.tool)}${l.required ? '<span class="chip sec">Required by policy</span>' : ''}</div></header><div class="body"><dl class="kv" style="margin-top:14px"><dt>State</dt><dd>${esc(l.state.replace('_', ' '))}</dd><dt>Result</dt><dd>${esc(l.summary || 'Nothing to report')}</dd>${l.requiredBy ? `<dt>Required by</dt><dd>${l.requiredBy.map(esc).join('<br>')}</dd>` : ''}${l.cost ? `<dt>Cost</dt><dd>$${l.cost.toFixed(2)}</dd>` : ''}</dl>${l.state === 'not_run' ? '<p class="note">The API Security engine was not scheduled because its connection token expired on the 10th. Renew it in Setup, then run it.</p>' : ''}</div>`);
  }

  // ---- POLICY ---------------------------------------------------------------------
  function policyPage() {
    const chip = (w) => w.k === 'sec' ? `<span class="chip sec">Security</span> <span style="font-size:12.5px">${esc(w.t)}</span>` : `<span class="chip reg">${esc(w.a)}</span> <span style="font-size:12.5px">${esc(w.t)}</span> <a class="mono" style="font-size:11px" href="#compliance" title="Resolves to a Henoyo obligation record">↗ ${esc(w.ob)}</a>`;
    const req = policy.steps.filter((x) => x.required), opt = policy.steps.filter((x) => !x.required);
    const hen = req.filter((x) => x.origin === 'henoyo').length;
    const grid = 'grid-template-columns:36px minmax(0,1.1fr) minmax(0,1.6fr) 150px 170px';
    const steps = `<div class="seq"><div class="step head" style="${grid}"><span>#</span><span>Scanner</span><span>Required because</span><span>Cadence</span><span>If it fails</span></div>${policy.steps.map((x) => `<div class="step" style="${grid}${x.required ? '' : ';background:rgb(var(--h-canvas) / .5)'}"><span class="n"${x.required ? '' : ' style="background:rgb(var(--h-surface-3));color:rgb(var(--h-text-2))"'}>${x.n}</span><div><div class="nm">${esc(x.label)}</div><div style="margin-top:4px;display:flex;gap:6px;align-items:center;flex-wrap:wrap">${origin(x.origin, x.tool)} <span class="chip ${x.required ? 'sec' : 'neutral'}">${x.required ? 'Required' : 'Optional'}</span></div></div><div style="display:grid;gap:7px">${x.why.map((w) => `<div>${chip(w)}</div>`).join('')}</div><div class="cad">${esc(x.cadence)}</div><div class="cad">${esc(x.onFail)}</div></div>`).join('')}</div>`;
    const reg = `<div class="req">${policy.regulatory.map((r) => `<div class="it"><span class="chip reg">${esc(r.a)}</span><div><div class="t">${esc(r.t)}</div><div class="c">${r.clause ? 'Clause: ' + esc(r.clause) : 'Clause reference not yet mapped. The pack cites the section, not a numbered clause.'} · <a href="#compliance">${esc(r.ob)}</a></div></div></div>`).join('')}</div>`;
    const sec = `<div class="req">${policy.security.map((r) => `<div class="it"><span class="chip sec">Security</span><div><div class="t">${esc(r.t)}</div><div class="c">${esc(r.c)}</div></div></div>`).join('')}</div>`;
    const gate = `<div class="gate">${policy.gate.map((g) => `<div><span class="chip ${g.effect === 'blocks' ? 'bad' : g.effect === 'flags' ? 'warn' : 'neutral'}">${g.effect[0].toUpperCase() + g.effect.slice(1)}</span> ${esc(g.text)}</div>`).join('')}</div>`;
    const m = K('docket-policy-matrix', { heading: 'Policy against reality', windowDays: 7, scanners: req.map((x) => ({ id: x.id, label: x.label, tool: x.tool, origin: x.origin, icon: { trivy: 'package', semgrep: 'file-code', apisec: 'shield-alert', triage: 'brain', swarm: 'crosshair' }[x.id] })), rows: matrix.map(([id, c, consequence]) => ({ id, label: appById(id).label, tier: appById(id).tier, consequence, cells: Object.fromEntries(Object.entries(c).map(([k, [state, ago]]) => [k, { state, ago }])) })), helpText: 'Each cell asks: did this required scanner finish inside its window for this application? The last column says what that adds up to: a stale scanner flags, a reproduced exploit blocks.', source: { label: 'Docket scans' }, asOf: iso(0) });
    go(`${head('Code Security', 'Policy', 'What every Tier 1 application must run, in what order, and why. A requirement without a source is a preference, so each step names the security rule or regulation behind it.', '<button class="btn">History</button><button class="btn primary">Edit policy</button>')}
      <div class="res" style="margin-bottom:16px"><div class="count"><b>${req.length}</b><span>Required scanners, of ${policy.steps.length} steps</span></div><div class="count"><b>${req.length - hen} + ${hen}</b><span>Third-party + Henoyo-built, required</span></div><div class="count"><b>7 days</b><span>Longest gap between scans</span></div><div class="count"><b>6</b><span>Applications under this policy</span></div></div>
      <div class="stack">${card('Tier 1 payments baseline: the sequence that runs', steps, { flush: true, tip: 'Scanners run in this order. Required steps count toward "did it run?"; optional steps run when they can. Each names the security rule or regulatory source behind it.', sub: `Applies to applications tagged Tier 1 · version 3 · approved by the CISO 12 Oct · ${opt.length} optional steps` })}
      <div class="cols2">${card('Regulatory requirements', reg, { sub: 'Each resolves to an obligation in Henoyo', tip: 'These are the regulations the policy answers to. The clause reference is filled in where the source gives one; otherwise the section is cited.' })}${card('Security requirements', sec, { sub: 'What the engineering rule is' })}</div>
      ${card('What the policy does about it', gate)}<div data-mount="m"></div></div>`, { m });
  }

  // ---- COMPLIANCE -----------------------------------------------------------------
  function compliancePage() {
    const packs = [['rbi-csf', 'RBI Cyber Security Framework', 40], ['sebi-cscrf', 'SEBI CSCRF', 43], ['owasp-api-2023', 'OWASP API Top 10 2023', 10], ['python-baseline', 'Python baseline', 18]];
    const stat = { pass: ['chip ok', 'Met'], fail: ['chip bad', 'Not met'], unknown: ['chip warn', 'Unknown'], not_observable: ['chip neutral', 'Not answerable from code'] };
    const rows = rbi.filter((c) => CFILTER === 'all' || c.status === CFILTER).map((c) => `<tr><td style="min-width:230px"><div class="tt">${esc(c.title)}</div><div class="ms mono">${esc(PACK)}:${esc(c.id)}</div></td><td><div class="cite"><div class="a"><span class="chip reg">RBI</span><span>${esc(c.instrument ? 'IT Governance MD' : 'Cyber Security Framework')}</span></div><div class="t">${esc(c.cite)}</div><div class="ob">Clause: not mapped · <a href="#" title="Resolves to a Henoyo control requirement">↗ obligation</a></div></div></td><td>${c.obs === 'source' ? 'In code' : c.obs === 'process' ? 'Process' : 'Runtime'}</td><td><span class="${stat[c.status][0]}">${stat[c.status][1]}</span>${c.escalated ? '<div class="ms" style="margin-top:4px;color:rgb(var(--h-text));font-weight:600">◆ Also reproduced</div>' : ''}</td><td style="max-width:360px">${esc(c.why)}${c.evidence ? `<div class="ms mono" style="margin-top:4px">${esc(c.evidence)}</div><pre class="code" style="margin-top:6px;padding:6px 8px;font-size:11.5px">${esc(c.quote)}</pre>` : ''}${c.finding ? `<div class="ms" style="margin-top:4px">Linked: ${esc(c.finding)}</div>` : ''}</td></tr>`).join('');
    go(`${head('Code Security', 'Compliance baseline', 'What the code says about each written requirement. A control result is a reading, not a reproduction, and it never blocks a pull request. Process controls are shown as not answerable from code, never guessed.', '<button class="btn">Upload a policy</button>')}
      <div class="stack"><div class="views" style="padding:0;border:0">${packs.map(([k, l, n]) => `<button class="view" aria-pressed="${PACK === k}" data-pack="${k}">${l}<b>${n}</b></button>`).join('')}</div>
      <div class="res">${[['all', '', 'All shown', rbi.length, ''], ['pass', 'ok', 'Met', 6, ''], ['fail', 'bad', 'Not met', 5, ''], ['unknown', 'un', 'Unknown', 3, ''], ['not_observable', 'na', 'Not answerable from code', 26, '']].map(([k, c, l, n]) => `<button class="count ${c}" data-cf="${k}" aria-pressed="${CFILTER === k}" style="text-align:left;cursor:pointer;${CFILTER === k ? 'outline:2px solid rgb(var(--h-text));' : ''}"><b>${n}</b><span>${l}</span></button>`).join('')}</div>
      <p class="note" style="margin:0">Card Payments API, scanned yesterday. 14 of 40 controls are readable from source. There is no score: a percentage rewards giving up on the hard controls.</p>
      ${card('Controls', `<table class="lv"><thead><tr><th>Control</th><th>Regulatory citation</th><th>Where it lives</th><th>Result</th><th>What was read</th></tr></thead><tbody>${rows}</tbody></table>`, { flush: true, tip: 'Citation shows the authority, the instrument and the section the control is drawn from, with a link to the obligation record in Henoyo so the clause can be filled in once, for every application.' })}</div>`);
    $('#main').querySelectorAll('[data-cf]').forEach((b) => b.addEventListener('click', () => { CFILTER = CFILTER === b.dataset.cf ? 'all' : b.dataset.cf; compliancePage(); }));
    $('#main').querySelectorAll('[data-pack]').forEach((b) => b.addEventListener('click', () => { PACK = b.dataset.pack; compliancePage(); }));
  }

  // ---- router ---------------------------------------------------------------------
  function render() {
    closeDrawer();
    const { r, id } = route();
    drawTabs(r);
    if (r === 'app') appPage(id); else if (r === 'apps') appsList(); else if (r === 'scan') scanPage(); else if (r === 'scans') scansList();
    else if (r === 'findings') findingsPage(); else if (r === 'policy') policyPage(); else if (r === 'compliance') compliancePage(); else home();
  }
  window.addEventListener('hashchange', () => { TAB = 'overview'; render(); });
  render();
})();
