/* Posture mockup (spec 5.1): the Home of Code Security as a 15-second read.
   Headline, six numbers, the map with "Look here first" and "Clearest right now" beside it,
   required checks by category, assessments by week, then the scan continuum.
   Real kit elements throughout: what you see is the component output, not a drawing. */
(function () {
  const { apps, iso } = window.S;
  const { posture: P, strip } = window.P;
  const $ = (s, r = document) => r.querySelector(s);
  const esc = (v) => String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const K = (tag, props) => { const e = document.createElement(tag); Object.assign(e, props); return e; };
  const help = (t) => `<button type="button" class="help" aria-label="About this section" data-tip="${esc(t)}">i</button>`;
  const card = (title, body, { sub = '', tip = '', flush = false } = {}) =>
    `<section class="hc"><header><div class="grow"><h3>${esc(title)}${tip ? help(tip) : ''}</h3>${sub ? `<p>${sub}</p>` : ''}</div></header><div class="${flush ? 'flush' : 'pad'}">${body}</div></section>`;

  // ---- shell: same tabs as the app, Home is current ---------------------------------------
  const NAV = [['home', 'Home'], ['apps', 'Applications'], ['scans', 'Scans'], ['findings', 'Findings'], ['compliance', 'Compliance'], ['policy', 'Policy']];
  $('#tabs').innerHTML = '<span class="app">Code Security</span>' + NAV.map(([k, l]) => `<a href="${k === 'home' ? '#' : 'index.html#' + k}" ${k === 'home' ? 'aria-current="page"' : ''}>${l}</a>`).join('');
  document.addEventListener('docket:open-app', (e) => { location.href = 'index.html#app/' + e.detail.id; });

  // ---- words -----------------------------------------------------------------------------------
  const LV = { action: ['Act today', 'bad'], attention: ['Watch', 'warn'], clear: ['Clear', 'ok'], unknown: ['Not assessed', 'off'] };
  const A = { down: 'Required checks slipping', up: 'Required checks catching up', steady: 'Required checks steady' };
  const S = { down: 'more problems proven', up: 'fewer problems proven', steady: 'proven problems steady' };
  const moveWords = (m) => (m.assurance === 'steady' && m.standing === 'steady' ? 'Steady for 2 weeks' : `${A[m.assurance]}, ${S[m.standing]}`);
  const byCell = (k) => P.points.filter((p) => p.cell === k);
  const n = (k) => byCell(k).length;
  const assessed = P.points.length;
  const total = assessed + P.unassessed.length;

  // ---- headline and the six numbers ---------------------------------------------------------
  const worst1 = P.leaders.worst[0];
  const sentence = `<span class="headline"><b>${n('bl')} of ${total} applications have proven problems and overdue checks.</b><span class="h2">${esc(worst1.label)} first. ${n('tl')} are quiet only because checks are overdue, ${n('tr')} have current checks and nothing proven, ${P.unassessed.length} ${P.unassessed.length === 1 ? 'is' : 'are'} not assessed.</span></span>`;

  const meetN = P.categories.reduce((a, c) => a + c.meet_policy, 0);
  const meetOf = P.categories.reduce((a, c) => a + c.apps, 0);
  const num = (value, label, tone = '', tip = '') => `<div class="count ${tone}"><b>${value}</b><span>${label}${tip ? help(tip) : ''}</span></div>`;
  const numbers = `<div class="res six">
    ${num(total, 'Applications', '', 'Every application the policies cover, assessed or not.')}
    ${num(P.assessments.total, `Assessments in ${P.assessments.days} days`, '', 'A scan or a pull-request check. Candidates and clean results count; only proven problems move a dot.')}
    ${num(strip.provenOpen, 'Proven exploits open', 'bad', 'Reproduced against a running target, still open. Carried forward until an exploit run shows them closed.')}
    ${num(`${meetN} of ${meetOf}`, 'Required checks current', 'ok', 'Every required check finished inside its window. This is about running the checks, not a verdict on any regulation.')}
    ${num(P.unassessed.length, 'Not assessed', 'un', 'No scan has run, so there is no position. They sit in the tray under the map.')}
    ${num(strip.oldestCritical, 'Oldest open critical', 'na', strip.oldestCriticalApp + ' has had a critical item open this long.')}
  </div>`;

  // ---- right of the map: where to look, and what is clear -------------------------------
  const lamp = (lv) => `<span class="lamp ${LV[lv][1]}"></span>`;
  const leaderRow = (l) => `<li data-app="${l.id}" tabindex="0" role="link" aria-label="${esc(l.label)}, ${LV[l.level][0]}. ${esc(l.reason)}. ${esc(moveWords(l.moved))}">
      <div>${lamp(l.level)}</div>
      <div class="lb"><div class="t">${esc(l.label)} <span class="chip neutral">${esc(l.tier)}</span> <span class="lw ${LV[l.level][1]}">${LV[l.level][0]}</span></div>
      <div class="r">${esc(l.reason)}</div><div class="mv">${esc(moveWords(l.moved))}</div></div></li>`;
  const looks = card('Look here first', `<ol class="wq lead">${P.leaders.worst.map(leaderRow).join('')}</ol>`, { flush: true, tip: 'The three applications to open first: reproduced exploits before anything else, then overdue checks, then the fewest problems open.', sub: 'Proven problems first, then overdue checks.' });
  const clear = card('Clearest right now', P.leaders.best.length ? `<ol class="wq lead">${P.leaders.best.map(leaderRow).join('')}</ol><p class="note flat">Only applications whose required checks are current and have nothing proven open. That is not a promise of safety.</p>` : '<div class="empty">No application has current checks and nothing proven open.</div>', { flush: true, tip: 'Never padded: fewer than three means fewer than three qualify. Not "best" and not "safest".', sub: 'Checks current, nothing proven.' });

  // ---- the map ---------------------------------------------------------------------------------------
  const quad = K('docket-quadrant', {
    heading: 'Posture map', points: P.points, unassessed: P.unassessed, quadrants: P.quadrants, snapshots: P.snapshots, bySnapshot: P.by_snapshot,
    asOfNote: 'As of 19 Oct 2026.', source: { label: 'Docket scans' }, asOf: iso(0),
  });

  // ---- required checks by category -----------------------------------------------------------------------
  const cats = P.categories.map((c) => {
    const bits = [c.levels.action ? `${c.levels.action} need action` : '', c.levels.attention ? `${c.levels.attention} to watch` : ''].filter(Boolean).join(', ');
    return `<div class="covrow cat"><div class="cl"><span class="cn">${esc(c.key)}</span><span class="cs">${esc(bits || 'None need attention')}</span></div>
      <div class="cbar" role="img" aria-label="${c.meet_policy} of ${c.apps} applications have every required check current"><span class="h" style="width:${(c.meet_policy / c.apps) * 100}%"></span></div>
      <div class="cc">${c.meet_policy} of ${c.apps}</div></div>`;
  }).join('');
  const catCard = card('Required checks current, by category', cats + '<p class="note" style="margin-top:12px">Applications whose every required check finished inside its window. This counts checks that ran; it is not a verdict on any regulation.</p>', { tip: 'Grouped by category and exposure. A bar is the share of applications whose required checks are all current under their own policy. Not applicable steps are left out of both counts.', sub: 'Under each application\'s own policy' });

  // ---- assessments by week ----------------------------------------------------------------------------
  const W = P.assessments.weekly;
  const paint = (k) => window.HenoyoKit.paint(k);
  const series = [['proven', 'Proven', 'critical'], ['candidates', 'Candidates', 'medium'], ['clean', 'Clean', 'low'], ['incomplete', 'Incomplete', 'info']]
    .map(([key, label, sev]) => ({ key, label, ...paint(sev), values: W.map((w) => w[key]) }));
  const weekly = K('henoyo-discovery-trend', {
    heading: 'Assessments, by week', periods: W.map((w) => ({ key: w.label, label: w.label })), series,
    helpText: 'Each scan or pull-request check, by the worst thing it found: proven (a reproduced exploit or a deterministic secret), incomplete (coverage partial or failed), candidates (scanner hits nobody has proven), or clean. Candidates never move a dot on the map.',
    source: { label: 'Docket scans' }, asOf: iso(0),
  });

  // ---- continuum (v1) ------------------------------------------------------------------------------------
  const order = ['action', 'attention', 'unknown', 'clear'];
  const cont = K('docket-continuum', {
    heading: 'Scan continuum', rows: [...apps].sort((a, b) => order.indexOf(a.level) - order.indexOf(b.level)).map((a) => ({ id: a.id, label: a.label, sub: a.tier, level: a.level, events: a.events })),
    from: iso(28), to: iso(0), cadenceDays: 7,
    helpText: 'Every scan of every application. A red diamond is a scan that proved an exploit. Amber hatching is time beyond the policy cadence with no scan.', source: { label: 'Docket scans' }, asOf: iso(0),
  });

  // ---- page -------------------------------------------------------------------------------------------------
  const main = $('#main');
  main.innerHTML = `<div class="pagehead"><div class="grow"><div class="eyebrow">Code Security</div><h1>Posture</h1><p class="sub">${sentence}</p></div>
      <button class="btn">Policies</button><button class="btn primary">Run a scan</button></div>
    <div class="stack">
      ${numbers}
      <div class="mapcols"><div data-mount="quad"></div><div class="stack">${looks}${clear}</div></div>
      <div class="cols2">${catCard}<div data-mount="weekly"></div></div>
      <div data-mount="cont"></div>
    </div>`;
  for (const [id, el] of Object.entries({ quad, weekly, cont })) main.querySelector(`[data-mount="${id}"]`).replaceWith(el);
  main.querySelectorAll('.wq.lead li').forEach((li) => {
    const go = () => (location.href = 'index.html#app/' + li.dataset.app);
    li.addEventListener('click', go);
    li.addEventListener('keydown', (e) => { if (e.key === 'Enter') go(); });
  });

  // Screenshot hooks: ?demo=movement,list,snap2,hover:card-payments,sort:days,cluster
  const demo = (new URLSearchParams(location.search).get('demo') || '').split(',').filter(Boolean);
  if (demo.length) {
    const r = quad.shadowRoot;
    const click = (sel) => r.querySelector(sel)?.click();
    const steps = demo.map((d) => () => {
      if (d === 'movement') click('[data-act="movement"]');
      else if (d === 'list') click('[data-view="list"]');
      else if (d.startsWith('snap')) click(`.stop[data-snap="${d.slice(4)}"]`);
      else if (d.startsWith('filter:')) { const [, k, v] = d.split(':'); const s = r.querySelector(`select[data-filter="${k}"]`); s.value = v; s.dispatchEvent(new Event('change', { bubbles: true })); }
      else if (d.startsWith('sort:')) click(`[data-sort="${d.slice(5)}"]`);
      else if (d.startsWith('hover:')) r.querySelector(`.dot[data-key="${d.slice(6)}"]`)?.dispatchEvent(new PointerEvent('pointerover', { bubbles: true, composed: true }));
      else if (d === 'cluster') click('.dot[data-kind="cluster"]');
    });
    steps.forEach((f, i) => setTimeout(f, 300 + i * 250));
  }
})();
