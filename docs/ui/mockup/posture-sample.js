/* SAMPLE DATA for the posture mockup. Nothing here is a real scan.
   The shape is `posture` in docs/ui/policy-and-posture.md section 4. In the product the server
   computes every cell, note, movement and leader; here this file plays the server, using the
   same rules (right half = every required check current, upper half = nothing proven open,
   candidates never move a dot). The 12 applications are the ones in sample.js. */
(function () {
  const snapshots = ['2026-09-21', '2026-09-28', '2026-10-05', '2026-10-12', '2026-10-19'];

  // The server's rule, in one place: the half a dot sits in is decided by rule; the number only places it inside.
  const cellOf = (a, s) => (s >= 50 ? (a >= 50 ? 'tr' : 'tl') : a >= 50 ? 'br' : 'bl');

  const quadrants = [
    { key: 'tl', title: 'Checks overdue, nothing proven', note: 'Quiet is not safe: a required check is missing or stale.' },
    { key: 'tr', title: 'Checks current, nothing proven', note: 'Required checks are current and no proven problem is open. That is not a promise of safety.' },
    { key: 'bl', title: 'Checks overdue, problems proven', note: 'Proven problems and gaps in coverage. Look here first.' },
    { key: 'br', title: 'Checks current, problems proven', note: 'The risk is real and well evidenced. Fix it.' },
  ];

  const POLICY = {
    'banking-customer': 'Banking, customer-facing',
    'banking-partner': 'Banking, partner-facing',
    'banking-internal': 'Banking, internal',
    nonbanking: 'Non-banking',
  };

  // trail: one [assurance, standing, level] per snapshot, oldest first; null = not yet assessed.
  const defs = [
    { id: 'card-payments', label: 'Card Payments API', tier: 'Tier 1', category: 'Banking', exposure: 'Customer-facing', policy: 'banking-customer',
      a: 38, s: 12, level: 'action', days: 9, moved: { assurance: 'down', standing: 'down' },
      an: '4 of 5 required scanners current', sn: '2 reproduced exploits and a hardcoded key open',
      trail: [[90, 90, 'clear'], [82, 90, 'clear'], [66, 90, 'clear'], [44, 24, 'action'], [38, 12, 'action']],
      reason: '2 exploits reproduced and a hardcoded key; API Security is 9 days stale' },
    { id: 'disputes', label: 'Disputes Service', tier: 'Tier 1', category: 'Banking', exposure: 'Customer-facing', policy: 'banking-customer',
      a: 84, s: 18, level: 'action', days: 2, moved: { assurance: 'steady', standing: 'down' },
      an: 'All 5 required scanners current', sn: '1 reproduced exploit open (SSRF)',
      trail: [[86, 90, 'clear'], [80, 90, 'clear'], [78, 90, 'clear'], [84, 90, 'clear'], [84, 18, 'action']],
      reason: 'SSRF reproduced on the evidence-fetch endpoint' },
    { id: 'kyc-gateway', label: 'KYC Vendor Gateway', tier: 'Tier 1', category: 'Banking', exposure: 'Partner-facing', policy: 'banking-partner',
      a: 25, s: 31, level: 'attention', days: 4, moved: { assurance: 'down', standing: 'down' },
      an: 'Nothing has run for 11 days (window 7)', sn: 'Reachable critical CVE in log4j-core, not yet reproduced',
      trail: [[74, 90, 'clear'], [68, 90, 'clear'], [60, 90, 'clear'], [82, 32, 'attention'], [25, 31, 'attention']],
      reason: 'Reachable critical CVE in log4j-core; nothing has run for 11 days' },
    { id: 'upi-adapter', label: 'UPI Switch Adapter', tier: 'Tier 1', category: 'Banking', exposure: 'Partner-facing', policy: 'banking-partner',
      a: 78, s: 58, level: 'attention', days: 28, moved: { assurance: 'steady', standing: 'down' },
      an: 'All 5 required scanners current', sn: 'Needs a person to judge: 2 uncertain high',
      trail: [[80, 90, 'clear'], [76, 90, 'clear'], [82, 90, 'clear'], [86, 90, 'clear'], [78, 58, 'attention']],
      reason: '2 possible secrets in source; triage is uncertain' },
    { id: 'admin-ledger', label: 'Admin Ledger', tier: 'Tier 1', category: 'Banking', exposure: 'Internal', policy: 'banking-internal',
      a: 38, s: 90, level: 'attention', days: 28, moved: { assurance: 'steady', standing: 'steady' },
      an: '4 of 5 required scanners current', sn: 'Nothing proven open',
      trail: [[30, 90, 'attention'], [34, 90, 'attention'], [36, 90, 'attention'], [38, 90, 'attention'], [38, 90, 'attention']],
      reason: 'API Security has never run: no staging URL is configured' },
    { id: 'loan-origination', label: 'Loan Origination', tier: 'Tier 2', category: 'Banking', exposure: 'Internal', policy: 'banking-internal',
      a: 22, s: 90, level: 'attention', days: 5, moved: { assurance: 'down', standing: 'steady' },
      an: 'Nothing has run for 12 days (window 7)', sn: 'Nothing proven open',
      trail: [[72, 90, 'clear'], [66, 90, 'clear'], [60, 90, 'clear'], [56, 90, 'clear'], [22, 90, 'attention']],
      reason: 'No scan for 12 days; the policy asks for one every 7' },
    { id: 'netbanking-web', label: 'Net Banking Web', tier: 'Tier 1', category: 'Banking', exposure: 'Customer-facing', policy: 'banking-customer',
      a: 94, s: 90, level: 'clear', days: 28, moved: { assurance: 'steady', standing: 'steady' },
      an: 'All 5 required scanners current, last ran 1 day ago', sn: 'Nothing proven open',
      trail: [[90, 90, 'clear'], [94, 90, 'clear'], [92, 90, 'clear'], [95, 90, 'clear'], [94, 90, 'clear']],
      reason: 'All checks ran yesterday; nothing proven open' },
    { id: 'acct-statements', label: 'Account Statements', tier: 'Tier 2', category: 'Banking', exposure: 'Customer-facing', policy: 'banking-customer',
      a: 84, s: 90, level: 'clear', days: 28, moved: { assurance: 'steady', standing: 'steady' },
      an: 'All 5 required scanners current, last ran 3 days ago', sn: 'Nothing proven open',
      trail: [null, [82, 90, 'clear'], [86, 90, 'clear'], [88, 90, 'clear'], [84, 90, 'clear']],
      reason: 'All checks ran in the last 3 days; nothing proven open' },
    { id: 'treasury-reports', label: 'Treasury Reports', tier: 'Tier 3', category: 'Non-banking', exposure: 'Internal', policy: 'nonbanking',
      a: 90, s: 90, level: 'clear', days: 28, moved: { assurance: 'steady', standing: 'steady' },
      an: 'All 4 required scanners current, last ran 2 days ago', sn: 'Nothing proven open',
      trail: [[86, 90, 'clear'], [84, 90, 'clear'], [90, 90, 'clear'], [88, 90, 'clear'], [90, 90, 'clear']],
      reason: 'All checks ran 2 days ago; nothing proven open' },
    { id: 'notifications', label: 'Notification Service', tier: 'Tier 3', category: 'Non-banking', exposure: 'Internal', policy: 'nonbanking',
      a: 72, s: 90, level: 'clear', days: 28, moved: { assurance: 'steady', standing: 'steady' },
      an: 'All 4 required scanners current, last ran 4 days ago', sn: 'Nothing proven open',
      trail: [[76, 90, 'clear'], [70, 90, 'clear'], [74, 90, 'clear'], [78, 90, 'clear'], [72, 90, 'clear']],
      reason: 'All checks ran in the last 4 days; nothing proven open' },
    { id: 'branch-locator', label: 'Branch Locator', tier: 'Tier 3', category: 'Non-banking', exposure: 'Customer-facing', policy: 'nonbanking',
      a: 72, s: 90, level: 'clear', days: 14, moved: { assurance: 'steady', standing: 'steady' },
      an: 'All 4 required scanners current, last ran 4 days ago', sn: 'Nothing proven open',
      trail: [null, null, [70, 90, 'clear'], [74, 90, 'clear'], [72, 90, 'clear']],
      reason: 'All checks ran in the last 4 days; nothing proven open' },
  ];

  const points = defs.map((d) => ({
    id: d.id, label: d.label, tier: d.tier, category: d.category, exposure: d.exposure,
    policy: d.policy, policy_name: POLICY[d.policy], level: d.level,
    assurance: d.a, standing: d.s, cell: cellOf(d.a, d.s), days_in_cell: d.days,
    assurance_note: d.an, standing_note: d.sn, moved: d.moved,
    trail: d.trail.map((t, i) => (t ? { at: snapshots[i], assurance: t[0], standing: t[1], cell: cellOf(t[0], t[1]), level: t[2] } : null)),
  }));

  const unassessed = [
    { id: 'legacy-feed', label: 'Legacy Partner Feed', tier: 'Tier 2', category: 'Banking', exposure: 'Partner-facing', reason: 'Never scanned; no repository connection yet' },
  ];

  const total = points.length + unassessed.length;
  const by_snapshot = snapshots.map((at, i) => {
    const c = { at, tl: 0, tr: 0, bl: 0, br: 0 };
    let n = 0;
    for (const p of points) { const t = p.trail[i]; if (t) { c[t.cell] += 1; n += 1; } }
    c.unassessed = total - n;
    return c;
  });

  const rank = { action: 0, attention: 1 };
  const worst = points.filter((p) => p.level === 'action' || p.level === 'attention')
    .sort((a, b) => rank[a.level] - rank[b.level] || ['bl', 'br', 'tl', 'tr'].indexOf(a.cell) - ['bl', 'br', 'tl', 'tr'].indexOf(b.cell) || a.standing - b.standing)
    .slice(0, 3);
  const best = points.filter((p) => p.cell === 'tr' && p.level === 'clear').sort((a, b) => b.assurance - a.assurance).slice(0, 3);
  const lead = (p) => ({ id: p.id, label: p.label, tier: p.tier, level: p.level, cell: p.cell, moved: p.moved, reason: defs.find((d) => d.id === p.id).reason, days_in_cell: p.days_in_cell });

  // Applications grouped by "category · exposure"; meet_policy = every required check current (matrix logic).
  const meet = { 'card-payments': false, 'kyc-gateway': false, 'admin-ledger': false, 'loan-origination': false };
  const groups = {};
  for (const p of points) {
    const key = `${p.category} · ${p.exposure}`;
    const g = (groups[key] = groups[key] || { key, apps: 0, meet_policy: 0, levels: { action: 0, attention: 0, clear: 0, unknown: 0 } });
    g.apps += 1; g.levels[p.level] += 1;
    if (meet[p.id] !== false) g.meet_policy += 1;
  }
  const categories = Object.values(groups).sort((a, b) => b.apps - a.apps);

  const weekly = [
    { label: '28 Sep', proven: 0, candidates: 4, clean: 3, incomplete: 1 },
    { label: '5 Oct', proven: 0, candidates: 5, clean: 3, incomplete: 1 },
    { label: '12 Oct', proven: 1, candidates: 6, clean: 3, incomplete: 2 },
    { label: '19 Oct', proven: 3, candidates: 5, clean: 4, incomplete: 3 },
  ];
  const outcomes = weekly.reduce((o, w) => ({ proven: o.proven + w.proven, candidates: o.candidates + w.candidates, clean: o.clean + w.clean, incomplete: o.incomplete + w.incomplete }), { proven: 0, candidates: 0, clean: 0, incomplete: 0 });

  window.P = {
    posture: {
      as_of: '2026-10-19', history_days: 28, snapshots, points, by_snapshot, unassessed, quadrants,
      leaders: { worst: worst.map(lead), best: best.map(lead) },
      assessments: { days: 28, total: Object.values(outcomes).reduce((a, b) => a + b, 0), scan: 36, pr: 8, outcomes, weekly },
      categories,
    },
    strip: { apps: total, provenOpen: 3, oldestCritical: '9 d', oldestCriticalApp: 'Card Payments API' },
  };
})();
