/* SAMPLE DATA for the mockup. Nothing here is a real scan. Shapes mirror report.json
   (docs/ui/design.md, "Data contract"); control titles and citations are the real
   strings from engine/docket/compliance/builtin/rbi-csf.json. */
(function () {
  const NOW = Date.now(), D = 86400000;
  const iso = (d, h = 0) => new Date(NOW - d * D - h * 3600000).toISOString();
  const ev = (d, cov, proven, cand, kind) => ({ id: 'scan-' + Math.round(d * 100) + Math.random().toString(36).slice(2, 5), at: iso(d), coverage: cov, proven, candidates: cand, kind: kind || 'scan' });

  const apps = [
    { id: 'card-payments', label: 'Card Payments API', repo: 'ibank/card-payments', tier: 'Tier 1', level: 'action', owner: 'Meera Nair', lang: 'Python · FastAPI',
      reason: '2 exploits reproduced; the API Security engine has not run in 9 days', age: '3 d',
      events: [ev(24, 'full', 0, 9), ev(17, 'full', 0, 11), ev(9, 'full', 1, 14), ev(5, 'full', 0, 2, 'pr'), ev(1, 'partial', 2, 17)] },
    { id: 'disputes', label: 'Disputes Service', repo: 'ibank/disputes', tier: 'Tier 1', level: 'action', owner: 'Arjun Rao', lang: 'Java · Spring',
      reason: 'SSRF reproduced on the evidence-fetch endpoint', age: '2 d',
      events: [ev(22, 'full', 0, 7), ev(15, 'full', 0, 8), ev(8, 'full', 0, 9), ev(2, 'full', 1, 10)] },
    { id: 'kyc-gateway', label: 'KYC Vendor Gateway', repo: 'ibank/kyc-gateway', tier: 'Tier 1', level: 'attention', owner: 'Divya Menon', lang: 'Java · Spring',
      reason: 'Critical CVE in log4j-core is reachable; last scan was 11 days ago', age: '11 d',
      events: [ev(25, 'full', 0, 8), ev(18, 'full', 0, 8), ev(11, 'full', 0, 9)] },
    { id: 'admin-ledger', label: 'Admin Ledger', repo: 'ibank/admin-ledger', tier: 'Tier 1', level: 'attention', owner: 'Karan Shah', lang: 'Node · Express',
      reason: 'Nuclei skipped on every scan: no staging URL is configured', age: '14 d',
      events: [ev(21, 'full', 0, 5), ev(14, 'partial', 0, 4), ev(7, 'partial', 0, 4), ev(2, 'partial', 0, 6)] },
    { id: 'upi-adapter', label: 'UPI Switch Adapter', repo: 'ibank/upi-adapter', tier: 'Tier 1', level: 'attention', owner: 'Sana Iqbal', lang: 'Go',
      reason: '2 possible secrets in source; triage is uncertain', age: '3 d',
      events: [ev(23, 'full', 0, 4), ev(16, 'full', 0, 4), ev(9, 'full', 0, 5), ev(3, 'full', 0, 6)] },
    { id: 'loan-origination', label: 'Loan Origination', repo: 'ibank/loan-origination', tier: 'Tier 2', level: 'attention', owner: 'Rahul Verma', lang: 'Java · Spring',
      reason: 'No scan for 12 days; policy asks for one every 7', age: '12 d',
      events: [ev(27, 'full', 0, 6), ev(19, 'full', 0, 5), ev(12, 'full', 0, 6)] },
    { id: 'netbanking-web', label: 'Net Banking Web', repo: 'ibank/netbanking-web', tier: 'Tier 1', level: 'clear', owner: 'Isha Kapoor', lang: 'TypeScript · Next',
      reason: 'Nothing open that was proven', age: '1 d',
      events: [ev(26, 'full', 0, 3), ev(19, 'full', 0, 3), ev(12, 'full', 0, 2), ev(5, 'full', 0, 2), ev(2, 'full', 0, 1, 'pr'), ev(1, 'full', 0, 2)] },
    { id: 'acct-statements', label: 'Account Statements', repo: 'ibank/account-statements', tier: 'Tier 2', level: 'clear', owner: 'Vikram Joshi', lang: 'Python · Django',
      reason: 'Nothing open that was proven', age: '1 d',
      events: [ev(27, 'full', 0, 2), ev(20, 'full', 0, 2), ev(13, 'full', 0, 1), ev(6, 'full', 0, 1), ev(1, 'full', 0, 1)] },
    { id: 'notifications', label: 'Notification Service', repo: 'ibank/notifications', tier: 'Tier 3', level: 'clear', owner: 'Asha Pillai', lang: 'Go',
      reason: 'Nothing open that was proven', age: '4 d',
      events: [ev(25, 'full', 0, 1), ev(18, 'full', 0, 1), ev(11, 'full', 0, 0), ev(4, 'full', 0, 1)] },
    { id: 'treasury-reports', label: 'Treasury Reports', repo: 'ibank/treasury-reports', tier: 'Tier 3', level: 'clear', owner: 'Nitin Desai', lang: 'Python',
      reason: 'Nothing open that was proven', age: '2 d',
      events: [ev(22, 'full', 0, 3), ev(15, 'full', 0, 2), ev(8, 'full', 0, 2), ev(2, 'full', 0, 2)] },
    { id: 'branch-locator', label: 'Branch Locator', repo: 'ibank/branch-locator', tier: 'Tier 3', level: 'clear', owner: 'Pooja Reddy', lang: 'TypeScript',
      reason: 'Nothing open that was proven', age: '3 d',
      events: [ev(24, 'full', 0, 0), ev(17, 'full', 0, 1), ev(10, 'full', 0, 0), ev(3, 'full', 0, 0)] },
    { id: 'legacy-feed', label: 'Legacy Partner Feed', repo: 'ibank/legacy-partner-feed', tier: 'Tier 2', level: 'unknown', owner: 'Unassigned', lang: 'Java 8',
      reason: 'Never scanned; no repository connection yet', age: '',
      events: [] },
  ];

  const sev = (k) => ({ critical: 'crit', high: 'high', medium: 'med', low: 'low', info: 'info' })[k];

  const findings = [
    { id: 'f1', sev: 'critical', title: 'SQL injection in POST /payments/refund', sub: 'CWE-89 · parameter ref_id', app: 'card-payments', proof: 'reproduced', by: { origin: 'henoyo', name: 'Docket SQLi specialist' }, age: '3 d', status: 'Fix proposed' },
    { id: 'f2', sev: 'high', title: 'Broken object-level authorisation on GET /cards/{id}', sub: 'CWE-639 · any user reads any card', app: 'card-payments', proof: 'reproduced', by: { origin: 'henoyo', name: 'Docket IDOR specialist' }, age: '3 d', status: 'Open' },
    { id: 'f3', sev: 'high', title: 'Server-side request forgery in POST /disputes/evidence/fetch', sub: 'CWE-918 · url parameter reaches internal metadata service', app: 'disputes', proof: 'reproduced', by: { origin: 'henoyo', name: 'Docket SSRF specialist' }, age: '2 d', status: 'Open' },
    { id: 'f4', sev: 'critical', title: 'Hardcoded API key in config/prod.py:14', sub: 'CWE-798 · key matches the payment processor format', app: 'card-payments', proof: 'deterministic', by: { origin: 'third_party', name: 'Trivy' }, age: '9 d', status: 'Open' },
    { id: 'f5', sev: 'critical', title: 'log4j-core 2.14.1 is vulnerable (CVE-2021-44228, CVSS 10.0)', sub: 'Reachable from the request logger in KycAuditFilter', app: 'kyc-gateway', proof: 'candidate', by: { origin: 'third_party', name: 'Trivy' }, age: '11 d', status: 'Open', reach: 'Reachable' },
    { id: 'f6', sev: 'medium', title: 'Formatted SQL query in reports/export.py:64', sub: 'CWE-89 · semgrep python.sqlalchemy.formatted-sql-query', app: 'card-payments', proof: 'candidate', by: { origin: 'third_party', name: 'Semgrep' }, age: '9 d', status: 'Triaged', reach: 'Reachable' },
    { id: 'f7', sev: 'medium', title: 'No rate limit on POST /login', sub: 'API-RL-001 · brute force is not throttled', app: 'card-payments', proof: 'candidate', by: { origin: 'henoyo', name: 'API Security engine' }, age: '9 d', status: 'Open' },
    { id: 'f8', sev: 'high', title: 'Possible cloud key in deploy/ci.yml:22', sub: 'CWE-798 · triage could not tell a live key from a placeholder', app: 'upi-adapter', proof: 'candidate', by: { origin: 'third_party', name: 'Trivy' }, age: '3 d', status: 'Triaged', reach: 'Uncertain' },
    { id: 'f9', sev: 'medium', title: 'Debug mode enabled in config/settings.js', sub: 'CWE-489 · only loaded in the test harness', app: 'admin-ledger', proof: 'not_reachable', by: { origin: 'third_party', name: 'Semgrep' }, age: '14 d', status: 'Triaged: not reachable', reach: 'Not reachable' },
    { id: 'f10', sev: 'low', title: 'Missing Content-Security-Policy header on GET /', sub: 'nuclei http-missing-security-headers', app: 'netbanking-web', proof: 'candidate', by: { origin: 'third_party', name: 'Nuclei' }, age: '1 d', status: 'Open' },
  ];

  // Latest scan of the hero application, laid out as it ran (seconds from start).
  const lanes = [
    { id: 'trivy', label: 'Dependencies and secrets', tool: 'Trivy', origin: 'third_party', group: 'pre', state: 'done', icon: 'package', start: 6, end: 62, required: true, requiredBy: ['Tier 1 baseline: no secret in source'], candidates: 3, summary: '2 critical CVEs, 1 secret' },
    { id: 'semgrep', label: 'Static analysis', tool: 'Semgrep', origin: 'third_party', group: 'pre', state: 'done', icon: 'file-code', start: 62, end: 195, required: true, requiredBy: ['Tier 1 baseline: injection patterns checked'], candidates: 17 },
    { id: 'nuclei', label: 'Web templates', tool: 'Nuclei', origin: 'third_party', group: 'pre', state: 'done', icon: 'radar', start: 195, end: 280, required: false, candidates: 2, summary: 'Optional: runs when a staging URL is set' },
    { id: 'apisec', label: 'API Security engine', origin: 'henoyo', group: 'pre', state: 'not_run', icon: 'shield-alert', start: 280, end: 365, required: true, requiredBy: ['Tier 1 baseline: every exposed endpoint tested', 'OWASP API Security Top 10 2023'], summary: 'Not scheduled: its connection token expired' },
    { id: 'recon', label: 'Attack-surface recon', origin: 'henoyo', group: 'agents', state: 'done', icon: 'crosshair', start: 280, end: 365, required: false, summary: '38 routes mapped' },
    { id: 'triage', label: 'Triage', origin: 'henoyo', group: 'agents', state: 'done', icon: 'brain', start: 285, end: 450, required: true, requiredBy: ['Tier 1 baseline'], summary: '17 judged: 5 exploitable, 9 not reachable, 3 unsure', cost: 0.41 },
    { id: 'compliance', label: 'Compliance reader', origin: 'henoyo', group: 'agents', state: 'done', icon: 'scroll-text', start: 365, end: 500, required: false, summary: '14 of 40 controls read (advisory)', cost: 0.38 },
    { id: 'swarm', label: 'Exploit swarm', origin: 'henoyo', group: 'agents', state: 'done', icon: 'crosshair', start: 365, end: 665, required: true, requiredBy: ['Tier 1 baseline'], proven: 2, summary: '3 specialists, 2 exploits proven', cost: 0.71 },
    { id: 'sw-sqli', label: 'SQL injection', origin: 'henoyo', group: 'agents', state: 'done', icon: 'crosshair', start: 370, end: 580, parentId: 'swarm', proven: 1 },
    { id: 'sw-idor', label: 'Object-level authorisation', origin: 'henoyo', group: 'agents', state: 'done', icon: 'crosshair', start: 372, end: 650, parentId: 'swarm', proven: 1 },
    { id: 'sw-ssrf', label: 'SSRF', origin: 'henoyo', group: 'agents', state: 'done', icon: 'crosshair', start: 375, end: 485, parentId: 'swarm', proven: 0 },
    { id: 'fix', label: 'Fix proposals', origin: 'henoyo', group: 'agents', state: 'done', icon: 'wrench', start: 665, end: 760, required: false, summary: '2 patches, 1 pull request', cost: 0.34 },
  ];
  const groups = [
    { key: 'pre', label: 'Before the agents', sub: 'Deterministic scanners, run in policy order' },
    { key: 'agents', label: 'Docket agents', sub: 'Henoyo exploit validation: recon, triage, compliance, exploit, fix' },
  ];

  const health = {
    level: 'action',
    verdict: 'Two exploits were reproduced against staging yesterday. One has a fix pull request waiting for review.',
    reasons: [
      'SQL injection in POST /payments/refund was reproduced; the proof is attached.',
      'Object-level authorisation fails on GET /cards/{id}; any signed-in user can read any card.',
      'The API Security engine has not run for 9 days. The Tier 1 policy requires it every 7.',
    ],
    annunciators: [
      { key: 'proven', label: 'Proven exploits', state: 'bad', value: '2', hint: 'reproduced, still open' },
      { key: 'secrets', label: 'Secrets in code', state: 'bad', value: '1', hint: 'config/prod.py' },
      { key: 'deps', label: 'Critical CVEs', state: 'bad', value: '2', hint: 'none reachable yet' },
      { key: 'coverage', label: 'Required scanners', state: 'warn', value: '4 of 5', hint: 'API Security did not run' },
      { key: 'fresh', label: 'Last scan', state: 'ok', value: '1 d', hint: 'inside the 7-day window' },
      { key: 'comp', label: 'RBI CSF (advisory)', state: 'off', value: '5 not met', hint: 'of 14 readable from code', advisory: true },
      { key: 'fix', label: 'Fix pull requests', state: 'ok', value: '1 open', hint: 'PR #482 awaiting review' },
    ],
    analytes: [
      { key: 'proven', label: 'Proven exploitable', hint: 'Reproduced with a working request', value: 2, display: '2', scaleMax: 6, bands: [{ from: 0, to: 0.4, tone: 'ok' }, { from: 0.4, to: 6, tone: 'bad' }], ref: '0', flag: 'bad', flagWord: 'Out of range', trend: [0, 0, 0, 1, 1, 1, 1, 2], previous: '1' },
      { key: 'reach', label: 'Reachable, not yet proven', hint: 'Scanner hits that triage could trace to an endpoint', value: 5, display: '5', scaleMax: 12, bands: [{ from: 0, to: 3, tone: 'ok' }, { from: 3, to: 12, tone: 'warn' }], ref: '3 or fewer', flag: 'warn', flagWord: 'High', trend: [2, 3, 3, 4, 4, 4, 4, 5], previous: '4' },
      { key: 'secrets', label: 'Secrets in source', hint: 'Credentials committed to the repository', value: 1, display: '1', scaleMax: 4, bands: [{ from: 0, to: 0.4, tone: 'ok' }, { from: 0.4, to: 4, tone: 'bad' }], ref: '0', flag: 'bad', flagWord: 'Out of range', trend: [0, 0, 0, 0, 1, 1, 1, 1], previous: '1' },
      { key: 'cves', label: 'Critical dependency CVEs', hint: 'CVSS 9.0 or higher, in a shipped package', value: 2, display: '2', scaleMax: 6, bands: [{ from: 0, to: 0.4, tone: 'ok' }, { from: 0.4, to: 6, tone: 'bad' }], ref: '0', flag: 'bad', flagWord: 'Out of range', trend: [3, 3, 3, 2, 2, 2, 2, 2], previous: '2' },
      { key: 'age', label: 'Oldest open critical', hint: 'Days since it was first seen', value: 9, display: '9 d', scaleMax: 30, bands: [{ from: 0, to: 7, tone: 'ok' }, { from: 7, to: 14, tone: 'warn' }, { from: 14, to: 30, tone: 'bad' }], ref: '7 days or fewer', flag: 'warn', flagWord: 'High', trend: [0, 0, 0, 2, 4, 6, 8, 9], previous: '8 d' },
      { key: 'cov', label: 'Required scanners that ran', hint: 'Against the Tier 1 baseline policy', value: 4, display: '4 of 5', scaleMax: 5, bands: [{ from: 0, to: 4, tone: 'bad' }, { from: 4, to: 4.9, tone: 'warn' }, { from: 4.9, to: 5, tone: 'ok' }], ref: '5 of 5', flag: 'warn', flagWord: 'Low', trend: [5, 5, 5, 5, 5, 5, 5, 4], previous: '5 of 5', higherIsBetter: true },
      { key: 'triage', label: 'Triage uncertain', hint: 'Findings triage left for a person to judge', value: 1, display: '1', scaleMax: 6, bands: [{ from: 0, to: 2, tone: 'ok' }, { from: 2, to: 4, tone: 'warn' }, { from: 4, to: 6, tone: 'bad' }], ref: '2 or fewer', flag: 'ok', flagWord: 'In range', trend: [0, 1, 1, 2, 1, 1, 1, 1], previous: '1' },
    ],
  };

  const proof = {
    id: 'f1',
    request: 'POST /payments/refund HTTP/1.1\nHost: staging.card-payments.ibank.example\nAuthorization: Bearer <redacted>\nContent-Type: application/json\n\n{"ref_id":"1001\' OR \'1\'=\'1","amount":1}',
    response: 'HTTP/1.1 200 OK\nContent-Type: application/json\n\n{"refunds":[{"ref_id":"1001","card_last4":"4417","amount":1250.00},\n {"ref_id":"1002","card_last4":"9023","amount":88.10},\n ... 1,846 more rows]}',
    notes: 'The refund lookup concatenates ref_id into the query. A tautology returned every refund in the table instead of one. A time-delay payload (pg_sleep(5)) reproduced a 5.02 s delay against a 0.18 s baseline.',
    triage: 'EXPLOITABLE: handler refund_lookup() in payments/refund.py:61 builds the query with an f-string and no parameterisation; the route is authenticated but not tenant-scoped.',
    fix: '--- a/payments/refund.py\n+++ b/payments/refund.py\n@@ -61,3 +61,3 @@\n-    q = f"SELECT * FROM refunds WHERE ref_id = \'{ref_id}\'"\n-    rows = db.execute(q)\n+    rows = db.execute(text("SELECT * FROM refunds WHERE ref_id = :ref"), {"ref": ref_id})',
  };

  // The policy for Tier 1 applications. `why` entries cite requirements; regulatory ones
  // carry the pack's own citation string and the Henoyo obligation they resolve to.
  const policy = {
    name: 'Tier 1 payments baseline', applies: 'Applications tagged Tier 1 (6)', cadence: 7,
    steps: [
      { n: 1, id: 'trivy', label: 'Dependencies and secrets', tool: 'Trivy', origin: 'third_party', phase: 'Before the agents', required: true, cadence: 'At least every 7 days, and on every pull request', onFail: 'Blocks on a secret in source. A critical CVE goes to triage.',
        why: [{ k: 'sec', t: 'No credentials in source' }, { k: 'reg', a: 'RBI', t: 'Cyber Security Framework, Annex 1: Secure configuration', ob: 'rbi-csf:secrets' }] },
      { n: 2, id: 'semgrep', label: 'Static analysis', tool: 'Semgrep', origin: 'third_party', phase: 'Before the agents', required: true, cadence: 'At least every 7 days, and on every pull request', onFail: 'Flags the application as out of policy; feeds triage',
        why: [{ k: 'sec', t: 'Injection and unsafe-deserialisation patterns checked' }, { k: 'reg', a: 'RBI', t: 'Cyber Security Framework, Annex 1: Application security life cycle', ob: 'rbi-csf:input-validation' }] },
      { n: 3, id: 'nuclei', label: 'Web templates', tool: 'Nuclei', origin: 'third_party', phase: 'Before the agents', required: false, cadence: 'When a staging URL is configured', onFail: 'None. Optional.',
        why: [{ k: 'sec', t: 'Known-exposure checks against the running staging site' }] },
      { n: 4, id: 'apisec', label: 'API Security engine', origin: 'henoyo', phase: 'Before the agents', required: true, cadence: 'At least every 7 days, and on any API spec change', onFail: 'Flags the application as out of policy',
        why: [{ k: 'sec', t: 'Every exposed endpoint is tested for authentication, rate limits and CORS' }, { k: 'reg', a: 'OWASP', t: 'API Security Top 10, 2023 edition', ob: 'owasp-api-2023' }] },
      { n: 5, id: 'recon', label: 'Attack-surface recon', origin: 'henoyo', phase: 'Docket agents', required: false, cadence: 'With every exploit run', onFail: 'None. Optional.',
        why: [{ k: 'sec', t: 'Maps the routes the exploit agents will try' }] },
      { n: 6, id: 'triage', label: 'Triage', origin: 'henoyo', phase: 'Docket agents', required: true, cadence: 'After every scanner run', onFail: 'Flags the application as out of policy. An exhausted run stays uncertain.',
        why: [{ k: 'sec', t: 'Every scanner hit is read against the source and judged reachable, not reachable, or uncertain' }] },
      { n: 7, id: 'compliance', label: 'Compliance reader', origin: 'henoyo', phase: 'Docket agents', required: false, cadence: 'Weekly', onFail: 'Advises only. Never blocks.',
        why: [{ k: 'reg', a: 'RBI', t: 'Cyber Security Framework: the packs assigned to this policy', ob: 'rbi-csf' }, { k: 'reg', a: 'SEBI', t: 'CSCRF: the packs assigned to this policy', ob: 'sebi-cscrf' }] },
      { n: 8, id: 'swarm', label: 'Exploit validation (Docket agents)', origin: 'henoyo', phase: 'Docket agents', required: true, cadence: 'At least every 7 days, and on pull requests that change routes', onFail: 'Blocks on any reproduced exploit',
        why: [{ k: 'sec', t: 'A finding needs a reproduced proof before it counts as an exploit' }, { k: 'reg', a: 'RBI', t: 'Cyber Security Framework, Annex 1: VAPT and red team exercises', ob: 'rbi-csf:vapt' }] },
      { n: 9, id: 'fix', label: 'Fix proposals', origin: 'henoyo', phase: 'Docket agents', required: false, cadence: 'After a proven exploit', onFail: 'None. Optional.',
        why: [{ k: 'sec', t: 'Each proven exploit gets a proposed patch and a pull request' }] },
    ],
    regulatory: [
      { a: 'RBI', t: 'Cyber Security Framework, Annex 1 (Application security life cycle; Secure configuration; VAPT and red team exercises)', ob: 'rbi-csf', clause: null },
      { a: 'RBI', t: 'Master Direction on IT Governance (Cryptographic controls)', ob: 'rbi-csf:crypto-algorithms', clause: null },
      { a: 'SEBI', t: 'CSCRF Protect (Identity management and access control)', ob: 'sebi-cscrf', clause: null },
      { a: 'OWASP', t: 'API Security Top 10, 2023 edition', ob: 'owasp-api-2023', clause: 'API1 to API10' },
    ],
    security: [
      { t: 'No credentials in source', c: 'A deterministic rule: a secret in code blocks the pull request.' },
      { t: 'Every exposed API endpoint is tested', c: 'By the API Security engine, at least every 7 days.' },
      { t: 'Only proof blocks a release', c: 'A reproduced exploit, a triage verdict of confirmed, or a deterministic rule such as a secret. A scanner hit alone does not.' },
      { t: 'Triage never guesses', c: 'A scanner hit it cannot judge stays uncertain for a person. It is never marked a false positive by default.' },
    ],
    gate: [
      { effect: 'blocks', text: 'A reproduced exploit, a secret in source or another deterministic rule, or a triage verdict of confirmed.' },
      { effect: 'flags', text: 'A required scanner that did not run inside its window.' },
      { effect: 'advises', text: 'Compliance results. They annotate the pull request and never block it: a control that cannot be judged must not turn every pull request red.' },
    ],
  };

  // Policy against reality: required scanners only (the same definition the pipeline and health card use).
  const matrix = [
    ['card-payments', { trivy: ['ok', '1 d'], semgrep: ['ok', '1 d'], apisec: ['stale', '9 d'], triage: ['ok', '1 d'], swarm: ['ok', '1 d'] }, { effect: 'flags', text: 'API Security engine is 9 days stale' }],
    ['disputes', { trivy: ['ok', '2 d'], semgrep: ['ok', '2 d'], apisec: ['ok', '2 d'], triage: ['ok', '2 d'], swarm: ['ok', '2 d'] }, { effect: 'blocks', text: 'Reproduced SSRF is open' }],
    ['kyc-gateway', { trivy: ['stale', '11 d'], semgrep: ['stale', '11 d'], apisec: ['stale', '11 d'], triage: ['stale', '11 d'], swarm: ['stale', '11 d'] }, { effect: 'flags', text: 'Nothing has run for 11 days' }],
    ['admin-ledger', { trivy: ['ok', '2 d'], semgrep: ['ok', '2 d'], apisec: ['missing', 'never'], triage: ['ok', '2 d'], swarm: ['ok', '2 d'] }, { effect: 'flags', text: 'API Security engine has never run' }],
    ['upi-adapter', { trivy: ['ok', '3 d'], semgrep: ['ok', '3 d'], apisec: ['ok', '3 d'], triage: ['ok', '3 d'], swarm: ['ok', '3 d'] }, null],
    ['netbanking-web', { trivy: ['ok', '1 d'], semgrep: ['ok', '1 d'], apisec: ['ok', '1 d'], triage: ['ok', '1 d'], swarm: ['ok', '1 d'] }, null],
  ];

  const rbi = [
    { id: 'crypto-transit', title: 'Data in transit encrypted', obs: 'source', sev: 'critical', cite: 'Annex 1: Cryptographic and network controls', status: 'pass', why: 'TLS 1.2 or higher is enforced on every listener; HSTS is set.', evidence: 'config/tls.py:12', quote: 'ssl_min_version = TLSVersion.TLSv1_2' },
    { id: 'crypto-rest', title: 'Sensitive data encrypted at rest and not stored unnecessarily', obs: 'source', sev: 'critical', cite: 'Annex 1: Data leak prevention', status: 'unknown', why: 'The ORM models do not say whether the column store is encrypted; that is set outside the repository.', evidence: '', quote: '' },
    { id: 'crypto-algorithms', title: 'Approved cryptographic algorithms only', obs: 'source', sev: 'high', cite: 'Master Direction on IT Governance: Cryptographic controls', instrument: 'IT Governance', status: 'fail', why: 'MD5 is used to derive the card token hash.', evidence: 'tokens/hash.py:31', quote: 'digest = hashlib.md5(pan.encode()).hexdigest()' },
    { id: 'secrets', title: 'No credentials embedded in application code', obs: 'source', sev: 'critical', cite: 'Annex 1: Secure configuration', status: 'fail', why: 'A payment-processor API key is committed.', evidence: 'config/prod.py:14', quote: 'PROCESSOR_KEY = "pk_live_..."', finding: 'Hardcoded API key (Trivy)' },
    { id: 'access-control', title: 'Least privilege enforced at the handler', obs: 'source', sev: 'critical', cite: 'Annex 1: User access control / management', status: 'fail', escalated: true, why: 'GET /cards/{id} does not check ownership. This was reproduced.', evidence: 'cards/routes.py:44', quote: 'card = Card.get(id)  # no owner check', finding: 'Broken object-level authorisation (reproduced)' },
    { id: 'input-validation', title: 'Untrusted input validated before use', obs: 'source', sev: 'critical', cite: 'Annex 1: Application security life cycle', status: 'fail', escalated: true, why: 'refund_lookup builds SQL from request input. This was reproduced.', evidence: 'payments/refund.py:61', quote: 'q = f"SELECT * FROM refunds WHERE ref_id = \'{ref_id}\'"', finding: 'SQL injection (reproduced)' },
    { id: 'session', title: 'Sessions bounded and invalidated', obs: 'source', sev: 'high', cite: 'Annex 1: User access control / management', status: 'pass', why: 'Sessions expire after 15 minutes idle and are revoked on logout.', evidence: 'auth/session.py:27', quote: 'SESSION_IDLE_TIMEOUT = 900' },
    { id: 'audit-log-events', title: 'Security-relevant events are logged', obs: 'source', sev: 'high', cite: 'Annex 1: Audit log settings', status: 'pass', why: 'Login, refund and card-view events write structured audit records.', evidence: 'audit/log.py:9', quote: 'def audit(event, actor, **ctx):' },
    { id: 'vapt', title: 'Vulnerability assessment and penetration testing programme', obs: 'process', sev: 'high', cite: 'Annex 1: VAPT and red team exercises', status: 'not_observable', why: 'Whether a programme exists is not written in code. Docket runs count as evidence once attached in Henoyo.', evidence: '', quote: '' },
    { id: 'ciso', title: 'Chief Information Security Officer appointed', obs: 'process', sev: 'high', cite: 'Master Direction on IT Governance: Information security function', status: 'not_observable', why: 'An organisational fact. Answered in the IRM pack, not from code.', evidence: '', quote: '' },
  ];

  const trend = {
    periods: [-7, -6, -5, -4, -3, -2, -1, 0].map((w, i) => ({ key: 'w' + i, label: w === 0 ? 'This week' : (-w) + ' w ago' })),
    series: [
      { key: 'critical', label: 'Critical', values: [0, 1, 0, 1, 1, 0, 2, 2] },
      { key: 'high', label: 'High', values: [1, 1, 2, 1, 2, 2, 1, 2] },
      { key: 'medium', label: 'Medium', values: [2, 3, 2, 2, 3, 3, 2, 1] },
    ],
  };

  window.S = { NOW, iso, apps, findings, lanes, groups, health, proof, policy, matrix, rbi, trend, sev };
})();
