/* SAMPLE DATA for the Policies mockup. Nothing here is a real scan.
   Shapes follow docs/ui/policy-and-posture.md sections 2, 3 and 5.3: catalog slots with tool
   alternatives and availability, the three seeded policies, guideline packs, and per-application
   "days since this slot last finished" so the "If you save" panel can recompute in the browser.
   Needs sample.js (window.S) loaded first: the last run of Card Payments reuses its pipeline lanes. */
(function () {
  const S = window.S;

  const T = (id, name, origin, availability, def) => ({ id, name, origin, availability, ...(def ? { default: true } : {}) });
  const sarif = [
    T('codeql', 'CodeQL', 'third_party', 'imports'), T('sonarqube', 'SonarQube', 'third_party', 'imports'),
    T('checkmarx', 'Checkmarx', 'third_party', 'imports'), T('snyk-code', 'Snyk Code', 'third_party', 'imports'),
    T('veracode', 'Veracode', 'third_party', 'imports'), T('sarif', 'Any SARIF 2.1.0 tool', 'third_party', 'imports'),
  ];
  const agent = (id, name) => [T(id, name, 'henoyo', 'runs', true)];

  // Catalog (GET /api/catalog). `reads` and `detection` feed the "Preview a run" plan.
  const slots = [
    { id: 'trivy', label: 'Dependencies and secrets', capability: 'Dependency and secret scanning', phase: 'pre', icon: 'package', origin: 'third_party',
      what: 'Reads dependency manifests and source for known vulnerable packages and committed secrets.',
      reads: 'Lockfiles, manifests and every source file', produces: 'Dependency CVEs and secret candidates', command: 'trivy fs --scanners vuln,secret --format sarif .',
      cadence: 'At least every window, and on every pull request',
      tools: [T('trivy', 'Trivy', 'third_party', 'runs', true), T('grype', 'Grype', 'third_party', 'planned'), T('snyk-oss', 'Snyk Open Source', 'third_party', 'planned'),
        T('gitleaks', 'Gitleaks', 'third_party', 'planned'), T('depcheck', 'OWASP Dependency-Check', 'third_party', 'planned')] },
    { id: 'semgrep', label: 'Static analysis', capability: 'Static analysis', phase: 'pre', icon: 'file-code', origin: 'third_party',
      what: 'Reads source for injection and unsafe patterns.',
      reads: 'Source files in the repository', produces: 'Static candidates (never findings until proven)', command: 'semgrep --config=p/default --sarif',
      cadence: 'At least every window, and on every pull request',
      tools: [T('semgrep', 'Semgrep', 'third_party', 'runs', true), ...sarif] },
    { id: 'nuclei', label: 'Web templates', capability: 'Web exposure templates', phase: 'pre', icon: 'radar', origin: 'third_party',
      what: 'Runs known-exposure templates against the staging site.',
      reads: 'The running staging URL', produces: 'Template hits (candidates)', command: 'nuclei -u $STAGING_URL -severity medium,high,critical -jsonl',
      cadence: 'When a staging URL is set',
      tools: [T('nuclei', 'Nuclei', 'third_party', 'runs', true), T('zap', 'OWASP ZAP', 'third_party', 'planned')] },
    { id: 'apisec', label: 'API Security engine', capability: 'API security testing', phase: 'pre', icon: 'shield-alert', origin: 'henoyo',
      what: 'Tests every exposed endpoint for authentication, rate limits and CORS.',
      reads: 'The API specification and the running API', produces: 'API findings with request and response', command: '',
      cadence: 'At least every window',
      tools: [T('apisec', 'Henoyo API Security engine', 'henoyo', 'planned', true)] },
    { id: 'recon', label: 'Attack-surface recon', capability: 'Attack-surface recon', phase: 'agents', icon: 'crosshair', origin: 'henoyo',
      what: 'Maps the routes and parameters the exploit agents will try.', reads: 'Routes in source, the OpenAPI file and the staging site', produces: 'A surface map',
      command: '', cadence: 'With every exploit run', tools: agent('recon', 'Recon agent') },
    { id: 'triage', label: 'Triage', capability: 'Triage', phase: 'agents', icon: 'brain', origin: 'henoyo',
      what: 'Reads each scanner hit against the source and judges it reachable, not reachable or uncertain.', reads: 'Scanner candidates and the source they point at', produces: 'A verdict per candidate: confirmed, not reachable or uncertain',
      command: '', cadence: 'After every scanner run', tools: agent('triage', 'Triage agent') },
    { id: 'compliance', label: 'Compliance reader', capability: 'Guideline reading', phase: 'agents', icon: 'scroll-text', origin: 'henoyo', locked: true,
      what: 'Reads the code against the selected guidelines. Advisory only.', reads: 'Source files, for the controls that can be judged from code', produces: 'A cited reading per control (pass, fail or unknown)',
      command: '', cadence: 'Weekly', tools: agent('compliance', 'Compliance reader') },
    { id: 'swarm', label: 'Exploit swarm', capability: 'Exploit validation', phase: 'agents', icon: 'crosshair', origin: 'henoyo',
      what: 'Specialist agents try to reproduce each credible finding. A finding exists only with a working proof.', reads: 'Triaged candidates and the running target', produces: 'Reproduced exploits with request and response',
      command: '', cadence: 'At least every window', tools: agent('swarm', 'Exploit swarm') },
    { id: 'fix', label: 'Fix proposals', capability: 'Fix proposals', phase: 'agents', icon: 'wrench', origin: 'henoyo',
      what: 'Proposes a patch and a pull request for each proven exploit.', reads: 'Proven exploits and the code they touch', produces: 'A patch and a fix pull request',
      command: '', cadence: 'After a proven exploit', tools: agent('fix', 'Fix agent') },
  ];

  const starts = [
    { kind: 'manual', label: 'Run now', availability: 'works', note: 'From the console or the command line' },
    { kind: 'pull_request', label: 'Pull request', availability: 'works', note: 'Where the repository is watched' },
    { kind: 'schedule', label: 'Every N days', availability: 'planned', note: 'The cadence is judged, Docket does not start it yet' },
  ];

  const guidelines = [
    { id: 'rbi-csf', authority: 'RBI', title: 'Cyber Security Framework for banks', controls: 40, observable: 14 },
    { id: 'sebi-cscrf', authority: 'SEBI', title: 'CSCRF for regulated entities', controls: 52, observable: 17 },
    { id: 'owasp-api-2023', authority: 'OWASP', title: 'API Security Top 10, 2023', controls: 10, observable: 10 },
    { id: 'nist-ssdf', authority: 'NIST', title: 'Secure Software Development Framework 1.1', controls: 42, observable: 19 },
  ];

  const profile = {
    category: ['Banking', 'Non-banking'],
    exposure: ['Customer-facing', 'Partner-facing', 'Internal'],
    stack: ['Web', 'API', 'Mobile', 'Batch'],
    tier: ['Tier 1', 'Tier 2', 'Tier 3'],
  };

  // `ran`: days since each slot last finished inside a FULL scan (null: never). `proven`: reproduced exploits open.
  const A = (id, category, exposure, stack, tier, ran, proven) => {
    const base = S.apps.find((a) => a.id === id) || { label: id, repo: '' };
    return { id, label: base.label, repo: base.repo, tier, category, exposure, stack, ran, proven: proven || 0 };
  };
  const apps = [
    A('card-payments', 'Banking', 'Customer-facing', 'API', 'Tier 1', { trivy: 1, semgrep: 1, nuclei: 1, recon: 1, triage: 1, swarm: 1, compliance: 1, fix: 1 }, 2),
    A('disputes', 'Banking', 'Customer-facing', 'API', 'Tier 1', { trivy: 2, semgrep: 2, nuclei: 2, recon: 2, triage: 2, swarm: 2, compliance: 2, fix: null }, 1),
    A('upi-adapter', 'Banking', 'Customer-facing', 'API', 'Tier 1', { trivy: 3, semgrep: 3, nuclei: null, recon: 3, triage: 3, swarm: 3, compliance: 3, fix: null }),
    A('loan-origination', 'Banking', 'Customer-facing', 'Web', 'Tier 2', { trivy: 12, semgrep: 12, nuclei: null, recon: 12, triage: 12, swarm: null, compliance: null, fix: null }),
    A('netbanking-web', 'Banking', 'Customer-facing', 'Web', 'Tier 1', { trivy: 1, semgrep: 1, nuclei: 1, recon: 1, triage: 1, swarm: 1, compliance: 1, fix: null }),
    A('acct-statements', 'Banking', 'Customer-facing', 'Web', 'Tier 2', { trivy: 1, semgrep: 1, nuclei: null, recon: null, triage: 1, swarm: 9, compliance: null, fix: null }),
    A('kyc-gateway', 'Banking', 'Partner-facing', 'API', 'Tier 1', { trivy: 11, semgrep: 11, nuclei: null, recon: 11, triage: 11, swarm: 11, compliance: null, fix: null }),
    A('legacy-feed', 'Banking', 'Partner-facing', 'Batch', 'Tier 2', { trivy: null, semgrep: null, nuclei: null, recon: null, triage: null, swarm: null, compliance: null, fix: null }),
    A('admin-ledger', 'Banking', 'Internal', 'Web', 'Tier 1', { trivy: 2, semgrep: 2, nuclei: null, recon: null, triage: 2, swarm: 2, compliance: null, fix: null }),
    A('notifications', 'Banking', 'Internal', 'API', 'Tier 3', { trivy: 4, semgrep: 4, nuclei: null, recon: null, triage: 4, swarm: null, compliance: null, fix: null }),
    A('treasury-reports', 'Banking', 'Internal', 'Batch', 'Tier 3', { trivy: 2, semgrep: 2, nuclei: null, recon: null, triage: 2, swarm: null, compliance: null, fix: null }),
    A('branch-locator', 'Non-banking', 'Customer-facing', 'Web', 'Tier 3', { trivy: 3, semgrep: 3, nuclei: 3, recon: null, triage: 3, swarm: null, compliance: null, fix: null }),
    { id: 'merchant-portal', label: 'Merchant Portal', repo: 'ibank/merchant-portal', tier: 'Tier 2', category: 'Non-banking', exposure: 'Customer-facing', stack: 'Web', proven: 0,
      ran: { trivy: 6, semgrep: 6, nuclei: 6, recon: null, triage: 15, swarm: null, compliance: null, fix: null } },
    { id: 'partner-docs', label: 'Partner Docs Site', repo: 'ibank/partner-docs', tier: 'Tier 3', category: 'Non-banking', exposure: 'Partner-facing', stack: 'Web', proven: 0,
      ran: { trivy: 8, semgrep: 8, nuclei: null, recon: null, triage: 8, swarm: null, compliance: null, fix: null } },
  ];

  const step = (id, required, tool) => ({ id, required, tool: tool || null });
  // Seeded policies (the spec's seed). `status: saved` ones are in docket_policy.json.
  const policies = [
    { id: 'banking-customer', name: 'Banking, customer-facing', applies_when: { category: ['Banking'], exposure: ['Customer-facing'], stack: [], tier: [] }, cadence_days: 7,
      steps: [step('trivy', true), step('semgrep', true, 'codeql'), step('nuclei', false), step('recon', false), step('triage', true), step('swarm', true), step('compliance', false), step('fix', false)],
      guidelines: ['rbi-csf', 'sebi-cscrf', 'owasp-api-2023'], version: 3, status: 'saved', default: false },
    { id: 'internal', name: 'Internal applications', applies_when: { category: [], exposure: ['Internal'], stack: [], tier: [] }, cadence_days: 14,
      steps: [step('trivy', true), step('semgrep', true), step('triage', false), step('fix', false)],
      guidelines: [], version: 1, status: 'saved', default: false },
    { id: 'non-banking-web', name: 'Non-banking, web', applies_when: { category: ['Non-banking'], exposure: ['Customer-facing', 'Partner-facing'], stack: ['Web'], tier: [] }, cadence_days: 14,
      steps: [step('trivy', true), step('semgrep', true, 'sonarqube'), step('nuclei', true), step('triage', false), step('compliance', false)],
      guidelines: ['owasp-api-2023'], version: 2, status: 'saved', default: false },
  ];
  const DEFAULT_POLICY = { id: 'default', name: 'Standard baseline (built in)', applies_when: { category: [], exposure: [], stack: [], tier: [] }, cadence_days: 14,
    steps: [step('trivy', true), step('semgrep', true)], guidelines: [], version: 1, status: 'saved', default: true };

  // The last recorded run of an application: lanes in the v1 Lane shape, the gate result if one was recorded,
  // and per-lane evidence (tool version, commit, SARIF time) for the drawer.
  const cp = S.lanes.filter((l) => l.id !== 'apisec').map((l) => ({ ...l }));
  const by = (id) => cp.find((l) => l.id === id);
  Object.assign(by('semgrep'), { tool: 'CodeQL', summary: 'Imported from codeql.sarif' });
  Object.assign(by('trivy'), { requiredBy: [] }); Object.assign(by('triage'), { requiredBy: [] }); Object.assign(by('swarm'), { requiredBy: [] }); Object.assign(by('semgrep'), { requiredBy: [] });
  by('nuclei').summary = '2 template hits';
  const lastRuns = {
    'card-payments': {
      label: 'Card Payments API, full scan, yesterday', at: 1, lanes: cp,
      gateResult: { effect: 'blocks', text: '2 reproduced exploits are open: SQL injection on POST /payments/refund, and broken object-level authorisation on GET /cards/{id}.' },
      evidence: { semgrep: { tool: 'CodeQL', version: '2.17.4', commit: '9f3c2ab', sarif_at: '18 Oct 2026, 02:14 UTC', note: 'Imported from codeql.sarif. Freshness is the SARIF\'s own time.' },
        trivy: { tool: 'Trivy', version: '0.52.2', commit: '9f3c2ab' }, triage: { tool: 'Triage agent', version: 'docket 0.9' }, swarm: { tool: 'Exploit swarm', version: 'docket 0.9' } },
    },
    'loan-origination': {
      label: 'Loan Origination, full scan, 12 days ago', at: 12, gateResult: null,
      lanes: [
        { id: 'trivy', label: 'Dependencies and secrets', tool: 'Trivy', origin: 'third_party', group: 'pre', state: 'done', icon: 'package', start: 4, end: 51, required: true, candidates: 3 },
        { id: 'semgrep', label: 'Static analysis', tool: 'Semgrep', origin: 'third_party', group: 'pre', state: 'done', icon: 'file-code', start: 51, end: 170, required: true, candidates: 6 },
        { id: 'nuclei', label: 'Web templates', tool: 'Nuclei', origin: 'third_party', group: 'pre', state: 'skipped', icon: 'radar', required: false, summary: 'No staging URL is set' },
        { id: 'recon', label: 'Attack-surface recon', origin: 'henoyo', group: 'agents', state: 'done', icon: 'crosshair', start: 170, end: 240, required: false, summary: '21 routes mapped' },
        { id: 'triage', label: 'Triage', origin: 'henoyo', group: 'agents', state: 'done', icon: 'brain', start: 175, end: 330, required: true, summary: '6 judged: 1 exploitable, 4 not reachable, 1 unsure' },
        { id: 'swarm', label: 'Exploit swarm', origin: 'henoyo', group: 'agents', state: 'not_run', icon: 'crosshair', required: true, summary: 'Not started: the target was not reachable' },
      ],
      evidence: { trivy: { tool: 'Trivy', version: '0.52.1', commit: '41d0e77' }, semgrep: { tool: 'Semgrep', version: '1.78.0', commit: '41d0e77' } },
    },
  };

  window.P = { slots, starts, gate: S.policy.gate, guidelines, profile, apps, policies, DEFAULT_POLICY, lastRuns, matrixSource: S.matrix };
})();
