/** CWE identifiers carry no meaning on screen without their names, and "CWE-668" is
 *  not something a developer should have to go look up mid-triage.
 *
 *  Deliberately a curated list rather than a scraped full catalogue: only entries
 *  whose meaning is stated confidently belong here, because a WRONG name on a
 *  security finding is worse than no name. Anything unlisted renders as the bare id
 *  and still links out to MITRE, so coverage gaps degrade quietly.
 *
 *  Names are shortened to what fits a table cell; MITRE's official titles are longer. */
const NAMES: Record<string, string> = {
  "CWE-22": "Path traversal",
  "CWE-78": "OS command injection",
  "CWE-79": "Cross-site scripting",
  "CWE-89": "SQL injection",
  "CWE-94": "Code injection",
  "CWE-95": "Eval injection",
  "CWE-96": "Static code injection",
  "CWE-120": "Buffer overflow",
  "CWE-125": "Out-of-bounds read",
  "CWE-250": "Execution with unnecessary privileges",
  "CWE-269": "Improper privilege management",
  "CWE-276": "Incorrect default permissions",
  "CWE-287": "Improper authentication",
  "CWE-295": "Improper certificate validation",
  "CWE-306": "Missing auth for critical function",
  "CWE-311": "Missing encryption of sensitive data",
  "CWE-319": "Cleartext transmission",
  "CWE-321": "Hard-coded cryptographic key",
  "CWE-327": "Broken or risky crypto",
  "CWE-352": "Cross-site request forgery",
  "CWE-377": "Insecure temporary file",
  "CWE-416": "Use after free",
  "CWE-434": "Unrestricted file upload",
  "CWE-489": "Active debug code",
  "CWE-502": "Deserialization of untrusted data",
  "CWE-538": "Sensitive info in accessible file",
  "CWE-601": "Open redirect",
  "CWE-611": "XML external entity (XXE)",
  "CWE-639": "Authorization bypass via user key",
  "CWE-668": "Resource exposed to wrong sphere",
  "CWE-704": "Incorrect type conversion",
  "CWE-706": "Incorrectly resolved name or reference",
  "CWE-787": "Out-of-bounds write",
  "CWE-798": "Hard-coded credentials",
  "CWE-862": "Missing authorization",
  "CWE-863": "Incorrect authorization",
  "CWE-915": "Uncontrolled object attribute modification",
  "CWE-916": "Weak password hashing",
  "CWE-918": "Server-side request forgery",
  "CWE-939": "Improper authorization in URL scheme handler",
  "CWE-1333": "Inefficient regex (ReDoS)",
  "CWE-1357": "Reliance on untrustworthy component",
};

export const cweName = (id: string): string | null => NAMES[id] ?? null;

export const cweLabel = (id: string): string => {
  const name = cweName(id);
  return name ? `${id} · ${name}` : id;
};

/** MITRE's own page. `CWE-89` -> .../definitions/89.html */
export const cweUrl = (id: string): string =>
  `https://cwe.mitre.org/data/definitions/${id.replace(/^CWE-/i, "")}.html`;
