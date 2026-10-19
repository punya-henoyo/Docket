/** The Code Security endpoints (engine/docket/portfolio). Everything is computed server-side. */
import type {
  ApplicationDetail, Catalog, PipelineDetail, PolicyBody, PolicyListPayload, PolicyPayload, PolicyPreview, Portfolio, PortfolioFinding,
} from "../portfolio";
import { req } from "./client";

export const getPortfolio = () => req<Portfolio>("/api/portfolio");
export const getApplication = (id: string) => req<ApplicationDetail>(`/api/application/${encodeURIComponent(id)}`);
export const getPipeline = (run: string) => req<PipelineDetail>(`/api/pipeline/${encodeURIComponent(run)}`);
export const getFindings = () => req<{ findings: PortfolioFinding[] }>("/api/findings").then((r) => r.findings);
export const getPolicy = () => req<PolicyPayload>("/api/policy");

/* ── Policies builder ──────────────────────────────────────────────────────────────────────────── */
export const getCatalog = () => req<Catalog>("/api/catalog");
export const getPolicies = (policy?: string) =>
  req<PolicyListPayload>(policy ? `/api/policy?policy=${encodeURIComponent(policy)}` : "/api/policy");

/** A write that reports the server's own reasons. `req` keeps only one message and throws on 4xx; a
 *  refused save has a LIST of reasons ({errors}) the author must see next to the draft. */
export interface Written<T> { ok: boolean; status: number; body: T | null; errors: string[] }
async function write<T>(method: string, path: string, body?: unknown): Promise<Written<T>> {
  let res: Response;
  try {
    res = await fetch(path, {
      method, cache: "no-store", headers: { "Content-Type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch {
    return { ok: false, status: 0, body: null, errors: ["Cannot reach the docket server. Is `docket connect` running?"] };
  }
  let payload: unknown = null;
  try { payload = await res.json(); } catch { /* an empty or non-JSON body is reported below */ }
  const o = (payload && typeof payload === "object" ? payload : {}) as { errors?: unknown; error?: unknown };
  const errors = Array.isArray(o.errors) ? o.errors.map(String) : o.error ? [String(o.error)] : [];
  if (!res.ok && errors.length === 0) errors.push(`The server refused the request (${res.status}).`);
  return { ok: res.ok, status: res.status, body: res.ok ? (payload as T) : null, errors };
}
export const previewPolicy = (draft: PolicyBody) => write<PolicyPreview>("POST", "/api/policy/preview", draft);
export const savePolicy = (draft: PolicyBody) =>
  write<{ id: string; version: number; created: boolean; warnings: string[] }>("PUT", `/api/policy/${encodeURIComponent(draft.id)}`, draft);
export const deletePolicy = (id: string) => write<{ id: string; deleted: boolean }>("DELETE", `/api/policy/${encodeURIComponent(id)}`);
