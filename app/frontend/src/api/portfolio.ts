/** The Code Security endpoints (engine/docket/portfolio). Everything is computed server-side. */
import type { ApplicationDetail, PipelineDetail, PolicyPayload, Portfolio, PortfolioFinding } from "../portfolio";
import { req } from "./client";

export const getPortfolio = () => req<Portfolio>("/api/portfolio");
export const getApplication = (id: string) => req<ApplicationDetail>(`/api/application/${encodeURIComponent(id)}`);
export const getPipeline = (run: string) => req<PipelineDetail>(`/api/pipeline/${encodeURIComponent(run)}`);
export const getFindings = () => req<{ findings: PortfolioFinding[] }>("/api/findings").then((r) => r.findings);
export const getPolicy = () => req<PolicyPayload>("/api/policy");
