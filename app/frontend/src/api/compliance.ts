/** Control packs: list, read, upload a policy, delete an uploaded one.
 *
 *  The upload sends the file's RAW BYTES with the name in the query string, not
 *  multipart/form-data. That is not a shortcut: it keeps a form-encoding dependency out
 *  of a Python backend that has four runtime packages, and it means the identical
 *  handler serves both of docket's servers. Do not "fix" this into a FormData post.
 */
import { ApiError, req } from "./client";
import type { ControlPack, PackSummary } from "../types";

export const listPacks = () => req<{ packs: PackSummary[] }>("/api/compliance/packs");

export const getPack = (id: string) =>
  req<{ pack: ControlPack }>(`/api/compliance/packs/${encodeURIComponent(id)}`);

export interface UploadResult {
  pack: ControlPack;
  path: string;
  /** Clauses that did NOT become controls, with the reason. Shown, never hidden: these
   *  are the customer's own requirements, and they must see what was left out before
   *  anything is audited against the pack. */
  dropped: { title: string; reason: string }[];
  truncated: boolean;
  /** The backend's own one-line summary. Rendered verbatim so the console cannot state
   *  a different count from the one the pack actually holds. */
  summary: string;
}

/** Upload a policy document. An agent compiles it into a reviewable pack, so this is
 *  slower than a normal call — seconds, not milliseconds. */
export async function uploadPack(file: File): Promise<UploadResult> {
  const body = await file.arrayBuffer();
  return req<UploadResult>(
    `/api/compliance/packs?filename=${encodeURIComponent(file.name)}`,
    {
      method: "POST",
      headers: { "Content-Type": "application/octet-stream" },
      body,
    },
  );
}

/** Paste-instead-of-upload. Same endpoint; the name only has to carry an extension the
 *  backend can route on. */
export const uploadPolicyText = (name: string, text: string) =>
  req<UploadResult>(
    `/api/compliance/packs?filename=${encodeURIComponent(name.endsWith(".md") ? name : `${name}.md`)}`,
    {
      method: "POST",
      headers: { "Content-Type": "application/octet-stream" },
      body: new TextEncoder().encode(text),
    },
  );

export const deletePack = (id: string) =>
  req<{ deleted: string }>(`/api/compliance/packs/${encodeURIComponent(id)}`, {
    method: "DELETE",
  });

export { ApiError };
