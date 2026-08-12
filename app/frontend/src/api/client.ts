/** The one fetch wrapper. Every API module goes through it, so error handling and the
 *  "backend is not running" case are stated once.
 *
 *  There is no mock layer and no fixture data anywhere in this console: if the backend
 *  is down, calls reject and the UI says so rather than inventing a dashboard. A
 *  security tool that shows plausible-looking numbers when it is disconnected is worse
 *  than one that shows an error.
 */

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

export async function req<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response;
  try {
    response = await fetch(path, { cache: "no-store", ...init });
  } catch {
    throw new ApiError("Cannot reach the docket server. Is `docket connect` running?", 0);
  }
  const text = await response.text();
  let payload: unknown = null;
  try {
    payload = text ? JSON.parse(text) : null;
  } catch {
    throw new ApiError(`Unexpected non-JSON response from ${path}`, response.status);
  }
  if (!response.ok) {
    // Both backends report a reason; FastAPI uses `detail`, the connect server `error`.
    // Surfacing it is the difference between "refused" and "refused because the target
    // is not loopback".
    const detail =
      payload && typeof payload === "object"
        ? String(
            (payload as Record<string, unknown>).detail ??
              (payload as Record<string, unknown>).error ??
              `Request failed (${response.status})`,
          )
        : `Request failed (${response.status})`;
    throw new ApiError(detail, response.status);
  }
  return payload as T;
}

export const postJson = <T>(path: string, body: unknown) =>
  req<T>(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
