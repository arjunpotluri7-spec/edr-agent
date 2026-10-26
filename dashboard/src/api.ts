import type { Host, IncidentDetail, IncidentList, Stats } from "./types";

export interface IncidentQuery {
  minScore?: number;
  host?: string;
  label?: string;
}

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
  }
}

// The optional read token (EDR_READ_TOKEN_HASH on the server) is kept in memory only.
let readToken: string | null = null;
export function setReadToken(token: string | null): void {
  readToken = token && token.trim() ? token.trim() : null;
}

async function getJson<T>(path: string, signal?: AbortSignal): Promise<T> {
  const headers: Record<string, string> = { Accept: "application/json" };
  if (readToken) {
    headers.Authorization = `Bearer ${readToken}`;
  }
  const res = await fetch(path, { headers, signal, credentials: "omit" });
  if (!res.ok) {
    throw new ApiError(
      res.status === 401 ? "The server needs a read token." : `Request failed (${res.status}).`,
      res.status,
    );
  }
  return (await res.json()) as T;
}

export function incidentsPath(q: IncidentQuery): string {
  const params = new URLSearchParams();
  if (q.minScore && q.minScore > 0) params.set("min_score", String(q.minScore));
  if (q.host) params.set("host", q.host);
  if (q.label) params.set("label", q.label);
  const qs = params.toString();
  return `/api/v1/incidents${qs ? `?${qs}` : ""}`;
}

export const api = {
  hosts: (signal?: AbortSignal) => getJson<Host[]>("/api/v1/hosts", signal),
  stats: (signal?: AbortSignal) => getJson<Stats>("/api/v1/stats", signal),
  incidents: (q: IncidentQuery, signal?: AbortSignal) =>
    getJson<IncidentList>(incidentsPath(q), signal),
  incident: (id: string, signal?: AbortSignal) =>
    getJson<IncidentDetail>(`/api/v1/incidents/${encodeURIComponent(id)}`, signal),
};
