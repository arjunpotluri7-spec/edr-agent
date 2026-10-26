import { render, screen, waitFor, fireEvent } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import App from "./App";
import incident from "./test/fixtures/incident_phishing.json";

const summary = {
  id: incident.id,
  host: incident.host,
  score: incident.score,
  label: incident.label,
  agent_score: 100,
  server_score: 100,
  score_mismatch: false,
  first_seen: incident.first_seen,
  last_seen: incident.last_seen,
  root_image: incident.root_image,
  root_pid: incident.root_pid,
  signal_count: incident.signal_count,
  attack: incident.attack,
};

function mockFetch() {
  const calls: string[] = [];
  const fetchMock = vi.fn(async (url: string) => {
    calls.push(url);
    const body = url.startsWith("/api/v1/hosts")
      ? [{ name: "WS-ALICE-01", agent_id: "a", first_seen: "2026-10-20T09:00:00+00:00", last_seen: "2026-10-20T09:20:00+00:00", event_count: 11, incident_count: 1, max_score: 100 }]
      : url.startsWith("/api/v1/stats")
        ? { hosts: 1, events: 11, incidents: 1, incidents_by_label: { critical: 1 }, score_mismatches: 0, incident_threshold: 50 }
        : url.startsWith("/api/v1/incidents/")
          ? incident
          : { total: 1, items: [summary] };
    return new Response(JSON.stringify(body), { status: 200, headers: { "Content-Type": "application/json" } });
  });
  vi.stubGlobal("fetch", fetchMock);
  return calls;
}

afterEach(() => {
  vi.unstubAllGlobals();
  window.location.hash = "";
});

describe("App", () => {
  it("loads hosts, stats and incidents, then filters by host", async () => {
    const calls = mockFetch();
    render(<App />);
    expect(await screen.findByText("WS-ALICE-01", { selector: ".host-name" })).toBeInTheDocument();
    expect(screen.getByText(/incidents \(threshold 50\)/)).toBeInTheDocument();
    expect(await screen.findByLabelText("score 100, critical")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /WS-ALICE-01/ }));
    await waitFor(() => expect(calls).toContain("/api/v1/incidents?host=WS-ALICE-01"));
  });

  it("opens the incident detail view", async () => {
    mockFetch();
    render(<App />);
    fireEvent.click(await screen.findByRole("button", { name: /details for/i }));
    expect(await screen.findByRole("heading", { name: /Score breakdown/ })).toBeInTheDocument();
    expect(window.location.hash).toBe(`#/incidents/${incident.id}`);
  });

  it("shows a readable error when the server is unreachable", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => { throw new TypeError("network"); }));
    render(<App />);
    expect(await screen.findByText("Could not reach the EDR server.")).toBeInTheDocument();
  });
});
