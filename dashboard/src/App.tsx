import { useCallback, useEffect, useState } from "react";
import { api, ApiError, setReadToken } from "./api";
import { HostsList } from "./components/HostsList";
import { IncidentDetailView } from "./components/IncidentDetailView";
import { IncidentsTable } from "./components/IncidentsTable";
import type { Host, IncidentDetail, IncidentList, Stats } from "./types";

type Theme = "system" | "light" | "dark";

function incidentFromHash(): string | null {
  const m = /^#\/incidents\/(inc-[0-9a-f]{16})$/.exec(window.location.hash);
  return m ? (m[1] ?? null) : null;
}

export default function App() {
  const [hosts, setHosts] = useState<Host[]>([]);
  const [stats, setStats] = useState<Stats | null>(null);
  const [list, setList] = useState<IncidentList | null>(null);
  const [detail, setDetail] = useState<IncidentDetail | null>(null);
  const [openId, setOpenId] = useState<string | null>(incidentFromHash());
  const [host, setHost] = useState("");
  const [minScore, setMinScore] = useState(0);
  const [label, setLabel] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [theme, setTheme] = useState<Theme>("system");
  const [token, setToken] = useState("");
  const [refresh, setRefresh] = useState(0);

  useEffect(() => {
    if (theme === "system") {
      delete document.documentElement.dataset.theme;
    } else {
      document.documentElement.dataset.theme = theme;
    }
  }, [theme]);

  useEffect(() => {
    const onHash = () => setOpenId(incidentFromHash());
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);

  const fail = useCallback((e: unknown) => {
    if (e instanceof DOMException && e.name === "AbortError") return;
    setError(e instanceof ApiError ? e.message : "Could not reach the EDR server.");
  }, []);

  useEffect(() => {
    const ctrl = new AbortController();
    Promise.all([api.hosts(ctrl.signal), api.stats(ctrl.signal)])
      .then(([h, s]) => {
        setHosts(h);
        setStats(s);
        setError(null);
      })
      .catch(fail);
    return () => ctrl.abort();
  }, [fail, refresh]);

  useEffect(() => {
    const ctrl = new AbortController();
    api
      .incidents({ minScore, host, label }, ctrl.signal)
      .then(setList)
      .catch(fail);
    return () => ctrl.abort();
  }, [minScore, host, label, fail, refresh]);

  useEffect(() => {
    if (!openId) {
      return;
    }
    const ctrl = new AbortController();
    api.incident(openId, ctrl.signal).then(setDetail).catch(fail);
    return () => ctrl.abort();
  }, [openId, fail, refresh]);

  const loading = stats === null && error === null;
  // Only show a detail that belongs to the incident currently in the URL.
  const shown = detail && detail.id === openId ? detail : null;

  const open = (id: string) => {
    window.location.hash = `#/incidents/${id}`;
    setOpenId(id);
  };
  const back = () => {
    window.location.hash = "";
    setOpenId(null);
  };

  return (
    <div className="app">
      <header className="top">
        <h1>EDR Agent</h1>
        <p className="muted small">Monitor-only telemetry and risk scoring</p>
        <div className="top-controls">
          <label>
            Theme{" "}
            <select value={theme} onChange={(e) => setTheme(e.target.value as Theme)}>
              <option value="system">System</option>
              <option value="light">Light</option>
              <option value="dark">Dark</option>
            </select>
          </label>
          <form
            onSubmit={(e) => {
              e.preventDefault();
              setReadToken(token);
              setRefresh((n) => n + 1);
            }}
          >
            <label>
              Read token{" "}
              <input
                type="password"
                autoComplete="off"
                value={token}
                onChange={(e) => setToken(e.target.value)}
                placeholder="only if the server requires one"
              />
            </label>{" "}
            <button type="submit">Apply</button>
          </form>
        </div>
      </header>

      {stats && (
        <ul className="stats" aria-label="Summary">
          <li>
            <strong>{stats.hosts}</strong> hosts
          </li>
          <li>
            <strong>{stats.events}</strong> events
          </li>
          <li>
            <strong>{stats.incidents}</strong> incidents (threshold {stats.incident_threshold})
          </li>
          <li className={stats.score_mismatches > 0 ? "warn" : undefined}>
            <strong>{stats.score_mismatches}</strong> agent/server score mismatches
          </li>
        </ul>
      )}

      <div role="status" aria-live="polite" className="status">
        {loading ? "Loading..." : ""}
        {error && <span className="error">{error}</span>}
      </div>

      <div className="layout">
        <aside>
          <h2>Hosts</h2>
          <HostsList hosts={hosts} selected={host} onSelect={setHost} />
        </aside>
        <main>
          {shown ? (
            <IncidentDetailView incident={shown} onBack={back} />
          ) : (
            <>
              <h2>Incidents</h2>
              <form className="filters" aria-label="Filters" onSubmit={(e) => e.preventDefault()}>
                <label>
                  Minimum score{" "}
                  <input
                    type="number"
                    min={0}
                    max={100}
                    value={minScore}
                    onChange={(e) => setMinScore(Math.max(0, Math.min(100, Number(e.target.value) || 0)))}
                  />
                </label>
                <label>
                  Label{" "}
                  <select value={label} onChange={(e) => setLabel(e.target.value)}>
                    <option value="">Any</option>
                    <option value="critical">critical</option>
                    <option value="high">high</option>
                    <option value="medium">medium</option>
                    <option value="low">low</option>
                  </select>
                </label>
                <label>
                  Host{" "}
                  <select value={host} onChange={(e) => setHost(e.target.value)}>
                    <option value="">All hosts</option>
                    {hosts.map((h) => (
                      <option key={h.name} value={h.name}>
                        {h.name}
                      </option>
                    ))}
                  </select>
                </label>
              </form>
              {list && <IncidentsTable items={list.items} onOpen={open} />}
            </>
          )}
        </main>
      </div>
    </div>
  );
}
