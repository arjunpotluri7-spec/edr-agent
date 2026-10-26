import type { IncidentDetail } from "../types";
import { basename, shortTime } from "../format";
import { Evidence } from "./Evidence";
import { ProcessTree } from "./ProcessTree";
import { ScoreBadge } from "./ScoreBadge";
import { ScoreBreakdown } from "./ScoreBreakdown";

export function IncidentDetailView({
  incident,
  onBack,
}: {
  incident: IncidentDetail;
  onBack: () => void;
}) {
  return (
    <article aria-labelledby="incident-h">
      <button type="button" className="link" onClick={onBack}>
        Back to incidents
      </button>
      <h2 id="incident-h">
        {incident.host}: {basename(incident.root_image)} <ScoreBadge score={incident.score} label={incident.label} />
      </h2>
      <p className="muted">
        {incident.id} | {shortTime(incident.first_seen)} to {shortTime(incident.last_seen)} | agent score{" "}
        {incident.agent_score ?? "not reported"}, server score {incident.server_score ?? "not computed"}
      </p>
      {incident.score_mismatch && (
        <p className="warn" role="status">
          The agent and the server scored this incident differently. The server's score is shown.
        </p>
      )}
      <div className="grid">
        <ScoreBreakdown items={incident.breakdown} score={incident.score} />
        <section aria-labelledby="signals-h">
          <h3 id="signals-h">Signals</h3>
          <ul className="signals">
            {incident.signals.map((s, i) => (
              <li key={`${s.event_id}-${s.rule_id}-${i}`}>
                <strong>{s.title}</strong> <span className="muted">({s.rule_id}, {s.severity})</span>
                <div className="small">
                  {shortTime(s.ts)} | {basename(s.image)} pid {s.pid} | {s.attack.join(", ")}
                  {s.repeat > 0 ? ` | repeat ${s.repeat}` : ""}
                </div>
              </li>
            ))}
          </ul>
          {incident.correlations.length > 0 && (
            <>
              <h4>Correlations</h4>
              <ul>
                {incident.correlations.map((c) => (
                  <li key={c.id}>
                    {c.title} <span className="muted">({c.id})</span>
                  </li>
                ))}
              </ul>
            </>
          )}
        </section>
      </div>
      <ProcessTree nodes={incident.process_tree} />
      <Evidence events={incident.evidence} />
    </article>
  );
}
