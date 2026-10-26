import type { IncidentSummary } from "../types";
import { basename, shortTime } from "../format";
import { ScoreBadge } from "./ScoreBadge";

interface Props {
  items: IncidentSummary[];
  onOpen: (id: string) => void;
}

export function IncidentsTable({ items, onOpen }: Props) {
  if (items.length === 0) {
    return <p className="muted">No incidents match these filters.</p>;
  }
  return (
    <div className="table-wrap">
      <table>
        <caption>Incidents, highest score first</caption>
        <thead>
          <tr>
            <th scope="col">Score</th>
            <th scope="col">Host</th>
            <th scope="col">Root process</th>
            <th scope="col">Signals</th>
            <th scope="col">Last activity</th>
            <th scope="col">
              <span className="sr-only">Open</span>
            </th>
          </tr>
        </thead>
        <tbody>
          {items.map((inc) => (
            <tr key={inc.id}>
              <td>
                <ScoreBadge score={inc.score} label={inc.label} />
                {inc.score_mismatch && (
                  <span className="warn small" title="Agent and server scores differ">
                    {" "}
                    agent {inc.agent_score ?? "-"} / server {inc.server_score ?? "-"}
                  </span>
                )}
              </td>
              <td>{inc.host}</td>
              <td>
                <code>{basename(inc.root_image)}</code> <span className="muted">({inc.root_pid})</span>
              </td>
              <td>{inc.signal_count}</td>
              <td>{shortTime(inc.last_seen)}</td>
              <td>
                <button
                  type="button"
                  className="link"
                  aria-label={`Details for ${inc.id}`}
                  onClick={() => onOpen(inc.id)}
                >
                  Details
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
