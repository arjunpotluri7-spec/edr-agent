import type { Host } from "../types";
import { shortTime } from "../format";

interface Props {
  hosts: Host[];
  selected: string;
  onSelect: (host: string) => void;
}

export function HostsList({ hosts, selected, onSelect }: Props) {
  if (hosts.length === 0) {
    return <p className="muted">No hosts have reported yet.</p>;
  }
  return (
    <ul className="hosts" aria-label="Hosts">
      {hosts.map((h) => (
        <li key={h.name}>
          <button
            type="button"
            className={h.name === selected ? "host active" : "host"}
            aria-pressed={h.name === selected}
            onClick={() => onSelect(h.name === selected ? "" : h.name)}
          >
            <span className="host-name">{h.name}</span>
            <span className="muted small">
              {h.event_count} events, {h.incident_count} incident{h.incident_count === 1 ? "" : "s"}
              {h.max_score !== null ? `, max ${h.max_score}` : ""}
            </span>
            <span className="muted small">last seen {shortTime(h.last_seen.slice(0, 19))}</span>
          </button>
        </li>
      ))}
    </ul>
  );
}
