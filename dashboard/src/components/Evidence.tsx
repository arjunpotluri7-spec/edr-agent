import type { EvidenceEvent } from "../types";
import { shortTime } from "../format";

const SKIP = new Set(["id", "ts", "type", "host", "source", "process_guid", "parent_process_guid"]);

export function Evidence({ events }: { events: EvidenceEvent[] }) {
  return (
    <section aria-labelledby="evidence-h">
      <h3 id="evidence-h">Evidence events</h3>
      {events.map((ev) => (
        <details key={ev.id} className="evidence">
          <summary>
            <code>{ev.type}</code> {shortTime(ev.ts)} <span className="muted">{ev.id}</span>
          </summary>
          <dl>
            {Object.entries(ev)
              .filter(([k, v]) => !SKIP.has(k) && v !== null && v !== "")
              .map(([k, v]) => (
                <div key={k} className="kv">
                  <dt>{k}</dt>
                  <dd>{String(v)}</dd>
                </div>
              ))}
          </dl>
        </details>
      ))}
    </section>
  );
}
