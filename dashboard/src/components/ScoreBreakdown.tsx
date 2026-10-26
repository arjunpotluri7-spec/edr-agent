import type { BreakdownItem } from "../types";
import { breakdownLine } from "../format";

export function ScoreBreakdown({ items, score }: { items: BreakdownItem[]; score: number }) {
  return (
    <section aria-labelledby="breakdown-h">
      <h3 id="breakdown-h">Score breakdown</h3>
      <ol className="breakdown">
        {items.map((item, i) => {
          const line = breakdownLine(item);
          return (
            <li key={i} className={`step step-${item.kind}`}>
              <span className="step-value">{line.value}</span>
              <span>{line.text}</span>
            </li>
          );
        })}
        <li className="step step-total">
          <span className="step-value">= {score}</span>
          <span>final score</span>
        </li>
      </ol>
    </section>
  );
}
