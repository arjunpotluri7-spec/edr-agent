import type { Label } from "../types";

export function ScoreBadge({ score, label }: { score: number; label: Label }) {
  return (
    <span className={`badge badge-${label}`} aria-label={`score ${score}, ${label}`}>
      <strong>{score}</strong> {label}
    </span>
  );
}
