// Shapes returned by the edr_server read API (see server/src/edr_server/app.py).

export type Label = "low" | "medium" | "high" | "critical";

export interface Host {
  name: string;
  agent_id: string;
  first_seen: string;
  last_seen: string;
  event_count: number;
  incident_count: number;
  max_score: number | null;
}

export interface IncidentSummary {
  id: string;
  host: string;
  score: number;
  label: Label;
  agent_score: number | null;
  server_score: number | null;
  score_mismatch: boolean;
  first_seen: string;
  last_seen: string;
  root_image: string;
  root_pid: number;
  signal_count: number;
  attack: string[];
}

export interface Signal {
  rule_id: string;
  title: string;
  severity: Label;
  points: number;
  base_points: number;
  repeat: number;
  ts: string;
  pid: number;
  image: string;
  event_id: string;
  detail: string;
  attack: string[];
}

export type BreakdownItem =
  | { kind: "signal"; rule_id: string; label: string; detail: string; points: number }
  | { kind: "low_cap"; label: string; points: number }
  | {
      kind: "multiplier";
      correlation: string;
      label: string;
      multiplier_percent: number;
      before: number;
      after: number;
    }
  | { kind: "bonus"; correlation: string; label: string; points: number; after: number }
  | { kind: "floor"; correlation: string; label: string; after: number }
  | { kind: "cap"; label: string; after: number };

export interface TreeNode {
  pid: number;
  ppid: number | null;
  image: string;
  command_line: string;
  start: string | null;
  depth: number;
}

export interface Correlation {
  id: string;
  title: string;
  multiplier_percent: number;
  bonus: number;
  min_score: number;
}

export type EvidenceEvent = Record<string, string | number | boolean | null> & {
  id: string;
  ts: string;
  type: string;
};

export interface IncidentDetail extends IncidentSummary {
  signals: Signal[];
  correlations: Correlation[];
  breakdown: BreakdownItem[];
  process_tree: TreeNode[];
  evidence: EvidenceEvent[];
}

export interface IncidentList {
  total: number;
  items: IncidentSummary[];
}

export interface Stats {
  hosts: number;
  events: number;
  incidents: number;
  incidents_by_label: Partial<Record<Label, number>>;
  score_mismatches: number;
  incident_threshold: number;
}
