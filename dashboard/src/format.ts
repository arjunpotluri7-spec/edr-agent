import type { BreakdownItem } from "./types";

export function basename(path: string): string {
  const cut = Math.max(path.lastIndexOf("\\"), path.lastIndexOf("/"));
  return path.slice(cut + 1);
}

export function multiplier(percent: number): string {
  return `x${(percent / 100).toString()}`;
}

// One line per scoring step, e.g. "+40 encoded PowerShell" or "x1.5 correlation: ...".
export function breakdownLine(item: BreakdownItem): { value: string; text: string } {
  switch (item.kind) {
    case "signal":
      return { value: `+${item.points}`, text: `${item.label} (${item.detail})` };
    case "low_cap":
      return { value: String(item.points), text: item.label };
    case "multiplier":
      return {
        value: multiplier(item.multiplier_percent),
        text: `correlation: ${item.correlation} (${item.before} -> ${item.after})`,
      };
    case "bonus":
      return { value: `+${item.points}`, text: `correlation bonus: ${item.correlation}` };
    case "floor":
      return { value: `min ${item.after}`, text: `raised by correlation: ${item.correlation}` };
    case "cap":
      return { value: "= 100", text: item.label };
  }
}

export function shortTime(iso: string): string {
  return iso ? iso.replace("T", " ").replace(/\.\d{3}Z$/, " UTC") : "";
}
