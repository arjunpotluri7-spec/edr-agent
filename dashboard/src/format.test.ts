import { describe, expect, it } from "vitest";
import { basename, breakdownLine, multiplier } from "./format";

describe("format", () => {
  it("formats every breakdown step", () => {
    expect(
      breakdownLine({ kind: "signal", rule_id: "r", label: "Encoded PowerShell", detail: "powershell.exe", points: 40 }),
    ).toEqual({ value: "+40", text: "Encoded PowerShell (powershell.exe)" });
    expect(
      breakdownLine({ kind: "multiplier", correlation: "encoded-ps-then-network", label: "x", multiplier_percent: 150, before: 75, after: 113 }),
    ).toEqual({ value: "x1.5", text: "correlation: encoded-ps-then-network (75 -> 113)" });
    expect(breakdownLine({ kind: "low_cap", label: "capped", points: -5 }).value).toBe("-5");
    expect(breakdownLine({ kind: "bonus", correlation: "c", label: "b", points: 15, after: 55 }).value).toBe("+15");
    expect(breakdownLine({ kind: "floor", correlation: "c", label: "f", after: 60 }).value).toBe("min 60");
    expect(breakdownLine({ kind: "cap", label: "score capped at 100", after: 100 }).value).toBe("= 100");
  });

  it("handles paths and multipliers", () => {
    expect(basename("C:\\Windows\\System32\\cmd.exe")).toBe("cmd.exe");
    expect(basename("/usr/bin/x")).toBe("x");
    expect(multiplier(125)).toBe("x1.25");
  });
});
