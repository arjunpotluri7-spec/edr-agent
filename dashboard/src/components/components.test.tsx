import { fireEvent, render, screen, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import incident from "../test/fixtures/incident_phishing.json";
import type { IncidentDetail, IncidentSummary } from "../types";
import { IncidentDetailView } from "./IncidentDetailView";
import { IncidentsTable } from "./IncidentsTable";
import { ScoreBreakdown } from "./ScoreBreakdown";

const detail = incident as unknown as IncidentDetail;

describe("ScoreBreakdown", () => {
  it("lists each contribution of the real phishing-chain incident", () => {
    render(<ScoreBreakdown items={detail.breakdown} score={detail.score} />);
    const list = screen.getByRole("list");
    const items = within(list).getAllByRole("listitem");
    expect(items[0]).toHaveTextContent("+40");
    expect(items[0]).toHaveTextContent("PowerShell launched with an encoded command");
    expect(list).toHaveTextContent("+35Outbound connection not in the host baseline (203.0.113.50:8443 not in baseline for powershell.exe)");
    expect(list).toHaveTextContent("x1.5correlation: encoded-ps-then-network (163 -> 245)");
    expect(items[items.length - 1]).toHaveTextContent("= 100");
  });
});

describe("IncidentsTable", () => {
  const rows: IncidentSummary[] = [
    { ...detail, id: "inc-0000000000000001" },
    { ...detail, id: "inc-0000000000000002", score: 55, label: "medium", score_mismatch: true, agent_score: 12, server_score: 55 },
  ];

  it("renders rows and opens an incident", () => {
    const onOpen = vi.fn();
    render(<IncidentsTable items={rows} onOpen={onOpen} />);
    expect(screen.getByRole("table", { name: /highest score first/i })).toBeInTheDocument();
    expect(screen.getByLabelText("score 100, critical")).toBeInTheDocument();
    expect(screen.getByText(/agent 12 \/ server 55/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /details for inc-0000000000000002/i }));
    expect(onOpen).toHaveBeenCalledWith("inc-0000000000000002");
  });

  it("shows an empty state", () => {
    render(<IncidentsTable items={[]} onOpen={() => undefined} />);
    expect(screen.getByText(/no incidents match/i)).toBeInTheDocument();
  });
});

describe("IncidentDetailView", () => {
  it("shows the process tree, decoded evidence and correlations", () => {
    render(<IncidentDetailView incident={detail} onBack={() => undefined} />);
    const tree = screen.getByRole("region", { name: "Process tree" });
    expect(within(tree).getByText("OUTLOOK.EXE")).toBeInTheDocument();
    expect(within(tree).getByText("powershell.exe")).toBeInTheDocument();
    expect(screen.getByText("Encoded PowerShell followed by an anomalous outbound connection")).toBeInTheDocument();
    expect(screen.getByText("Write-Output 'edr-agent demo: simulated download cradle'")).toBeInTheDocument();
  });
});
