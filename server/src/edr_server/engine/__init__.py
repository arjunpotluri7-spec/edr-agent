"""Python implementation of the EDR Agent detection and scoring engine.

It mirrors the C++ engine in agent/src/engine exactly (same rules, same integer scoring), so
the server can re-score incoming telemetry and flag any disagreement with the agent.
"""

from edr_server.engine.config import RuleSet, Scoring, load_baseline, load_rules, load_scoring
from edr_server.engine.scorer import Engine

__all__ = ["Engine", "RuleSet", "Scoring", "load_baseline", "load_rules", "load_scoring"]
