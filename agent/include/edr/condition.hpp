// Evaluates a rule condition against an enriched event (mirrors engine/conditions.py).
#pragma once

#include "edr/event.hpp"
#include "edr/rules.hpp"

namespace edr {

// Regex subjects are truncated to this many bytes so a huge command line cannot stall matching.
inline constexpr std::size_t kMaxRegexInput = 4096;

bool evaluate(const Condition& condition, const Event& event);

}  // namespace edr
