#!/usr/bin/env bash
# Runs the same lint steps as CI: clang-format on all C++ sources, clang-tidy on the portable
# sources. Expects the pinned tools from tools/requirements.txt on PATH (for example
# ../.tools/bin) and a configured dev build (cmake --preset dev) for compile_commands.json.
# The Windows-only sources are compiled (and warned on) by the MSVC CI job instead.
set -euo pipefail
cd "$(dirname "$0")/.."

sources=$(find src include tests -name '*.cpp' -o -name '*.hpp' | sort)
clang-format --dry-run --Werror $sources
echo "clang-format: ok"

extra=()
if [[ "$(uname)" == "Darwin" ]]; then
  # The pip clang-tidy does not know the macOS SDK; point it at the SDK and its libc++ headers.
  sdk=$(xcrun --show-sdk-path)
  extra=(--extra-arg="-isysroot${sdk}" --extra-arg="-isystem${sdk}/usr/include/c++/v1")
fi
tidy_sources=$(find src/core src/engine src/collectors src/output src/cli -name '*.cpp' | sort)
clang-tidy -p build/dev --quiet "${extra[@]}" $tidy_sources
echo "clang-tidy: ok"
