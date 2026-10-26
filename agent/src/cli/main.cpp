#include <string>
#include <vector>

#include "cli.hpp"

int main(int argc, char** argv) try {
  std::vector<std::string> args;
  args.reserve(static_cast<std::size_t>(argc > 0 ? argc - 1 : 0));
  for (int i = 1; i < argc; ++i) {
    args.emplace_back(argv[i]);  // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
  }
  return edr::cli::main_impl(args);
} catch (...) {
  return 3;  // main_impl reports its own errors; this only guards allocation failures
}
