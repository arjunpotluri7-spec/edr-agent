include(FetchContent)

set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
set(BUILD_GMOCK OFF CACHE BOOL "" FORCE)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_Declare(
  googletest
  GIT_REPOSITORY https://github.com/google/googletest.git
  GIT_TAG v1.18.0
  GIT_SHALLOW TRUE
  SYSTEM  # GoogleTest headers are not subject to our warnings-as-errors (matters for MSVC /WX)
)
FetchContent_MakeAvailable(googletest)

add_executable(edr_tests
  test_cli.cpp
  test_config.cpp
  test_encoded.cpp
  test_etw.cpp
  test_json_yaml.cpp
  test_netutil.cpp
  test_output.cpp
  test_replay.cpp
  test_rules.cpp
  test_scorer.cpp
  test_sysmon.cpp
  test_xml.cpp
)
target_link_libraries(edr_tests PRIVATE edr_cli edr_core edr_flags GTest::gtest_main)
# Repository root (samples/ and rules/ live there, next to agent/).
cmake_path(GET PROJECT_SOURCE_DIR PARENT_PATH EDR_REPO_ROOT)
target_compile_definitions(edr_tests PRIVATE EDR_REPO_DIR="${EDR_REPO_ROOT}"
                                             EDR_TEST_DIR="${CMAKE_CURRENT_SOURCE_DIR}")

include(GoogleTest)
gtest_discover_tests(edr_tests DISCOVERY_TIMEOUT 60 WORKING_DIRECTORY ${EDR_REPO_ROOT})

# The committed samples must be exactly what samples/tools/generate_samples.py produces.
find_package(Python3 COMPONENTS Interpreter)
if(Python3_Interpreter_FOUND)
  add_test(NAME samples_generate_check
           COMMAND ${Python3_EXECUTABLE} ${EDR_REPO_ROOT}/samples/tools/generate_samples.py --check)
endif()
