cmake_minimum_required(VERSION 3.25)

project(edr_agent VERSION 0.1.0 DESCRIPTION "Monitor-only endpoint telemetry and detection agent"
        LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(EDR_BUILD_TESTS "Build the GoogleTest suite" ON)
option(EDR_WERROR "Treat compiler warnings as errors" OFF)
option(EDR_ENABLE_WINDOWS_COLLECTORS
       "Build the Sysmon and ETW collectors and the WinHTTP transport (Windows only)" ${WIN32})
set(EDR_SANITIZE "" CACHE STRING "Sanitizers to enable, e.g. address,undefined")

if(EDR_ENABLE_WINDOWS_COLLECTORS AND NOT WIN32)
  message(FATAL_ERROR "EDR_ENABLE_WINDOWS_COLLECTORS=ON needs a Windows toolchain")
endif()

# Warnings and sanitizers apply to this project's targets only, never to GoogleTest.
add_library(edr_flags INTERFACE)
if(MSVC)
  target_compile_options(edr_flags INTERFACE /W4 /permissive- /utf-8 /EHsc)
  target_compile_definitions(edr_flags INTERFACE _CRT_SECURE_NO_WARNINGS UNICODE _UNICODE)
  if(EDR_WERROR)
    target_compile_options(edr_flags INTERFACE /WX)
  endif()
else()
  target_compile_options(edr_flags INTERFACE -Wall -Wextra -Wpedantic -Wshadow -Wconversion
                                             -Wsign-conversion -Wnon-virtual-dtor)
  if(EDR_WERROR)
    target_compile_options(edr_flags INTERFACE -Werror)
  endif()
endif()

if(EDR_SANITIZE)
  add_compile_options(-fsanitize=${EDR_SANITIZE} -fno-omit-frame-pointer -fno-sanitize-recover=all)
  add_link_options(-fsanitize=${EDR_SANITIZE})
endif()

find_package(Threads REQUIRED)

# Portable core: everything except the Windows collectors and transport.
add_library(edr_core STATIC
  src/core/json.cpp
  src/core/log.cpp
  src/core/textutil.cpp
  src/core/xml.cpp
  src/core/yaml.cpp
  src/engine/condition.cpp
  src/engine/encoded_command.cpp
  src/engine/event.cpp
  src/engine/netutil.cpp
  src/engine/rules.cpp
  src/engine/scorer.cpp
  src/collectors/etw_mapping.cpp
  src/collectors/replay_collector.cpp
  src/collectors/sysmon_mapping.cpp
  src/output/agent_config.cpp
  src/output/output.cpp
)
target_include_directories(edr_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(edr_core PUBLIC Threads::Threads PRIVATE edr_flags)

if(EDR_ENABLE_WINDOWS_COLLECTORS)
  target_sources(edr_core PRIVATE
    src/windows/win_common.cpp
    src/windows/sysmon_collector.cpp
    src/windows/etw_collector.cpp
    src/windows/winhttp_transport.cpp
  )
  target_compile_definitions(edr_core PUBLIC EDR_WINDOWS_COLLECTORS=1 WIN32_LEAN_AND_MEAN NOMINMAX)
  target_link_libraries(edr_core PUBLIC wevtapi tdh advapi32 winhttp)
endif()

add_library(edr_cli STATIC src/cli/cli.cpp)
target_include_directories(edr_cli PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/src/cli)
target_compile_definitions(edr_cli PRIVATE EDR_AGENT_VERSION="${PROJECT_VERSION}")
target_link_libraries(edr_cli PUBLIC edr_core PRIVATE edr_flags)

add_executable(edr-agent src/cli/main.cpp)
target_link_libraries(edr-agent PRIVATE edr_cli edr_flags)

include(GNUInstallDirs)
install(TARGETS edr-agent RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

enable_testing()
if(EDR_BUILD_TESTS)
  add_subdirectory(tests)
endif()
