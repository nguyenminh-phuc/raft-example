# References
# https://github.com/sunsided/cmake
# https://pabloariasal.github.io/2018/02/19/its-time-to-do-cmake-right/
# https://atomheartother.github.io/c++/2018/07/12/CPPDynLib.html
# https://foonathan.net/2016/03/cmake-install/
cmake_minimum_required(VERSION 3.17)
project(mini-distributed-dns)

include(FeatureSummary)
include(GNUInstallDirs)

if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug CACHE STRING "Build types: Debug, Release, RelWithDebInfo and MinSizeRel" FORCE)
endif ()

# If no installation prefix is given manually, install locally.
if (CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
    set(CMAKE_INSTALL_PREFIX "${CMAKE_BINARY_DIR}/install" CACHE STRING "Install location" FORCE)
endif ()

set(INSTALL_CONFIGDIR ${CMAKE_INSTALL_LIBDIR}/cmake)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

option(BUILD_SHARED_LIBS "Build shared library" ON)
option(ENABLE_ASAN "Enable AddressSanitizer" OFF)
option(ENABLE_MSAN "Enable MemorySanitizer" OFF)
option(ENABLE_TSAN "Enable ThreadSanitizer" OFF)
option(ENABLE_UBSAN "Enable UndefinedBehaviorSanitizer" OFF)

add_subdirectory(minidns)
add_subdirectory(dns_client)
add_subdirectory(dns_server)
add_subdirectory(rpc_client)

if (TARGET minidns::minidns)
    feature_summary(WHAT ALL)
endif ()
