cmake_minimum_required(VERSION 3.17)
project(minidns VERSION 0.0.1 LANGUAGES C CXX)

include(CMakePackageConfigHelpers)
include(TestBigEndian)

find_package(Threads REQUIRED)
find_package(unofficial-sqlite3 CONFIG REQUIRED)
find_package(Protobuf REQUIRED)
if (WIN32)
    find_path(tinycthread_INCLUDE_DIR NAMES tinycthread.h REQUIRED)
    find_library(tinycthread_LIBRARY NAMES tinycthread REQUIRED)
endif ()

option(ENABLE_LOGGING "Enable debug log" ON)
option(ENABLE_IPV6_STACK "Enable IPv6 stack" OFF)

protobuf_generate_cpp(RAFT_SRCS RAFT_HDRS proto/rpc.proto)

set(MD_HDRS
        include/minidns/config.h
        include/minidns/dns.h
        include/minidns/dns_service.h
        include/minidns/minidns.h
        include/minidns/network.h
        include/minidns/protobuf_wrapper.h
        include/minidns/raft.h
        include/minidns/raft_service.h
        include/minidns/rpc2.h
        include/minidns/server.h
        include/minidns/thread_pool.h
        include/minidns/threads_wrapper.h
        include/minidns/utils.h)

add_library(minidns
        ${MD_HDRS}
        src/database.h
        src/database.c
        src/dns.c
        src/dns_service.c
        src/network.c
        src/protobuf_wrapper.cc
        src/raft_service.c
        src/server.c
        src/thread_pool.c
        src/utils.c
        ${RAFT_HDRS}
        ${RAFT_SRCS})

add_library(minidns::minidns ALIAS minidns)

# BUILD_INTERFACE and INSTALL_INTERFACE: https://stackoverflow.com/a/25681179/12247864
target_include_directories(minidns
        PUBLIC
        $<BUILD_INTERFACE:${minidns_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
        $<$<BOOL:${WIN32}>:${tinycthread_INCLUDE_DIR}>
        PRIVATE
        ${CMAKE_CURRENT_BINARY_DIR}
        src)

target_compile_features(minidns
        PUBLIC c_std_11
        PRIVATE cxx_std_20)

# Windows: Do not use clang-cl, it fails to compile C++ files. Try clang and clang++ instead
# Check MSVC compatibility here: https://clang.llvm.org/docs/MSVCCompatibility.html
target_compile_options(minidns
        PRIVATE
        $<$<OR:$<C_COMPILER_ID:Clang>,$<CXX_COMPILER_ID:Clang>,$<C_COMPILER_ID:GNU>,$<CXX_COMPILER_ID:GNU>>:-Wall;-Wextra;-pedantic;-Wno-gnu-zero-variadic-macro-arguments>
        $<$<OR:$<C_COMPILER_ID:MSVC>,$<CXX_COMPILER_ID:MSVC>>:/W3>
        $<$<BOOL:${ENABLE_ASAN}>:-fsanitize=address;-fno-omit-frame-pointer>
        $<$<BOOL:${ENABLE_MSAN}>:-fsanitize=memory;-fPIE;-pie>
        $<$<BOOL:${ENABLE_TSAN}>:-fsanitize=thread>
        $<$<BOOL:${ENABLE_UBSAN}>:-fsanitize=address;-fsanitize=undefined>)

# https://stackoverflow.com/a/13639476/12247864
if (MSVC)
    set_source_files_properties(${RAFT_SRCS} PROPERTIES COMPILE_FLAGS "/wd4251 /wd4996")
endif ()

# -rdynamic: https://stackoverflow.com/a/3899916/12247864
target_link_libraries(minidns
        PUBLIC Threads::Threads $<$<BOOL:${WIN32}>:${tinycthread_LIBRARY}>
        PRIVATE
        $<$<BOOL:${WIN32}>:Ws2_32> unofficial::sqlite3::sqlite3 protobuf::libprotobuf
        $<$<BOOL:${ENABLE_ASAN}>:-fsanitize=address> $<$<BOOL:${ENABLE_ASAN}>:-fno-omit-frame-pointer>
        $<$<BOOL:${ENABLE_MSAN}>:-fsanitize=memory> $<$<BOOL:${ENABLE_MSAN}>:-fPIE> $<$<BOOL:${ENABLE_MSAN}>:-pie>
        $<$<BOOL:${ENABLE_TSAN}>:-fsanitize=thread>
        $<$<BOOL:${ENABLE_UBSAN}>:-fsanitize=address> $<$<BOOL:${ENABLE_UBSAN}>:-fsanitize=undefined>
        $<$<AND:$<STREQUAL:${CMAKE_BUILD_TYPE},"Debug">,$<OR:$<C_COMPILER_ID:Clang>,$<CXX_COMPILER_ID:Clang>,$<C_COMPILER_ID:GNU>,$<CXX_COMPILER_ID:GNU>>>:-rdynamic>)

TEST_BIG_ENDIAN(BIG_ENDIAN)

target_compile_definitions(minidns
        PUBLIC
        MD_BIG_ENDIAN=${BIG_ENDIAN}
        $<$<BOOL:${ENABLE_LOGGING}>:MD_ENABLE_LOGGING>
        $<$<BOOL:${ENABLE_IPV6_STACK}>:MD_ENABLE_IPV6_STACK>
        $<$<BOOL:${BUILD_SHARED_LIBS}>:MD_DLL>
        $<$<BOOL:${WIN32}>:_CRT_SECURE_NO_WARNINGS>
        PRIVATE
        $<$<BOOL:${WIN32}>:NOMINMAX STRICT WIN32_LEAN_AND_MEAN>
        $<$<BOOL:${BUILD_SHARED_LIBS}>:MD_DLL_EXPORTS>)

set(PROJECT_CONFIG_VERSION_FILE "${PROJECT_BINARY_DIR}/minidns-config-version.cmake")
set(PROJECT_CONFIG_FILE "${PROJECT_BINARY_DIR}/minidns-config.cmake")

configure_package_config_file(
        cmake/minidns-config.cmake.in
        ${PROJECT_CONFIG_FILE}
        INSTALL_DESTINATION ${INSTALL_CONFIGDIR})

write_basic_package_version_file(${PROJECT_CONFIG_VERSION_FILE} COMPATIBILITY SameMajorVersion)

install(TARGETS minidns
        EXPORT minidns-targets
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/static)

install(FILES ${MD_HDRS}
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/minidns)

install(FILES
        ${PROJECT_CONFIG_VERSION_FILE}
        ${PROJECT_CONFIG_FILE}
        DESTINATION ${INSTALL_CONFIGDIR})

install(EXPORT minidns-targets
        FILE minidns-targets.cmake
        NAMESPACE minidns::
        DESTINATION ${INSTALL_CONFIGDIR})

export(EXPORT minidns-targets
        FILE ${CMAKE_CURRENT_BINARY_DIR}/minidns-targets.cmake
        NAMESPACE minidns::)

export(PACKAGE minidns)
