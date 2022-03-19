cmake_minimum_required(VERSION 3.17)
project(rpc_client VERSION 0.0.1 LANGUAGES CXX)

set(protobuf_FOUND TRUE)
find_package(minidns CONFIG REQUIRED HINTS
        ${CMAKE_INSTALL_PREFIX}/${INSTALL_CONFIGDIR}
        ${CMAKE_BINARY_DIR}/minidns)

find_package(Argtable3 CONFIG REQUIRED)

add_executable(rpc_client main.cc)

target_compile_features(rpc_client PRIVATE cxx_std_20)

target_compile_options(rpc_client
        PRIVATE
        $<$<OR:$<CXX_COMPILER_ID:AppleClang>,$<CXX_COMPILER_ID:Clang>,$<CXX_COMPILER_ID:GNU>>:-Wall;-Wextra;-pedantic>
        $<$<CXX_COMPILER_ID:MSVC>:/W3>)

target_compile_definitions(rpc_client PRIVATE __STDC_LIMIT_MACROS)

target_link_libraries(rpc_client
        PRIVATE
        minidns::minidns argtable3)

install(TARGETS rpc_client
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
