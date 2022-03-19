cmake_minimum_required(VERSION 3.16)
project(server VERSION 0.0.1 LANGUAGES CXX)

# Suppress error: minidns could not be found because dependency protobuf could not be found.
# find_package(Protobuf) sets `Protobuf_FOUND`, but find_package(minidns) searches for `protobuf_FOUND` (lowercase p)
# See https://stackoverflow.com/a/55218309/12247864
set(protobuf_FOUND TRUE)
find_package(minidns CONFIG REQUIRED HINTS
        ${CMAKE_INSTALL_PREFIX}/${INSTALL_CONFIGDIR}
        ${CMAKE_BINARY_DIR}/minidns)

find_package(Argtable3 CONFIG REQUIRED)

add_executable(server main.cpp)

target_compile_features(server PRIVATE cxx_std_20)

target_compile_options(server
        PRIVATE
        $<$<OR:$<CXX_COMPILER_ID:AppleClang>,$<CXX_COMPILER_ID:Clang>,$<CXX_COMPILER_ID:GNU>>:-Wall;-Wextra;-pedantic>
        $<$<CXX_COMPILER_ID:MSVC>:/W3>
        $<$<BOOL:${ENABLE_ASAN}>:-fsanitize=address;-fno-omit-frame-pointer>
        $<$<BOOL:${ENABLE_MSAN}>:-fsanitize=memory;-fPIE;-pie>
        $<$<BOOL:${ENABLE_TSAN}>:-fsanitize=thread>
        $<$<BOOL:${ENABLE_UBSAN}>:-fsanitize=address;-fsanitize=undefined>)

target_compile_definitions(server PRIVATE __STDC_LIMIT_MACROS)

target_link_libraries(server
        PRIVATE
        minidns::minidns argtable3
        $<$<BOOL:${ENABLE_ASAN}>:-fsanitize=address> $<$<BOOL:${ENABLE_ASAN}>:-fno-omit-frame-pointer>
        $<$<BOOL:${ENABLE_MSAN}>:-fsanitize=memory> $<$<BOOL:${ENABLE_MSAN}>:-fPIE> $<$<BOOL:${ENABLE_MSAN}>:-pie>
        $<$<BOOL:${ENABLE_TSAN}>:-fsanitize=thread>
        $<$<BOOL:${ENABLE_UBSAN}>:-fsanitize=address> $<$<BOOL:${ENABLE_UBSAN}>:-fsanitize=undefined>)

install(TARGETS server
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
