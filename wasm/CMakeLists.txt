cmake_minimum_required(VERSION 3.20)

message("libsodium_INCLUDE_DIR: ${libsodium_INCLUDE_DIR}")
message("libsecp256k1_SOURCE_DIR: ${libsecp256k1_SOURCE_DIR}")

# Create a wasm module called 'libpastel_wasm'
file(GLOB_RECURSE LIBPASTEL_SOURCES "../lib/src/*.cpp")
add_executable(libpastel_wasm ${LIBPASTEL_SOURCES})

set(SODIUM_WASM_DIR    "${CMAKE_BINARY_DIR}/libsodium-wasm")
set(SECP256K1_WASM_DIR "${CMAKE_BINARY_DIR}/libsecp256k1-wasm")

# Specify the include directories for the library
target_include_directories(libpastel_wasm PRIVATE
        ${CMAKE_SOURCE_DIR}/lib/include
        ${SODIUM_WASM_DIR}/include
        ${SECP256K1_WASM_DIR}/include
)

# Set specific Emscripten flags for WASM
# These flags can be adjusted based on your project's needs
set_target_properties(libpastel_wasm PROPERTIES
    SUFFIX ".html"  # This will generate an HTML file that loads the WASM module
    COMPILE_FLAGS "-gsource-map"
    LINK_FLAGS "--bind -s WASM=1 -s ALLOW_MEMORY_GROWTH=1 -s NO_EXIT_RUNTIME=1 -gsource-map"
)

target_link_libraries(libpastel_wasm "${SODIUM_WASM_DIR}/lib/libsodium.a")
target_link_libraries(libpastel_wasm "${SECP256K1_WASM_DIR}/lib/libsecp256k1.a")
