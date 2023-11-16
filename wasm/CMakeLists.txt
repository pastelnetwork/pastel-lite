cmake_minimum_required(VERSION 3.26)

# Create a wasm module called 'libpastel_wasm'
file(GLOB_RECURSE LIBPASTEL_SOURCES "../lib/src/*.cpp")
add_executable(libpastel_wasm ${LIBPASTEL_SOURCES})

message("libsecp256k1_SOURCE_DIR: ${libsecp256k1_SOURCE_DIR}")
message("libsodium_INCLUDE_DIR: ${libsodium_INCLUDE_DIR}")
message("openssl_wasm_DIR: ${CMAKE_SOURCE_DIR}/third_party/openssl-wasm/precompiled")

# Specify the include directories for the library
target_include_directories(libpastel_wasm PRIVATE
        ${libsecp256k1_SOURCE_DIR}/include
        ${libsodium_INCLUDE_DIR}
        ${openssl_wasm_DIR}/include
        ${CMAKE_SOURCE_DIR}/lib/include
)

# Set specific Emscripten flags for WASM
# These flags can be adjusted based on your project's needs
set_target_properties(libpastel_wasm PROPERTIES
    SUFFIX ".html"  # This will generate an HTML file that loads the WASM module
    COMPILE_FLAGS ""
    LINK_FLAGS "--bind -s WASM=1 -s NO_EXIT_RUNTIME=1"
)

# Link the pre-built static OpenSSL library
set(OPENSSL_WASM_LIB_PATH "${CMAKE_SOURCE_DIR}/third_party/openssl-wasm/precompiled/lib")
target_link_libraries(libpastel_wasm "${OPENSSL_WASM_LIB_PATH}/libcrypto.a")

## Optional, additional resources (like HTML/JS/CSS files)
#file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/path/to/your/resources/
#     DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/resources/)
