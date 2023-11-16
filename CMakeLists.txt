cmake_minimum_required(VERSION 3.26)
project(pastel_light VERSION 0.1 DESCRIPTION "Light Version of Pastel Node" LANGUAGES CXX)

# Set the C++ standard for the project
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

include(FetchContent)
include(ExternalProject)

# bitcoin/libsecp256k1cc
set(BUILD_SHARED_LIBS OFF CACHE INTERNAL "")
set(SECP256K1_DISABLE_SHARED ON CACHE INTERNAL "")
set(SECP256K1_ENABLE_MODULE_RECOVERY ON CACHE INTERNAL "")
FetchContent_Declare(
        libsecp256k1
        GIT_REPOSITORY https://github.com/bitcoin-core/secp256k1
        GIT_TAG master  # or specific commit/tag
)
FetchContent_MakeAvailable(libsecp256k1)

if (NOT EMSCRIPTEN)
    # libsodium
    find_package(unofficial-sodium CONFIG REQUIRED)

    # OpenSSL
    find_package(OpenSSL REQUIRED)

    add_subdirectory(lib)
    add_subdirectory(app)
else() # EMSCRIPTEN
    ExternalProject_Add(
            libsodium
            GIT_REPOSITORY https://github.com/jedisct1/libsodium.git
            GIT_TAG stable
            PREFIX ${CMAKE_BINARY_DIR}/libsodium
            CONFIGURE_COMMAND <SOURCE_DIR>/configure --prefix=<INSTALL_DIR>
            BUILD_COMMAND make
            INSTALL_COMMAND make install
            UPDATE_DISCONNECTED TRUE
    )
    set(libsodium_INCLUDE_DIR ${CMAKE_BINARY_DIR}/libsodium/include)

    add_subdirectory(wasm)
endif()
