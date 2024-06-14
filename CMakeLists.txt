cmake_minimum_required(VERSION 3.20)
project(pastel_lite VERSION 0.1 DESCRIPTION "Lite Version of Pastel Node" LANGUAGES CXX)

# Set the C++ standard for the project
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

include(FetchContent)
include(ExternalProject)

set(BOTAN_VERBOSE_OUTPUT ON)
set(BOTAN_VERBOSE_CONFIGURE ON)
set(BOTAN_VERBOSE_BUILD ON)
set(BOTAN_VERBOSE_INSTALL ON)
set(ZSTD_VERBOSE_INSTALL ON)

if (NOT EMSCRIPTEN)
    set(BUILD_SHARED_LIBS OFF CACHE INTERNAL "")

    # libsodium
    find_package(unofficial-sodium CONFIG REQUIRED)
    # zstd
    find_package(zstd CONFIG REQUIRED)

    # bitcoin/libsecp256k1cc
    set(SECP256K1_DISABLE_SHARED ON CACHE INTERNAL "")
    set(SECP256K1_ENABLE_MODULE_RECOVERY ON CACHE INTERNAL "")
    FetchContent_Declare(
            libsecp256k1
            GIT_REPOSITORY https://github.com/bitcoin-core/secp256k1
            GIT_TAG master  # or specific commit/tag
    )
    FetchContent_MakeAvailable(libsecp256k1)

    # fmt
    FetchContent_Declare(
            fmt
            GIT_REPOSITORY https://github.com/fmtlib/fmt.git
            GIT_TAG master
    )
    FetchContent_MakeAvailable(fmt)

    # Botan
    set(BOTAN_LIB_DIR "${CMAKE_BINARY_DIR}/libbotan-lib")
    if (EXISTS ${BOTAN_LIB_DIR})
        message(STATUS "${BOTAN_LIB_DIR} already built. Skipping build.")
    else()
        ExternalProject_Add(
            libbotan
            GIT_REPOSITORY https://github.com/randombit/botan.git
            GIT_TAG master
            PREFIX ${CMAKE_BINARY_DIR}/libbotan
            BUILD_IN_SOURCE 1
            CONFIGURE_COMMAND ./configure.py --prefix=${BOTAN_LIB_DIR} --disable-shared-library --minimized-build --enable-modules=auto_rng,system_rng,hash,shake,shake_xof,sha3,ed448,pbkdf2,hmac,x448,base64,sha2_32,sha2_64
            BUILD_COMMAND make
            INSTALL_COMMAND make install
            LOG_DOWNLOAD ON
            LOG_BUILD ON
            LOG_INSTALL ON
        )
    endif ()

    add_subdirectory(lib)
    add_subdirectory(app)
    add_subdirectory(python_bindings)
else () # EMSCRIPTEN
    # Add libsodium as an external project
    set(SODIUM_WASM_DIR "${CMAKE_BINARY_DIR}/libsodium-wasm")
    if (EXISTS ${SODIUM_WASM_DIR})
        message(STATUS "${SODIUM_WASM_DIR} already built. Skipping build.")
    else()
        ExternalProject_Add(
                libsodium
                GIT_REPOSITORY https://github.com/jedisct1/libsodium.git
                GIT_TAG stable
                PREFIX ${CMAKE_BINARY_DIR}/libsodium
                BUILD_IN_SOURCE 1  # Build in the source directory
                CONFIGURE_COMMAND ""
                BUILD_IN_SOURCE 1
                BUILD_COMMAND sh ${CMAKE_BINARY_DIR}/libsodium/src/libsodium/dist-build/emscripten.sh --standard
                INSTALL_COMMAND ${CMAKE_COMMAND} -E copy_directory ${CMAKE_BINARY_DIR}/libsodium/src/libsodium/libsodium-js ${SODIUM_WASM_DIR}
                LOG_DOWNLOAD ON
                LOG_BUILD ON
                LOG_INSTALL ON
        )
    endif()
    # Add libsecp256k1 as an external project
    set(SECP256K1_WASM_DIR "${CMAKE_BINARY_DIR}/libsecp256k1-wasm")
    if (EXISTS ${SECP256K1_WASM_DIR})
        message(STATUS "${SECP256K1_WASM_DIR} already built. Skipping build.")
    else()
        ExternalProject_Add(
                libsecp256k1
                GIT_REPOSITORY https://github.com/bitcoin-core/secp256k1.git
                GIT_TAG master  # or a specific commit/tag
                PREFIX ${CMAKE_BINARY_DIR}/libsecp256k1
                BUILD_IN_SOURCE 1  # Build in the source directory
                UPDATE_COMMAND ./autogen.sh
                CONFIGURE_COMMAND emconfigure ./configure --enable-module-recovery --disable-shared --prefix=${SECP256K1_WASM_DIR}
                BUILD_COMMAND emmake make
                INSTALL_COMMAND make install
                LOG_DOWNLOAD ON
                LOG_BUILD ON
                LOG_INSTALL ON
        )
    endif()
    # Add libbotan as an external project
    set(BOTAN_WASM_DIR "${CMAKE_BINARY_DIR}/libbotan-wasm")
    if (EXISTS ${BOTAN_WASM_DIR})
        message(STATUS "${BOTAN_WASM_DIR} already built. Skipping build.")
    else()
        ExternalProject_Add(
            libbotan
            GIT_REPOSITORY https://github.com/randombit/botan.git
            GIT_TAG master
            PREFIX ${CMAKE_BINARY_DIR}/libbotan
            BUILD_IN_SOURCE 1
            CONFIGURE_COMMAND ./configure.py --prefix=${BOTAN_WASM_DIR} --os=emscripten --cpu=wasm --cc=emcc --disable-shared-library --minimized-build --enable-modules=auto_rng,system_rng,hash,shake,shake_xof,sha3,ed448,pbkdf2,hmac,x448,base64,sha2_32,sha2_64
            BUILD_COMMAND make
            INSTALL_COMMAND make install
            LOG_DOWNLOAD ON
            LOG_BUILD ON
            LOG_INSTALL ON
        )
    endif()
    # Add fmt as an external project
    set(FMT_WASM_DIR "${CMAKE_BINARY_DIR}/fmt-wasm")
    if (EXISTS ${FMT_WASM_DIR})
        message(STATUS "${FMT_WASM_DIR} already built. Skipping build.")
    else()
        ExternalProject_Add(
                fmt
                GIT_REPOSITORY https://github.com/fmtlib/fmt.git
                GIT_TAG master
                PREFIX ${CMAKE_BINARY_DIR}/fmt
                BUILD_IN_SOURCE 1
                CONFIGURE_COMMAND emcmake cmake -DFMT_TEST=OFF -DCMAKE_INSTALL_PREFIX=${FMT_WASM_DIR}
                BUILD_COMMAND emmake make
                INSTALL_COMMAND make install
                LOG_DOWNLOAD ON
                LOG_BUILD ON
                LOG_INSTALL ON
        )
    endif()
    #
    set(ZSTD_WASM_DIR "${CMAKE_BINARY_DIR}/zstd-wasm")
    if (EXISTS ${ZSTD_WASM_DIR})
        message(STATUS "${ZSTD_WASM_DIR} already built. Skipping build.")
    else()
        ExternalProject_Add(
                zstd
                GIT_REPOSITORY https://github.com/facebook/zstd.git
                GIT_TAG v1.5.5
                PREFIX ${CMAKE_BINARY_DIR}/zstd
                # BUILD_IN_SOURCE 1
                CONFIGURE_COMMAND emcmake cmake ${CMAKE_BINARY_DIR}/zstd/src/zstd/build/cmake -DCMAKE_INSTALL_PREFIX=${ZSTD_WASM_DIR} -DZSTD_BUILD_TESTS=OFF -DZSTD_LEGACY_SUPPORT=OFF -DZSTD_BUILD_SHARED=OFF -DZSTD_BUILD_PROGRAMS=OFF -DZSTD_BUILD_STATIC=ON
                BUILD_COMMAND emmake make
                INSTALL_COMMAND make install
                LOG_DOWNLOAD ON
                LOG_BUILD ON
                LOG_INSTALL ON
        )
    endif()

    add_subdirectory(wasm)
endif ()
