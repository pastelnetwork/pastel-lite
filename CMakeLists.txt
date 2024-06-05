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

function(check_and_add_external_project name git_repo git_tag build_dir update_command configure_command build_command install_command)
    if (EXISTS ${build_dir})
        message(STATUS "${name} already built. Skipping build.")
    else()
        ExternalProject_Add(
                ${name}
                GIT_REPOSITORY ${git_repo}
                GIT_TAG ${git_tag}
                PREFIX ${build_dir}
                BUILD_IN_SOURCE 1
                UPDATE_COMMAND ${update_command}
                CONFIGURE_COMMAND ${configure_command}
                BUILD_COMMAND ${build_command}
                INSTALL_COMMAND ${install_command}
                LOG_DOWNLOAD ON
                LOG_BUILD ON
                LOG_INSTALL ON
        )
        ExternalProject_Add_StepTargets(${name} build)
    endif()
endfunction()

if (NOT EMSCRIPTEN)
    set(BUILD_SHARED_LIBS OFF CACHE INTERNAL "")

    # libsodium
    find_package(unofficial-sodium CONFIG REQUIRED)
    find_package(GTest CONFIG REQUIRED)

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
            GIT_TAG master  # or specific commit/tag
    )
    FetchContent_MakeAvailable(fmt)

    # Botan
    check_and_add_external_project(
            libbotan
            https://github.com/randombit/botan.git
            master
            ${CMAKE_BINARY_DIR}/libbotan
            ""
            ./configure.py --prefix=${CMAKE_BINARY_DIR}/libbotan --disable-shared-library --minimized-build --enable-modules=auto_rng,system_rng,hash,shake,shake_xof,sha3,ed448,pbkdf2,hmac,x448,base64,sha2_32,sha2_64
            make
            make install
    )
    add_custom_target(botan ALL
        DEPENDS ${CMAKE_BINARY_DIR}/libbotan/lib/libbotan-3.a
    )
    add_dependencies(botan libbotan-build)

    add_subdirectory(lib)
    add_subdirectory(app)
    add_subdirectory(tests)
else () # EMSCRIPTEN
    # Add libsodium as an external project
    check_and_add_external_project(
            libsodium
            https://github.com/jedisct1/libsodium.git
            stable
            ${CMAKE_BINARY_DIR}/libsodium
            ""
            ""
            sh ${CMAKE_BINARY_DIR}/libsodium/src/libsodium/dist-build/emscripten.sh --standard
            ${CMAKE_COMMAND} -E copy_directory ${CMAKE_BINARY_DIR}/libsodium/src/libsodium/libsodium-js ${CMAKE_BINARY_DIR}/libsodium-wasm
    )
    # Add libsecp256k1 as an external project
    check_and_add_external_project(
            libsecp256k1
            https://github.com/bitcoin-core/secp256k1.git
            master
            ${CMAKE_BINARY_DIR}/libsecp256k1-wasm
            ./autogen.sh
            emconfigure ./configure --enable-module-recovery --disable-shared --prefix=${CMAKE_BINARY_DIR}/libsecp256k1-wasm
            emmake make
            make install
    )
    # Add libbotan as an external project
    check_and_add_external_project(
            libbotan
            https://github.com/randombit/botan.git
            master
            ${CMAKE_BINARY_DIR}/libbotan-wasm
            ""
            ./configure.py --prefix=${CMAKE_BINARY_DIR}/libbotan-wasm --os=emscripten --cpu=wasm --cc=emcc --disable-shared-library --minimized-build --enable-modules=auto_rng,system_rng,hash,shake,shake_xof,sha3,ed448,pbkdf2,hmac,x448,base64,sha2_32,sha2_64
            emmake make
            make install
    )
    # Add fmt as an external project
    check_and_add_external_project(
            fmt
            https://github.com/fmtlib/fmt.git
            master
            ${CMAKE_BINARY_DIR}/fmt-wasm
            emcmake cmake -DFMT_TEST=OFF -DCMAKE_INSTALL_PREFIX=${CMAKE_BINARY_DIR}/fmt-wasm .
            emmake make
            make install
    )

    add_subdirectory(wasm)
endif ()
