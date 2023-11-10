# Create a static library called 'libpastel'
add_library(libpastel STATIC
        src/libpastel.cpp src/pubkey.cpp src/key_io.cpp
        src/ecc_context.cpp src/hash.cpp src/uint256.cpp src/utilstrencodings.cpp
        src/support/cleanse.cpp src/support/lockedpool.cpp
        src/crypto/equihash.cpp src/crypto/hmac_sha256.cpp src/crypto/hmac_sha512.cpp src/crypto/ripemd160.cpp
        src/crypto/sha1.cpp src/crypto/sha256.cpp src/crypto/sha512.cpp
        src/compat/glibc_compat.cpp src/compat/glibc_sanity.cpp src/compat/glibcxx_sanity.cpp src/compat/strnlen.cpp
)

# Specify the include directories for the library
target_include_directories(libpastel PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
        PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
        PRIVATE include/crypto
        PRIVATE include/support
        PRIVATE include/compat
        PRIVATE include/support/allocators
)

target_include_directories(libpastel PRIVATE ${libsecp256k1_SOURCE_DIR}/include)
target_link_libraries(libpastel PRIVATE OpenSSL::SSL OpenSSL::Crypto sodium)

# Set the C++ standard for the library
target_compile_features(libpastel PUBLIC cxx_std_20)
