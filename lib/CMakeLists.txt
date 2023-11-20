cmake_minimum_required(VERSION 3.20)

# Create a static library called 'libpastel'
file(GLOB_RECURSE LIBPASTEL_SOURCES "*.cpp")
add_library(libpastel STATIC ${LIBPASTEL_SOURCES})

# Specify the include directories for the library
target_include_directories(libpastel PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)
target_include_directories(libpastel PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${libsecp256k1_SOURCE_DIR}/include
)

target_link_libraries(libpastel PRIVATE secp256k1)
target_link_libraries(libpastel PRIVATE OpenSSL::SSL OpenSSL::Crypto)
target_link_libraries(libpastel PRIVATE unofficial-sodium::sodium unofficial-sodium::sodium_config_public)

# Set the C++ standard for the library
target_compile_features(libpastel PUBLIC cxx_std_20)


