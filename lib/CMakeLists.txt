cmake_minimum_required(VERSION 3.20)

# Create a static library called 'libpastel'
file(GLOB_RECURSE LIBPASTEL_SOURCES "*.cpp")
add_library(pastel STATIC ${LIBPASTEL_SOURCES})

# Specify the include directories for the library
target_include_directories(pastel PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)
target_include_directories(pastel PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${libsecp256k1_SOURCE_DIR}/include
        ${zstd_SOURCE_DIR}/lib
        ${BOTAN_LIB_DIR}/include/botan-3
)

target_link_libraries(pastel PRIVATE secp256k1
        unofficial-sodium::sodium unofficial-sodium::sodium_config_public
        fmt::fmt
        "${BOTAN_LIB_DIR}/lib/libbotan-3.a"
        zstd::libzstd_static
)

# Set the C++ standard for the library
target_compile_features(pastel PUBLIC cxx_std_20)
set_target_properties(pastel PROPERTIES POSITION_INDEPENDENT_CODE ON)

#add_dependencies(pastel botan)

add_custom_command(TARGET pastel POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy
        ${CMAKE_BINARY_DIR}/lib/libpastel.a
        ${CMAKE_SOURCE_DIR}
    COMMENT "Copying libpastel.a to the project root"
)
