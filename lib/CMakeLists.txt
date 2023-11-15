# Create a static library called 'libpastel'
file(GLOB_RECURSE MY_PROJECT_SOURCES "*.cpp")
add_library(libpastel STATIC ${MY_PROJECT_SOURCES})

# Specify the include directories for the library
target_include_directories(libpastel PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
        PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_include_directories(libpastel PRIVATE ${libsecp256k1_SOURCE_DIR}/include)
target_link_libraries(libpastel PRIVATE secp256k1)
target_link_libraries(libpastel PRIVATE OpenSSL::SSL OpenSSL::Crypto)
target_link_libraries(libpastel PRIVATE unofficial-sodium::sodium unofficial-sodium::sodium_config_public)

# Set the C++ standard for the library
target_compile_features(libpastel PUBLIC cxx_std_20)
