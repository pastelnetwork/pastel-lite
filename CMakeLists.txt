cmake_minimum_required(VERSION 3.26)
project(pastel_light)
project(pastel_light VERSION 0.1 DESCRIPTION "Light Version of Pastel Node" LANGUAGES CXX)

# Set the C++ standard for the project
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

include(FetchContent)
include(ExternalProject)

# bitcoin/libsecp256k1cc
FetchContent_Declare(
  libsecp256k1
  GIT_REPOSITORY https://github.com/bitcoin-core/secp256k1
  GIT_TAG master  # or specific commit/tag
)
FetchContent_MakeAvailable(libsecp256k1)

# libsodium
find_package(unofficial-sodium CONFIG REQUIRED)

# OpenSSL
find_package(OpenSSL REQUIRED)

# Add subdirectories
add_subdirectory(lib)
add_subdirectory(app)