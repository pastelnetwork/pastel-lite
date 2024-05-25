cmake_minimum_required(VERSION 3.20)
project(PastelTests)

# Enable testing
enable_testing()

# Add test source files
file(GLOB TEST_SOURCES "*.cpp")

# Create the test executable
add_executable(runTests ${TEST_SOURCES}
        decoder.h)

# Link the test executable against Google Test and the Pastel library
target_link_libraries(runTests PRIVATE GTest::gtest GTest::gtest_main pastel)

# Add the test to CTest
add_test(NAME runTests COMMAND runTests)
