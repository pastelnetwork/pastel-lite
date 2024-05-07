cmake_minimum_required(VERSION 3.20)

# Create an executable called 'pastel_lite'
add_executable(pastel_lite main.cpp)

# Link the static library 'libpastel' with the application 'pastel_light'
target_link_libraries(pastel_lite PRIVATE pastel)

# Set the C++ standard for the executable
target_compile_features(pastel_lite PRIVATE cxx_std_20)
