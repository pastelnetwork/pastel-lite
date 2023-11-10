# Create an executable called 'pastel_light'
add_executable(pastel_light
    main.cpp
)

# Link the static library 'libpastel' with the application 'pastel_light'
target_link_libraries(pastel_light PRIVATE libpastel)
target_link_libraries(pastel_light PRIVATE unofficial-sodium::sodium unofficial-sodium::sodium_config_public)
target_link_libraries(pastel_light PRIVATE OpenSSL::SSL OpenSSL::Crypto)

# Set the C++ standard for the executable
target_compile_features(pastel_light PRIVATE cxx_std_20)
