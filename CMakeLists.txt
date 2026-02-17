cmake_minimum_required(VERSION 3.15)
project(test_chacha C)

# Set C standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Source files
set(SOURCES
    src/tiny_chacha.c
    test/test_chacha.c
)

# Create executable
add_executable(test_chacha ${SOURCES})

# Compiler macros (Tiny-ChaCha feature flags + optional prefix)
target_compile_definitions(test_chacha PRIVATE
    ENABLE_CHACHA=1
    ENABLE_XCHACHA=1

    TSHASH_PREFIX=MyLib_    # optional function prefix
)

# Compiler flags
if(MSVC)
    target_compile_options(test_chacha PRIVATE /W3)
    target_compile_options(test_chacha PRIVATE
        $<$<CONFIG:Release>:/O2>
    )
else()
    target_compile_options(test_chacha PRIVATE -Wall -Wextra -O2 -s)
endif()

# Output directories
set_target_properties(test_chacha PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_BINARY_DIR}/bin/Debug"
    RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/bin/Release"
)