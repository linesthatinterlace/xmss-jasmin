cmake_minimum_required(VERSION 3.16)
project(xmss_jasmin C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# Strict warnings; -Wvla enforces Jasmin Rule J1 (no VLAs)
add_compile_options(
    -Wall
    -Wextra
    -Wpedantic
    -Wvla
    -Wmissing-prototypes
    -Wstrict-prototypes
    -Wshadow
    -Wconversion
    -Wsign-conversion
)

option(XMSS_WERROR "Treat warnings as errors" OFF)
if(XMSS_WERROR)
    add_compile_options(-Werror)
endif()

# Timeout multiplier for tests (increase for emulated runs, e.g. QEMU)
set(XMSS_TEST_TIMEOUT_SCALE "1" CACHE STRING
    "Multiplier for test timeouts (e.g. 4 for QEMU)")

# Debug build: sanitizers
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    if(NOT CMAKE_CROSSCOMPILING)
        add_compile_options(-fsanitize=address,undefined)
        add_link_options(-fsanitize=address,undefined)
    endif()
endif()

# -----------------------------------------------------------------------
# XMSS library
# -----------------------------------------------------------------------
add_library(xmss STATIC
    src/params.c
    src/address.c
    src/utils.c
    src/hash/sha2_local.c
    src/hash/shake_local.c
    src/hash/xmss_hash.c
    src/wots.c
    src/ltree.c
    src/treehash.c
    src/bds.c
    src/bds_serialize.c
    src/xmss.c
    src/xmss_mt.c
)

target_include_directories(xmss PUBLIC
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/src
    ${PROJECT_SOURCE_DIR}/src/hash
)

# -----------------------------------------------------------------------
# Tests
# -----------------------------------------------------------------------
enable_testing()
add_subdirectory(test)
