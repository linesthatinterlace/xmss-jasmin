cmake_minimum_required(VERSION 3.16)

# Helper: add a test that links against xmss with standard include paths.
# Extra include dirs can be appended after the test name.
function(add_xmss_test test_name)
    add_executable(${test_name} ${test_name}.c)
    target_link_libraries(${test_name} xmss)
    target_include_directories(${test_name} PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/src
        ${ARGN}
    )
    add_test(NAME ${test_name} COMMAND ${test_name})
endfunction()

# === Three-tier test organisation ===
#
# Tier 1 — "fast": compile-time checks, no tree ops, < 1 s each.
#   Fail fast: if these break, nothing else matters.
#
# Tier 2 — "core": correctness tests (sign/verify roundtrips, BDS serial,
#   BDS exhaustive H=5, XMSS-MT boundary). Under 5 min total.
#   These catch the *class* of bug (floor-vs-ceil, state machine) quickly.
#
# Tier 3 — "deep": KAT validation (512+ sigs), full H=10 exhaustive,
#   ACVP cross-checks. 5-15 min total.  Deep validation for CI.
#
# Usage:
#   ctest -L fast           # Tier 1 only (seconds)
#   ctest -L core           # Tier 2 only (< 5 min)
#   ctest -L deep           # Tier 3 only (5-15 min)
#   ctest                   # All tiers

# Tier 1: fast (< 1 s each)
add_xmss_test(test_params)
add_xmss_test(test_address)
add_xmss_test(test_hash          ${CMAKE_SOURCE_DIR}/src/hash)
add_xmss_test(test_wots)
add_xmss_test(test_xmss_mt_params)
add_xmss_test(test_utils_internal ${CMAKE_SOURCE_DIR}/src/hash)

set_tests_properties(
    test_params test_address test_hash test_wots test_xmss_mt_params test_utils_internal
    PROPERTIES LABELS "fast"
)

# Tier 2: core correctness (< 5 min total)
add_xmss_test(test_xmss)
add_xmss_test(test_bds)
add_xmss_test(test_bds_serial)
add_xmss_test(test_xmss_mt)

set_tests_properties(
    test_xmss test_bds test_bds_serial test_xmss_mt
    PROPERTIES LABELS "core"
)

# test_bds_exhaustive has fast H=5 subtests (<5s) and slow H=10 subtests (~10 min).
# Label it "core" because the H=5 portion alone catches the important bugs.
add_xmss_test(test_bds_exhaustive)
set_tests_properties(test_bds_exhaustive PROPERTIES LABELS "core")

# Tier 3: deep validation (5-15 min total)
add_xmss_test(test_xmss_kat)
add_xmss_test(test_xmss_mt_kat     ${CMAKE_SOURCE_DIR}/src/hash)
add_xmss_test(test_xmss_acvp_kat)

set_tests_properties(
    test_xmss_kat test_xmss_mt_kat test_xmss_acvp_kat
    PROPERTIES LABELS "deep"
)

# Timeouts: generous limits to catch hangs without breaking slow runs.
# Use XMSS_TEST_TIMEOUT_SCALE (default 1) to increase for emulated runs.
math(EXPR FAST_TIMEOUT      "30  * ${XMSS_TEST_TIMEOUT_SCALE}")
math(EXPR CORE_TIMEOUT      "120 * ${XMSS_TEST_TIMEOUT_SCALE}")
math(EXPR DEEP_TIMEOUT      "300 * ${XMSS_TEST_TIMEOUT_SCALE}")
math(EXPR EXHAUSTIVE_TIMEOUT "900 * ${XMSS_TEST_TIMEOUT_SCALE}")

set_tests_properties(
    test_params test_address test_hash test_wots test_xmss_mt_params test_utils_internal
    PROPERTIES TIMEOUT ${FAST_TIMEOUT}
)
set_tests_properties(
    test_xmss test_bds test_bds_serial test_xmss_mt
    PROPERTIES TIMEOUT ${CORE_TIMEOUT}
)
set_tests_properties(
    test_bds_exhaustive
    PROPERTIES TIMEOUT ${EXHAUSTIVE_TIMEOUT}
)
set_tests_properties(
    test_xmss_kat test_xmss_mt_kat test_xmss_acvp_kat
    PROPERTIES TIMEOUT ${DEEP_TIMEOUT}
)
