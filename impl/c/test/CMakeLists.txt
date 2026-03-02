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

# Fast tests (no tree operations, < 1 s each)
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

# Slow tests (keygen/sign/verify roundtrips, KAT, BDS)
add_xmss_test(test_xmss)
add_xmss_test(test_xmss_kat)
add_xmss_test(test_bds)
add_xmss_test(test_bds_serial)
add_xmss_test(test_bds_exhaustive)
add_xmss_test(test_xmss_mt)
add_xmss_test(test_xmss_mt_kat     ${CMAKE_SOURCE_DIR}/src/hash)
add_xmss_test(test_xmss_acvp_kat)

set_tests_properties(
    test_xmss test_xmss_kat test_bds test_bds_serial test_xmss_mt test_xmss_mt_kat
    test_xmss_acvp_kat
    PROPERTIES LABELS "slow"
)

# The exhaustive BDS test has fast H=5 subtests and slow H=10 subtests.
# Label it "slow" overall; the H=5 portion completes in <5s.
set_tests_properties(test_bds_exhaustive PROPERTIES LABELS "slow")

# Timeouts: generous limits to catch hangs without breaking slow runs.
# Fast tests should finish in well under 30 s; slow tests under 5 min.
# Use XMSS_TEST_TIMEOUT_SCALE (default 1) to increase for emulated runs.
math(EXPR FAST_TIMEOUT      "30  * ${XMSS_TEST_TIMEOUT_SCALE}")
math(EXPR SLOW_TIMEOUT      "120 * ${XMSS_TEST_TIMEOUT_SCALE}")
math(EXPR VERY_SLOW_TIMEOUT "300 * ${XMSS_TEST_TIMEOUT_SCALE}")

set_tests_properties(
    test_params test_address test_hash test_wots test_xmss_mt_params test_utils_internal
    PROPERTIES TIMEOUT ${FAST_TIMEOUT}
)
set_tests_properties(
    test_xmss test_bds test_bds_serial test_xmss_mt_kat test_xmss_acvp_kat
    PROPERTIES TIMEOUT ${SLOW_TIMEOUT}
)
set_tests_properties(
    test_xmss_kat test_xmss_mt test_bds_exhaustive
    PROPERTIES TIMEOUT ${VERY_SLOW_TIMEOUT}
)
