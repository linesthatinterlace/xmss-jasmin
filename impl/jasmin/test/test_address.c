/* test_address.c — C test harness for address.jinc */
#include <stdio.h>
#include <stdint.h>
#include <string.h>

/* Jasmin-exported functions */
extern int test_adrs_to_bytes(uint8_t *out);
extern int test_adrs_set_type_zeroes(uint8_t *out);

static void print_hex(const char *label, const uint8_t *buf, size_t len)
{
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++)
        printf("%02x", buf[i]);
    printf("\n");
}

static int test_basic(void)
{
    uint8_t out[32];
    memset(out, 0xFF, sizeof(out));

    int rc = test_adrs_to_bytes(out);
    if (rc != 0) {
        printf("FAIL: test_adrs_to_bytes returned %d\n", rc);
        return 1;
    }

    print_hex("adrs_bytes", out, 32);

    /* Expected big-endian encoding:
     * w[0] = layer = 3             -> 00 00 00 03
     * w[1] = tree_hi = 0 (set_type zeroed it) -> 00 00 00 00
     * w[2] = tree_lo = 0 (set_type zeroed it) -> 00 00 00 00
     * w[3] = type = 0 (OTS)        -> 00 00 00 00
     *
     * Wait — set_type only zeros words 4-7, not 1-2.
     * Actually re-reading the test: set_layer(3), set_tree(0x123456789ABCDEF0),
     * then set_type(0) which zeros words 4-7 only.
     * So:
     * w[0] = 3                      -> 00 00 00 03
     * w[1] = 0x12345678             -> 12 34 56 78
     * w[2] = 0x9ABCDEF0             -> 9A BC DE F0
     * w[3] = 0 (OTS type)           -> 00 00 00 00
     * w[4] = 42 (ots)               -> 00 00 00 2A
     * w[5] = 7 (chain)              -> 00 00 00 07
     * w[6] = 1 (hash/key_and_mask)  -> 00 00 00 01
     * w[7] = 0                      -> 00 00 00 00
     */
    uint8_t expected[32] = {
        0x00, 0x00, 0x00, 0x03,  /* layer=3 */
        0x12, 0x34, 0x56, 0x78,  /* tree high */
        0x9A, 0xBC, 0xDE, 0xF0,  /* tree low */
        0x00, 0x00, 0x00, 0x00,  /* type=0 (OTS) */
        0x00, 0x00, 0x00, 0x2A,  /* ots=42 */
        0x00, 0x00, 0x00, 0x07,  /* chain=7 */
        0x00, 0x00, 0x00, 0x01,  /* hash=1 */
        0x00, 0x00, 0x00, 0x00,  /* unused */
    };

    if (memcmp(out, expected, 32) != 0) {
        print_hex("expected ", expected, 32);
        printf("FAIL: adrs_to_bytes mismatch\n");
        return 1;
    }

    printf("PASS: test_adrs_to_bytes\n");
    return 0;
}

static int test_set_type_zeroes(void)
{
    uint8_t out[32];
    memset(out, 0xFF, sizeof(out));

    int rc = test_adrs_set_type_zeroes(out);
    if (rc != 0) {
        printf("FAIL: test_adrs_set_type_zeroes returned %d\n", rc);
        return 1;
    }

    print_hex("adrs_bytes", out, 32);

    /* Expected: layer=0, tree=0, type=1 (LTREE), words 4-7 = 0
     * (set_type must have zeroed the ots=99 that was set earlier) */
    uint8_t expected[32] = {
        0x00, 0x00, 0x00, 0x00,  /* layer=0 */
        0x00, 0x00, 0x00, 0x00,  /* tree high=0 */
        0x00, 0x00, 0x00, 0x00,  /* tree low=0 */
        0x00, 0x00, 0x00, 0x01,  /* type=1 (LTREE) */
        0x00, 0x00, 0x00, 0x00,  /* zeroed by set_type */
        0x00, 0x00, 0x00, 0x00,  /* zeroed by set_type */
        0x00, 0x00, 0x00, 0x00,  /* zeroed by set_type */
        0x00, 0x00, 0x00, 0x00,  /* zeroed by set_type */
    };

    if (memcmp(out, expected, 32) != 0) {
        print_hex("expected ", expected, 32);
        printf("FAIL: set_type did not zero words 4-7\n");
        return 1;
    }

    printf("PASS: test_adrs_set_type_zeroes\n");
    return 0;
}

int main(void)
{
    int failures = 0;
    failures += test_basic();
    failures += test_set_type_zeroes();

    if (failures == 0)
        printf("\nAll address tests passed.\n");
    else
        printf("\n%d address test(s) FAILED.\n", failures);

    return failures;
}
