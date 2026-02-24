/* test_utils.c — C test harness for utils.jinc */
#include <stdio.h>
#include <stdint.h>
#include <string.h>

extern int test_ull_to_bytes_4(uint8_t *out, uint64_t val);
extern int test_ull_to_bytes_8(uint8_t *out, uint64_t val);
extern uint64_t test_bytes_to_ull_4(const uint8_t *inp);
extern uint64_t test_bytes_to_ull_8(const uint8_t *inp);
extern uint64_t test_ct_memcmp_32(const uint8_t *a, const uint8_t *b);
extern int test_memzero_32(uint8_t *p);

static int failures = 0;

static void check(const char *name, int cond)
{
    if (!cond) {
        printf("FAIL: %s\n", name);
        failures++;
    } else {
        printf("PASS: %s\n", name);
    }
}

static void test_ull_to_bytes(void)
{
    uint8_t buf[8];

    /* 4-byte: 0x12345678 -> 12 34 56 78 */
    memset(buf, 0xFF, sizeof(buf));
    test_ull_to_bytes_4(buf, 0x12345678ULL);
    check("ull_to_bytes(4, 0x12345678)",
          buf[0]==0x12 && buf[1]==0x34 && buf[2]==0x56 && buf[3]==0x78);

    /* 4-byte: 0 -> 00 00 00 00 */
    memset(buf, 0xFF, sizeof(buf));
    test_ull_to_bytes_4(buf, 0);
    check("ull_to_bytes(4, 0)",
          buf[0]==0 && buf[1]==0 && buf[2]==0 && buf[3]==0);

    /* 8-byte: 0x0102030405060708 */
    memset(buf, 0xFF, sizeof(buf));
    test_ull_to_bytes_8(buf, 0x0102030405060708ULL);
    check("ull_to_bytes(8, 0x0102030405060708)",
          buf[0]==0x01 && buf[1]==0x02 && buf[2]==0x03 && buf[3]==0x04 &&
          buf[4]==0x05 && buf[5]==0x06 && buf[6]==0x07 && buf[7]==0x08);
}

static void test_bytes_to_ull(void)
{
    uint8_t buf4[4] = {0x12, 0x34, 0x56, 0x78};
    uint64_t v = test_bytes_to_ull_4(buf4);
    check("bytes_to_ull(4) == 0x12345678", v == 0x12345678ULL);

    uint8_t buf8[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    v = test_bytes_to_ull_8(buf8);
    check("bytes_to_ull(8) == 0x0102030405060708", v == 0x0102030405060708ULL);

    /* Roundtrip */
    uint8_t rt[8];
    test_ull_to_bytes_8(rt, 0xDEADBEEFCAFEBABEULL);
    v = test_bytes_to_ull_8(rt);
    check("roundtrip(0xDEADBEEFCAFEBABE)", v == 0xDEADBEEFCAFEBABEULL);
}

static void test_ct_memcmp(void)
{
    uint8_t a[32], b[32];
    memset(a, 0x42, 32);
    memset(b, 0x42, 32);

    check("ct_memcmp(equal) == 0", test_ct_memcmp_32(a, b) == 0);

    b[31] = 0x43;  /* differ in last byte */
    check("ct_memcmp(differ last) != 0", test_ct_memcmp_32(a, b) != 0);

    memset(b, 0x42, 32);
    b[0] = 0x43;   /* differ in first byte */
    check("ct_memcmp(differ first) != 0", test_ct_memcmp_32(a, b) != 0);
}

static void test_memzero(void)
{
    uint8_t buf[32];
    memset(buf, 0xFF, 32);
    test_memzero_32(buf);

    int all_zero = 1;
    for (int i = 0; i < 32; i++) {
        if (buf[i] != 0) { all_zero = 0; break; }
    }
    check("memzero(32) clears all bytes", all_zero);
}

int main(void)
{
    test_ull_to_bytes();
    test_bytes_to_ull();
    test_ct_memcmp();
    test_memzero();

    if (failures == 0)
        printf("\nAll utils tests passed.\n");
    else
        printf("\n%d utils test(s) FAILED.\n", failures);
    return failures;
}
