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
extern uint64_t test_load_be32(const uint8_t *inp);
extern int test_u32x8_to_be_bytes(uint8_t *out, const uint32_t *inp);
extern int test_store_be64_off56(uint8_t *out, uint64_t val);

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

static void test_load_be32_fn(void)
{
    uint8_t blk[64];
    memset(blk, 0, sizeof(blk));

    blk[0]=0x12; blk[1]=0x34; blk[2]=0x56; blk[3]=0x78;
    check("load_be32(0x12345678)", test_load_be32(blk) == 0x12345678ULL);

    memset(blk, 0, sizeof(blk));
    blk[0]=0xFF; blk[1]=0xFF; blk[2]=0xFF; blk[3]=0xFF;
    check("load_be32(0xFFFFFFFF)", test_load_be32(blk) == 0xFFFFFFFFULL);

    memset(blk, 0, sizeof(blk));
    check("load_be32(0x00000000)", test_load_be32(blk) == 0);

    /* Inverse of ull_to_bytes(4): store then load */
    uint8_t rt[64];
    memset(rt, 0, sizeof(rt));
    test_ull_to_bytes_4(rt, 0xDEADBEEFULL);
    check("load_be32 o ull_to_bytes roundtrip",
          test_load_be32(rt) == 0xDEADBEEFULL);
}

static void test_u32x8_to_be_bytes_fn(void)
{
    /* Two words: 0x12345678, 0xAABBCCDD — check BE byte order in output */
    uint32_t words[8] = { 0x12345678, 0xAABBCCDD, 0, 0, 0, 0, 0, 0 };
    uint8_t out[32];
    memset(out, 0xFF, sizeof(out));
    test_u32x8_to_be_bytes(out, words);
    check("u32x8_to_be_bytes word0",
          out[0]==0x12 && out[1]==0x34 && out[2]==0x56 && out[3]==0x78);
    check("u32x8_to_be_bytes word1",
          out[4]==0xAA && out[5]==0xBB && out[6]==0xCC && out[7]==0xDD);
    check("u32x8_to_be_bytes zero words", out[8]==0 && out[31]==0);

    /* All-ones */
    uint32_t ones[8];
    memset(ones, 0xFF, sizeof(ones));
    test_u32x8_to_be_bytes(out, ones);
    int all_ff = 1;
    for (int i = 0; i < 32; i++) if (out[i] != 0xFF) { all_ff = 0; break; }
    check("u32x8_to_be_bytes all-0xFFFFFFFF", all_ff);
}

static void test_store_be64_fn(void)
{
    uint8_t blk[64];

    /* 0x0102030405060708 at offset 56 */
    test_store_be64_off56(blk, 0x0102030405060708ULL);
    check("store_be64 bytes 56-63",
          blk[56]==0x01 && blk[57]==0x02 && blk[58]==0x03 && blk[59]==0x04 &&
          blk[60]==0x05 && blk[61]==0x06 && blk[62]==0x07 && blk[63]==0x08);
    /* Bytes before offset 56 must be zero */
    int pre_zero = 1;
    for (int i = 0; i < 56; i++) if (blk[i] != 0) { pre_zero = 0; break; }
    check("store_be64 bytes 0-55 are zero", pre_zero);

    /* 96*8 = 768 = 0x0300 — value used in sha256_hash96 padding */
    test_store_be64_off56(blk, 768ULL);
    check("store_be64(768) high bytes zero", blk[56]==0 && blk[62]==0x03);
    check("store_be64(768) low byte", blk[63]==0x00);

    /* Roundtrip with load_be32 on the high word */
    test_store_be64_off56(blk, 0xDEADBEEFCAFEBABEULL);
    check("store_be64 high word via load_be32",
          test_load_be32(blk + 56) == 0xDEADBEEFULL);
}

int main(void)
{
    test_ull_to_bytes();
    test_bytes_to_ull();
    test_ct_memcmp();
    test_memzero();
    test_load_be32_fn();
    test_u32x8_to_be_bytes_fn();
    test_store_be64_fn();

    if (failures == 0)
        printf("\nAll utils tests passed.\n");
    else
        printf("\n%d utils test(s) FAILED.\n", failures);
    return failures;
}
