/* test_sha256.c — FIPS 180-4 test vectors for SHA-256 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>

extern int test_sha256(uint8_t *out, const uint8_t *inp, uint64_t inlen);
extern int test_xmss_prf(uint8_t *out, const uint8_t *key, const uint8_t *adrs);

static int check(const char *label, const uint8_t *got,
                 const uint8_t *expected, int len) {
    if (memcmp(got, expected, len) != 0) {
        printf("FAIL %s\n  got: ", label);
        for (int i = 0; i < len; i++) printf("%02x", got[i]);
        printf("\n  exp: ");
        for (int i = 0; i < len; i++) printf("%02x", expected[i]);
        printf("\n");
        return 1;
    }
    printf("PASS %s\n", label);
    return 0;
}

int main(void) {
    uint8_t out[32];
    int fail = 0;

    /* Vector 1: empty string */
    {
        const uint8_t expected[] = {
            0xe3,0xb0,0xc4,0x42,0x98,0xfc,0x1c,0x14,
            0x9a,0xfb,0xf4,0xc8,0x99,0x6f,0xb9,0x24,
            0x27,0xae,0x41,0xe4,0x64,0x9b,0x93,0x4c,
            0xa4,0x95,0x99,0x1b,0x78,0x52,0xb8,0x55
        };
        test_sha256(out, (const uint8_t *)"", 0);
        fail |= check("SHA-256(\"\")", out, expected, 32);
    }

    /* Vector 2: "abc" */
    {
        const uint8_t expected[] = {
            0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,
            0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
            0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,
            0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad
        };
        test_sha256(out, (const uint8_t *)"abc", 3);
        fail |= check("SHA-256(\"abc\")", out, expected, 32);
    }

    /* Vector 3: "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
     * (56 bytes — forces two-block padding) */
    {
        const char *msg = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        const uint8_t expected[] = {
            0x24,0x8d,0x6a,0x61,0xd2,0x06,0x38,0xb8,
            0xe5,0xc0,0x26,0x93,0x0c,0x3e,0x60,0x39,
            0xa3,0x3c,0xe4,0x59,0x64,0xff,0x21,0x67,
            0xf6,0xec,0xed,0xd4,0x19,0xdb,0x06,0xc1
        };
        test_sha256(out, (const uint8_t *)msg, strlen(msg));
        fail |= check("SHA-256(448-bit)", out, expected, 32);
    }

    /* Vector 4: 64 bytes of 'a' (exactly one full block) */
    {
        const char *msg = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        const uint8_t expected[] = {
            0xff,0xe0,0x54,0xfe,0x7a,0xe0,0xcb,0x6d,
            0xc6,0x5c,0x3a,0xf9,0xb6,0x1d,0x52,0x09,
            0xf4,0x39,0x85,0x1d,0xb4,0x3d,0x0b,0xa5,
            0x99,0x73,0x37,0xdf,0x15,0x46,0x68,0xeb
        };
        test_sha256(out, (const uint8_t *)msg, 64);
        fail |= check("SHA-256(64 bytes)", out, expected, 32);
    }

    /* Vector 5: XMSS PRF — SHA-256(toByte(3,32) || key || adrs)
     * Compute reference: key=all-zeros, adrs=all-zeros
     * Input is 96 bytes: 31 zero bytes + 0x03 + 32 zero bytes + 32 zero bytes
     * = 31*0x00 + 0x03 + 64*0x00 */
    {
        uint8_t key[32] = {0};
        uint8_t adrs[32] = {0};
        /* Compute expected via oneshot: build the 96-byte preimage */
        uint8_t preimage[96] = {0};
        preimage[31] = 0x03; /* toByte(3, 32) */
        /* key and adrs are already zero */
        uint8_t expected[32];
        test_sha256(expected, preimage, 96);

        test_xmss_prf(out, key, adrs);
        fail |= check("XMSS PRF(0,0)", out, expected, 32);
    }

    return fail ? 1 : 0;
}
