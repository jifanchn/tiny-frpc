#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "../tiny-frpc/include/tools.h"

// Simple assertion macro
#define TEST_ASSERT(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "FAIL: %s\n", msg); \
            return -1; \
        } else { \
            printf("PASS: %s\n", msg); \
        } \
    } while (0)

#define TEST_ASSERT_STR_EQ(exp, act, msg) \
    do { \
        if (strcmp((exp), (act)) != 0) { \
            fprintf(stderr, "FAIL: %s (expected: %s, actual: %s)\n", msg, (exp), (act)); \
            return -1; \
        } else { \
            printf("PASS: %s\n", msg); \
        } \
    } while (0)

static int test_endian() {
    printf("\n=== Testing endian conversions ===\n");
    TEST_ASSERT(tools_htonl(0x11223344u) == 0x44332211u || tools_htonl(0x11223344u) == 0x11223344u,
                "tools_htonl should produce a valid conversion");
    TEST_ASSERT(tools_ntohl(tools_htonl(0x01020304u)) == 0x01020304u,
                "ntohl(htonl(x)) == x");
    TEST_ASSERT(tools_ntohs(tools_htons(0x1234u)) == 0x1234u,
                "ntohs(htons(x)) == x");
    return 0;
}

static int test_md5_hex_basic() {
    printf("\n=== Testing tools_md5_hex ===\n");
    char out[33];
    TEST_ASSERT(tools_md5_hex((const uint8_t*)"abc", 3, out) == 0, "tools_md5_hex should return 0");
    TEST_ASSERT_STR_EQ("900150983cd24fb0d6963f7d28e17f72", out, "MD5(\"abc\") should match known value");
    return 0;
}

static int test_auth_key() {
    printf("\n=== Testing tools_get_auth_key ===\n");
    // Align with Go: util.GetAuthKey("test_token", 1700000000) = md5("test_token1700000000")
    char out[33];
    TEST_ASSERT(tools_get_auth_key("test_token", 1700000000LL, out) == 0, "tools_get_auth_key should return 0");
    // This value can be verified in Go: fmt.Printf("%x\n", md5.Sum([]byte("test_token1700000000")))
    TEST_ASSERT_STR_EQ("4f925203f36a0bda717e3b1a26c8a2f0", out, "AuthKey should match Go util.GetAuthKey");
    return 0;
}

int main() {
    printf("Running tools tests...\n");

    int failed = 0;
    if (test_endian() != 0) failed++;
    if (test_md5_hex_basic() != 0) failed++;
    if (test_auth_key() != 0) failed++;

    printf("\n=== Test Results ===\n");
    if (failed == 0) {
        printf("All tests passed!\n");
        return 0;
    }
    printf("%d test(s) failed!\n", failed);
    return 1;
}


