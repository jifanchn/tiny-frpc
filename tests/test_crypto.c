/**
 * @file test_crypto.c
 * @brief Unit tests for crypto module
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <errno.h>

#include "crypto.h"

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

#define TEST_ASSERT_EQ(exp, act, msg) \
    do { \
        if ((exp) != (act)) { \
            fprintf(stderr, "FAIL: %s (expected: %d, actual: %d)\n", msg, (int)(exp), (int)(act)); \
            return -1; \
        } else { \
            printf("PASS: %s\n", msg); \
        } \
    } while (0)

static void hex_dump(const char* prefix, const uint8_t* data, size_t len) {
    printf("%s: ", prefix);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

// Known test vector for SHA1
// SHA1("abc") = a9993e364706816aba3e25717850c26c9cd0d89d
static int test_sha1_basic(void) {
    printf("\n=== Testing SHA1 basic ===\n");
    
    const char* input = "abc";
    uint8_t expected[] = {
        0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a,
        0xba, 0x3e, 0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c,
        0x9c, 0xd0, 0xd8, 0x9d
    };
    
    uint8_t digest[SHA1_DIGEST_SIZE];
    sha1_hash((const uint8_t*)input, strlen(input), digest);
    
    hex_dump("SHA1(abc)", digest, SHA1_DIGEST_SIZE);
    
    TEST_ASSERT(memcmp(digest, expected, SHA1_DIGEST_SIZE) == 0, "SHA1(abc) should match expected");
    
    return 0;
}

// SHA1("") = da39a3ee5e6b4b0d3255bfef95601890afd80709
static int test_sha1_empty(void) {
    printf("\n=== Testing SHA1 empty string ===\n");
    
    uint8_t expected[] = {
        0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d,
        0x32, 0x55, 0xbf, 0xef, 0x95, 0x60, 0x18, 0x90,
        0xaf, 0xd8, 0x07, 0x09
    };
    
    uint8_t digest[SHA1_DIGEST_SIZE];
    sha1_hash((const uint8_t*)"", 0, digest);
    
    hex_dump("SHA1(empty)", digest, SHA1_DIGEST_SIZE);
    
    TEST_ASSERT(memcmp(digest, expected, SHA1_DIGEST_SIZE) == 0, "SHA1(empty) should match expected");
    
    return 0;
}

// SHA1 incremental update
static int test_sha1_incremental(void) {
    printf("\n=== Testing SHA1 incremental ===\n");
    
    const char* full = "The quick brown fox jumps over the lazy dog";
    
    uint8_t expected[SHA1_DIGEST_SIZE];
    sha1_hash((const uint8_t*)full, strlen(full), expected);
    
    // Compute incrementally
    sha1_ctx_t ctx;
    sha1_init(&ctx);
    sha1_update(&ctx, (const uint8_t*)"The quick brown ", 16);
    sha1_update(&ctx, (const uint8_t*)"fox jumps over ", 15);
    sha1_update(&ctx, (const uint8_t*)"the lazy dog", 12);
    
    uint8_t digest[SHA1_DIGEST_SIZE];
    sha1_final(&ctx, digest);
    
    TEST_ASSERT(memcmp(digest, expected, SHA1_DIGEST_SIZE) == 0, "Incremental SHA1 should match full");
    
    return 0;
}

// PBKDF2-SHA1 test
static int test_pbkdf2(void) {
    printf("\n=== Testing PBKDF2-SHA1 ===\n");
    
    // Test case: password="password", salt="salt", iterations=1, dkLen=20
    // Expected result from RFC 6070:
    // 0c60c80f961f0e71f3a9b524af6012062fe037a6
    const char* password = "password";
    const char* salt = "salt";
    uint8_t expected[] = {
        0x0c, 0x60, 0xc8, 0x0f, 0x96, 0x1f, 0x0e, 0x71,
        0xf3, 0xa9, 0xb5, 0x24, 0xaf, 0x60, 0x12, 0x06,
        0x2f, 0xe0, 0x37, 0xa6
    };
    
    uint8_t dk[20];
    int ret = pbkdf2_sha1((const uint8_t*)password, strlen(password),
                          (const uint8_t*)salt, strlen(salt),
                          1, dk, sizeof(dk));
    
    TEST_ASSERT_EQ(0, ret, "pbkdf2_sha1 should succeed");
    hex_dump("PBKDF2 result", dk, 20);
    
    TEST_ASSERT(memcmp(dk, expected, 20) == 0, "PBKDF2 result should match RFC 6070");
    
    return 0;
}

// PBKDF2 with FRP parameters
static int test_pbkdf2_frp(void) {
    printf("\n=== Testing PBKDF2 with FRP parameters ===\n");
    
    // FRP uses: salt="frp", iterations=64
    const char* token = "test_token";
    
    uint8_t dk[16];
    int ret = pbkdf2_sha1((const uint8_t*)token, strlen(token),
                          (const uint8_t*)FRP_CRYPTO_SALT, strlen(FRP_CRYPTO_SALT),
                          64, dk, sizeof(dk));
    
    TEST_ASSERT_EQ(0, ret, "pbkdf2_sha1 with FRP params should succeed");
    hex_dump("FRP derived key", dk, 16);
    
    // Just verify we got a valid key (non-zero)
    int non_zero = 0;
    for (size_t i = 0; i < sizeof(dk); i++) {
        if (dk[i] != 0) non_zero++;
    }
    TEST_ASSERT(non_zero > 0, "Derived key should not be all zeros");
    
    return 0;
}

// AES-128 encryption test
static int test_aes128_basic(void) {
    printf("\n=== Testing AES-128 basic ===\n");
    
    // Test vector from FIPS 197 Appendix C.1
    // Key: 000102030405060708090a0b0c0d0e0f
    // Plain: 00112233445566778899aabbccddeeff
    // Cipher: 69c4e0d86a7b0430d8cdb78070b4c55a
    uint8_t key[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    uint8_t plain[] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
    };
    uint8_t expected[] = {
        0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
        0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a
    };
    
    aes128_ctx_t ctx;
    aes128_init(&ctx, key);
    
    uint8_t cipher[16];
    aes128_encrypt_block(&ctx, plain, cipher);
    
    hex_dump("AES cipher", cipher, 16);
    
    TEST_ASSERT(memcmp(cipher, expected, 16) == 0, "AES-128 cipher should match FIPS 197");
    
    return 0;
}

// AES-CFB encryption/decryption roundtrip
static int test_aes_cfb_roundtrip(void) {
    printf("\n=== Testing AES-CFB roundtrip ===\n");
    
    uint8_t key[16] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };
    uint8_t iv[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    
    const char* plaintext = "Hello, this is a test message for AES-CFB encryption!";
    size_t len = strlen(plaintext);
    
    uint8_t* ciphertext = (uint8_t*)malloc(len);
    uint8_t* decrypted = (uint8_t*)malloc(len);
    
    // Encrypt
    aes_cfb_ctx_t enc_ctx;
    aes_cfb_encrypt_init(&enc_ctx, key, iv);
    aes_cfb_encrypt(&enc_ctx, (const uint8_t*)plaintext, ciphertext, len);
    
    // Verify ciphertext is different from plaintext
    TEST_ASSERT(memcmp(plaintext, ciphertext, len) != 0, "Ciphertext should differ from plaintext");
    
    // Decrypt
    aes_cfb_ctx_t dec_ctx;
    aes_cfb_decrypt_init(&dec_ctx, key, iv);
    aes_cfb_decrypt(&dec_ctx, ciphertext, decrypted, len);
    
    // Verify decryption
    TEST_ASSERT(memcmp(plaintext, decrypted, len) == 0, "Decrypted should match original plaintext");
    
    free(ciphertext);
    free(decrypted);
    
    return 0;
}

// AES-CFB partial block handling
static int test_aes_cfb_partial_blocks(void) {
    printf("\n=== Testing AES-CFB partial blocks ===\n");
    
    uint8_t key[16] = {0};
    uint8_t iv[16] = {0};
    
    // Test with various sizes (1 byte, 15 bytes, 17 bytes, etc.)
    size_t test_sizes[] = {1, 7, 15, 16, 17, 31, 32, 33, 100};
    
    for (size_t i = 0; i < sizeof(test_sizes) / sizeof(test_sizes[0]); i++) {
        size_t len = test_sizes[i];
        uint8_t* plain = (uint8_t*)malloc(len);
        uint8_t* cipher = (uint8_t*)malloc(len);
        uint8_t* decrypted = (uint8_t*)malloc(len);
        
        // Fill with pattern
        for (size_t j = 0; j < len; j++) {
            plain[j] = (uint8_t)(j & 0xFF);
        }
        
        aes_cfb_ctx_t enc_ctx, dec_ctx;
        aes_cfb_encrypt_init(&enc_ctx, key, iv);
        aes_cfb_encrypt(&enc_ctx, plain, cipher, len);
        
        aes_cfb_decrypt_init(&dec_ctx, key, iv);
        aes_cfb_decrypt(&dec_ctx, cipher, decrypted, len);
        
        if (memcmp(plain, decrypted, len) != 0) {
            fprintf(stderr, "FAIL: AES-CFB roundtrip failed for size %zu\n", len);
            free(plain);
            free(cipher);
            free(decrypted);
            return -1;
        }
        printf("PASS: AES-CFB roundtrip size %zu\n", len);
        
        free(plain);
        free(cipher);
        free(decrypted);
    }
    
    return 0;
}

// FRP crypto stream test using socketpair
static int test_frp_crypto_stream(void) {
    printf("\n=== Testing FRP crypto stream ===\n");
    
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
        fprintf(stderr, "FAIL: socketpair failed: %s\n", strerror(errno));
        return -1;
    }
    
    frp_crypto_stream_t* write_stream = frp_crypto_stream_new("test_token");
    frp_crypto_stream_t* read_stream = frp_crypto_stream_new("test_token");
    
    TEST_ASSERT(write_stream != NULL, "frp_crypto_stream_new(write) should succeed");
    TEST_ASSERT(read_stream != NULL, "frp_crypto_stream_new(read) should succeed");
    
    const char* test_data = "Hello from FRP crypto stream!";
    size_t data_len = strlen(test_data);
    
    // Write encrypted data
    int written = frp_crypto_write(write_stream, sv[0], (const uint8_t*)test_data, data_len);
    TEST_ASSERT(written > 0, "frp_crypto_write should succeed");
    
    // Read and decrypt
    uint8_t buf[256];
    int read_n = frp_crypto_read(read_stream, sv[1], buf, sizeof(buf), 5000);
    TEST_ASSERT(read_n > 0, "frp_crypto_read should succeed");
    TEST_ASSERT((size_t)read_n == data_len, "Read length should match data length");
    TEST_ASSERT(memcmp(buf, test_data, data_len) == 0, "Decrypted data should match original");
    
    printf("PASS: FRP crypto stream roundtrip successful\n");
    
    frp_crypto_stream_free(write_stream);
    frp_crypto_stream_free(read_stream);
    close(sv[0]);
    close(sv[1]);
    
    return 0;
}

// FRP crypto stream multiple writes
static int test_frp_crypto_stream_multiple_writes(void) {
    printf("\n=== Testing FRP crypto stream multiple writes ===\n");
    
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
        fprintf(stderr, "FAIL: socketpair failed: %s\n", strerror(errno));
        return -1;
    }
    
    frp_crypto_stream_t* write_stream = frp_crypto_stream_new("multi_token");
    frp_crypto_stream_t* read_stream = frp_crypto_stream_new("multi_token");
    
    const char* msg1 = "First message";
    const char* msg2 = "Second message with more data";
    const char* msg3 = "Third";
    
    // Write three messages
    TEST_ASSERT(frp_crypto_write(write_stream, sv[0], (const uint8_t*)msg1, strlen(msg1)) > 0, "write msg1");
    TEST_ASSERT(frp_crypto_write(write_stream, sv[0], (const uint8_t*)msg2, strlen(msg2)) > 0, "write msg2");
    TEST_ASSERT(frp_crypto_write(write_stream, sv[0], (const uint8_t*)msg3, strlen(msg3)) > 0, "write msg3");
    
    // Read all in one buffer
    size_t total_len = strlen(msg1) + strlen(msg2) + strlen(msg3);
    uint8_t* buf = (uint8_t*)malloc(total_len + 1);
    memset(buf, 0, total_len + 1);
    
    size_t total_read = 0;
    while (total_read < total_len) {
        int n = frp_crypto_read(read_stream, sv[1], buf + total_read, total_len - total_read, 5000);
        if (n <= 0) break;
        total_read += (size_t)n;
    }
    
    TEST_ASSERT(total_read == total_len, "Total read should match total written");
    
    // Verify content
    char expected[256];
    snprintf(expected, sizeof(expected), "%s%s%s", msg1, msg2, msg3);
    TEST_ASSERT(memcmp(buf, expected, total_len) == 0, "Content should match");
    
    free(buf);
    frp_crypto_stream_free(write_stream);
    frp_crypto_stream_free(read_stream);
    close(sv[0]);
    close(sv[1]);
    
    return 0;
}

// Error handling tests
static int test_crypto_error_handling(void) {
    printf("\n=== Testing crypto error handling ===\n");
    
    // NULL token - now returns valid stream (for FRPS compatibility with empty token)
    frp_crypto_stream_t* stream = frp_crypto_stream_new(NULL);
    TEST_ASSERT(stream != NULL, "frp_crypto_stream_new(NULL) should return valid stream (FRPS compatibility)");
    frp_crypto_stream_free(stream);
    
    // Empty token - now returns valid stream (for FRPS compatibility)
    stream = frp_crypto_stream_new("");
    TEST_ASSERT(stream != NULL, "frp_crypto_stream_new(empty) should return valid stream (FRPS compatibility)");
    frp_crypto_stream_free(stream);
    
    // Free NULL stream (should not crash)
    frp_crypto_stream_free(NULL);
    printf("PASS: frp_crypto_stream_free(NULL) should not crash\n");
    
    // Invalid fd for write/read
    stream = frp_crypto_stream_new("test_token");
    TEST_ASSERT(stream != NULL, "frp_crypto_stream_new should succeed");
    
    int ret = frp_crypto_write(stream, -1, (const uint8_t*)"test", 4);
    TEST_ASSERT(ret < 0, "frp_crypto_write to invalid fd should fail");
    
    uint8_t buf[32];
    ret = frp_crypto_read(stream, -1, buf, sizeof(buf), 100);
    TEST_ASSERT(ret < 0, "frp_crypto_read from invalid fd should fail");
    
    frp_crypto_stream_free(stream);
    
    return 0;
}

int main(void) {
    printf("Running crypto unit tests...\n");
    int failed = 0;
    
    if (test_sha1_basic() != 0) failed++;
    if (test_sha1_empty() != 0) failed++;
    if (test_sha1_incremental() != 0) failed++;
    if (test_pbkdf2() != 0) failed++;
    if (test_pbkdf2_frp() != 0) failed++;
    if (test_aes128_basic() != 0) failed++;
    if (test_aes_cfb_roundtrip() != 0) failed++;
    if (test_aes_cfb_partial_blocks() != 0) failed++;
    if (test_frp_crypto_stream() != 0) failed++;
    if (test_frp_crypto_stream_multiple_writes() != 0) failed++;
    if (test_crypto_error_handling() != 0) failed++;
    
    printf("\n=== Test Results ===\n");
    if (failed == 0) {
        printf("All tests passed!\n");
        return 0;
    }
    printf("%d test(s) failed!\n", failed);
    return 1;
}

