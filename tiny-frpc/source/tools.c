/**
 * @file tools.c
 * @brief Lightweight utility helpers (embedded-friendly)
 */
#include "../include/tools.h"
#include "wrapper.h"
#include <string.h>
#include <stdio.h>

/* Detect host endianness */
static int is_little_endian(void) {
    static uint32_t test = 1;
    return *((uint8_t*)&test) == 1;
}

/* Byte-order conversion helpers */
uint32_t tools_htonl(uint32_t hostlong) {
    if (is_little_endian()) {
        return ((hostlong & 0xFF) << 24) |
               ((hostlong & 0xFF00) << 8) |
               ((hostlong & 0xFF0000) >> 8) |
               ((hostlong & 0xFF000000) >> 24);
    }
    return hostlong;
}

uint16_t tools_htons(uint16_t hostshort) {
    if (is_little_endian()) {
        return ((hostshort & 0xFF) << 8) | ((hostshort & 0xFF00) >> 8);
    }
    return hostshort;
}

uint32_t tools_ntohl(uint32_t netlong) {
    return tools_htonl(netlong); /* host<->network conversion is symmetric */
}

uint16_t tools_ntohs(uint16_t netshort) {
    return tools_htons(netshort); /* host<->network conversion is symmetric */
}

/* 
 * Time helper.
 * Uses wrapper layer for platform portability.
 */
uint64_t tools_get_time_ms(void) {
    return wrapped_get_time_ms();
}

void tools_init(void) {
    /* Initialize internal state if needed */
}

void tools_sleep_ms(uint32_t ms) {
    wrapped_usleep(ms * 1000);
} 

// -----------------------------
// MD5 (RFC 1321) minimal implementation
// -----------------------------

typedef struct {
    uint32_t state[4];   // A, B, C, D
    uint64_t bit_count;  // Number of bits processed
    uint8_t buffer[64];  // Input buffer
} tools_md5_ctx_t;

static uint32_t tools_md5_rotl32(uint32_t x, uint32_t n) {
    return (x << n) | (x >> (32U - n));
}

static uint32_t tools_md5_load_le32(const uint8_t* p) {
    return ((uint32_t)p[0]) |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static void tools_md5_store_le32(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)(v & 0xFF);
    p[1] = (uint8_t)((v >> 8) & 0xFF);
    p[2] = (uint8_t)((v >> 16) & 0xFF);
    p[3] = (uint8_t)((v >> 24) & 0xFF);
}

// MD5 auxiliary functions
#define MD5_F(x, y, z) (((x) & (y)) | (~(x) & (z)))
#define MD5_G(x, y, z) (((x) & (z)) | ((y) & ~(z)))
#define MD5_H(x, y, z) ((x) ^ (y) ^ (z))
#define MD5_I(x, y, z) ((y) ^ ((x) | ~(z)))

#define MD5_STEP(f, a, b, c, d, x, t, s) \
    do {                                 \
        (a) += f((b), (c), (d)) + (x) + (t); \
        (a) = tools_md5_rotl32((a), (s));     \
        (a) += (b);                           \
    } while (0)

static void tools_md5_transform(uint32_t state[4], const uint8_t block[64]) {
    uint32_t a = state[0];
    uint32_t b = state[1];
    uint32_t c = state[2];
    uint32_t d = state[3];

    uint32_t x[16];
    for (int i = 0; i < 16; i++) {
        x[i] = tools_md5_load_le32(block + (i * 4));
    }

    // Round 1
    MD5_STEP(MD5_F, a, b, c, d, x[ 0], 0xd76aa478,  7);
    MD5_STEP(MD5_F, d, a, b, c, x[ 1], 0xe8c7b756, 12);
    MD5_STEP(MD5_F, c, d, a, b, x[ 2], 0x242070db, 17);
    MD5_STEP(MD5_F, b, c, d, a, x[ 3], 0xc1bdceee, 22);
    MD5_STEP(MD5_F, a, b, c, d, x[ 4], 0xf57c0faf,  7);
    MD5_STEP(MD5_F, d, a, b, c, x[ 5], 0x4787c62a, 12);
    MD5_STEP(MD5_F, c, d, a, b, x[ 6], 0xa8304613, 17);
    MD5_STEP(MD5_F, b, c, d, a, x[ 7], 0xfd469501, 22);
    MD5_STEP(MD5_F, a, b, c, d, x[ 8], 0x698098d8,  7);
    MD5_STEP(MD5_F, d, a, b, c, x[ 9], 0x8b44f7af, 12);
    MD5_STEP(MD5_F, c, d, a, b, x[10], 0xffff5bb1, 17);
    MD5_STEP(MD5_F, b, c, d, a, x[11], 0x895cd7be, 22);
    MD5_STEP(MD5_F, a, b, c, d, x[12], 0x6b901122,  7);
    MD5_STEP(MD5_F, d, a, b, c, x[13], 0xfd987193, 12);
    MD5_STEP(MD5_F, c, d, a, b, x[14], 0xa679438e, 17);
    MD5_STEP(MD5_F, b, c, d, a, x[15], 0x49b40821, 22);

    // Round 2
    MD5_STEP(MD5_G, a, b, c, d, x[ 1], 0xf61e2562,  5);
    MD5_STEP(MD5_G, d, a, b, c, x[ 6], 0xc040b340,  9);
    MD5_STEP(MD5_G, c, d, a, b, x[11], 0x265e5a51, 14);
    MD5_STEP(MD5_G, b, c, d, a, x[ 0], 0xe9b6c7aa, 20);
    MD5_STEP(MD5_G, a, b, c, d, x[ 5], 0xd62f105d,  5);
    MD5_STEP(MD5_G, d, a, b, c, x[10], 0x02441453,  9);
    MD5_STEP(MD5_G, c, d, a, b, x[15], 0xd8a1e681, 14);
    MD5_STEP(MD5_G, b, c, d, a, x[ 4], 0xe7d3fbc8, 20);
    MD5_STEP(MD5_G, a, b, c, d, x[ 9], 0x21e1cde6,  5);
    MD5_STEP(MD5_G, d, a, b, c, x[14], 0xc33707d6,  9);
    MD5_STEP(MD5_G, c, d, a, b, x[ 3], 0xf4d50d87, 14);
    MD5_STEP(MD5_G, b, c, d, a, x[ 8], 0x455a14ed, 20);
    MD5_STEP(MD5_G, a, b, c, d, x[13], 0xa9e3e905,  5);
    MD5_STEP(MD5_G, d, a, b, c, x[ 2], 0xfcefa3f8,  9);
    MD5_STEP(MD5_G, c, d, a, b, x[ 7], 0x676f02d9, 14);
    MD5_STEP(MD5_G, b, c, d, a, x[12], 0x8d2a4c8a, 20);

    // Round 3
    MD5_STEP(MD5_H, a, b, c, d, x[ 5], 0xfffa3942,  4);
    MD5_STEP(MD5_H, d, a, b, c, x[ 8], 0x8771f681, 11);
    MD5_STEP(MD5_H, c, d, a, b, x[11], 0x6d9d6122, 16);
    MD5_STEP(MD5_H, b, c, d, a, x[14], 0xfde5380c, 23);
    MD5_STEP(MD5_H, a, b, c, d, x[ 1], 0xa4beea44,  4);
    MD5_STEP(MD5_H, d, a, b, c, x[ 4], 0x4bdecfa9, 11);
    MD5_STEP(MD5_H, c, d, a, b, x[ 7], 0xf6bb4b60, 16);
    MD5_STEP(MD5_H, b, c, d, a, x[10], 0xbebfbc70, 23);
    MD5_STEP(MD5_H, a, b, c, d, x[13], 0x289b7ec6,  4);
    MD5_STEP(MD5_H, d, a, b, c, x[ 0], 0xeaa127fa, 11);
    MD5_STEP(MD5_H, c, d, a, b, x[ 3], 0xd4ef3085, 16);
    MD5_STEP(MD5_H, b, c, d, a, x[ 6], 0x04881d05, 23);
    MD5_STEP(MD5_H, a, b, c, d, x[ 9], 0xd9d4d039,  4);
    MD5_STEP(MD5_H, d, a, b, c, x[12], 0xe6db99e5, 11);
    MD5_STEP(MD5_H, c, d, a, b, x[15], 0x1fa27cf8, 16);
    MD5_STEP(MD5_H, b, c, d, a, x[ 2], 0xc4ac5665, 23);

    // Round 4
    MD5_STEP(MD5_I, a, b, c, d, x[ 0], 0xf4292244,  6);
    MD5_STEP(MD5_I, d, a, b, c, x[ 7], 0x432aff97, 10);
    MD5_STEP(MD5_I, c, d, a, b, x[14], 0xab9423a7, 15);
    MD5_STEP(MD5_I, b, c, d, a, x[ 5], 0xfc93a039, 21);
    MD5_STEP(MD5_I, a, b, c, d, x[12], 0x655b59c3,  6);
    MD5_STEP(MD5_I, d, a, b, c, x[ 3], 0x8f0ccc92, 10);
    MD5_STEP(MD5_I, c, d, a, b, x[10], 0xffeff47d, 15);
    MD5_STEP(MD5_I, b, c, d, a, x[ 1], 0x85845dd1, 21);
    MD5_STEP(MD5_I, a, b, c, d, x[ 8], 0x6fa87e4f,  6);
    MD5_STEP(MD5_I, d, a, b, c, x[15], 0xfe2ce6e0, 10);
    MD5_STEP(MD5_I, c, d, a, b, x[ 6], 0xa3014314, 15);
    MD5_STEP(MD5_I, b, c, d, a, x[13], 0x4e0811a1, 21);
    MD5_STEP(MD5_I, a, b, c, d, x[ 4], 0xf7537e82,  6);
    MD5_STEP(MD5_I, d, a, b, c, x[11], 0xbd3af235, 10);
    MD5_STEP(MD5_I, c, d, a, b, x[ 2], 0x2ad7d2bb, 15);
    MD5_STEP(MD5_I, b, c, d, a, x[ 9], 0xeb86d391, 21);

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;

    // Clean stack copy
    memset(x, 0, sizeof(x));
}

static void tools_md5_init_ctx(tools_md5_ctx_t* ctx) {
    ctx->bit_count = 0;
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xefcdab89;
    ctx->state[2] = 0x98badcfe;
    ctx->state[3] = 0x10325476;
    memset(ctx->buffer, 0, sizeof(ctx->buffer));
}

static void tools_md5_update_ctx(tools_md5_ctx_t* ctx, const uint8_t* data, size_t len) {
    size_t buffer_idx = (size_t)((ctx->bit_count >> 3) & 0x3F);
    ctx->bit_count += ((uint64_t)len) * 8;

    size_t part_len = 64 - buffer_idx;
    size_t i = 0;

    if (len >= part_len) {
        memcpy(&ctx->buffer[buffer_idx], data, part_len);
        tools_md5_transform(ctx->state, ctx->buffer);

        for (i = part_len; i + 63 < len; i += 64) {
            tools_md5_transform(ctx->state, &data[i]);
        }
        buffer_idx = 0;
    }

    memcpy(&ctx->buffer[buffer_idx], &data[i], len - i);
}

static void tools_md5_final_ctx(tools_md5_ctx_t* ctx, uint8_t digest[16]) {
    uint8_t padding[64];
    memset(padding, 0, sizeof(padding));
    padding[0] = 0x80;

    uint8_t length_le[8];
    // MD5 appends length in bits as little-endian 64-bit
    uint64_t bit_count = ctx->bit_count;
    for (int i = 0; i < 8; i++) {
        length_le[i] = (uint8_t)((bit_count >> (8 * i)) & 0xFF);
    }

    size_t buffer_idx = (size_t)((ctx->bit_count >> 3) & 0x3F);
    size_t pad_len = (buffer_idx < 56) ? (56 - buffer_idx) : (120 - buffer_idx);

    tools_md5_update_ctx(ctx, padding, pad_len);
    tools_md5_update_ctx(ctx, length_le, 8);

    tools_md5_store_le32(&digest[0], ctx->state[0]);
    tools_md5_store_le32(&digest[4], ctx->state[1]);
    tools_md5_store_le32(&digest[8], ctx->state[2]);
    tools_md5_store_le32(&digest[12], ctx->state[3]);

    // Clear context
    memset(ctx, 0, sizeof(*ctx));
}

int tools_md5_hex(const uint8_t* data, size_t len, char out_hex[33]) {
    if (!data || !out_hex) {
        return -1;
    }

    tools_md5_ctx_t ctx;
    uint8_t digest[16];
    tools_md5_init_ctx(&ctx);
    tools_md5_update_ctx(&ctx, data, len);
    tools_md5_final_ctx(&ctx, digest);

    static const char hex_chars[] = "0123456789abcdef";
    for (int i = 0; i < 16; i++) {
        out_hex[i * 2] = hex_chars[(digest[i] >> 4) & 0x0F];
        out_hex[i * 2 + 1] = hex_chars[digest[i] & 0x0F];
    }
    out_hex[32] = '\0';
    return 0;
}

int tools_get_auth_key(const char* token, int64_t timestamp, char out_hex[33]) {
    if (!token || !out_hex) {
        return -1;
    }

    tools_md5_ctx_t ctx;
    uint8_t digest[16];
    tools_md5_init_ctx(&ctx);
    tools_md5_update_ctx(&ctx, (const uint8_t*)token, strlen(token));

    char ts_buf[32];
    snprintf(ts_buf, sizeof(ts_buf), "%lld", (long long)timestamp);
    tools_md5_update_ctx(&ctx, (const uint8_t*)ts_buf, strlen(ts_buf));

    tools_md5_final_ctx(&ctx, digest);

    static const char hex_chars[] = "0123456789abcdef";
    for (int i = 0; i < 16; i++) {
        out_hex[i * 2] = hex_chars[(digest[i] >> 4) & 0x0F];
        out_hex[i * 2 + 1] = hex_chars[digest[i] & 0x0F];
    }
    out_hex[32] = '\0';
    return 0;
}