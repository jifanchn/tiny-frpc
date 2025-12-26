/**
 * @file crypto.c
 * @brief Cryptographic utilities for FRP protocol
 */
#include "../include/crypto.h"
#include "wrapper.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>

// =====================
// Helper functions
// =====================

static uint32_t rotl32(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

// =====================
// SHA1 Implementation
// =====================

void sha1_init(sha1_ctx_t* ctx) {
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xEFCDAB89;
    ctx->state[2] = 0x98BADCFE;
    ctx->state[3] = 0x10325476;
    ctx->state[4] = 0xC3D2E1F0;
    ctx->bit_count = 0;
    memset(ctx->buffer, 0, sizeof(ctx->buffer));
}

static void sha1_transform(uint32_t state[5], const uint8_t block[64]) {
    uint32_t w[80];
    uint32_t a, b, c, d, e, f, k, temp;
    
    // Prepare message schedule
    for (int i = 0; i < 16; i++) {
        w[i] = ((uint32_t)block[i*4] << 24) |
               ((uint32_t)block[i*4+1] << 16) |
               ((uint32_t)block[i*4+2] << 8) |
               ((uint32_t)block[i*4+3]);
    }
    for (int i = 16; i < 80; i++) {
        w[i] = rotl32(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
    }
    
    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];
    
    for (int i = 0; i < 80; i++) {
        if (i < 20) {
            f = (b & c) | ((~b) & d);
            k = 0x5A827999;
        } else if (i < 40) {
            f = b ^ c ^ d;
            k = 0x6ED9EBA1;
        } else if (i < 60) {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8F1BBCDC;
        } else {
            f = b ^ c ^ d;
            k = 0xCA62C1D6;
        }
        
        temp = rotl32(a, 5) + f + e + k + w[i];
        e = d;
        d = c;
        c = rotl32(b, 30);
        b = a;
        a = temp;
    }
    
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
}

void sha1_update(sha1_ctx_t* ctx, const uint8_t* data, size_t len) {
    size_t buffer_idx = (size_t)((ctx->bit_count >> 3) & 0x3F);
    ctx->bit_count += ((uint64_t)len) * 8;
    
    size_t part_len = 64 - buffer_idx;
    size_t i = 0;
    
    if (len >= part_len) {
        memcpy(&ctx->buffer[buffer_idx], data, part_len);
        sha1_transform(ctx->state, ctx->buffer);
        
        for (i = part_len; i + 63 < len; i += 64) {
            sha1_transform(ctx->state, &data[i]);
        }
        buffer_idx = 0;
    }
    
    memcpy(&ctx->buffer[buffer_idx], &data[i], len - i);
}

void sha1_final(sha1_ctx_t* ctx, uint8_t digest[SHA1_DIGEST_SIZE]) {
    uint8_t padding[64];
    memset(padding, 0, sizeof(padding));
    padding[0] = 0x80;
    
    // SHA1 appends length in bits as big-endian 64-bit
    uint8_t length_be[8];
    uint64_t bit_count = ctx->bit_count;
    for (int i = 7; i >= 0; i--) {
        length_be[7 - i] = (uint8_t)((bit_count >> (8 * i)) & 0xFF);
    }
    
    size_t buffer_idx = (size_t)((ctx->bit_count >> 3) & 0x3F);
    size_t pad_len = (buffer_idx < 56) ? (56 - buffer_idx) : (120 - buffer_idx);
    
    sha1_update(ctx, padding, pad_len);
    sha1_update(ctx, length_be, 8);
    
    // Output hash in big-endian
    for (int i = 0; i < 5; i++) {
        digest[i*4]     = (uint8_t)((ctx->state[i] >> 24) & 0xFF);
        digest[i*4 + 1] = (uint8_t)((ctx->state[i] >> 16) & 0xFF);
        digest[i*4 + 2] = (uint8_t)((ctx->state[i] >> 8) & 0xFF);
        digest[i*4 + 3] = (uint8_t)(ctx->state[i] & 0xFF);
    }
    
    memset(ctx, 0, sizeof(*ctx));
}

void sha1_hash(const uint8_t* data, size_t len, uint8_t digest[SHA1_DIGEST_SIZE]) {
    sha1_ctx_t ctx;
    sha1_init(&ctx);
    sha1_update(&ctx, data, len);
    sha1_final(&ctx, digest);
}

// =====================
// HMAC-SHA1
// =====================

static void hmac_sha1(const uint8_t* key, size_t key_len,
                      const uint8_t* data, size_t data_len,
                      uint8_t out[SHA1_DIGEST_SIZE]) {
    uint8_t k[64];
    uint8_t o_key_pad[64];
    uint8_t i_key_pad[64];
    
    // If key is longer than block size, hash it
    if (key_len > 64) {
        sha1_hash(key, key_len, k);
        memset(k + SHA1_DIGEST_SIZE, 0, 64 - SHA1_DIGEST_SIZE);
    } else {
        memcpy(k, key, key_len);
        memset(k + key_len, 0, 64 - key_len);
    }
    
    // Create padded keys
    for (int i = 0; i < 64; i++) {
        o_key_pad[i] = k[i] ^ 0x5C;
        i_key_pad[i] = k[i] ^ 0x36;
    }
    
    // Inner hash
    sha1_ctx_t ctx;
    sha1_init(&ctx);
    sha1_update(&ctx, i_key_pad, 64);
    sha1_update(&ctx, data, data_len);
    uint8_t inner_hash[SHA1_DIGEST_SIZE];
    sha1_final(&ctx, inner_hash);
    
    // Outer hash
    sha1_init(&ctx);
    sha1_update(&ctx, o_key_pad, 64);
    sha1_update(&ctx, inner_hash, SHA1_DIGEST_SIZE);
    sha1_final(&ctx, out);
}

// =====================
// PBKDF2-SHA1
// =====================

int pbkdf2_sha1(const uint8_t* password, size_t password_len,
                const uint8_t* salt, size_t salt_len,
                uint32_t iterations,
                uint8_t* dk, size_t dk_len) {
    if (!password || !salt || !dk || dk_len == 0 || iterations == 0) {
        return -1;
    }
    
    size_t blocks = (dk_len + SHA1_DIGEST_SIZE - 1) / SHA1_DIGEST_SIZE;
    size_t output_offset = 0;
    
    // Allocate buffer for salt + block index
    uint8_t* salt_block = (uint8_t*)malloc(salt_len + 4);
    if (!salt_block) {
        return -1;
    }
    memcpy(salt_block, salt, salt_len);
    
    for (size_t block = 1; block <= blocks; block++) {
        // Append block index (big-endian)
        salt_block[salt_len]     = (uint8_t)((block >> 24) & 0xFF);
        salt_block[salt_len + 1] = (uint8_t)((block >> 16) & 0xFF);
        salt_block[salt_len + 2] = (uint8_t)((block >> 8) & 0xFF);
        salt_block[salt_len + 3] = (uint8_t)(block & 0xFF);
        
        // U_1 = HMAC(password, salt || block)
        uint8_t u[SHA1_DIGEST_SIZE];
        uint8_t t[SHA1_DIGEST_SIZE];
        hmac_sha1(password, password_len, salt_block, salt_len + 4, u);
        memcpy(t, u, SHA1_DIGEST_SIZE);
        
        // U_2 to U_c
        for (uint32_t i = 2; i <= iterations; i++) {
            uint8_t u_next[SHA1_DIGEST_SIZE];
            hmac_sha1(password, password_len, u, SHA1_DIGEST_SIZE, u_next);
            memcpy(u, u_next, SHA1_DIGEST_SIZE);
            for (int j = 0; j < SHA1_DIGEST_SIZE; j++) {
                t[j] ^= u[j];
            }
        }
        
        // Copy to output
        size_t to_copy = dk_len - output_offset;
        if (to_copy > SHA1_DIGEST_SIZE) {
            to_copy = SHA1_DIGEST_SIZE;
        }
        memcpy(dk + output_offset, t, to_copy);
        output_offset += to_copy;
    }
    
    free(salt_block);
    return 0;
}

// =====================
// AES-128 Implementation
// =====================

// AES S-box
static const uint8_t aes_sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

// Rcon (round constant)
static const uint8_t rcon[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

static uint32_t aes_subword(uint32_t w) {
    return ((uint32_t)aes_sbox[(w >> 24) & 0xFF] << 24) |
           ((uint32_t)aes_sbox[(w >> 16) & 0xFF] << 16) |
           ((uint32_t)aes_sbox[(w >> 8) & 0xFF] << 8) |
           ((uint32_t)aes_sbox[w & 0xFF]);
}

static uint32_t aes_rotword(uint32_t w) {
    return (w << 8) | (w >> 24);
}

void aes128_init(aes128_ctx_t* ctx, const uint8_t key[16]) {
    // Load key into round_keys[0..3]
    for (int i = 0; i < 4; i++) {
        ctx->round_keys[i] = ((uint32_t)key[4*i] << 24) |
                             ((uint32_t)key[4*i+1] << 16) |
                             ((uint32_t)key[4*i+2] << 8) |
                             ((uint32_t)key[4*i+3]);
    }
    
    // Key expansion
    for (int i = 4; i < 44; i++) {
        uint32_t temp = ctx->round_keys[i - 1];
        if (i % 4 == 0) {
            temp = aes_subword(aes_rotword(temp)) ^ ((uint32_t)rcon[i/4] << 24);
        }
        ctx->round_keys[i] = ctx->round_keys[i - 4] ^ temp;
    }
}

static void aes_add_round_key(uint8_t state[16], const uint32_t* rk) {
    for (int i = 0; i < 4; i++) {
        state[4*i]     ^= (uint8_t)((rk[i] >> 24) & 0xFF);
        state[4*i + 1] ^= (uint8_t)((rk[i] >> 16) & 0xFF);
        state[4*i + 2] ^= (uint8_t)((rk[i] >> 8) & 0xFF);
        state[4*i + 3] ^= (uint8_t)(rk[i] & 0xFF);
    }
}

static void aes_sub_bytes(uint8_t state[16]) {
    for (int i = 0; i < 16; i++) {
        state[i] = aes_sbox[state[i]];
    }
}

static void aes_shift_rows(uint8_t state[16]) {
    uint8_t temp;
    
    // Row 1: shift left by 1
    temp = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = temp;
    
    // Row 2: shift left by 2
    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;
    
    // Row 3: shift left by 3
    temp = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = state[3];
    state[3] = temp;
}

static uint8_t xtime(uint8_t x) {
    return (x << 1) ^ ((x >> 7) * 0x1b);
}

static void aes_mix_columns(uint8_t state[16]) {
    for (int i = 0; i < 4; i++) {
        uint8_t a = state[4*i];
        uint8_t b = state[4*i + 1];
        uint8_t c = state[4*i + 2];
        uint8_t d = state[4*i + 3];
        
        uint8_t t = a ^ b ^ c ^ d;
        state[4*i]     ^= t ^ xtime(a ^ b);
        state[4*i + 1] ^= t ^ xtime(b ^ c);
        state[4*i + 2] ^= t ^ xtime(c ^ d);
        state[4*i + 3] ^= t ^ xtime(d ^ a);
    }
}

void aes128_encrypt_block(const aes128_ctx_t* ctx, const uint8_t in[16], uint8_t out[16]) {
    uint8_t state[16];
    memcpy(state, in, 16);
    
    // Initial round
    aes_add_round_key(state, &ctx->round_keys[0]);
    
    // Rounds 1-9
    for (int round = 1; round <= 9; round++) {
        aes_sub_bytes(state);
        aes_shift_rows(state);
        aes_mix_columns(state);
        aes_add_round_key(state, &ctx->round_keys[round * 4]);
    }
    
    // Final round (no MixColumns)
    aes_sub_bytes(state);
    aes_shift_rows(state);
    aes_add_round_key(state, &ctx->round_keys[40]);
    
    memcpy(out, state, 16);
}

// =====================
// AES-128-CFB
// =====================

void aes_cfb_encrypt_init(aes_cfb_ctx_t* ctx, const uint8_t key[16], const uint8_t iv[16]) {
    aes128_init(&ctx->aes_ctx, key);
    memcpy(ctx->iv, iv, AES_BLOCK_SIZE);
    memset(ctx->stream, 0, AES_BLOCK_SIZE);
    ctx->stream_offset = AES_BLOCK_SIZE;  // Force new block on first byte
}

void aes_cfb_decrypt_init(aes_cfb_ctx_t* ctx, const uint8_t key[16], const uint8_t iv[16]) {
    aes_cfb_encrypt_init(ctx, key, iv);  // Same initialization
}

void aes_cfb_encrypt(aes_cfb_ctx_t* ctx, const uint8_t* in, uint8_t* out, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (ctx->stream_offset >= AES_BLOCK_SIZE) {
            // Generate new keystream block
            aes128_encrypt_block(&ctx->aes_ctx, ctx->iv, ctx->stream);
            ctx->stream_offset = 0;
        }
        
        // XOR plaintext with keystream
        out[i] = in[i] ^ ctx->stream[ctx->stream_offset];
        
        // Update IV for CFB (ciphertext feeds back)
        ctx->iv[ctx->stream_offset] = out[i];
        ctx->stream_offset++;
    }
}

void aes_cfb_decrypt(aes_cfb_ctx_t* ctx, const uint8_t* in, uint8_t* out, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (ctx->stream_offset >= AES_BLOCK_SIZE) {
            // Generate new keystream block
            aes128_encrypt_block(&ctx->aes_ctx, ctx->iv, ctx->stream);
            ctx->stream_offset = 0;
        }
        
        // Save ciphertext before decryption
        uint8_t cipher_byte = in[i];
        
        // XOR ciphertext with keystream to get plaintext
        out[i] = cipher_byte ^ ctx->stream[ctx->stream_offset];
        
        // Update IV for CFB (ciphertext feeds back)
        ctx->iv[ctx->stream_offset] = cipher_byte;
        ctx->stream_offset++;
    }
}

// =====================
// FRP Crypto Stream
// =====================

struct frp_crypto_stream {
    uint8_t derived_key[16];
    aes_cfb_ctx_t enc_ctx;
    aes_cfb_ctx_t dec_ctx;
    bool iv_sent;
    bool iv_received;
    uint8_t send_iv[AES_BLOCK_SIZE];
};

frp_crypto_stream_t* frp_crypto_stream_new(const char* token) {
    if (!token || token[0] == '\0') {
        return NULL;
    }
    
    frp_crypto_stream_t* stream = (frp_crypto_stream_t*)malloc(sizeof(frp_crypto_stream_t));
    if (!stream) {
        return NULL;
    }
    
    memset(stream, 0, sizeof(*stream));
    
    // Derive key using PBKDF2
    // FRP uses: pbkdf2.Key(key, []byte(DefaultSalt), 64, aes.BlockSize, sha1.New)
    int ret = pbkdf2_sha1((const uint8_t*)token, strlen(token),
                          (const uint8_t*)FRP_CRYPTO_SALT, strlen(FRP_CRYPTO_SALT),
                          64,
                          stream->derived_key, 16);
    if (ret != 0) {
        free(stream);
        return NULL;
    }
    
    // Generate random IV for sending
    // In production, this should use a proper random source
    uint64_t time_ms = wrapped_get_time_ms();
    uint8_t seed_data[32];
    memcpy(seed_data, &time_ms, sizeof(time_ms));
    memcpy(seed_data + 8, token, strlen(token) < 24 ? strlen(token) : 24);
    
    // Use hash of time + token as "random" IV (not cryptographically secure but works for testing)
    sha1_ctx_t sha_ctx;
    uint8_t hash[SHA1_DIGEST_SIZE];
    sha1_init(&sha_ctx);
    sha1_update(&sha_ctx, seed_data, sizeof(seed_data));
    sha1_update(&sha_ctx, (const uint8_t*)&time_ms, sizeof(time_ms));  // Add more entropy
    sha1_final(&sha_ctx, hash);
    memcpy(stream->send_iv, hash, AES_BLOCK_SIZE);
    
    // Initialize encryption context
    aes_cfb_encrypt_init(&stream->enc_ctx, stream->derived_key, stream->send_iv);
    
    stream->iv_sent = false;
    stream->iv_received = false;
    
    return stream;
}

void frp_crypto_stream_free(frp_crypto_stream_t* stream) {
    if (stream) {
        memset(stream, 0, sizeof(*stream));
        free(stream);
    }
}

int frp_crypto_write(frp_crypto_stream_t* stream, int fd, const uint8_t* data, size_t len) {
    if (!stream || fd < 0 || (!data && len > 0)) {
        return -1;
    }
    
    // First write: send IV
    if (!stream->iv_sent) {
        stream->iv_sent = true;
        
        size_t iv_written = 0;
        while (iv_written < AES_BLOCK_SIZE) {
            ssize_t n = wrapped_write(fd, stream->send_iv + iv_written, AES_BLOCK_SIZE - iv_written);
            if (n < 0) {
                if (wrapped_get_errno() == WRAPPED_EINTR) {
                    continue;
                }
                return -1;
            }
            if (n == 0) {
                return -1;
            }
            iv_written += (size_t)n;
        }
    }
    
    if (len == 0) {
        return 0;
    }
    
    // Encrypt and send data
    uint8_t* cipher = (uint8_t*)malloc(len);
    if (!cipher) {
        return -1;
    }
    
    aes_cfb_encrypt(&stream->enc_ctx, data, cipher, len);
    
    size_t total_written = 0;
    while (total_written < len) {
        ssize_t n = wrapped_write(fd, cipher + total_written, len - total_written);
        if (n < 0) {
            if (wrapped_get_errno() == WRAPPED_EINTR) {
                continue;
            }
            free(cipher);
            return -1;
        }
        if (n == 0) {
            free(cipher);
            return -1;
        }
        total_written += (size_t)n;
    }
    
    free(cipher);
    return (int)len;
}

// Helper to wait and read exact bytes
static int crypto_read_exact(int fd, uint8_t* buf, size_t len, int timeout_ms) {
    size_t off = 0;
    while (off < len) {
        // Wait for data
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);
        
        struct timeval tv;
        struct timeval* ptv = NULL;
        if (timeout_ms >= 0) {
            tv.tv_sec = timeout_ms / 1000;
            tv.tv_usec = (timeout_ms % 1000) * 1000;
            ptv = &tv;
        }
        
        int sel;
        do {
            sel = wrapped_select(fd + 1, &rfds, NULL, NULL, ptv);
        } while (sel < 0 && wrapped_get_errno() == WRAPPED_EINTR);
        
        if (sel == 0) {
            wrapped_set_errno(WRAPPED_ETIMEDOUT);
            return -1;
        }
        if (sel < 0) {
            return -1;
        }
        
        ssize_t n = wrapped_read(fd, buf + off, len - off);
        if (n < 0) {
            if (wrapped_get_errno() == WRAPPED_EINTR) {
                continue;
            }
            return -1;
        }
        if (n == 0) {
            wrapped_set_errno(WRAPPED_ECONNRESET);
            return -1;
        }
        off += (size_t)n;
    }
    return 0;
}

int frp_crypto_read(frp_crypto_stream_t* stream, int fd, uint8_t* buf, size_t len, int timeout_ms) {
    if (!stream || fd < 0 || !buf || len == 0) {
        return -1;
    }
    
    // First read: receive IV
    if (!stream->iv_received) {
        uint8_t iv[AES_BLOCK_SIZE];
        if (crypto_read_exact(fd, iv, AES_BLOCK_SIZE, timeout_ms) != 0) {
            return -1;
        }
        
        // Initialize decryption context with received IV
        aes_cfb_decrypt_init(&stream->dec_ctx, stream->derived_key, iv);
        stream->iv_received = true;
    }
    
    // Read encrypted data
    // First, wait for data to be available
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(fd, &rfds);
    
    struct timeval tv;
    struct timeval* ptv = NULL;
    if (timeout_ms >= 0) {
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        ptv = &tv;
    }
    
    int sel;
    do {
        sel = wrapped_select(fd + 1, &rfds, NULL, NULL, ptv);
    } while (sel < 0 && wrapped_get_errno() == WRAPPED_EINTR);
    
    if (sel == 0) {
        wrapped_set_errno(WRAPPED_ETIMEDOUT);
        return -1;
    }
    if (sel < 0) {
        return -1;
    }
    
    ssize_t n = wrapped_read(fd, buf, len);
    if (n < 0) {
        return -1;
    }
    if (n == 0) {
        return 0;  // EOF
    }
    
    // Decrypt in place
    aes_cfb_decrypt(&stream->dec_ctx, buf, buf, (size_t)n);
    
    return (int)n;
}

