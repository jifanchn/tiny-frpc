/**
 * @file crypto.h
 * @brief Cryptographic utilities for FRP protocol
 * 
 * Implements:
 * - SHA1 hash
 * - PBKDF2-SHA1 key derivation
 * - AES-128-CFB encryption/decryption
 */
#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdint.h>
#include <stddef.h>

// AES block size
#define AES_BLOCK_SIZE 16

// SHA1 digest size
#define SHA1_DIGEST_SIZE 20

// FRP default salt for PBKDF2
#define FRP_CRYPTO_SALT "frp"

// =====================
// SHA1
// =====================

typedef struct {
    uint32_t state[5];
    uint64_t bit_count;
    uint8_t buffer[64];
} sha1_ctx_t;

void sha1_init(sha1_ctx_t* ctx);
void sha1_update(sha1_ctx_t* ctx, const uint8_t* data, size_t len);
void sha1_final(sha1_ctx_t* ctx, uint8_t digest[SHA1_DIGEST_SIZE]);
void sha1_hash(const uint8_t* data, size_t len, uint8_t digest[SHA1_DIGEST_SIZE]);

// =====================
// PBKDF2-SHA1
// =====================

/**
 * PBKDF2 key derivation using SHA1
 * 
 * @param password Password bytes
 * @param password_len Password length
 * @param salt Salt bytes
 * @param salt_len Salt length
 * @param iterations Number of iterations
 * @param dk Derived key output buffer
 * @param dk_len Desired derived key length
 * @return 0 on success, -1 on error
 */
int pbkdf2_sha1(const uint8_t* password, size_t password_len,
                const uint8_t* salt, size_t salt_len,
                uint32_t iterations,
                uint8_t* dk, size_t dk_len);

// =====================
// AES-128
// =====================

typedef struct {
    uint32_t round_keys[44];  // 4 * (10 + 1) = 44 words for AES-128
} aes128_ctx_t;

void aes128_init(aes128_ctx_t* ctx, const uint8_t key[16]);
void aes128_encrypt_block(const aes128_ctx_t* ctx, const uint8_t in[16], uint8_t out[16]);

// =====================
// AES-128-CFB
// =====================

typedef struct {
    aes128_ctx_t aes_ctx;
    uint8_t iv[AES_BLOCK_SIZE];
    uint8_t stream[AES_BLOCK_SIZE];
    size_t stream_offset;  // Used bytes in current stream block
} aes_cfb_ctx_t;

/**
 * Initialize AES-CFB context for encryption
 * 
 * @param ctx Context to initialize
 * @param key 16-byte AES key
 * @param iv 16-byte IV
 */
void aes_cfb_encrypt_init(aes_cfb_ctx_t* ctx, const uint8_t key[16], const uint8_t iv[16]);

/**
 * Initialize AES-CFB context for decryption
 * 
 * @param ctx Context to initialize
 * @param key 16-byte AES key
 * @param iv 16-byte IV
 */
void aes_cfb_decrypt_init(aes_cfb_ctx_t* ctx, const uint8_t key[16], const uint8_t iv[16]);

/**
 * Encrypt data using AES-CFB
 * 
 * @param ctx Encryption context
 * @param in Input plaintext
 * @param out Output ciphertext (can be same as in)
 * @param len Data length
 */
void aes_cfb_encrypt(aes_cfb_ctx_t* ctx, const uint8_t* in, uint8_t* out, size_t len);

/**
 * Decrypt data using AES-CFB
 * 
 * @param ctx Decryption context
 * @param in Input ciphertext
 * @param out Output plaintext (can be same as in)
 * @param len Data length
 */
void aes_cfb_decrypt(aes_cfb_ctx_t* ctx, const uint8_t* in, uint8_t* out, size_t len);

// =====================
// FRP Crypto Stream
// =====================

typedef struct frp_crypto_stream frp_crypto_stream_t;

/**
 * Create a new FRP crypto stream
 * 
 * @param token Authentication token (used as password for PBKDF2)
 * @return New crypto stream or NULL on error
 */
frp_crypto_stream_t* frp_crypto_stream_new(const char* token);

/**
 * Free crypto stream
 */
void frp_crypto_stream_free(frp_crypto_stream_t* stream);

/**
 * Encrypt and send data through the stream
 * The first write will prepend the IV
 * 
 * @param stream Crypto stream
 * @param fd File descriptor to write to
 * @param data Data to encrypt and send
 * @param len Data length
 * @return Bytes written (logical), or negative on error
 */
int frp_crypto_write(frp_crypto_stream_t* stream, int fd, const uint8_t* data, size_t len);

/**
 * Read and decrypt data from the stream
 * The first read will consume the IV
 * 
 * @param stream Crypto stream
 * @param fd File descriptor to read from
 * @param buf Buffer to store decrypted data
 * @param len Maximum bytes to read
 * @param timeout_ms Timeout in milliseconds (-1 for blocking)
 * @return Bytes read, 0 on EOF, or negative on error
 */
int frp_crypto_read(frp_crypto_stream_t* stream, int fd, uint8_t* buf, size_t len, int timeout_ms);

#endif // CRYPTO_H

