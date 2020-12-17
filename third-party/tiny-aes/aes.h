#ifndef _AES_H_
#define _AES_H_

#include <stdint.h>

#define AES128 1
#define AES_BLOCKLEN 16 // Block length in bytes - AES is 128b block only

#define AES_KEYLEN 16   // Key length in bytes
#define AES_keyExpSize 176

struct AES_ctx {
    uint8_t RoundKey[AES_keyExpSize];
    uint8_t Iv[AES_BLOCKLEN];
    uint8_t Used;
};

void AES_init_ctx(struct AES_ctx *ctx, const uint8_t *key);

#if (defined(CBC) && (CBC == 1)) || (defined(CTR) && (CTR == 1))
void AES_init_ctx_iv(struct AES_ctx* ctx, const uint8_t* key, const uint8_t* iv);
void AES_ctx_set_iv(struct AES_ctx* ctx, const uint8_t* iv);
#endif

// buffer size MUST be mutile of AES_BLOCKLEN;
// Suggest https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS7 for padding scheme
// NOTES: you need to set IV in ctx via AES_init_ctx_iv() or AES_ctx_set_iv()
//        no IV should ever be reused with the same key
void AES_CFB_encrypt_buffer(struct AES_ctx *ctx, uint8_t *buf, uint32_t length);

void AES_CFB_decrypt_buffer(struct AES_ctx *ctx, uint8_t *buf, uint32_t length);

#endif // _AES_H_
