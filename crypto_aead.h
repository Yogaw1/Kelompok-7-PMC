#ifndef CRYPTO_AEAD_H
#define CRYPTO_AEAD_H

#include <stdint.h>

typedef uint8_t byte;

typedef struct {
  int (*aead_encrypt)(
    byte *ciphertext, uint64_t *clen,
    const byte *message, uint64_t mlen,
    const byte *ad, uint64_t adlen,
    const byte *nonce, const byte *key);

  int (*aead_decrypt)(
    byte *message, uint64_t *mlen,
    const byte *ciphertext, uint64_t clen,
    const byte *ad, uint64_t adlen,
    const byte *nonce, const byte *key);

  uint64_t keybytes;
  uint64_t nsecbytes;
  uint64_t npubbytes;
  uint64_t aead_bytes;
} crypto_aead_ops_t;

extern crypto_aead_ops_t crypto_aead_op;
#endif 