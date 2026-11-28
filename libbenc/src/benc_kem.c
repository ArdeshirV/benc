/* benc_kem.c - post-quantum key encapsulation (Kyber-768)
 *
 * Thin adapter over the vendored pq-crystals Kyber-768 reference
 * implementation in vendor/kyber (public domain / Apache-2.0, see
 * vendor/kyber/LICENSE).  The rest of benc only sees this small interface,
 * so the KEM backend stays swappable.
 *
 * Key and ciphertext sizes are the reference implementation's:
 *   pk 1184, sk 2400, ct 1088, shared secret 32.
 */

#define _POSIX_C_SOURCE 200809L
#include "benc/benc_platform.h"
#include "benc/benc_kem.h"

struct benc_kem { int dummy; };

#include <stdlib.h>
#include <string.h>

#include "../../vendor/kyber/api.h"

/* The project's size macros must match the reference implementation. */
typedef char benc_kem_size_check[
    pqcrystals_kyber768_ref_PUBLICKEYBYTES == BENC_KEM_PUBLIC_KEY_LEN &&
    pqcrystals_kyber768_ref_SECRETKEYBYTES == BENC_KEM_SECRET_KEY_LEN &&
    pqcrystals_kyber768_ref_CIPHERTEXTBYTES == BENC_KEM_CIPHERTEXT_LEN &&
    pqcrystals_kyber768_ref_BYTES == BENC_KEM_SHARED_SECRET_LEN ? 1 : -1];

benc_kem *benc_kem_new(const char *alg)
{
    if (!alg || strcmp(alg, BENC_KEM_ALG_NAME) != 0)
        return NULL;
    return (benc_kem *)calloc(1, sizeof(benc_kem));
}

void benc_kem_free(benc_kem *kem)
{
    free(kem);
}

int benc_kem_keypair(benc_kem *kem, uint8_t *pk, size_t *pklen,
                     uint8_t *sk, size_t *sklen)
{
    uint8_t coins[pqcrystals_kyber768_ref_KEYPAIRCOINBYTES];

    if (!kem || !pk || !pklen || !sk || !sklen)
        return -1;
    if (benc_random(coins, sizeof coins) != 0)
        return -1;
    if (pqcrystals_kyber768_ref_keypair_derand(pk, sk, coins) != 0)
        return -1;
    *pklen = BENC_KEM_PUBLIC_KEY_LEN;
    *sklen = BENC_KEM_SECRET_KEY_LEN;
    return 0;
}

int benc_kem_encapsulate(benc_kem *kem, uint8_t *ct, size_t *ctlen,
                         uint8_t *ss, size_t *sslen,
                         const uint8_t *pk, size_t pklen)
{
    uint8_t coins[pqcrystals_kyber768_ref_ENCCOINBYTES];

    if (!kem || !ct || !ctlen || !ss || !sslen || !pk)
        return -1;
    if (pklen != BENC_KEM_PUBLIC_KEY_LEN)
        return -1;
    if (benc_random(coins, sizeof coins) != 0)
        return -1;
    if (pqcrystals_kyber768_ref_enc_derand(ct, ss, pk, coins) != 0)
        return -1;
    *ctlen = BENC_KEM_CIPHERTEXT_LEN;
    *sslen = BENC_KEM_SHARED_SECRET_LEN;
    return 0;
}

int benc_kem_decapsulate(benc_kem *kem, uint8_t *ss, size_t *sslen,
                         const uint8_t *ct, size_t ctlen,
                         const uint8_t *sk, size_t sklen)
{
    if (!kem || !ss || !sslen || !ct || !sk)
        return -1;
    if (ctlen != BENC_KEM_CIPHERTEXT_LEN || sklen != BENC_KEM_SECRET_KEY_LEN)
        return -1;
    /* Never fails: a bad ciphertext yields the implicit-rejection secret. */
    pqcrystals_kyber768_ref_dec(ss, ct, sk);
    *sslen = BENC_KEM_SHARED_SECRET_LEN;
    return 0;
}
