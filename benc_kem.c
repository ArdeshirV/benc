/* benc_kem.c - ML-KEM-768 key encapsulation wrapper (liboqs backend)
 *
 * Implements the benc_kem interface using liboqs
 * (https://github.com/open-quantum-safe/liboqs), the NIST FIPS 203 reference
 * implementation.  liboqs is MIT licensed.
 *
 * Compiled ONLY when BENC_WITH_MLKEM is defined.  When liboqs is not installed
 * (or the Makefile does not enable BENC_WITH_MLKEM), none of this code is
 * compiled and post-quantum commands are simply unavailable; the existing
 * password-only path is unaffected.
 */

#include "benc_platform.h"
#include "benc_kem.h"

#ifdef BENC_WITH_MLKEM

#include <oqs/kem.h>

#include <string.h>

struct benc_kem {
    const OQS_KEM *kem;
};

benc_kem *benc_kem_new(const char *alg)
{
    const OQS_KEM *kem = NULL;

    if (alg == NULL)
        return NULL;

    /* liboqs resolves the algorithm by name; ML-KEM-768 is
       OQS_KEM_alg_ml_kem_768. */
    if (strcmp(alg, BENC_KEM_ALG_NAME) == 0)
        kem = OQS_KEM_alg_ml_kem_768;

    if (kem == NULL)
        return NULL;

    benc_kem *self = (benc_kem *)calloc(1, sizeof(*self));
    if (self == NULL)
        return NULL;

    self->kem = kem;
    return self;
}

void benc_kem_free(benc_kem *kem)
{
    if (kem == NULL)
        return;
    free(kem);
}

int benc_kem_keypair(benc_kem *kem,
                     uint8_t *pk, size_t *pklen,
                     uint8_t *sk, size_t *sklen)
{
    size_t pk_len = 0, sk_len = 0;
    int rc;

    if (kem == NULL || kem->kem == NULL || pk == NULL || pklen == NULL ||
        sk == NULL || sklen == NULL)
        return -1;

    rc = OQS_KEM_keypair(kem->kem, pk, &pk_len, sk, &sk_len);
    if (rc != OQS_OK)
        return -1;

    if (pk_len > BENC_KEM_PUBLIC_KEY_LEN_MAX ||
        sk_len > BENC_KEM_SECRET_KEY_LEN_MAX)
        return -1;

    *pklen = pk_len;
    *sklen = sk_len;
    return 0;
}

int benc_kem_encapsulate(benc_kem *kem,
                         uint8_t *ct, size_t *ctlen,
                         uint8_t *ss, size_t *sslen,
                         const uint8_t *pk, size_t pklen)
{
    size_t ct_len = 0, ss_len = 0;
    int rc;

    if (kem == NULL || kem->kem == NULL || ct == NULL || ctlen == NULL ||
        ss == NULL || sslen == NULL || pk == NULL)
        return -1;

    rc = OQS_KEM_encapsulate(kem->kem, ct, &ct_len, ss, &ss_len, pk);
    if (rc != OQS_OK)
        return -1;

    if (ct_len > BENC_KEM_CIPHERTEXT_LEN_MAX ||
        ss_len > BENC_KEM_SHARED_SECRET_LEN_MAX)
        return -1;

    *ctlen = ct_len;
    *sslen = ss_len;
    return 0;
}

int benc_kem_decapsulate(benc_kem *kem,
                         uint8_t *ss, size_t *sslen,
                         const uint8_t *ct, size_t ctlen,
                         const uint8_t *sk, size_t sklen)
{
    size_t ss_len = 0;
    int rc;

    if (kem == NULL || kem->kem == NULL || ss == NULL || sslen == NULL ||
        ct == NULL || sk == NULL)
        return -1;

    rc = OQS_KEM_decapsulate(kem->kem, ss, &ss_len, ct, ctlen, sk);
    if (rc != OQS_OK)
        return -1;

    if (ss_len > BENC_KEM_SHARED_SECRET_LEN_MAX)
        return -1;

    *sslen = ss_len;
    return 0;
}

#endif /* BENC_WITH_MLKEM */
