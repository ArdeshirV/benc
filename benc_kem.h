/* benc_kem.h - post-quantum key encapsulation interface (ML-KEM-768)
 *
 * This header isolates the post-quantum key encapsulation primitive behind a
 * small, backend-agnostic interface.  The core benc code (container format,
 * encrypt/decrypt, CLI) never references liboqs directly: it only calls the
 * functions below.  That keeps it possible to support a different KEM
 * implementation later, or to build without any post-quantum support at all.
 *
 * The implementation below wraps liboqs (https://github.com/open-quantum-safe/liboqs),
 * MIT licensed, NIST FIPS 203 reference implementation of ML-KEM-768.
 *
 * All of this is compiled ONLY when BENC_WITH_MLKEM is defined (see Makefile).
 * When liboqs is unavailable the Makefile builds without BENC_WITH_MLKEM and
 * post-quantum commands are simply not offered; existing password-only
 * containers are unaffected.
 */

#ifndef BENC_KEM_H
#define BENC_KEM_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ML-KEM-768 sizes, per NIST FIPS 203. */
#define BENC_KEM_ALG_NAME     "ml-kem-768"
#define BENC_KEM_PUBLIC_KEY_LEN  1168
#define BENC_KEM_SECRET_KEY_LEN  2400
#define BENC_KEM_CIPHERTEXT_LEN  1088
#define BENC_KEM_SHARED_SECRET_LEN 32

/* Opaque handle to a KEM implementation instance. */
typedef struct benc_kem benc_kem;

/* Initialize a KEM instance for the named algorithm (e.g. "ml-kem-768").
 * Returns NULL on failure (unknown algorithm, allocation failure). */
extern benc_kem *benc_kem_new(const char *alg);

/* Release a KEM instance. */
extern void benc_kem_free(benc_kem *kem);

/* Generate a keypair.  Writes pk (public key) and sk (secret key). */
extern int benc_kem_keypair(benc_kem *kem,
                            uint8_t *pk, size_t *pklen,
                            uint8_t *sk, size_t *sklen);

/* Encapsulate a shared secret for the given public key.
 * Writes ct (ciphertext) and ss (shared secret). */
extern int benc_kem_encapsulate(benc_kem *kem,
                                uint8_t *ct, size_t *ctlen,
                                uint8_t *ss, size_t *sslen,
                                const uint8_t *pk, size_t pklen);

/* Decapsulate a ciphertext using the secret key, recovering the shared secret. */
extern int benc_kem_decapsulate(benc_kem *kem,
                                uint8_t *ss, size_t *sslen,
                                const uint8_t *ct, size_t ctlen,
                                const uint8_t *sk, size_t sklen);

/* Canonical lengths for ML-KEM-768. */
#define BENC_KEM_PUBLIC_KEY_LEN_MAX  BENC_KEM_PUBLIC_KEY_LEN
#define BENC_KEM_SECRET_KEY_LEN_MAX  BENC_KEM_SECRET_KEY_LEN
#define BENC_KEM_CIPHERTEXT_LEN_MAX  BENC_KEM_CIPHERTEXT_LEN
#define BENC_KEM_SHARED_SECRET_LEN_MAX BENC_KEM_SHARED_SECRET_LEN

#ifdef __cplusplus
}
#endif

#endif /* BENC_KEM_H */
