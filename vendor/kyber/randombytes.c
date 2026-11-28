/* randombytes.c - entropy adapter for the vendored Kyber reference code.
 *
 * The reference implementation calls randombytes() from its convenience
 * keypair/enc entry points.  benc uses the *_derand() variants instead so it
 * can report RNG failures, but the symbol still has to exist.  It is wired to
 * the project's platform RNG (benc_random) rather than a private generator.
 */

#define _POSIX_C_SOURCE 200809L
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include "benc_platform.h"
#include "randombytes.h"

void randombytes(uint8_t *out, size_t outlen)
{
    /* No silent weak fallback: abort if the OS RNG is unavailable. */
    if (benc_random(out, outlen) != 0)
        abort();
}
