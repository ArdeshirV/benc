# pq-crystals Kyber reference implementation

Vendored copy of the `ref/` directory from
<https://github.com/pq-crystals/kyber> (branch `main`), used for Kyber-768
(`KYBER_K=3`). Do not edit these files; adapt them through `benc_kem.c` and
`randombytes.c` at this directory's edge.

License: public domain (CC0) or Apache-2.0 — see `LICENSE`.

`randombytes.c` is project-specific: it forwards the reference code's entropy
call to benc's platform RNG (`benc_random`). benc itself uses the
`*_derand()` entry points so RNG failures can be reported.
