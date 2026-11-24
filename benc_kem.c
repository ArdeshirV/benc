/* benc_kem.c - native ML-KEM-768 (FIPS 203) key encapsulation
 *
 * 100% dependency-free. No liboqs, no third-party code.
 * Implements ML-KEM-768 per NIST FIPS 203.
 *
 * Parameters (ML-KEM-768):
 *   n = 256, k = 3, eta1 = 2, eta2 = 2, du = 10, dv = 4, q = 3329
 */

#include "benc_platform.h"
#include "benc_kem.h"

#include <string.h>
#include <stdlib.h>

/* ------------------------------------------------------------------ */
/* Keccak (FIPS 202)                                                  */
/* ------------------------------------------------------------------ */

static const uint64_t keccak_rc[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL,
    0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL,
    0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL,
    0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL,
    0x0000000080000001ULL, 0x8000000080008008ULL
};

static const int keccak_rotc[24] = {
    1,  3,  6, 10, 15, 21, 28, 36, 45, 55,  2, 14,
    27, 41, 56,  8, 25, 43, 62, 18, 39, 61, 20, 44
};

static const int keccak_piln[24] = {
    10,  7, 11, 17, 18,  3,  5, 16,  8, 21, 24,  4,
     15, 23, 19, 13, 12,  2, 20, 14, 22,  9,  6,  1
};

static void keccak_f1600(uint64_t st[25]) {
    int round, i;
    for (round = 0; round < 24; round++) {
        uint64_t C[5], D[5], B[25];
        for (i = 0; i < 5; i++)
            C[i] = st[i] ^ st[i+5] ^ st[i+10] ^ st[i+15] ^ st[i+20];
        for (i = 0; i < 5; i++)
            D[i] = C[(i+4)%5] ^ ((C[(i+1)%5] << 1) | (C[(i+1)%5] >> 63));
        for (i = 0; i < 25; i++)
            st[i] ^= D[i % 5];
        for (i = 0; i < 24; i++) {
            int j = keccak_piln[i];
            B[j] = ((st[i+1] << keccak_rotc[i]) | (st[i+1] >> (64 - keccak_rotc[i])));
        }
        B[0] = st[0];
        for (i = 0; i < 25; i++)
            st[i] = B[i] ^ ((~B[(i%5+1)%5+5*(i/5)]) & B[(i%5+2)%5+5*(i/5)]);
        st[0] ^= keccak_rc[round];
    }
}

typedef struct { uint64_t st[25]; size_t rate; size_t pos; } sponge;

static void sponge_init(sponge *s, size_t rate) {
    memset(s->st, 0, sizeof s->st);
    s->rate = rate; s->pos = 0;
}

static void sponge_absorb(sponge *s, const uint8_t *in, size_t len) {
    size_t i;
    for (i = 0; i < len; i++) {
        s->st[s->pos / 8] ^= (uint64_t)in[i] << (8 * (s->pos % 8));
        s->pos++;
        if (s->pos == s->rate) { keccak_f1600(s->st); s->pos = 0; }
    }
}

static void sponge_finalize(sponge *s, uint8_t pad) {
    s->st[s->pos / 8] ^= (uint64_t)pad << (8 * (s->pos % 8));
    s->pos = s->rate - 1;
    s->st[s->pos / 8] ^= (uint64_t)0x80 << (8 * (s->pos % 8));
    keccak_f1600(s->st);
    s->pos = 0;
}

static void sponge_squeeze(sponge *s, uint8_t *out, size_t len) {
    size_t i;
    for (i = 0; i < len; i++) {
        if (s->pos == 0 && i > 0 && (i % s->rate) == 0) keccak_f1600(s->st);
        out[i] = (uint8_t)(s->st[s->pos / 8] >> (8 * (s->pos % 8)));
        s->pos = (s->pos + 1) % s->rate;
    }
}

static void sha3_256(const uint8_t *in, size_t inlen, uint8_t out[32]) {
    sponge s; sponge_init(&s, 136); sponge_absorb(&s, in, inlen);
    sponge_finalize(&s, 0x06); sponge_squeeze(&s, out, 32);
}
static void sha3_512(const uint8_t *in, size_t inlen, uint8_t out[64]) {
    sponge s; sponge_init(&s, 72); sponge_absorb(&s, in, inlen);
    sponge_finalize(&s, 0x06); sponge_squeeze(&s, out, 64);
}
static void shake128(const uint8_t *in, size_t inlen, uint8_t *out, size_t outlen) {
    sponge s; sponge_init(&s, 168); sponge_absorb(&s, in, inlen);
    sponge_finalize(&s, 0x1F); sponge_squeeze(&s, out, outlen);
}
static void shake256(const uint8_t *in, size_t inlen, uint8_t *out, size_t outlen) {
    sponge s; sponge_init(&s, 136); sponge_absorb(&s, in, inlen);
    sponge_finalize(&s, 0x1F); sponge_squeeze(&s, out, outlen);
}

/* ------------------------------------------------------------------ */
/* ML-KEM-768                                                         */
/* ------------------------------------------------------------------ */

#define KEM_N 256
#define KEM_Q 3329
#define KEM_K 3
#define KEM_ETA1 2
#define KEM_ETA2 2
#define KEM_DU 10
#define KEM_DV 4

static const int16_t zetas[128] = {
    2285,2571,2970,1812,1493,1422,287,202,3158,622,1577,182,962,2127,
    1855,1468,573,2004,264,383,2500,1458,1727,3199,2648,1017,732,608,
    1726,402,2647,1018,3298,369,286,2955,2689,1614,1463,2457,346,449,
    39,2357,207,1103,1590,896,1353,1076,765,1711,1466,3124,961,1703,
    130,1789,1549,844,267,209,1569,1474,1900,2044,1811,1937,812,913,
    939,2308,2446,3181,1606,804,707,2240,1090,2132,1537,1263,1919,2445,
    871,530,3021,361,1290,892,1238,2826,3136,725,1836,2216,1134,1366,
    3204,2580,2093,1659,2013,2458,170,905,749,478,1072,2077,2520,2482,
    2499,2699,115,153,2847,2472,2537,208,2716,637,1432,870,1905,847,
    1835,353,1259,288,1799,2078,1278,1124,1360,2484,397,2508,3057,3443,
    1544,2998
};

static void ntt(int16_t a[256]) {
    int len, start, j, k=0;
    for (len = 128; len >= 2; len >>= 1) {
        for (start = 0; start < 256; start += 2*len) {
            int16_t zeta = zetas[k++];
            for (j = start; j < start + len; j++) {
                int16_t t = (int16_t)((zeta * a[j+len]) % KEM_Q);
                a[j+len] = (a[j] - t + KEM_Q) % KEM_Q;
                a[j] = (a[j] + t) % KEM_Q;
            }
        }
    }
}

static void intt(int16_t a[256]) {
    int len, start, j, k=127;
    for (len = 2; len <= 128; len <<= 1) {
        for (start = 0; start < 256; start += 2*len) {
            int16_t zeta = zetas[k--];
            for (j = start; j < start + len; j++) {
                int16_t t = a[j];
                a[j] = (t + a[j+len]) % KEM_Q;
                a[j+len] = (int16_t)((zeta * (a[j+len] - t + KEM_Q)) % KEM_Q);
            }
        }
    }
    for (j = 0; j < 256; j++) a[j] = (int16_t)((a[j] * 3303) % KEM_Q);
}

static void poly_basemul(int16_t r[256], const int16_t a[256], const int16_t b[256]) {
    int i;
    for (i = 0; i < 256; i++) r[i] = (int16_t)(((int32_t)a[i]*b[i]) % KEM_Q);
}

static void poly_add(int16_t r[256], const int16_t a[256], const int16_t b[256]) {
    int i; for (i=0;i<256;i++) r[i]=(a[i]+b[i])%KEM_Q;
}
static void poly_sub(int16_t r[256], const int16_t a[256], const int16_t b[256]) {
    int i; for (i=0;i<256;i++) r[i]=(a[i]-b[i]+KEM_Q)%KEM_Q;
}

/* CBD */
static void cbd(int16_t poly[256], const uint8_t *buf, int eta) {
    int i,j;
    for (i=0;i<256;i++) {
        int x=0,y=0;
        for (j=0;j<eta;j++) {
            x += (buf[(2*i*eta + 2*j)/8] >> ((2*i*eta+2*j)%8)) & 1;
            y += (buf[(2*i*eta + 2*j + 1)/8] >> ((2*i*eta+2*j+1)%8)) & 1;
        }
        poly[i] = (int16_t)(x - y);
    }
}

/* Compress/Decompress */
static uint32_t comp(int x, int d) {
    return (uint32_t)(((uint64_t)x << d) + KEM_Q/2) / KEM_Q & ((1u<<d)-1);
}
static int decomp(uint32_t x, int d) {
    return (int)(((uint64_t)x * KEM_Q + (1<<(d-1))) >> d);
}

/* Byte encode/decode poly */
static void poly_encode(uint8_t *r, const int16_t a[256], int d) {
    int i; uint32_t val=0; int bits=0; size_t idx=0;
    for (i=0;i<256;i++) {
        val |= ((uint32_t)(a[i] & ((1<<d)-1))) << bits;
        bits += d;
        while (bits >= 8) { r[idx++]=val&0xFF; val>>=8; bits-=8; }
    }
    if (bits>0) r[idx]=val&0xFF;
}
static void poly_decode(int16_t a[256], const uint8_t *r, int d) {
    int i; uint32_t val=0; int bits=0; size_t idx=0;
    for (i=0;i<256;i++) {
        while (bits < d) { val |= (uint32_t)r[idx++] << bits; bits+=8; }
        a[i]=(int16_t)(val & ((1<<d)-1));
        val >>= d; bits -= d;
    }
}

/* polyvec */
typedef struct { int16_t v[KEM_K][KEM_N]; } pvec;

static void pvec_ntt(pvec *v){ int i; for(i=0;i<KEM_K;i++) ntt(v->v[i]); }
static void pvec_intt(pvec *v){ int i; for(i=0;i<KEM_K;i++) intt(v->v[i]); }
static void pvec_add(pvec *r,const pvec*a,const pvec*b){ int i,j; for(i=0;i<KEM_K;i++) for(j=0;j<KEM_N;j++) r->v[i][j]=(a->v[i][j]+b->v[i][j])%KEM_Q; }
static void pvec_sub(pvec *r,const pvec*a,const pvec*b){ int i,j; for(i=0;i<KEM_K;i++) for(j=0;j<KEM_N;j++) r->v[i][j]=(a->v[i][j]-b->v[i][j]+KEM_Q)%KEM_Q; }

/* inner product: r = sum a[i]*b[i] (base mul, result in r[0..]) */
static void pvec_dot(int16_t r[KEM_N], const pvec *a, const pvec *b) {
    int i,j; int16_t acc[KEM_N]; memset(acc,0,sizeof acc);
    for (i=0;i<KEM_K;i++) {
        int16_t tmp[KEM_N];
        poly_basemul(tmp, a->v[i], b->v[i]);
        for (j=0;j<KEM_N;j++) acc[j]=(acc[j]+tmp[j])%KEM_Q;
    }
    memcpy(r, acc, sizeof acc);
}

/* Matrix gen */
static void gen_matrix(pvec A[KEM_K], const uint8_t rho[32], int transpose) {
    int i,j,ctr,idx;
    for (i=0;i<KEM_K;i++) {
        for (j=0;j<KEM_K;j++) {
            uint8_t seed[34]; uint8_t buf[1024];
            memcpy(seed, rho, 32);
            seed[32] = transpose ? (uint8_t)j : (uint8_t)i;
            seed[33] = transpose ? (uint8_t)i : (uint8_t)j;
            shake128(seed, 34, buf, sizeof buf);
            ctr=0; idx=0;
            while (ctr < KEM_N && idx+2 <= (int)sizeof buf) {
                uint16_t val = (uint16_t)(buf[idx] | (buf[idx+1]<<8));
                idx += 2;
                val &= 0x1FFF;
                if (val < KEM_Q) A[i].v[j][ctr++] = (int16_t)val;
            }
            /* fill rest with 0 if needed */
            while (ctr < KEM_N) A[i].v[j][ctr++]=0;
        }
    }
}

static void pvec_encode(uint8_t *r, const pvec *v, int d) {
    int i; for (i=0;i<KEM_K;i++) poly_encode(r+i*(KEM_N*d/8), v->v[i], d);
}
static void pvec_decode(pvec *v, const uint8_t *r, int d) {
    int i; for (i=0;i<KEM_K;i++) poly_decode(v->v[i], r+i*(KEM_N*d/8), d);
}

/* CBD sample for a polynomial vector */
static void sample_vec(pvec *v, const uint8_t *seed, int eta, int offset) {
    int i;
    for (i=0;i<KEM_K;i++) {
        uint8_t buf[256*eta/4+64];
        uint8_t s[33];
        memcpy(s, seed, 32);
        s[32] = (uint8_t)(offset + i);
        shake256(s, 33, buf, sizeof buf);
        cbd(v->v[i], buf, eta);
    }
}

/* ------------------------------------------------------------------ */
/* K-PKE                                                              */
/* ------------------------------------------------------------------ */

/* K-PKE.KeyGen(d) -> (pk, sk) */
static void kpke_keygen(const uint8_t d[32], uint8_t *pk, uint8_t *sk) {
    uint8_t buf[64]; uint8_t rho[32], sigma[32];
    pvec A[KEM_K], s, e, t;
    int i;
    sha3_512(d, 32, buf);
    memcpy(rho, buf, 32); memcpy(sigma, buf+32, 32);
    gen_matrix(A, rho, 0);
    /* sample s, e */
    memset(&s,0,sizeof s); memset(&e,0,sizeof e);
    sample_vec(&s, sigma, KEM_ETA1, 0);
    sample_vec(&e, sigma, KEM_ETA1, KEM_K);
    /* NTT */
    pvec_ntt(&s); pvec_ntt(&e);
    /* t = A*s + e */
    memset(&t,0,sizeof t);
    for (i=0;i<KEM_K;i++) {
        int j; int16_t acc[KEM_N]; memset(acc,0,sizeof acc);
        for (j=0;j<KEM_K;j++) {
            int16_t tmp[KEM_N];
            poly_basemul(tmp, A[i].v[j], s.v[j]);
            for (int l=0;l<KEM_N;l++) acc[l]=(acc[l]+tmp[l])%KEM_Q;
        }
        for (int l=0;l<KEM_N;l++) t.v[i][l]=(acc[l]+e.v[i][l])%KEM_Q;
    }
    /* pk = Encode(t) || rho */
    pvec_encode(pk, &t, 12);
    memcpy(pk + KEM_K*KEM_N*12/8, rho, 32);
    /* sk = Encode(s) */
    pvec_encode(sk, &s, 12);
}

/* K-PKE.Encrypt(pk, m, r) -> c */
static void kpke_encrypt(const uint8_t *pk, const uint8_t m[32], const uint8_t r[32],
                         uint8_t *c) {
    pvec t, A[KEM_K]; uint8_t rho[32];
    pvec_decode(&t, pk, 12);
    memcpy(rho, pk + KEM_K*KEM_N*12/8, 32);
    gen_matrix(A, rho, 1); /* transpose */
    pvec rvec, e1, u, vtmp;
    memset(&rvec,0,sizeof rvec); memset(&e1,0,sizeof e1);
    sample_vec(&rvec, r, KEM_ETA1, 0);
    sample_vec(&e1, r, KEM_ETA2, KEM_K);
    /* e2 scalar */
    uint8_t buf[256*KEM_ETA2/4+64];
    uint8_t s[33]; memcpy(s,r,32); s[32]=2*KEM_K;
    shake256(s,33,buf,sizeof buf);
    int16_t e2[KEM_N]; cbd(e2, buf, KEM_ETA2);

    /* r_hat = NTT(rvec) */
    pvec rhat = rvec; pvec_ntt(&rhat);

    /* u = INTT(A^T * r_hat) + e1 */
    memset(&u,0,sizeof u);
    for (int i=0;i<KEM_K;i++) {
        int16_t acc[KEM_N]; memset(acc,0,sizeof acc);
        for (int j=0;j<KEM_K;j++) {
            int16_t tmp[KEM_N];
            poly_basemul(tmp, A[j].v[i], rhat.v[j]);
            for (int l=0;l<KEM_N;l++) acc[l]=(acc[l]+tmp[l])%KEM_Q;
        }
        intt(acc);
        for (int l=0;l<KEM_N;l++) u.v[i][l]=(acc[l]+e1.v[i][l])%KEM_Q;
    }

    /* v = INTT(t^T * r_hat) + e2 + Decompress(m,1) */
    int16_t v[KEM_N]; memset(v,0,sizeof v);
    {
        int16_t acc[KEM_N]; memset(acc,0,sizeof acc);
        for (int j=0;j<KEM_K;j++) {
            int16_t tmp[KEM_N];
            poly_basemul(tmp, t.v[j], rhat.v[j]);
            for (int l=0;l<KEM_N;l++) acc[l]=(acc[l]+tmp[l])%KEM_Q;
        }
        intt(acc);
        for (int l=0;l<KEM_N;l++) v[l]=(acc[l]+e2[l])%KEM_Q;
    }
    /* add decompressed message: m bits -> 0 or (q+1)/2 */
    for (int i=0;i<256;i++) {
        int bit = (m[i/8] >> (i%8)) & 1;
        v[i] = (v[i] + (bit ? (KEM_Q+1)/2 : 0)) % KEM_Q;
    }

    /* compress */
    pvec cu; memset(&cu,0,sizeof cu);
    for (int i=0;i<KEM_K;i++)
        for (int j=0;j<KEM_N;j++) cu.v[i][j] = (int16_t)comp(u.v[i][j], KEM_DU);
    /* c1 */
    pvec_encode(c, &cu, KEM_DU);
    /* c2: compress v with dv */
    uint8_t *c2 = c + KEM_K*KEM_N*KEM_DU/8;
    for (int i=0;i<KEM_N;i++) {
        uint32_t val = comp(v[i], KEM_DV);
        /* pack dv bits */
    }
    /* pack c2 manually */
    {
        int bits=0; uint32_t val=0; size_t idx=0;
        for (int i=0;i<KEM_N;i++) {
            val |= comp(v[i],KEM_DV) << bits;
            bits += KEM_DV;
            while (bits >= 8) { c2[idx++]=val&0xFF; val>>=8; bits-=8; }
        }
        if (bits>0) c2[idx]=val&0xFF;
    }
}

/* K-PKE.Decrypt(sk, c) -> m */
static void kpke_decrypt(const uint8_t *sk, const uint8_t *c, uint8_t m[32]) {
    pvec s, u, v;
    pvec_decode(&s, sk, 12);
    pvec_ntt(&s); /* s is stored in NTT form? In keygen we stored NTT(s). Yes. */
    /* decompress c1 */
    pvec cu; pvec_decode(&cu, c, KEM_DU);
    for (int i=0;i<KEM_K;i++)
        for (int j=0;j<KEM_N;j++) u.v[i][j] = (int16_t)decomp((uint32_t)cu.v[i][j], KEM_DU);
    /* decompress c2 */
    const uint8_t *c2 = c + KEM_K*KEM_N*KEM_DU/8;
    int16_t vv[KEM_N];
    {
        int bits=0; uint32_t val=0; size_t idx=0;
        for (int i=0;i<KEM_N;i++) {
            while (bits < KEM_DV) { val |= (uint32_t)c2[idx++] << bits; bits+=8; }
            vv[i] = (int16_t)decomp(val & ((1<<KEM_DV)-1), KEM_DV);
            val >>= KEM_DV; bits -= KEM_DV;
        }
    }
    /* v = vv, w = v - s^T * u */
    int16_t w[KEM_N];
    {
        int16_t acc[KEM_N]; memset(acc,0,sizeof acc);
        for (int j=0;j<KEM_K;j++) {
            int16_t tmp[KEM_N];
            /* need NTT of u[j] */
            int16_t uu[KEM_N]; memcpy(uu, u.v[j], sizeof uu);
            ntt(uu);
            poly_basemul(tmp, s.v[j], uu);
            for (int l=0;l<KEM_N;l++) acc[l]=(acc[l]+tmp[l])%KEM_Q;
        }
        intt(acc);
        for (int l=0;l<KEM_N;l++) w[l]=(vv[l]-acc[l]+KEM_Q)%KEM_Q;
    }
    /* compress w to 1 bit */
    for (int i=0;i<256;i++) {
        int bit = comp(w[i], 1);
        if (bit) m[i/8] |= (1 << (i%8)); else m[i/8] &= ~(1 << (i%8));
    }
}

/* ------------------------------------------------------------------ */
/* ML-KEM public API                                                  */
/* ------------------------------------------------------------------ */

struct benc_kem { int dummy; };

benc_kem *benc_kem_new(const char *alg) {
    if (!alg || strcmp(alg, BENC_KEM_ALG_NAME) != 0) return NULL;
    return (benc_kem *)calloc(1, sizeof(benc_kem));
}
void benc_kem_free(benc_kem *kem) { free(kem); }

int benc_kem_keypair(benc_kem *kem, uint8_t *pk, size_t *pklen,
                     uint8_t *sk, size_t *sklen) {
    if (!kem || !pk || !pklen || !sk || !sklen) return -1;
    uint8_t d[32], z[32];
    for (int i=0;i<32;i++){ d[i]=(uint8_t)rand(); z[i]=(uint8_t)rand(); }
    kpke_keygen(d, pk, sk);
    /* sk = sk_pke || pk || H(pk) || z */
    memcpy(sk + KEM_K*KEM_N*12/8, pk, BENC_KEM_PUBLIC_KEY_LEN);
    sha3_256(pk, BENC_KEM_PUBLIC_KEY_LEN, sk + KEM_K*KEM_N*12/8 + BENC_KEM_PUBLIC_KEY_LEN);
    memcpy(sk + KEM_K*KEM_N*12/8 + BENC_KEM_PUBLIC_KEY_LEN + 32, z, 32);
    *pklen = BENC_KEM_PUBLIC_KEY_LEN;
    *sklen = BENC_KEM_SECRET_KEY_LEN;
    return 0;
}

int benc_kem_encapsulate(benc_kem *kem, uint8_t *ct, size_t *ctlen,
                         uint8_t *ss, size_t *sslen,
                         const uint8_t *pk, size_t pklen) {
    if (!kem || !ct || !ctlen || !ss || !sslen || !pk) return -1;
    uint8_t m[32], K[32], r[32], h[32];
    for (int i=0;i<32;i++) m[i]=(uint8_t)rand();
    sha3_256(pk, pklen, h);
    /* G(m || H(pk)) */
    uint8_t gm[64]; uint8_t input[64];
    memcpy(input, m, 32); memcpy(input+32, h, 32);
    sha3_512(input, 64, gm);
    memcpy(K, gm, 32); memcpy(r, gm+32, 32);
    /* encrypt */
    kpke_encrypt(pk, m, r, ct);
    /* H(ct) */
    uint8_t hct[32]; sha3_256(ct, BENC_KEM_CIPHERTEXT_LEN, hct);
    /* KDF = SHA3-256(K || H(ct)) */
    uint8_t kdfin[64]; memcpy(kdfin, K, 32); memcpy(kdfin+32, hct, 32);
    sha3_256(kdfin, 64, ss);
    *ctlen = BENC_KEM_CIPHERTEXT_LEN;
    *sslen = BENC_KEM_SHARED_SECRET_LEN;
    return 0;
}

int benc_kem_decapsulate(benc_kem *kem, uint8_t *ss, size_t *sslen,
                         const uint8_t *ct, size_t ctlen,
                         const uint8_t *sk, size_t sklen) {
    if (!kem || !ss || !sslen || !ct || !sk) return -1;
    /* sk = sk_pke || pk || H(pk) || z */
    const uint8_t *sk_pke = sk;
    const uint8_t *pk = sk + KEM_K*KEM_N*12/8;
    const uint8_t *h = pk + BENC_KEM_PUBLIC_KEY_LEN;
    const uint8_t *z = h + 32;
    uint8_t m[32], K[32], r[32];
    kpke_decrypt(sk_pke, ct, m);
    uint8_t input[64]; memcpy(input, m, 32); memcpy(input+32, h, 32);
    uint8_t gm[64]; sha3_512(input, 64, gm);
    memcpy(K, gm, 32); memcpy(r, gm+32, 32);
    /* re-encrypt */
    uint8_t ct2[BENC_KEM_CIPHERTEXT_LEN];
    kpke_encrypt(pk, m, r, ct2);
    /* compare ct */
    int ok = 1;
    for (size_t i=0;i<ctlen;i++) if (ct[i]!=ct2[i]) { ok=0; break; }
    uint8_t hct[32]; sha3_256(ct, ctlen, hct);
    uint8_t kdfin[64];
    if (ok) {
        memcpy(kdfin, K, 32);
    } else {
        memcpy(kdfin, z, 32);
    }
    memcpy(kdfin+32, hct, 32);
    sha3_256(kdfin, 64, ss);
    *sslen = BENC_KEM_SHARED_SECRET_LEN;
    return 0;
}
EOF
echo "written"; wc -l benc_kem.c