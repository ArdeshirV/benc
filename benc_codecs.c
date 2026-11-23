/* benc_codecs.c - self contained native LZMA2 and Zstd codecs for benc. */

#include "benc_codecs.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* ------------------------------------------------------------------ */
/* file helpers                                                        */
/* ------------------------------------------------------------------ */

static int bc_read_file(const char *path, uint8_t **out, size_t *len)
{
    FILE *fp = fopen(path, "rb");
    long sz;
    uint8_t *buf;

    if (!fp)
        return -1;
    if (fseek(fp, 0, SEEK_END) != 0) { fclose(fp); return -1; }
    sz = ftell(fp);
    if (sz < 0) { fclose(fp); return -1; }
    if (fseek(fp, 0, SEEK_SET) != 0) { fclose(fp); return -1; }
    buf = (uint8_t *)malloc((size_t)sz + 1);
    if (!buf) { fclose(fp); return -1; }
    if (sz > 0 && fread(buf, 1, (size_t)sz, fp) != (size_t)sz) { free(buf); fclose(fp); return -1; }
    fclose(fp);
    buf[sz] = 0;
    *out = buf;
    *len = (size_t)sz;
    return 0;
}

static int bc_write_file(const char *path, const uint8_t *data, size_t len)
{
    FILE *fp = fopen(path, "wb");
    int ok = 1;

    if (!fp)
        return -1;
    if (len > 0 && fwrite(data, 1, len, fp) != len)
        ok = 0;
    if (fclose(fp) != 0)
        ok = 0;
    return ok ? 0 : -1;
}

/* ------------------------------------------------------------------ */
/* Zstd native codec                                                   */
/*                                                                    */
/* Self-contained encoder and decoder.  The encoder emits raw blocks   */
/* and compressed blocks that use the predefined FSE tables            */
/* with raw literals; the decoder reads that subset, so no libzstd is  */
/* needed.  Frames are ordinary Zstandard frames and can be read by    */
/* the reference `zstd` tool.                                          */
/* ------------------------------------------------------------------ */

#define BZ_MAGIC0      0x28u
#define BZ_MAGIC1      0xB5u
#define BZ_MAGIC2      0x2Fu
#define BZ_MAGIC3      0xFDu
#define BZ_BLOCK_MAX   UINT32_C(131072) /* 128 KiB, the default block max */
#define BZ_WINDOW      (UINT32_C(1) << 20) /* matches the frame descriptor */
#define BZ_MIN_MATCH   3u
#define BZ_MAX_SEQ     0x7EFFu          /* 2-byte sequence count limit   */
#define BZ_HASH_BITS   16
#define BZ_HASH_SIZE   (UINT32_C(1) << BZ_HASH_BITS)
#define BZ_LL_MAX      35
#define BZ_ML_MAX      52
#define BZ_OF_MAX      28               /* predefined offset table range */
#define BZ_LL_LOG      6
#define BZ_ML_LOG      6
#define BZ_OF_LOG      5

/* A 16-bit size_t (e.g. ia16 DOS) cannot describe a single object as
 * large as the encoder tables, so those targets emit raw blocks only.
 * The decoder is unaffected. */
#if SIZE_MAX < 131072
#define BZ_RAW_ONLY 1
#endif

static const uint8_t bz_ll_bits[BZ_LL_MAX + 1] = {
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    1, 1, 1, 1, 2, 2, 3, 3,
    4, 6, 7, 8, 9, 10, 11, 12,
    13, 14, 15, 16
};

static const uint8_t bz_ml_bits[BZ_ML_MAX + 1] = {
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    1, 1, 1, 1, 2, 2, 3, 3,
    4, 4, 5, 7, 8, 9, 10, 11,
    12, 13, 14, 15, 16
};

static const int16_t bz_ll_norm[BZ_LL_MAX + 1] = {
    4, 3, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 1, 1, 1,
    2, 2, 2, 2, 2, 2, 2, 2,
    2, 3, 2, 1, 1, 1, 1, 1,
    -1, -1, -1, -1
};

static const int16_t bz_ml_norm[BZ_ML_MAX + 1] = {
    1, 4, 3, 2, 2, 2, 2, 2,
    2, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, -1, -1,
    -1, -1, -1, -1, -1
};

static const int16_t bz_of_norm[BZ_OF_MAX + 1] = {
    1, 1, 1, 1, 1, 1, 2, 2,
    2, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1,
    -1, -1, -1, -1, -1
};

#ifndef BZ_RAW_ONLY
typedef struct {
    int32_t  deltaFindState;
    uint32_t deltaNbBits;
} bz_sym_tt;

typedef struct {
    uint32_t table_log;
    uint32_t max_symbol;
    uint16_t state_table[64];
    bz_sym_tt sym_tt[BZ_ML_MAX + 1];
} bz_ctable;
#endif

typedef struct {
    uint16_t next_state;
    uint8_t  nb_bits;
    uint8_t  nb_add;
    uint32_t base;
} bz_dentry;

typedef struct {
    uint32_t table_log;
    bz_dentry table[64];
} bz_dtable;

#ifndef BZ_RAW_ONLY
typedef struct {
    uint32_t litlen;
    uint32_t matchlen;
    uint32_t offset;
} bz_seq;

/* Encoder scratch, allocated once per frame and reused for every block. */
typedef struct {
    uint32_t *head;         /* BZ_HASH_SIZE entries */
    uint32_t *prev;         /* BZ_BLOCK_MAX entries */
    uint8_t  *lits;         /* BZ_BLOCK_MAX bytes   */
    bz_seq   *seqs;         /* BZ_MAX_SEQ entries   */
} bz_scratch;
#endif

#ifndef BZ_RAW_ONLY
static bz_ctable bz_ct_ll, bz_ct_ml, bz_ct_of;
#endif
static bz_dtable bz_dt_ll, bz_dt_ml, bz_dt_of;
static uint32_t bz_ll_base[BZ_LL_MAX + 1];
static uint32_t bz_ml_base[BZ_ML_MAX + 1];
static uint32_t bz_of_base[BZ_OF_MAX + 1];
static int bz_ready;

static uint32_t bz_highbit(uint32_t v)
{
    uint32_t r = 0;

    while (v >>= 1)
        r++;
    return r;
}

#ifndef BZ_RAW_ONLY
static uint32_t bz_hash3(const uint8_t *p)
{
    uint32_t v = (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
                 ((uint32_t)p[2] << 16);
    return (v * 2654435761u) >> (32 - BZ_HASH_BITS);
}
#endif

/* ---- FSE tables (predefined distributions) ----------------------- */

#ifndef BZ_RAW_ONLY
static void bz_ctable_build(bz_ctable *ct, const int16_t *norm,
                            uint32_t max_symbol, uint32_t table_log)
{
    uint32_t table_size = 1u << table_log;
    uint32_t mask = table_size - 1;
    uint32_t step = (table_size >> 1) + (table_size >> 3) + 3;
    uint32_t cumul[BZ_ML_MAX + 2];
    uint8_t symbols[64];
    uint32_t high = table_size - 1;
    uint32_t u, s, position, total = 0;

    ct->table_log = table_log;
    ct->max_symbol = max_symbol;
    cumul[0] = 0;
    for (u = 1; u <= max_symbol + 1; u++) {
        if (norm[u - 1] == -1) {
            cumul[u] = cumul[u - 1] + 1;
            symbols[high--] = (uint8_t)(u - 1);
        } else {
            cumul[u] = cumul[u - 1] + (uint32_t)norm[u - 1];
        }
    }
    position = 0;
    for (s = 0; s <= max_symbol; s++) {
        int32_t i, n = norm[s];
        for (i = 0; i < n; i++) {
            symbols[position] = (uint8_t)s;
            position = (position + step) & mask;
            while (position > high)
                position = (position + step) & mask;
        }
    }
    for (u = 0; u < table_size; u++)
        ct->state_table[cumul[symbols[u]]++] = (uint16_t)(table_size + u);

    for (s = 0; s <= max_symbol; s++) {
        if (norm[s] == 0) {
            ct->sym_tt[s].deltaNbBits = ((table_log + 1) << 16) - table_size;
            ct->sym_tt[s].deltaFindState = 0;
        } else if (norm[s] == -1 || norm[s] == 1) {
            ct->sym_tt[s].deltaNbBits = (table_log << 16) - table_size;
            ct->sym_tt[s].deltaFindState = (int32_t)total - 1;
            total++;
        } else {
            uint32_t max_bits = table_log -
                                bz_highbit((uint32_t)norm[s] - 1u);
            uint32_t min_state = (uint32_t)norm[s] << max_bits;
            ct->sym_tt[s].deltaNbBits = (max_bits << 16) - min_state;
            ct->sym_tt[s].deltaFindState = (int32_t)total - norm[s];
            total += (uint32_t)norm[s];
        }
    }
}

#endif

static void bz_dtable_build(bz_dtable *dt, const int16_t *norm,
                            uint32_t max_symbol, uint32_t table_log,
                            const uint32_t *base, const uint8_t *nb_add)
{
    uint32_t table_size = 1u << table_log;
    uint32_t mask = table_size - 1;
    uint32_t step = (table_size >> 1) + (table_size >> 3) + 3;
    uint16_t next[BZ_ML_MAX + 1];
    uint8_t symbols[64];
    uint32_t high = table_size - 1;
    uint32_t position = 0;
    uint32_t s, u;

    for (s = 0; s <= max_symbol; s++) {
        next[s] = (uint16_t)(norm[s] == -1 ? 1 : norm[s]);
        if (norm[s] == -1)
            symbols[high--] = (uint8_t)s;
    }
    for (s = 0; s <= max_symbol; s++) {
        int32_t i, n = norm[s];
        for (i = 0; i < n; i++) {
            symbols[position] = (uint8_t)s;
            position = (position + step) & mask;
            while (position > high)
                position = (position + step) & mask;
        }
    }
    dt->table_log = table_log;
    for (u = 0; u < table_size; u++) {
        uint32_t sym = symbols[u];
        uint32_t ns = next[sym]++;
        uint32_t bits = table_log - bz_highbit(ns);

        dt->table[u].next_state = (uint16_t)((ns << bits) - table_size);
        dt->table[u].nb_bits = (uint8_t)bits;
        dt->table[u].nb_add = nb_add ? nb_add[sym] : (uint8_t)sym;
        dt->table[u].base = base[sym];
    }
}

static void bz_tables_init(void)
{
    uint32_t c;

    if (bz_ready)
        return;
    bz_ll_base[0] = 0;
    for (c = 1; c <= BZ_LL_MAX; c++)
        bz_ll_base[c] = bz_ll_base[c - 1] + (1u << bz_ll_bits[c - 1]);
    bz_ml_base[0] = 3;
    for (c = 1; c <= BZ_ML_MAX; c++)
        bz_ml_base[c] = bz_ml_base[c - 1] + (1u << bz_ml_bits[c - 1]);
    for (c = 0; c <= BZ_OF_MAX; c++)
        bz_of_base[c] = 1u << c;

#ifndef BZ_RAW_ONLY
    bz_ctable_build(&bz_ct_ll, bz_ll_norm, BZ_LL_MAX, BZ_LL_LOG);
    bz_ctable_build(&bz_ct_ml, bz_ml_norm, BZ_ML_MAX, BZ_ML_LOG);
    bz_ctable_build(&bz_ct_of, bz_of_norm, BZ_OF_MAX, BZ_OF_LOG);
#endif
    bz_dtable_build(&bz_dt_ll, bz_ll_norm, BZ_LL_MAX, BZ_LL_LOG,
                    bz_ll_base, bz_ll_bits);
    bz_dtable_build(&bz_dt_ml, bz_ml_norm, BZ_ML_MAX, BZ_ML_LOG,
                    bz_ml_base, bz_ml_bits);
    bz_dtable_build(&bz_dt_of, bz_of_norm, BZ_OF_MAX, BZ_OF_LOG,
                    bz_of_base, NULL);
    bz_ready = 1;
}

/* ---- bit stream -------------------------------------------------- */

#ifndef BZ_RAW_ONLY
typedef struct {
    uint32_t acc;
    unsigned nbits;
    uint8_t *buf;
    size_t   cap;
    size_t   pos;
    int      err;
} bz_bw;
#endif

typedef struct {
    const uint8_t *buf;
    long bit;
    int err;
} bz_br;

#ifndef BZ_RAW_ONLY
static void bz_bw_flush(bz_bw *w)
{
    while (w->nbits >= 8) {
        if (w->pos < w->cap)
            w->buf[w->pos] = (uint8_t)(w->acc & 0xFFu);
        else
            w->err = 1;
        w->pos++;
        w->acc >>= 8;
        w->nbits -= 8;
    }
}

/* Callers pass at most 16 bits while the accumulator holds fewer than 8
 * pending bits, so it never overflows. */
static void bz_bw_put(bz_bw *w, uint32_t v, unsigned n)
{
    if (n == 0)
        return;
    w->acc |= (v & ((1u << n) - 1u)) << w->nbits;
    w->nbits += n;
    bz_bw_flush(w);
}

static size_t bz_bw_close(bz_bw *w)
{
    bz_bw_put(w, 1, 1);             /* end marker */
    if (w->nbits > 0) {
        if (w->pos < w->cap)
            w->buf[w->pos] = (uint8_t)(w->acc & 0xFFu);
        else
            w->err = 1;
        w->pos++;
        w->nbits = 0;
    }
    return w->err ? 0 : w->pos;
}

#endif

static int bz_br_init(bz_br *r, const uint8_t *buf, size_t len)
{
    unsigned last, hb;

    if (len == 0)
        return -1;
    last = buf[len - 1];
    if (last == 0)
        return -1;
    hb = 7;
    while (!((last >> hb) & 1u))
        hb--;
    r->buf = buf;
    r->bit = (long)len * 8 - 8 + (long)hb - 1;
    r->err = 0;
    return 0;
}

static uint32_t bz_br_get(bz_br *r, unsigned n)
{
    uint32_t v = 0;

    while (n--) {
        if (r->bit < 0) {
            r->err = 1;
            return 0;
        }
        v = (v << 1) | ((r->buf[r->bit >> 3] >> (r->bit & 7)) & 1u);
        r->bit--;
    }
    return v;
}

/* ---- FSE state encode/decode ------------------------------------- */

#ifndef BZ_RAW_ONLY
typedef struct {
    uint32_t value;
    const bz_ctable *ct;
} bz_cstate;

static void bz_cstate_init(bz_cstate *st, const bz_ctable *ct,
                           uint32_t symbol)
{
    const bz_sym_tt *tt = &ct->sym_tt[symbol];
    uint32_t nb = (tt->deltaNbBits + (1u << 15)) >> 16;
    uint32_t v = (nb << 16) - tt->deltaNbBits;

    st->ct = ct;
    st->value = ct->state_table[(int32_t)(v >> nb) + tt->deltaFindState];
}

static void bz_cstate_encode(bz_bw *w, bz_cstate *st, uint32_t symbol)
{
    const bz_sym_tt *tt = &st->ct->sym_tt[symbol];
    uint32_t nb = (st->value + tt->deltaNbBits) >> 16;
    int32_t idx = (int32_t)(st->value >> nb) + tt->deltaFindState;

    bz_bw_put(w, st->value, nb);
    st->value = st->ct->state_table[idx];
}

static void bz_cstate_flush(bz_bw *w, const bz_cstate *st)
{
    bz_bw_put(w, st->value, st->ct->table_log);
}

/* ---- encoder ----------------------------------------------------- */

#endif /* !BZ_RAW_ONLY */

#ifndef BZ_RAW_ONLY
static int bz_ll_code(uint32_t v)
{
    int c = 0;

    while (c < BZ_LL_MAX && v >= bz_ll_base[c + 1])
        c++;
    return c;
}

static int bz_ml_code(uint32_t v)
{
    int c = 0;

    while (c < BZ_ML_MAX && v >= bz_ml_base[c + 1])
        c++;
    return c;
}

/* Allocate the encoder scratch pool.  Returns NULL when memory is short,
 * in which case the caller stores every block raw. */
static uint8_t *bz_scratch_alloc(bz_scratch *sc)
{
    unsigned long total = (unsigned long)BZ_HASH_SIZE * sizeof(uint32_t) +
                          (unsigned long)BZ_BLOCK_MAX * sizeof(uint32_t) +
                          (unsigned long)BZ_BLOCK_MAX +
                          (unsigned long)BZ_MAX_SEQ * sizeof(bz_seq);
    uint8_t *arena;

    /* A 16-bit size_t cannot describe the pool: store every block raw. */
    if (total > (unsigned long)(size_t)-1)
        return NULL;
    arena = (uint8_t *)malloc((size_t)total);
    if (!arena)
        return NULL;
    sc->head = (uint32_t *)arena;
    sc->prev = sc->head + BZ_HASH_SIZE;
    sc->lits = (uint8_t *)(sc->prev + BZ_BLOCK_MAX);
    sc->seqs = (bz_seq *)(sc->lits + BZ_BLOCK_MAX);
    return arena;
}

/* Parse one block into literals + sequences.  Returns the literal byte
 * count. */
static size_t bz_parse_block(const uint8_t *in, size_t len, int level,
                             bz_scratch *sc, size_t *nbseq)
{
    uint32_t *head = sc->head;
    uint32_t *prev = sc->prev;
    uint8_t *lits = sc->lits;
    bz_seq *seqs = sc->seqs;
    size_t i = 0, lit_start = 0, lit_pos = 0, n = 0;
    int chain = 8 + level * 16;
    int nice = 48 + level * 32;
    uint32_t h;

    if (chain > 256)
        chain = 256;
    if (nice > 1024)
        nice = 1024;
    for (h = 0; h < BZ_HASH_SIZE; h++)
        head[h] = 0xFFFFFFFFu;

    while (i + BZ_MIN_MATCH <= len && n < BZ_MAX_SEQ) {
        uint32_t cand;
        uint32_t best_len = 0, best_off = 0;
        int tries = chain;

        h = bz_hash3(in + i);
        cand = head[h];
        prev[i] = cand;
        head[h] = (uint32_t)i;

        while (cand != 0xFFFFFFFFu && tries-- > 0) {
            size_t dist = i - cand;
            size_t maxl = len - i;
            size_t l = 0;

            while (l < maxl && in[cand + l] == in[i + l])
                l++;
            if (l > best_len) {
                best_len = (uint32_t)l;
                best_off = (uint32_t)dist;
                if (l >= (size_t)nice)
                    break;
            }
            if (cand == 0)
                break;
            cand = prev[cand];
        }

        if (best_len >= BZ_MIN_MATCH && best_off <= BZ_WINDOW) {
            uint32_t k;

            seqs[n].litlen = (uint32_t)(i - lit_start);
            seqs[n].matchlen = best_len;
            seqs[n].offset = best_off;
            n++;
            memcpy(lits + lit_pos, in + lit_start, i - lit_start);
            lit_pos += i - lit_start;
            for (k = 1; k < best_len && i + k + BZ_MIN_MATCH <= len; k++) {
                uint32_t h2 = bz_hash3(in + i + k);
                prev[i + k] = head[h2];
                head[h2] = (uint32_t)(i + k);
            }
            i += best_len;
            lit_start = i;
        } else {
            i++;
        }
    }
    memcpy(lits + lit_pos, in + lit_start, len - lit_start);
    lit_pos += len - lit_start;
    *nbseq = n;
    return lit_pos;
}

static void bz_put_literals_header(uint8_t *out, size_t lit_len,
                                   size_t *hdr_len)
{
    if (lit_len <= 31) {
        out[0] = (uint8_t)(lit_len << 3);
        *hdr_len = 1;
    } else if (lit_len <= 4095) {
        uint32_t v = ((uint32_t)lit_len << 4) | (1u << 2);
        out[0] = (uint8_t)(v & 0xFFu);
        out[1] = (uint8_t)(v >> 8);
        *hdr_len = 2;
    } else {
        uint32_t v = ((uint32_t)lit_len << 4) | (3u << 2);
        out[0] = (uint8_t)(v & 0xFFu);
        out[1] = (uint8_t)((v >> 8) & 0xFFu);
        out[2] = (uint8_t)((v >> 16) & 0xFFu);
        *hdr_len = 3;
    }
}

/* Encode one block.  Returns the compressed size, or 0 when the block is
 * not worth compressing (the caller then emits a raw block).  The output
 * buffer is only valid when the return value is nonzero. */
static size_t bz_encode_block(bz_scratch *sc, const uint8_t *in, size_t len,
                              int level, uint8_t *out, size_t out_cap)
{
    bz_seq *seqs = sc->seqs;
    size_t nbseq = 0, lit_len, lh, total, bits, n;
    bz_bw w;
    bz_cstate st_ll, st_ml, st_of;

    lit_len = bz_parse_block(in, len, level, sc, &nbseq);
    if (nbseq == 0)
        return 0;

    bz_put_literals_header(out, lit_len, &lh);
    if (lh + lit_len + 8 > out_cap)
        return 0;
    memcpy(out + lh, sc->lits, lit_len);

    total = lh + lit_len;
    if (nbseq < 128) {
        out[total++] = (uint8_t)nbseq;
    } else {
        out[total++] = (uint8_t)(0x80u | (nbseq >> 8));
        out[total++] = (uint8_t)(nbseq & 0xFFu);
    }
    out[total++] = 0x00;            /* all three tables predefined */

    w.acc = 0;
    w.nbits = 0;
    w.buf = out + total;
    w.cap = out_cap - total;
    w.pos = 0;
    w.err = 0;

    {
        bz_seq *s = &seqs[nbseq - 1];
        int llc = bz_ll_code(s->litlen);
        int mlc = bz_ml_code(s->matchlen);
        uint32_t ofv = s->offset + 3u;
        int ofc = (int)bz_highbit(ofv);

        bz_cstate_init(&st_ml, &bz_ct_ml, (uint32_t)mlc);
        bz_cstate_init(&st_of, &bz_ct_of, (uint32_t)ofc);
        bz_cstate_init(&st_ll, &bz_ct_ll, (uint32_t)llc);
        bz_bw_put(&w, s->litlen - bz_ll_base[llc], bz_ll_bits[llc]);
        bz_bw_put(&w, s->matchlen - bz_ml_base[mlc], bz_ml_bits[mlc]);
        bz_bw_put(&w, ofv - bz_of_base[ofc], (unsigned)ofc);
    }
    for (n = nbseq - 1; n-- > 0;) {
        bz_seq *s = &seqs[n];
        int llc = bz_ll_code(s->litlen);
        int mlc = bz_ml_code(s->matchlen);
        uint32_t ofv = s->offset + 3u;
        int ofc = (int)bz_highbit(ofv);

        bz_cstate_encode(&w, &st_of, (uint32_t)ofc);
        bz_cstate_encode(&w, &st_ml, (uint32_t)mlc);
        bz_cstate_encode(&w, &st_ll, (uint32_t)llc);
        bz_bw_put(&w, s->litlen - bz_ll_base[llc], bz_ll_bits[llc]);
        bz_bw_put(&w, s->matchlen - bz_ml_base[mlc], bz_ml_bits[mlc]);
        bz_bw_put(&w, ofv - bz_of_base[ofc], (unsigned)ofc);
    }
    bz_cstate_flush(&w, &st_ml);
    bz_cstate_flush(&w, &st_of);
    bz_cstate_flush(&w, &st_ll);
    bits = bz_bw_close(&w);
    if (bits == 0)
        return 0;
    total += bits;
    return total < len ? total : 0;
}

#endif /* !BZ_RAW_ONLY */

int benc_zstd_encode(const char *src, const char *dst, int level, int threads,
                     benc_progress_fn cb, void *cb_ctx)
{
    uint8_t *in = NULL, *out = NULL, *arena = NULL;
#ifndef BZ_RAW_ONLY
    bz_scratch sc;
#endif
    size_t in_len = 0, out_cap, pos = 0, op = 0;
    int rc = -1;

    (void)threads;
#ifdef BZ_RAW_ONLY
    (void)level;
#endif
    if (bc_read_file(src, &in, &in_len) != 0)
        return -1;
    if (cb)
        cb(0, (unsigned long long)in_len, cb_ctx);
    bz_tables_init();

    {
        unsigned long cap = (unsigned long)in_len +
                            ((unsigned long)in_len / BZ_BLOCK_MAX + 2) * 3 + 16;

        if (cap > (unsigned long)(size_t)-1)
            goto out;
        out_cap = (size_t)cap;
    }
    out = (uint8_t *)malloc(out_cap);
    if (!out)
        goto out;
#ifndef BZ_RAW_ONLY
    /* When the scratch pool cannot be allocated every block is stored raw. */
    arena = bz_scratch_alloc(&sc);
#endif

    out[op++] = BZ_MAGIC0;
    out[op++] = BZ_MAGIC1;
    out[op++] = BZ_MAGIC2;
    out[op++] = BZ_MAGIC3;
    out[op++] = 0x00;               /* no content size, no checksum */
    out[op++] = 0x50;               /* 1 MiB window */

    do {
        unsigned long lim = (unsigned long)(in_len - pos);
        size_t chunk;
        int last;
        size_t csize = 0;

        if (lim > BZ_BLOCK_MAX)
            lim = BZ_BLOCK_MAX;
        chunk = (size_t)lim;
        last = (pos + chunk >= in_len) ? 1 : 0;
#ifndef BZ_RAW_ONLY
        if (arena && chunk >= 8)
            csize = bz_encode_block(&sc, in + pos, chunk, level,
                                    out + op + 3, out_cap - op - 3);
#endif
        if (csize > 0) {
            uint32_t hdr = (uint32_t)last | (2u << 1) |
                           ((uint32_t)csize << 3);
            out[op++] = (uint8_t)(hdr & 0xFFu);
            out[op++] = (uint8_t)((hdr >> 8) & 0xFFu);
            out[op++] = (uint8_t)((hdr >> 16) & 0xFFu);
            op += csize;
        } else {
            uint32_t hdr = (uint32_t)last | ((uint32_t)chunk << 3);
            out[op++] = (uint8_t)(hdr & 0xFFu);
            out[op++] = (uint8_t)((hdr >> 8) & 0xFFu);
            out[op++] = (uint8_t)((hdr >> 16) & 0xFFu);
            memcpy(out + op, in + pos, chunk);
            op += chunk;
        }
        pos += chunk;
        if (cb)
            cb((unsigned long long)pos, (unsigned long long)in_len, cb_ctx);
    } while (pos < in_len);

    if (bc_write_file(dst, out, op) != 0)
        goto out;
    rc = 0;
out:
    free(out);
    free(in);
    free(arena);
    return rc;
}

/* ---- decoder ----------------------------------------------------- */

static int bz_grow(uint8_t **buf, size_t *cap, size_t need)
{
    size_t nc;
    uint8_t *nb;

    if (need <= *cap)
        return 0;
    nc = *cap ? *cap : 4096;
    while (nc < need) {
        if (nc > (size_t)-1 / 2)
            return -1;
        nc *= 2;
    }
    nb = (uint8_t *)realloc(*buf, nc);
    if (!nb)
        return -1;
    *buf = nb;
    *cap = nc;
    return 0;
}

static int bz_decode_block(const uint8_t *src, size_t src_len,
                           uint8_t *dst, size_t dst_cap, size_t *produced)
{
    size_t p = 0, lit_size, lit_len, op = 0, nbseq;
    const uint8_t *lits;
    bz_br br;
    uint32_t st_ll, st_ml, st_of;
    size_t seq;

    /* Literal counts and match offsets in a compressed block exceed a
     * 16-bit size_t, so such targets decode raw and RLE frames only. */
    if (sizeof(size_t) < 4)
        return -1;
    if (src_len < 4)
        return -1;

    {
        unsigned type = src[0] & 3u;
        unsigned lhl = (src[0] >> 2) & 3u;

        if (type == 2 || type == 3)
            return -1;
        if (lhl == 0 || lhl == 2) {
            p = 1;
            lit_size = (size_t)src[0] >> 3;
        } else if (lhl == 1) {
            if (src_len < 2)
                return -1;
            p = 2;
            lit_size = ((size_t)src[0] | ((size_t)src[1] << 8)) >> 4;
        } else {
            uint32_t v;

            if (src_len < 3)
                return -1;
            p = 3;
            v = ((uint32_t)src[0] | ((uint32_t)src[1] << 8) |
                 ((uint32_t)src[2] << 16)) >> 4;
            if (v > (uint32_t)(size_t)-1)
                return -1;
            lit_size = (size_t)v;
        }
        if (type == 1) {
            if (p >= src_len)
                return -1;
            lits = src + p;
            lit_len = 1;
            p += 1;
        } else {
            if (p + lit_size > src_len)
                return -1;
            lits = src + p;
            lit_len = lit_size;
            p += lit_size;
        }
        if (lit_size > dst_cap)
            return -1;
    }

    if (p >= src_len)
        return -1;
    nbseq = src[p++];
    if (nbseq >= 128) {
        if (nbseq == 255) {
            if (p + 2 > src_len)
                return -1;
            nbseq = 0x7F00u + (size_t)src[p] +
                    ((size_t)src[p + 1] << 8);
            p += 2;
        } else {
            if (p >= src_len)
                return -1;
            nbseq = ((nbseq - 128) << 8) + src[p++];
        }
    }
    if (nbseq == 0) {
        size_t i;

        if (lit_len == 1) {
            memset(dst, lits[0], lit_size);
        } else {
            for (i = 0; i < lit_size; i++)
                dst[i] = lits[i];
        }
        *produced = lit_size;
        return 0;
    }

    if (p >= src_len)
        return -1;
    if (src[p++] != 0x00)           /* predefined tables only */
        return -1;
    if (bz_br_init(&br, src + p, src_len - p) != 0)
        return -1;

    st_ll = bz_br_get(&br, bz_dt_ll.table_log);
    st_of = bz_br_get(&br, bz_dt_of.table_log);
    st_ml = bz_br_get(&br, bz_dt_ml.table_log);

    {
        size_t lp = 0;

        for (seq = 0; seq < nbseq; seq++) {
            bz_dentry le = bz_dt_ll.table[st_ll & 63u];
            bz_dentry me = bz_dt_ml.table[st_ml & 63u];
            bz_dentry oe = bz_dt_of.table[st_of & 31u];
            uint32_t ofv, ml, ll, k;

            ofv = oe.base + bz_br_get(&br, oe.nb_add);
            ml = me.base + bz_br_get(&br, me.nb_add);
            ll = le.base + bz_br_get(&br, le.nb_add);
            if (br.err || ofv <= 3)
                return -1;
            {
                size_t offset = (size_t)(ofv - 3u);

                if (lp > lit_size || ll > lit_size - lp)
                    return -1;
                if (op + ll + ml > dst_cap)
                    return -1;
                if (lit_len == 1) {
                    for (k = 0; k < ll; k++)
                        dst[op++] = lits[0];
                } else {
                    for (k = 0; k < ll; k++)
                        dst[op++] = lits[lp++];
                }
                if (offset > op)
                    return -1;
                for (k = 0; k < ml; k++) {
                    dst[op] = dst[op - offset];
                    op++;
                }
            }
            if (seq + 1 < nbseq) {
                st_ll = le.next_state + bz_br_get(&br, le.nb_bits);
                st_ml = me.next_state + bz_br_get(&br, me.nb_bits);
                st_of = oe.next_state + bz_br_get(&br, oe.nb_bits);
                if (br.err)
                    return -1;
            }
        }
        while (lp < lit_size) {
            if (op >= dst_cap)
                return -1;
            dst[op++] = (lit_len == 1) ? lits[0] : lits[lp];
            lp++;
        }
    }
    *produced = op;
    return 0;
}

int benc_zstd_decode(const char *src, const char *dst,
                     benc_progress_fn cb, void *cb_ctx)
{
    uint8_t *in = NULL, *out = NULL;
    size_t in_len = 0, out_cap = 0, op = 0, p;
    int rc = -1, checksum;

    if (bc_read_file(src, &in, &in_len) != 0)
        return -1;
    if (cb)
        cb(0, (unsigned long long)in_len, cb_ctx);
    bz_tables_init();

    if (in_len < 6 || in[0] != BZ_MAGIC0 || in[1] != BZ_MAGIC1 ||
        in[2] != BZ_MAGIC2 || in[3] != BZ_MAGIC3)
        goto out;

    p = 4;
    {
        unsigned fhd = in[p++];
        unsigned fcs_flag = (fhd >> 6) & 3u;
        unsigned single = (fhd >> 5) & 1u;
        unsigned did = fhd & 3u;
        size_t fcs_size, did_size;

        if (fhd & 0x08u)
            goto out;
        checksum = (int)((fhd >> 2) & 1u);
        if (!single) {
            if (p >= in_len)
                goto out;
            p++;
        }
        did_size = did == 0 ? 0 : did == 1 ? 1 : did == 2 ? 2 : 4;
        fcs_size = fcs_flag == 0 ? (single ? 1u : 0u)
                 : fcs_flag == 1 ? 2u : fcs_flag == 2 ? 4u : 8u;
        p += did_size + fcs_size;
        if (p > in_len)
            goto out;
    }

    for (;;) {
        uint32_t hdr, size, type;
        int last;

        if (p + 3 > in_len)
            goto out;
        hdr = (uint32_t)in[p] | ((uint32_t)in[p + 1] << 8) |
              ((uint32_t)in[p + 2] << 16);
        p += 3;
        last = (int)(hdr & 1u);
        type = (hdr >> 1) & 3u;
        size = hdr >> 3;
        if (type == 3 || size > BZ_BLOCK_MAX)
            goto out;

        if (type == 0) {
            if (size > in_len - p || size > (size_t)-1 - op)
                goto out;
            if (bz_grow(&out, &out_cap, op + size) != 0)
                goto out;
            memcpy(out + op, in + p, size);
            op += size;
            p += size;
        } else if (type == 1) {
            if (p >= in_len || size > (size_t)-1 - op)
                goto out;
            if (bz_grow(&out, &out_cap, op + size) != 0)
                goto out;
            memset(out + op, in[p], size);
            op += size;
            p += 1;
        } else {
            size_t produced = 0;

            if (p + size > in_len)
                goto out;
            if (bz_grow(&out, &out_cap, op + BZ_BLOCK_MAX) != 0)
                goto out;
            if (bz_decode_block(in + p, size, out + op,
                                out_cap - op, &produced) != 0)
                goto out;
            op += produced;
            p += size;
        }
        if (cb)
            cb((unsigned long long)p, (unsigned long long)in_len, cb_ctx);
        if (last)
            break;
    }

    if (checksum) {
        if (p + 4 > in_len)
            goto out;
        p += 4;
    }
    if (bc_write_file(dst, out, op) != 0)
        goto out;
    rc = 0;
out:
    free(out);
    free(in);
    return rc;
}

/* ------------------------------------------------------------------ */
/* LZMA / LZMA2 native codec                                          */
/* ------------------------------------------------------------------ */

#define LZMA_LC 3
#define LZMA_LP 0
#define LZMA_PB 2
#define LZMA_LP_MASK ((uint32_t)((1u << LZMA_LP) - 1u))
#define LZMA_NUM_STATES 12
#define LZMA_NUM_LIT_STATES 7
#define LZMA_NUM_POS_BITS 4
#define LZMA_NUM_POS_STATES (1u << LZMA_NUM_POS_BITS)
#define LZMA_NUM_POS_MASK ((uint32_t)((1u << LZMA_PB) - 1u))
#define LZMA_NUM_LEN_TO_POS_STATES 4
#define LZMA_NUM_POS_SLOT_BITS 6
#define LZMA_START_POS_MODEL_INDEX 4
#define LZMA_END_POS_MODEL_INDEX 14
#define LZMA_NUM_FULL_DISTANCES (1u << (LZMA_END_POS_MODEL_INDEX >> 1))
#define LZMA_NUM_ALIGN_BITS 4
#define LZMA_ALIGN_SIZE (1u << LZMA_NUM_ALIGN_BITS)
#define LZMA_LIT_SIZE 0x300
#define LZMA_MATCH_MIN_LEN 2
#define LZMA_MATCH_MAX_LEN 273
#define LZMA_PROB_INIT 1024
#define LZMA_BIT_MODEL_TOTAL (1u << 11)
#define LZMA_MOVE_BITS 5
#define LZMA_TOP_VALUE 0x01000000u

#define LZMA_WINDOW_BITS 17
#define LZMA_WINDOW (UINT32_C(1) << LZMA_WINDOW_BITS)
#define LZMA_WINDOW_MASK (LZMA_WINDOW - 1u)
#define LZMA_HASH_BITS 15
#define LZMA_HASH_SIZE (UINT32_C(1) << LZMA_HASH_BITS)
#define LZMA_HASH_MASK (LZMA_HASH_SIZE - 1u)
#define LZMA_CHUNK_MAX UINT32_C(65536)

typedef struct {
    uint16_t choice;
    uint16_t choice2;
    uint16_t low[LZMA_NUM_POS_STATES][8];
    uint16_t mid[LZMA_NUM_POS_STATES][8];
    uint16_t high[256];
} lzma_len_probs;

typedef struct {
    uint16_t is_match[LZMA_NUM_STATES * LZMA_NUM_POS_STATES];
    uint16_t is_rep[LZMA_NUM_STATES];
    uint16_t is_rep_g0[LZMA_NUM_STATES];
    uint16_t is_rep_g1[LZMA_NUM_STATES];
    uint16_t is_rep_g2[LZMA_NUM_STATES];
    uint16_t is_rep0_long[LZMA_NUM_STATES * LZMA_NUM_POS_STATES];
    uint16_t pos_slot[LZMA_NUM_LEN_TO_POS_STATES][1u << LZMA_NUM_POS_SLOT_BITS];
    uint16_t spec_pos[LZMA_NUM_FULL_DISTANCES];
    uint16_t align[LZMA_ALIGN_SIZE];
    lzma_len_probs match_len;
    lzma_len_probs rep_len;
    uint16_t literal[LZMA_LIT_SIZE << (LZMA_LC + LZMA_LP)];
} lzma_probs;

static void lzma_probs_init(lzma_probs *p)
{
    size_t i;
    uint16_t *q = (uint16_t *)p;
    size_t n = sizeof(*p) / sizeof(uint16_t);
    for (i = 0; i < n; i++)
        q[i] = LZMA_PROB_INIT;
}

/* ------------------------------------------------------------------ */
/* range coder                                                        */
/* ------------------------------------------------------------------ */

typedef struct {
    uint8_t *buf;
    size_t pos, cap;
    uint32_t range;
    uint64_t low;
    uint8_t cache;
    uint64_t cache_size;
    int overflow;
} lzma_rc_enc;

static void rc_enc_init(lzma_rc_enc *rc, uint8_t *buf, size_t cap)
{
    rc->buf = buf;
    rc->pos = 0;
    rc->cap = cap;
    rc->range = 0xFFFFFFFFu;
    rc->low = 0;
    rc->cache = 0;
    rc->cache_size = 1;
    rc->overflow = 0;
}

static void rc_enc_shift_low(lzma_rc_enc *rc)
{
    if ((uint32_t)rc->low < 0xFF000000u || (rc->low >> 32) != 0) {
        uint8_t temp = rc->cache;
        do {
            uint8_t b = (uint8_t)(temp + (uint8_t)(rc->low >> 32));
            if (rc->pos < rc->cap)
                rc->buf[rc->pos++] = b;
            else
                rc->overflow = 1;
            temp = 0xFF;
        } while (--rc->cache_size != 0);
        rc->cache = (uint8_t)((uint32_t)rc->low >> 24);
    }
    rc->cache_size++;
    rc->low = (uint32_t)rc->low << 8;
}

static void rc_enc_bit(lzma_rc_enc *rc, uint16_t *prob, int bit)
{
    uint32_t bound = (rc->range >> 11) * (uint32_t)(*prob);
    if (!bit) {
        rc->range = bound;
        *prob = (uint16_t)(*prob + (((1u << 11) - *prob) >> LZMA_MOVE_BITS));
    } else {
        rc->low += bound;
        rc->range -= bound;
        *prob = (uint16_t)(*prob - (*prob >> LZMA_MOVE_BITS));
    }
    while (rc->range < LZMA_TOP_VALUE) {
        rc->range <<= 8;
        rc_enc_shift_low(rc);
    }
}

static void rc_enc_direct(lzma_rc_enc *rc, uint32_t value, int nbits)
{
    int i;
    for (i = nbits; i > 0; i--) {
        rc->range >>= 1;
        if ((value >> (i - 1)) & 1u)
            rc->low += rc->range;
        while (rc->range < LZMA_TOP_VALUE) {
            rc->range <<= 8;
            rc_enc_shift_low(rc);
        }
    }
}

static void rc_enc_flush(lzma_rc_enc *rc)
{
    int i;
    for (i = 0; i < 5; i++)
        rc_enc_shift_low(rc);
}

/* ------------------------------------------------------------------ */
/* bit trees                                                          */
/* ------------------------------------------------------------------ */

static void rc_enc_bit_tree(lzma_rc_enc *rc, uint16_t *probs, int nbits,
                            uint32_t symbol)
{
    uint32_t m = 1;
    int i;
    for (i = nbits - 1; i >= 0; i--) {
        uint32_t bit = (symbol >> i) & 1u;
        rc_enc_bit(rc, &probs[m], (int)bit);
        m = (m << 1) | bit;
    }
}

static void rc_enc_bit_tree_reverse(lzma_rc_enc *rc, uint16_t *probs, int nbits,
                                    uint32_t symbol)
{
    uint32_t m = 1;
    int i;
    for (i = 0; i < nbits; i++) {
        uint32_t bit = (symbol >> i) & 1u;
        rc_enc_bit(rc, &probs[m], (int)bit);
        m = (m << 1) | bit;
    }
}

/* ------------------------------------------------------------------ */
/* literal coding                                                     */
/* ------------------------------------------------------------------ */

static void lzma_encode_literal(lzma_rc_enc *rc, lzma_probs *p, int state,
                                uint32_t pos, uint8_t prev, uint8_t match_byte,
                                uint8_t symbol)
{
    uint16_t *probs = p->literal +
        (size_t)LZMA_LIT_SIZE *
        (((pos & LZMA_LP_MASK) << LZMA_LC) + ((uint32_t)prev >> (8 - LZMA_LC)));
    uint32_t ctx = 1;
    int i;
    int same;

    if (state < LZMA_NUM_LIT_STATES) {
        for (i = 7; i >= 0; i--) {
            uint32_t bit = ((uint32_t)symbol >> i) & 1u;
            rc_enc_bit(rc, &probs[ctx], (int)bit);
            ctx = (ctx << 1) | bit;
        }
        return;
    }
    same = 1;
    for (i = 7; i >= 0; i--) {
        uint32_t bit = ((uint32_t)symbol >> i) & 1u;
        uint32_t mb = ((uint32_t)match_byte >> i) & 1u;
        uint16_t *pp;
        if (same) {
            pp = &probs[((1u + mb) << 8) + ctx];
            if (mb != bit)
                same = 0;
        } else {
            pp = &probs[ctx];
        }
        rc_enc_bit(rc, pp, (int)bit);
        ctx = (ctx << 1) | bit;
    }
}

/* ------------------------------------------------------------------ */
/* lengths and distances                                              */
/* ------------------------------------------------------------------ */

static int lzma_state_char(int s)
{
    if (s < 4)
        return 0;
    if (s < 10)
        return s - 3;
    return s - 6;
}

static int lzma_state_match(int s)
{
    return s < 7 ? 7 : 10;
}

static int lzma_state_rep(int s)
{
    return s < 7 ? 8 : 11;
}

static int lzma_state_short_rep(int s)
{
    return s < 7 ? 9 : 11;
}

static uint32_t lzma_get_pos_slot(uint32_t pos)
{
    uint32_t n = 0;
    uint32_t x = pos;
    if (pos < LZMA_START_POS_MODEL_INDEX)
        return pos;
    while (x > 1) {
        x >>= 1;
        n++;
    }
    return (n << 1) | ((pos >> (n - 1)) & 1u);
}

static void lzma_encode_len(lzma_rc_enc *rc, lzma_len_probs *lp,
                            uint32_t len, uint32_t pos_state)
{
    uint32_t sym = len - LZMA_MATCH_MIN_LEN;
    if (sym < 8) {
        rc_enc_bit(rc, &lp->choice, 0);
        rc_enc_bit_tree(rc, lp->low[pos_state], 3, sym);
    } else if (sym < 16) {
        rc_enc_bit(rc, &lp->choice, 1);
        rc_enc_bit(rc, &lp->choice2, 0);
        rc_enc_bit_tree(rc, lp->mid[pos_state], 3, sym - 8);
    } else {
        rc_enc_bit(rc, &lp->choice, 1);
        rc_enc_bit(rc, &lp->choice2, 1);
        rc_enc_bit_tree(rc, lp->high, 8, sym - 16);
    }
}

static void lzma_encode_dist(lzma_rc_enc *rc, lzma_probs *p, uint32_t dist0,
                             uint32_t len)
{
    uint32_t len_to_pos = (len - LZMA_MATCH_MIN_LEN < 4)
        ? (len - LZMA_MATCH_MIN_LEN) : 3u;
    uint32_t slot = lzma_get_pos_slot(dist0);
    rc_enc_bit_tree(rc, p->pos_slot[len_to_pos], LZMA_NUM_POS_SLOT_BITS, slot);
    if (slot >= LZMA_START_POS_MODEL_INDEX) {
        int num_direct = (int)((slot >> 1) - 1);
        uint32_t base = (2u | (slot & 1u)) << num_direct;
        uint32_t rem = dist0 - base;
        if (slot < LZMA_END_POS_MODEL_INDEX) {
            rc_enc_bit_tree_reverse(rc, p->spec_pos + base, num_direct, rem);
        } else {
            rc_enc_direct(rc, rem >> LZMA_NUM_ALIGN_BITS,
                          num_direct - LZMA_NUM_ALIGN_BITS);
            rc_enc_bit_tree_reverse(rc, p->align, LZMA_NUM_ALIGN_BITS,
                                    rem & (LZMA_ALIGN_SIZE - 1u));
        }
    }
}

/* ------------------------------------------------------------------ */
/* match finder                                                       */
/* ------------------------------------------------------------------ */

typedef struct {
    uint32_t *head;   /* hash -> latest absolute position (0xFFFFFFFF = none) */
    uint32_t *prev;   /* ring of size LZMA_WINDOW */
} lzma_matcher;

/* Encoder effort knobs derived from the compression level (preset 0..9).
 *   chain_depth : max candidates examined per position in the hash chain
 *   nice_len    : stop the chain search once a match reaches this length
 * Higher levels search deeper and stop later, buying ratio at the cost of
 * speed.  This mirrors xz's level->effort mapping closely enough to be
 * useful while staying tiny (no runtime tables to initialise). */
typedef struct {
    uint32_t chain_depth;
    uint32_t nice_len;
} lzma_opts;

static void lzma_opts_from_level(int level, lzma_opts *o)
{
    static const uint32_t depth_tab[10] =
        { 4u, 8u, 16u, 32u, 48u, 64u, 128u, 256u, 512u, 1024u };
    static const uint32_t nice_tab[10] =
        { 16u, 24u, 32u, 48u, 64u, 96u, 128u, 192u, 256u, 273u };

    if (level < 0)
        level = 6;          /* benc's LZMA2 default */
    if (level > 9)
        level = 9;
    o->chain_depth = depth_tab[level];
    o->nice_len = nice_tab[level];
}

static uint32_t lzma_hash(const uint8_t *p)
{
    uint32_t h = (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
                 ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
    return (h * 2654435761u) >> (32 - LZMA_HASH_BITS);
}

/* ------------------------------------------------------------------ */
/* LZMA encode one range-coded chunk [start,end)                      */
/* ------------------------------------------------------------------ */

/* The window is unreachable when size_t cannot hold its size. */
static uint32_t lzma_min_pos(size_t pos)
{
#if SIZE_MAX > LZMA_WINDOW
    if ((unsigned long)pos > LZMA_WINDOW)
        return (uint32_t)(pos - LZMA_WINDOW);
#else
    (void)pos;
#endif
    return 0;
}

static void lzma_encode_range(const uint8_t *in, size_t start, size_t end,
                              lzma_matcher *m, lzma_probs *p,
                              lzma_rc_enc *rc, const lzma_opts *opts)
{
    int state = 0;
    uint32_t reps[4] = { 1u, 1u, 1u, 1u };
    size_t pos = start;
    size_t insert_pos = start;

    while (pos < end) {
        /* insert all positions strictly below pos into the hash chains */
        while (insert_pos < pos && insert_pos + 4 <= end) {
            uint32_t h = lzma_hash(in + insert_pos);
            m->prev[insert_pos & LZMA_WINDOW_MASK] = m->head[h];
            m->head[h] = (uint32_t)insert_pos;
            insert_pos++;
        }
        uint32_t pos_state = (uint32_t)pos & LZMA_NUM_POS_MASK;
        uint32_t avail = (uint32_t)(end - pos);
        uint32_t max_len = avail < LZMA_MATCH_MAX_LEN ? avail : LZMA_MATCH_MAX_LEN;
        uint32_t best_len = 0;
        uint32_t best_dist = 0;
        uint32_t rep_best_len = 0;
        int rep_best = -1;
        int i;

        /* rep matches */
        for (i = 0; i < 4; i++) {
            uint32_t d = reps[i];
            uint32_t l = 0;
            if (d <= pos && avail >= LZMA_MATCH_MIN_LEN) {
                while (l < max_len && in[pos + l] == in[pos - d + l])
                    l++;
                if (l > rep_best_len && l >= LZMA_MATCH_MIN_LEN) {
                    rep_best_len = l;
                    rep_best = i;
                }
            }
        }

        /* normal match via hash chain (head only holds positions < pos) */
        if (max_len >= LZMA_MATCH_MIN_LEN && pos + 4 <= end) {
            uint32_t cand = m->head[lzma_hash(in + pos)];
            uint32_t chain = 0;
            uint32_t min_pos = lzma_min_pos(pos);
            while (cand != 0xFFFFFFFFu && chain < opts->chain_depth) {
                uint32_t d;
                if (cand < min_pos)
                    break;
                d = (uint32_t)pos - cand;
                if (best_len < max_len &&
                    in[cand + best_len] == in[pos + best_len]) {
                    uint32_t l = 0;
                    while (l < max_len && in[cand + l] == in[pos + l])
                        l++;
                    if (l > best_len) {
                        best_len = l;
                        best_dist = d;
                        if (l >= max_len)
                            break;
                    }
                }
                cand = m->prev[cand & LZMA_WINDOW_MASK];
                chain++;
                /* good-enough match: stop searching, save time */
                if (best_len >= opts->nice_len)
                    break;
            }
        }

        /* choose encoding */
        if (best_len >= LZMA_MATCH_MIN_LEN && best_len >= rep_best_len) {
            rc_enc_bit(rc, &p->is_match[state * LZMA_NUM_POS_STATES + pos_state],
                       1);
            rc_enc_bit(rc, &p->is_rep[state], 0);
            lzma_encode_len(rc, &p->match_len, best_len, pos_state);
            lzma_encode_dist(rc, p, best_dist - 1, best_len);
            reps[3] = reps[2];
            reps[2] = reps[1];
            reps[1] = reps[0];
            reps[0] = best_dist;
            state = lzma_state_match(state);
            pos += best_len;
        } else if (rep_best >= 0) {
            uint32_t d = reps[rep_best];
            rc_enc_bit(rc, &p->is_match[state * LZMA_NUM_POS_STATES + pos_state],
                       1);
            rc_enc_bit(rc, &p->is_rep[state], 1);
            if (rep_best == 0) {
                rc_enc_bit(rc, &p->is_rep_g0[state], 0);
                rc_enc_bit(rc, &p->is_rep0_long[state * LZMA_NUM_POS_STATES +
                                                  pos_state], 1);
            } else {
                rc_enc_bit(rc, &p->is_rep_g0[state], 1);
                if (rep_best == 1)
                    rc_enc_bit(rc, &p->is_rep_g1[state], 0);
                else {
                    rc_enc_bit(rc, &p->is_rep_g1[state], 1);
                    rc_enc_bit(rc, &p->is_rep_g2[state],
                               (int)(rep_best - 2));
                }
                reps[3] = reps[2];
                reps[2] = reps[1];
                reps[1] = reps[0];
                reps[0] = d;
            }
            lzma_encode_len(rc, &p->rep_len, rep_best_len, pos_state);
            state = lzma_state_rep(state);
            pos += rep_best_len;
        } else {
            uint8_t prev = pos > 0 ? in[pos - 1] : 0;
            uint8_t match_byte = 0;
            if (state >= LZMA_NUM_LIT_STATES)
                match_byte = in[pos - reps[0]];
            rc_enc_bit(rc, &p->is_match[state * LZMA_NUM_POS_STATES +
                                          pos_state], 0);
            lzma_encode_literal(rc, p, state, (uint32_t)pos, prev,
                                match_byte, (uint8_t)in[pos]);
            state = lzma_state_char(state);
            pos += 1;
        }
    }
}

/* ------------------------------------------------------------------ */
/* range decoder                                                      */
/* ------------------------------------------------------------------ */

typedef struct {
    const uint8_t *buf;
    size_t pos, end;
    uint32_t range, code;
} lzma_rc_dec;

static uint8_t rc_get(lzma_rc_dec *rc)
{
    if (rc->pos < rc->end)
        return rc->buf[rc->pos++];
    return 0;
}

static void rc_dec_init(lzma_rc_dec *rc, const uint8_t *buf, size_t start,
                        size_t end)
{
    int i;
    rc->buf = buf;
    rc->pos = start;
    rc->end = end;
    rc->range = 0xFFFFFFFFu;
    rc->code = 0;
    for (i = 0; i < 5; i++)
        rc->code = (rc->code << 8) | rc_get(rc);
}

static int rc_dec_bit(lzma_rc_dec *rc, uint16_t *prob)
{
    uint32_t bound = (rc->range >> 11) * (uint32_t)(*prob);
    int bit;
    if (rc->code < bound) {
        rc->range = bound;
        *prob = (uint16_t)(*prob + (((1u << 11) - *prob) >> LZMA_MOVE_BITS));
        bit = 0;
    } else {
        rc->code -= bound;
        rc->range -= bound;
        *prob = (uint16_t)(*prob - (*prob >> LZMA_MOVE_BITS));
        bit = 1;
    }
    if (rc->range < LZMA_TOP_VALUE) {
        rc->range <<= 8;
        rc->code = (rc->code << 8) | rc_get(rc);
    }
    return bit;
}

static uint32_t rc_dec_direct(lzma_rc_dec *rc, int nbits)
{
    uint32_t res = 0;
    int i;
    for (i = 0; i < nbits; i++) {
        uint32_t bit = 0;
        rc->range >>= 1;
        if (rc->code >= rc->range) {
            rc->code -= rc->range;
            bit = 1u;
        }
        res = (res << 1) | bit;
        if (rc->range < LZMA_TOP_VALUE) {
            rc->range <<= 8;
            rc->code = (rc->code << 8) | rc_get(rc);
        }
    }
    return res;
}

static uint32_t rc_dec_bit_tree(lzma_rc_dec *rc, uint16_t *probs, int nbits)
{
    uint32_t m = 1;
    int i;
    for (i = 0; i < nbits; i++)
        m = (m << 1) | (uint32_t)rc_dec_bit(rc, &probs[m]);
    return m - (1u << nbits);
}

static uint32_t rc_dec_bit_tree_reverse(lzma_rc_dec *rc, uint16_t *probs,
                                        int nbits)
{
    uint32_t m = 1;
    uint32_t symbol = 0;
    int i;
    for (i = 0; i < nbits; i++) {
        uint32_t bit = (uint32_t)rc_dec_bit(rc, &probs[m]);
        m = (m << 1) | bit;
        symbol |= bit << i;
    }
    return symbol;
}

static uint32_t lzma_decode_len(lzma_rc_dec *rc, lzma_len_probs *lp,
                                uint32_t pos_state);
static uint8_t lzma_decode_literal(lzma_rc_dec *rc, lzma_probs *p, int state,
                                   uint32_t pos, uint8_t prev,
                                   uint8_t match_byte);

/* ------------------------------------------------------------------ */
/* LZMA decode one range-coded chunk                                  */

static uint32_t lzma_decode_len(lzma_rc_dec *rc, lzma_len_probs *lp,
                                uint32_t pos_state)
{
    if (!rc_dec_bit(rc, &lp->choice)) {
        return rc_dec_bit_tree(rc, lp->low[pos_state], 3) + LZMA_MATCH_MIN_LEN;
    }
    if (!rc_dec_bit(rc, &lp->choice2)) {
        return rc_dec_bit_tree(rc, lp->mid[pos_state], 3) +
               LZMA_MATCH_MIN_LEN + 8;
    }
    return rc_dec_bit_tree(rc, lp->high, 8) +
           LZMA_MATCH_MIN_LEN + 16;
}

static uint8_t lzma_decode_literal(lzma_rc_dec *rc, lzma_probs *p, int state,
                                   uint32_t pos, uint8_t prev, uint8_t match_byte)
{
    uint16_t *probs = p->literal +
        (size_t)LZMA_LIT_SIZE *
        (((pos & LZMA_LP_MASK) << LZMA_LC) + ((uint32_t)prev >> (8 - LZMA_LC)));
    uint32_t symbol = 1;
    if (state >= LZMA_NUM_LIT_STATES) {
        uint32_t mb = match_byte;
        do {
            uint32_t match_bit = (mb >> 7) & 1u;
            uint32_t bit;
            mb <<= 1;
            bit = (uint32_t)rc_dec_bit(rc, &probs[((1u + match_bit) << 8) +
                                                   symbol]);
            symbol = (symbol << 1) | bit;
            if (match_bit != bit)
                break;
        } while (symbol < 0x100);
    }
    while (symbol < 0x100)
        symbol = (symbol << 1) | (uint32_t)rc_dec_bit(rc, &probs[symbol]);
    return (uint8_t)(symbol - 0x100);
}

/* ------------------------------------------------------------------ */
/* LZMA2 stream encode/decode                                         */
/* ------------------------------------------------------------------ */

static int bc_lzma2_encode_stream(const uint8_t *in, size_t in_len,
                                  uint8_t *out, size_t out_cap, size_t *out_len,
                                  const lzma_opts *opts,
                                  benc_progress_fn cb, void *cb_ctx)
{
    size_t pos = 0;
    size_t pos_out = 0;
    lzma_matcher m;
    lzma_probs *probs = NULL;
    uint8_t *tmp = NULL;
    size_t tmp_cap = 0;
    int have_matcher = 0;
    int rc_ret = -1;

    m.head = m.prev = NULL;
    if (in_len > 0) {
        unsigned long head_sz =
            (unsigned long)LZMA_HASH_SIZE * sizeof(uint32_t);
        unsigned long prev_sz = (unsigned long)LZMA_WINDOW * sizeof(uint32_t);

        /* A 16-bit size_t cannot describe the matcher; the stream then
         * falls back to uncompressed chunks. */
        if (head_sz <= (unsigned long)(size_t)-1 &&
            prev_sz <= (unsigned long)(size_t)-1) {
            m.head = (uint32_t *)malloc((size_t)head_sz);
            m.prev = (uint32_t *)malloc((size_t)prev_sz);
        }
        probs = (lzma_probs *)malloc(sizeof(lzma_probs));
        if (m.head && m.prev && probs) {
            size_t i;
            for (i = 0; i < LZMA_HASH_SIZE; i++)
                m.head[i] = 0xFFFFFFFFu;
            have_matcher = 1;
        } else {
            free(m.head);
            free(m.prev);
            free(probs);
            m.head = m.prev = NULL;
            probs = NULL;
        }
    }

    while (pos < in_len) {
        unsigned long lim = (unsigned long)(in_len - pos);
        size_t chunk;

        if (lim > LZMA_CHUNK_MAX)
            lim = LZMA_CHUNK_MAX;
        chunk = (size_t)lim;
        if (have_matcher) {
            size_t csize = 0;
            lzma_rc_enc rcc;
            lzma_probs_init(probs);
            if (tmp_cap < chunk + (chunk >> 3) + 1024) {
                size_t nc = chunk + (chunk >> 3) + 1024;
                uint8_t *nt = (uint8_t *)realloc(tmp, nc);
                if (!nt)
                    goto done;
                tmp = nt;
                tmp_cap = nc;
            }
            rc_enc_init(&rcc, tmp, tmp_cap);
            lzma_encode_range(in, pos, pos + chunk, &m, probs, &rcc, opts);
            rc_enc_flush(&rcc);
            if (!rcc.overflow)
                csize = rcc.pos;

            if (csize > 0 && csize < chunk
#if SIZE_MAX >= LZMA_CHUNK_MAX
                && csize <= LZMA_CHUNK_MAX
#endif
                ) {
                /* emit LZMA chunk */
                uint32_t usize_m1 = (uint32_t)chunk - 1;
                uint32_t csize_m1 = (uint32_t)csize - 1;
                uint8_t control =
                    (uint8_t)(0x80 | ((usize_m1 >> 16) & 0x1F) |
                              (pos == 0 ? 0xE0 : 0xA0));
                size_t need = pos_out + 5 + csize;
                if (need > out_cap)
                    goto done;
                out[pos_out++] = control;
                out[pos_out++] = (uint8_t)((usize_m1 >> 8) & 0xFF);
                out[pos_out++] = (uint8_t)(usize_m1 & 0xFF);
                out[pos_out++] = (uint8_t)((csize_m1 >> 8) & 0xFF);
                out[pos_out++] = (uint8_t)(csize_m1 & 0xFF);
                if (pos == 0)
                    out[pos_out++] = (uint8_t)(
                        (LZMA_PB * 5 + LZMA_LP) * 9 + LZMA_LC);
                memcpy(out + pos_out, tmp, csize);
                pos_out += csize;
                pos += chunk;
                if (cb)
                    cb((unsigned long long)pos, (unsigned long long)in_len, cb_ctx);
                continue;
            }
        }

        /* fallback: uncompressed chunk */
        {
            uint32_t n = (uint32_t)chunk - 1;
            size_t need = pos_out + 3 + chunk;
            if (need > out_cap)
                goto done;
            out[pos_out++] = (uint8_t)(pos == 0 ? 0x01 : 0x02);
            out[pos_out++] = (uint8_t)(n >> 8);
            out[pos_out++] = (uint8_t)(n & 0xFF);
            memcpy(out + pos_out, in + pos, chunk);
            pos_out += chunk;
            pos += chunk;
            if (cb)
                cb((unsigned long long)pos, (unsigned long long)in_len, cb_ctx);
        }
    }

    if (pos_out + 1 > out_cap)
        goto done;
    out[pos_out++] = 0x00; /* EOS */
    *out_len = pos_out;
    rc_ret = 0;

done:
    free(tmp);
    free(m.head);
    free(m.prev);
    free(probs);
    return rc_ret;
}

static int bc_lzma2_decode_stream(const uint8_t *in, size_t in_len,
                                  uint8_t **out_p, size_t *out_len,
                                  benc_progress_fn cb, void *cb_ctx)
{
    size_t ip = 0, op = 0;
    size_t out_cap = 4096;
    uint8_t *out = NULL;
    lzma_probs *probs = NULL;
    int state = 0;
    uint32_t reps[4] = { 1u, 1u, 1u, 1u };
    int have_probs = 0;
    int rc_ret = -1;

    out = (uint8_t *)malloc(out_cap);
    if (!out)
        return -1;

    while (ip < in_len) {
        unsigned control = in[ip++];
        if (control == 0x00)
            break; /* EOS */
        if (control < 0x80) {
            /* uncompressed chunk */
            uint32_t sz;
            if (ip + 2 > in_len)
                goto fail;
            sz = (((uint32_t)in[ip] << 8) | in[ip + 1]) + 1;
            ip += 2;
            if (ip + sz > in_len || op + (size_t)sz > out_cap) {
                size_t nc = op + (size_t)sz + 4096;
                uint8_t *no = (uint8_t *)realloc(out, nc);
                if (!no)
                    goto fail;
                out = no;
                out_cap = nc;
            }
            memcpy(out + op, in + ip, sz);
            op += (size_t)sz;
            ip += sz;
            continue;
        } else {
            /* LZMA chunk */
            uint32_t usize, csize;
            int reset_dict = (control >= 0xC0);
            int reset_state = (control >= 0xA0);
            if (ip + 4 > in_len)
                goto fail;
            usize = (((uint32_t)(control & 0x1F) << 16) |
                     ((uint32_t)in[ip] << 8) | in[ip + 1]) + 1;
            csize = (((uint32_t)in[ip + 2] << 8) | in[ip + 3]) + 1;
            ip += 4;
            if (reset_dict) {
                if (ip + 1 > in_len)
                    goto fail;
                ip += 1; /* props byte */
            }
            if (ip + csize > in_len)
                goto fail;
            if (!have_probs) {
                probs = (lzma_probs *)malloc(sizeof(lzma_probs));
                if (!probs)
                    goto fail;
                have_probs = 1;
            }
            if (reset_state || reset_dict) {
                lzma_probs_init(probs);
                state = 0;
                reps[0] = reps[1] = reps[2] = reps[3] = 1u;
            }
            {
                size_t chunk_end = ip + csize;
                lzma_rc_dec rc;
                rc_dec_init(&rc, in, ip, chunk_end);
                {
                    uint32_t produced = 0;
                    while (produced < usize) {
                        uint32_t pos_state = (uint32_t)op & LZMA_NUM_POS_MASK;
                        if (rc_dec_bit(&rc,
                                       &probs->is_match[state *
                                                    LZMA_NUM_POS_STATES +
                                                    pos_state]) == 0) {
                            uint32_t lit_pos = (uint32_t)op;
                            uint8_t prev = op > 0 ? out[op - 1] : 0;
                            uint8_t mb = 0;
                            uint8_t sym;
                            if (state >= LZMA_NUM_LIT_STATES) {
                                uint32_t d = reps[0];
                                if (d > op)
                                    goto fail;
                                mb = out[op - d];
                            }
                            sym = lzma_decode_literal(&rc, probs, state,
                                                      lit_pos, prev, mb);
                            if (op >= out_cap) {
                                size_t nc = out_cap * 2 + usize;
                                uint8_t *no = (uint8_t *)realloc(out, nc);
                                if (!no)
                                    goto fail;
                                out = no;
                                out_cap = nc;
                            }
                            out[op] = sym;
                            op++;
                            produced++;
                            state = lzma_state_char(state);
                        } else {
                            uint32_t len;
                            uint32_t dist;
                            if (rc_dec_bit(&rc, &probs->is_rep[state]) == 0) {
                                uint32_t slot;
                                len = lzma_decode_len(&rc, &probs->match_len,
                                                      pos_state);
                                slot = rc_dec_bit_tree(
                                    &rc,
                                    probs->pos_slot[(len - LZMA_MATCH_MIN_LEN < 4)
                                                    ? (len -
                                                      LZMA_MATCH_MIN_LEN)
                                                    : 3u],
                                    LZMA_NUM_POS_SLOT_BITS);
                                if (slot < LZMA_START_POS_MODEL_INDEX)
                                    dist = slot;
                                else {
                                    int num_direct = (int)((slot >> 1) - 1);
                                    dist = (2u | (slot & 1u)) << num_direct;
                                    if (slot < LZMA_END_POS_MODEL_INDEX)
                                        dist += rc_dec_bit_tree_reverse(
                                            &rc,
                                            probs->spec_pos + dist,
                                            num_direct);
                                    else {
                                        dist += rc_dec_direct(
                                            &rc,
                                            num_direct - LZMA_NUM_ALIGN_BITS)
                                            << LZMA_NUM_ALIGN_BITS;
                                        dist += rc_dec_bit_tree_reverse(
                                            &rc, probs->align,
                                            LZMA_NUM_ALIGN_BITS);
                                    }
                                }
                                dist += 1u;
                                reps[3] = reps[2];
                                reps[2] = reps[1];
                                reps[1] = reps[0];
                                reps[0] = dist;
                                state = lzma_state_match(state);
                            } else {
                                if (rc_dec_bit(&rc, &probs->is_rep_g0[state]) == 0) {
                                    if (rc_dec_bit(&rc, &probs->is_rep0_long[
                                            state * LZMA_NUM_POS_STATES +
                                            pos_state]) == 0) {
                                        if (reps[0] > op)
                                            goto fail;
                                        if (op >= out_cap) {
                                            size_t nc = out_cap * 2 + usize;
                                            uint8_t *no =
                                                (uint8_t *)realloc(out, nc);
                                            if (!no)
                                                goto fail;
                                            out = no;
                                            out_cap = nc;
                                        }
                                        out[op] = out[op - reps[0]];
                                        op++;
                                        produced++;
                                        state = lzma_state_short_rep(state);
                                        continue;
                                    }
                                } else {
                                    uint32_t d;
                                    if (rc_dec_bit(&rc, &probs->is_rep_g1[state]) == 0)
                                        d = reps[1];
                                    else {
                                        if (rc_dec_bit(&rc, &probs->is_rep_g2[state]) == 0)
                                            d = reps[2];
                                        else {
                                            d = reps[3];
                                            reps[3] = reps[2];
                                        }
                                        reps[2] = reps[1];
                                    }
                                    reps[1] = reps[0];
                                    reps[0] = d;
                                }
                                len = lzma_decode_len(&rc, &probs->rep_len,
                                                      pos_state);
                                dist = reps[0];
                                state = lzma_state_rep(state);
                            }
                            if (dist == 0 || dist > op)
                                goto fail;
                            if (op + len > out_cap) {
                                size_t nc = op + len + 4096;
                                uint8_t *no = (uint8_t *)realloc(out, nc);
                                if (!no)
                                    goto fail;
                                out = no;
                                out_cap = nc;
                            }
                            {
                                uint32_t k;
                                for (k = 0; k < len; k++) {
                                    out[op] = out[op - dist];
                                    op++;
                                }
                            }
                            produced += len;
                        }
                    }
                }
                ip = chunk_end;
                if (cb)
                    cb((unsigned long long)ip, (unsigned long long)in_len, cb_ctx);
            }
        }
    }

    *out_p = out;
    *out_len = op;
    rc_ret = 0;
    goto end;

fail:
    free(out);
    free(probs);
    return -1;
end:
    free(probs);
    return rc_ret;
}

int benc_lzma2_encode(const char *src, const char *dst, int preset, int threads,
                      benc_progress_fn cb, void *cb_ctx)
{
    uint8_t *in = NULL;
    size_t in_len = 0;
    uint8_t *out = NULL;
    size_t out_cap = 0;
    size_t out_len = 0;
    int rc = -1;
    lzma_opts opts;

    (void)threads;
    lzma_opts_from_level(preset, &opts);
    if (bc_read_file(src, &in, &in_len) != 0)
        return -1;
    if (cb)
        cb(0, (unsigned long long)in_len, cb_ctx);
    {
        unsigned long cap = (unsigned long)in_len + (in_len >> 14) + 4096;

        if (cap > (unsigned long)(size_t)-1)
            goto out;
        out_cap = (size_t)cap;
    }
    out = (uint8_t *)malloc(out_cap);
    if (!out)
        goto out;
    if (bc_lzma2_encode_stream(in, in_len, out, out_cap, &out_len, &opts,
                               cb, cb_ctx) != 0)
        goto out;
    if (bc_write_file(dst, out, out_len) != 0)
        goto out;
    rc = 0;
out:
    free(out);
    free(in);
    return rc;
}

int benc_lzma2_decode(const char *src, const char *dst,
                      benc_progress_fn cb, void *cb_ctx)
{
    uint8_t *in = NULL;
    size_t in_len = 0;
    uint8_t *out = NULL;
    size_t out_len = 0;
    int rc = -1;

    if (bc_read_file(src, &in, &in_len) != 0)
        return -1;
    if (cb)
        cb(0, (unsigned long long)in_len, cb_ctx);
    if (bc_lzma2_decode_stream(in, in_len, &out, &out_len, cb, cb_ctx) != 0)
        goto out;
    if (bc_write_file(dst, out, out_len) != 0)
        goto out;
    rc = 0;
out:
    free(out);
    free(in);
    return rc;
}
