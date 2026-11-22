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
/* ------------------------------------------------------------------ */

#define BC_ZSTD_MAGIC0 0x28
#define BC_ZSTD_MAGIC1 0xB5
#define BC_ZSTD_MAGIC2 0x2F
#define BC_ZSTD_MAGIC3 0xFD

static size_t bc_zstd_put_block(uint8_t *dst, int last, int type, uint32_t size, const uint8_t *src)
{
    {
        uint32_t v = (uint32_t)((last ? 1 : 0) | ((uint32_t)(type & 3) << 1) | ((uint32_t)size << 3));
        dst[0] = (uint8_t)(v & 0xFF);
        dst[1] = (uint8_t)((v >> 8) & 0xFF);
        dst[2] = (uint8_t)((v >> 16) & 0xFF);
    }
    if (type == 1) { /* RLE block: single byte value repeated `size` times */
        if (src)
            dst[3] = *src;
        return 4;
    }
    if (src && size > 0)
        memcpy(dst + 3, src, size);
    return 3 + (size_t)size;
}

int benc_zstd_encode(const char *src, const char *dst, int level, int threads)
{
    uint8_t *in;
    size_t in_len;
    uint8_t *comp;
    size_t comp_len;

    (void)level;
    (void)threads;
    if (bc_read_file(src, &in, &in_len) != 0)
        return -1;
    comp = (uint8_t *)malloc((size_t)(in_len + (uint32_t)in_len / (uint32_t)131072 + 32));
    if (!comp)
        return -1;
    comp[0] = BC_ZSTD_MAGIC0;
    comp[1] = BC_ZSTD_MAGIC1;
    comp[2] = BC_ZSTD_MAGIC2;
    comp[3] = BC_ZSTD_MAGIC3;
    comp[4] = 0x00;
    comp[5] = 0x50;
    comp_len = 6;
    {
        size_t off = 0;
        size_t pos = 6;
        while (off < in_len) {
            /* detect a run of identical bytes */
            uint32_t run = 1;
            while (off + run < in_len && run < (uint32_t)131072 &&
                   in[off + run] == in[off])
                run++;
            if (run >= 4) {
                int last = (off + run >= in_len) ? 1 : 0;
                pos += bc_zstd_put_block(comp + pos, last, 1, run, in + off);
                off += (size_t)run;
                continue;
            }
            /* raw block */
            {
                uint32_t chunk = (uint32_t)(in_len - off);
                int last = 0;
                if (chunk > (uint32_t)131072)
                    chunk = (uint32_t)131072;
                if (off + (size_t)chunk >= in_len)
                    last = 1;
                pos += bc_zstd_put_block(comp + pos, last, 0, chunk, in + off);
                off += (size_t)chunk;
            }
        }
        if (in_len == 0)
            comp_len = 6 + (size_t)bc_zstd_put_block(comp + 6, 1, 0, 0, NULL);
        else
            comp_len = pos;
    }
    if (bc_write_file(dst, comp, comp_len) != 0) {
        free(comp);
        free(in);
        return -1;
    }
    free(comp);
    free(in);
    return 0;
}

int benc_zstd_decode(const char *src, const char *dst)
{
    uint8_t *in;
    size_t in_len;
    uint8_t *out;
    uint32_t out_cap = 0;
    size_t out_len = 0;
    size_t off = 0;
    int last = 0;
    int type = 0;
    uint32_t size = 0;

    if (bc_read_file(src, &in, &in_len) != 0)
        return -1;
    if (in_len < 5 || in[0] != BC_ZSTD_MAGIC0 || in[1] != BC_ZSTD_MAGIC1 || in[2] != BC_ZSTD_MAGIC2 || in[3] != BC_ZSTD_MAGIC3)
        return -1;
    {
        uint32_t fhd = in[4];
        int fcs_flag = (int)((fhd >> 6) & 3);
        int single = (int)((fhd >> 5) & 1);
        int did_flag = (int)(fhd & 3);
        uint32_t fcs_size = 0;
        size_t did_size = 0;
        if (fcs_flag == 0)
            fcs_size = single ? 1u : 0u;
        else if (fcs_flag == 1)
            fcs_size = 2;
        else if (fcs_flag == 2)
            fcs_size = 4;
        else
            fcs_size = 8;
        if (did_flag == 0)
            did_size = 0;
        else if (did_flag == 1)
            did_size = 1;
        else if (did_flag == 2)
            did_size = 2;
        else
            did_size = 4;
        off = 5 + (single ? 0u : 1u) + did_size + fcs_size;
        if (fcs_size > 0) {
            uint32_t fcs = 0;
            int i;
            if (fcs_size == 1) {
                fcs = in[5];
            } else if (fcs_size == 2) {
                fcs = (uint32_t)in[5] | ((uint32_t)in[6] << 8);
                fcs = fcs + 256;
            } else if (fcs_size == 4) {
                fcs = 0;
                for (i = 0; i < 4; i++)
                    fcs |= ((uint32_t)in[5 + i]) << (8 * i);
            } else {
                uint64_t f = 0;
                int j;
                for (j = 0; j < 8; j++)
                    f |= ((uint64_t)in[5 + j]) << (8 * j);
                fcs = (uint32_t)f;
            }
            out_cap = fcs;
        }
    }
    {
        size_t out_alloc = 4096;
        out = (uint8_t *)malloc(out_alloc);
        if (!out)
            return -1;
        for (;;) {
        uint32_t b0 = in[off];
        uint32_t b1 = in[off + 1];
        uint32_t b2 = in[off + 2];
        uint32_t v = b0 | ((uint32_t)b1 << 8) | ((uint32_t)b2 << 16);
        last = (v & 1) ? 1 : 0;
        type = (int)((v >> 1) & 3);
        size = v >> 3;
        off += 3;
        if ((size_t)out_len + (size_t)size > out_alloc) {
            size_t nalloc = ((size_t)out_len + (size_t)size) * 2;
            uint8_t *nout = (uint8_t *)realloc(out, nalloc);
            if (!nout) {
                free(out);
                return -1;
            }
            out = nout;
            out_alloc = nalloc;
        }
        if (type == 0) {
            uint32_t i;
            for (i = 0; i < size; i++)
                out[out_len++] = in[off++];
        } else if (type == 1) {
            uint8_t b = in[off];
            uint32_t i;
            for (i = 0; i < size; i++)
                out[out_len++] = b;
            off += 1;
        } else if (type == 2) {
            if (out_len + size > out_cap)
                return -1;
            memcpy(out + out_len, in + off, size);
            out_len += size;
            off += size;
        } else {
            return -1;
        }
        if (last)
            break;
        }
    }
    if (bc_write_file(dst, out, out_len) != 0) {
        free(out);
        free(in);
        return -1;
    }
    free(out);
    free(in);
    return 0;
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
#define LZMA_NUM_POS_MASK (LZMA_NUM_POS_STATES - 1u)
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
#define LZMA_MAX_CHAIN 64

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
    uint16_t spec_pos[LZMA_NUM_FULL_DISTANCES - LZMA_END_POS_MODEL_INDEX];
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
            rc_enc_bit_tree_reverse(rc, p->spec_pos +
                                    (size_t)(base - slot - 1), num_direct, rem);
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

static uint32_t lzma_hash(const uint8_t *p)
{
    uint32_t h = (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
                 ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
    return (h * 2654435761u) >> (32 - LZMA_HASH_BITS);
}

/* ------------------------------------------------------------------ */
/* LZMA encode one range-coded chunk [start,end)                      */
/* ------------------------------------------------------------------ */

static void lzma_encode_range(const uint8_t *in, size_t start, size_t end,
                              lzma_matcher *m, lzma_probs *p,
                              lzma_rc_enc *rc)
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
            uint32_t min_pos =
                pos > LZMA_WINDOW ? (uint32_t)(pos - LZMA_WINDOW) : 0;
            while (cand != 0xFFFFFFFFu && chain < LZMA_MAX_CHAIN) {
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
            uint8_t prev = pos > start ? in[pos - 1] : 0;
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
        rc->range >>= 1;
        if (rc->code >= rc->range) {
            rc->code -= rc->range;
            res |= 1u << i;
        }
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
                                  uint8_t *out, size_t out_cap, size_t *out_len)
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
        m.head = (uint32_t *)malloc((size_t)LZMA_HASH_SIZE * sizeof(uint32_t));
        m.prev = (uint32_t *)malloc((size_t)LZMA_WINDOW * sizeof(uint32_t));
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
        size_t chunk = in_len - pos;
        if (chunk > LZMA_CHUNK_MAX)
            chunk = LZMA_CHUNK_MAX;

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
            lzma_encode_range(in, pos, pos + chunk, &m, probs, &rcc);
            rc_enc_flush(&rcc);
            if (!rcc.overflow)
                csize = rcc.pos;

            if (csize > 0 && csize < chunk && csize <= LZMA_CHUNK_MAX) {
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
                                  uint8_t **out_p, size_t *out_len)
{
    size_t ip = 0, op = 0;
    size_t out_cap = 4096;
    uint8_t *out = NULL;
    lzma_probs *probs = NULL;
    lzma_probs *p = probs;
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
                p = probs;
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
                                       &p->is_match[state *
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
                            if (rc_dec_bit(&rc, &p->is_rep[state]) == 0) {
                                uint32_t slot;
                                len = lzma_decode_len(&rc, &p->match_len,
                                                      pos_state);
                                slot = rc_dec_bit_tree(
                                    &rc,
                                    p->pos_slot[(len - LZMA_MATCH_MIN_LEN < 4)
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
                                            p->spec_pos +
                                                (size_t)(dist - slot - 1),
                                            num_direct);
                                    else {
                                        dist += rc_dec_direct(
                                            &rc,
                                            num_direct - LZMA_NUM_ALIGN_BITS)
                                            << LZMA_NUM_ALIGN_BITS;
                                        dist += rc_dec_bit_tree_reverse(
                                            &rc, p->align,
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
                                if (rc_dec_bit(&rc, &p->is_rep_g0[state]) == 0) {
                                    if (rc_dec_bit(&rc, &p->is_rep0_long[
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
                                    if (rc_dec_bit(&rc, &p->is_rep_g1[state]) == 0)
                                        d = reps[1];
                                    else {
                                        if (rc_dec_bit(&rc, &p->is_rep_g2[state]) == 0)
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
                                len = lzma_decode_len(&rc, &p->rep_len,
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

int benc_lzma2_encode(const char *src, const char *dst, int preset, int threads)
{
    uint8_t *in = NULL;
    size_t in_len = 0;
    uint8_t *out = NULL;
    size_t out_cap = 0;
    size_t out_len = 0;
    int rc = -1;

    (void)preset;
    (void)threads;
    if (bc_read_file(src, &in, &in_len) != 0)
        return -1;
    out_cap = in_len + (in_len >> 14) + 4096;
    out = (uint8_t *)malloc(out_cap);
    if (!out)
        goto out;
    if (bc_lzma2_encode_stream(in, in_len, out, out_cap, &out_len) != 0)
        goto out;
    if (bc_write_file(dst, out, out_len) != 0)
        goto out;
    rc = 0;
out:
    free(out);
    free(in);
    return rc;
}

int benc_lzma2_decode(const char *src, const char *dst)
{
    uint8_t *in = NULL;
    size_t in_len = 0;
    uint8_t *out = NULL;
    size_t out_len = 0;
    int rc = -1;

    if (bc_read_file(src, &in, &in_len) != 0)
        return -1;
    if (bc_lzma2_decode_stream(in, in_len, &out, &out_len) != 0)
        goto out;
    if (bc_write_file(dst, out, out_len) != 0)
        goto out;
    rc = 0;
out:
    free(out);
    free(in);
    return rc;
}
