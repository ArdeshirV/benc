/*
 * benc - portable password based file encryption CLI.
 *
 *   benc encrypt file.bin        -> file.bin.benc   (plain ASCII text)
 *   benc decrypt file.bin.benc   -> file.bin
 *
 * Self contained C99 encryption core.  Compression (LZMA2, Zstd) lives in
 * benc_codecs.c and directory packing in benc_tar.c; neither needs an
 * external library or tool.  Builds with gcc/clang
 * (Linux, macOS, Termux, *BSD), MinGW or MSVC (Windows) and DJGPP /
 * ia16-gcc (DOS; use -mcmodel=medium, the tiny model is too small).
 *
 * Construction (container format 5; formats 1 and 4 files still decrypt).  Versions
 * 2 and 3 belong to a different container lineage (SHAKE256 KDF,
 * ChaCha20-Cascade-512, KMAC256, encrypted names) and are rejected.
 *   preprocess: a directory is packed with tar, then the payload is
 *               compressed (lzma2 by default, zstd, or none) before it is
 *               encrypted
 *   keys      : PBKDF2-HMAC-SHA256(password, salt, iterations) -> 64 bytes
 *               (first 32 = cipher key, second 32 = MAC key)
 *   encryption: ChaCha20 (64 bit nonce, 64 bit block counter)
 *   integrity : HMAC-SHA256 over canonical header || ciphertext,
 *               encrypt-then-MAC, verified before a single byte of
 *               plaintext is written.
 *   container : text file, base64 body, human readable header.
 *
 * User interface rule: apart from --help / --version / info, the program
 * owns exactly ONE line of terminal output.  Prompts, retries, progress
 * and the final result are all drawn on that line, which is cleared and
 * redrawn as needed; the cursor only moves to a new line once the program
 * is finished.
 */

#if !defined(_WIN32) && !defined(__DJGPP__) && !defined(__MSDOS__) && \
    !defined(_DOS)
#  ifndef _POSIX_C_SOURCE
#    define _POSIX_C_SOURCE 200809L
#  endif
#  if defined(__APPLE__) && !defined(_DARWIN_C_SOURCE)
#    define _DARWIN_C_SOURCE 1
#  endif
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <stdarg.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include "benc_platform.h"
#include "benc_codecs.h"
#include "benc_tar.h"
#include "benc_kem.h"

/* ------------------------------------------------------------------ */
/* constants                                                           */
/* ------------------------------------------------------------------ */

#define BENC_NAME         "benc"
#define BENC_VERSION      "1.5.0"
#define BENC_FMT_VERSION  5u          /* what new containers are written as */
#define BENC_FMT_V4       4u          /* previous container format */
#define BENC_FMT_LEGACY   1u          /* oldest container still readable    */

#define BENC_SALT_LEN     16
#define BENC_NONCE_LEN    8
#define BENC_KEY_LEN      32
#define BENC_TAG_LEN      32
#define BENC_MAX_NAME     255
#define BENC_MAX_ITER     10000000UL

/* The iteration count is stored in every file header, so files stay
 * interchangeable between platforms.  Do not lower the default for DOS:
 * a small count would make DOS encrypted files easy to brute force.
 * Override with -DBENC_DEFAULT_ITER=N for quick tests only. */
#ifndef BENC_DEFAULT_ITER
#  define BENC_DEFAULT_ITER 210000UL
#endif

#define BENC_B64_BLOCK    48            /* input bytes per output line    */
#define BENC_B64_COLS     64            /* base64 characters per line     */

#if BENC_DOS
#  define BENC_CHUNK      (BENC_B64_BLOCK * 128)       /* 6 KiB           */
#  define BENC_RBUF       4096
#  define BENC_OBUF       1536
#  define BENC_COPY_BUF  1024
#  define BENC_MAX_PASSWORD 256
#else
#  define BENC_CHUNK      (BENC_B64_BLOCK * 1024)      /* 48 KiB          */
#  define BENC_RBUF       65536
#  define BENC_OBUF       16384
#  define BENC_COPY_BUF  65536
#  define BENC_MAX_PASSWORD 1024
#endif

#define BENC_PROGRESS_MS  150
#define BENC_MAX_TRIES    3

#define BENC_BEGIN_FILE   "-----BEGIN BENC FILE-----"
#define BENC_END_FILE     "-----END BENC FILE-----"
#define BENC_BEGIN_DATA   "-----BEGIN BENC DATA-----"
#define BENC_END_DATA     "-----END BENC DATA-----"

#define BENC_KDF_NAME     "PBKDF2-HMAC-SHA256"
#define BENC_CIPHER_NAME  "ChaCha20"
#define BENC_MAC_NAME     "HMAC-SHA256"
#define BENC_MAX_THREADS  1024

/* Exit codes.  These are part of the command line contract: scripts branch
 * on them, so the numeric values must stay stable.  Keep README.md in sync. */
enum {
    RC_OK          = 0,   /* success */
    RC_ERR         = 1,   /* unspecified error */
    RC_AUTH        = 2,   /* wrong password or tampered container */
    RC_USAGE       = 3,   /* bad command line / usage */
    RC_INPUT       = 4,   /* cannot open or read the input */
    RC_OUTPUT      = 5,   /* cannot create or write the output */
    RC_FORMAT      = 6,   /* not a benc file / malformed / truncated */
    RC_UNSUPPORTED = 7,   /* unsupported version, KDF, cipher or codec */
    RC_NOMEM       = 8,   /* out of memory */
    RC_PASSWORD    = 9,   /* missing, empty, too long or mismatched password */
    RC_CODEC       = 10,  /* compression or decompression failure */
    RC_SELFTEST    = 11   /* built-in self-test failed */
};

/* Code of the most recent failc() call.  Lets a command return a precise exit
 * status even when a failure is raised inside a helper that only returns
 * through `fail(); goto done;`. */
static int g_exit;
static uint8_t g_kem_ss[BENC_KEM_SHARED_SECRET_LEN];
static size_t g_kem_ss_len = 0;

/* Compression identifiers.  The order is part of the container: only the
 * name is written, but these values are used everywhere internally. */
enum {
    COMP_NONE = 0, COMP_LZMA2, COMP_ZSTD, COMP_COUNT
};

typedef struct {
    const char *name;      /* name stored in the container header */
    const char *alias;     /* second accepted command line spelling */
    int min_level, max_level, def_level;
    int threaded;          /* 1 when the backend can use extra threads */
} comp_spec;

static const comp_spec comp_specs[COMP_COUNT] = {
    { "none",   NULL,   0,  0,  0, 0 },
    { "lzma2",  "lzma", 0,  9,  6, 1 },
    { "zstd",   NULL,   1, 19,  3, 1 }
};

static int ci_equal(const char *a, const char *b);

static int comp_lookup(const char *name);

static int comp_lookup(const char *name)
{
    int i;

    for (i = 0; i < COMP_COUNT; i++)
        if (ci_equal(name, comp_specs[i].name) ||
            (comp_specs[i].alias && ci_equal(name, comp_specs[i].alias)))
            return i;
    return -1;
}

/* ------------------------------------------------------------------ */
/* small helpers                                                       */
/* ------------------------------------------------------------------ */

static void u64_to_dec(uint64_t v, char *out)
{
    char tmp[24];
    int i = 0, j = 0;

    if (v == 0) {
        out[0] = '0';
        out[1] = '\0';
        return;
    }
    while (v) {
        tmp[i++] = (char)('0' + (int)(v % 10u));
        v /= 10u;
    }
    while (i)
        out[j++] = tmp[--i];
    out[j] = '\0';
}

static int dec_to_u64(const char *s, uint64_t *out)
{
    uint64_t r = 0;
    int any = 0;

    for (; *s; s++) {
        unsigned d;
        if (*s < '0' || *s > '9')
            return -1;
        d = (unsigned)(*s - '0');
        if (r > (UINT64_MAX - d) / 10u)
            return -1;
        r = r * 10u + d;
        any = 1;
    }
    *out = r;
    return any ? 0 : -1;
}

/* 1234567 -> "1.1 MiB"; integer arithmetic only (no FPU needed) */
static void fmt_size(uint64_t v, char *out)
{
    static const char *const unit[] = { "B", "KiB", "MiB", "GiB", "TiB" };
    int u = 0;
    unsigned tenths;

    while (u < 4 && (v >> (10 * (u + 1))) != 0)
        u++;
    if (u == 0) {
        sprintf(out, "%u B", (unsigned)v);
        return;
    }
    tenths = (unsigned)(((v & (((uint64_t)1 << (10 * u)) - 1)) * 10u) >> (10 * u));
    sprintf(out, "%u.%u %s", (unsigned)(v >> (10 * u)), tenths, unit[u]);
}

static void fmt_secs(unsigned long ms, char *out)
{
    sprintf(out, "%lu.%lu s", ms / 1000ul, (ms % 1000ul) / 100ul);
}

static char *str_trim(char *s)
{
    char *e;

    while (*s == ' ' || *s == '\t')
        s++;
    e = s + strlen(s);
    while (e > s && (e[-1] == ' ' || e[-1] == '\t' || e[-1] == '\r' ||
                     e[-1] == '\n'))
        e--;
    *e = '\0';
    return s;
}

static int is_sep(char c)
{
    return c == '/' || c == '\\';
}

static const char *base_name(const char *path)
{
    const char *p, *b = path;

    for (p = path; *p; p++)
        if (is_sep(*p))
            b = p + 1;
    return b;
}

static int ci_equal(const char *a, const char *b)
{
    for (; *a && *b; a++, b++) {
        char x = *a, y = *b;
        if (x >= 'A' && x <= 'Z') x = (char)(x - 'A' + 'a');
        if (y >= 'A' && y <= 'Z') y = (char)(y - 'A' + 'a');
        if (x != y)
            return 0;
    }
    return *a == *b;
}

/* ------------------------------------------------------------------ */
/* single line terminal UI                                             */
/* ------------------------------------------------------------------ */

#define UI_MAXW 120

static int          ui_w = 78;     /* usable columns (terminal width - 1) */
static int          ui_tty;        /* stderr is a terminal                */
static int          ui_live;       /* draw progress (tty and not --quiet) */
static volatile int ui_len;        /* characters currently on the line    */

static void ui_init(int quiet)
{
    int w = 0;

    ui_tty = benc_isatty(2) != 0;
#if BENC_POSIX
#  ifdef TIOCGWINSZ
    {
        struct winsize ws;
        if (ioctl(2, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0)
            w = ws.ws_col;
    }
#  endif
    if (w <= 0) {
        const char *c = getenv("COLUMNS");
        if (c)
            w = atoi(c);
    }
#elif BENC_WINDOWS
    {
        CONSOLE_SCREEN_BUFFER_INFO ci;
        if (GetConsoleScreenBufferInfo(GetStdHandle(STD_ERROR_HANDLE), &ci))
            w = ci.srWindow.Right - ci.srWindow.Left + 1;
    }
#endif
    if (w <= 0)
        w = 80;
    ui_w = w - 1;
    if (ui_w > UI_MAXW)
        ui_w = UI_MAXW;
    if (ui_w < 24)
        ui_w = 24;
    ui_live = ui_tty && !quiet;
}

static void ui_write(const char *s, size_t n)
{
    fwrite(s, 1, n, stderr);
    fflush(stderr);
}

/* replace the contents of the status line; the cursor stays at its end */
static void ui_draw(const char *s)
{
    char out[2 * UI_MAXW + 8];
    size_t n = strlen(s), p = 0, pad = 0, i;

    if (n > (size_t)ui_w)
        n = (size_t)ui_w;
    out[p++] = '\r';
    memcpy(out + p, s, n);
    p += n;
    if ((size_t)ui_len > n) {
        pad = (size_t)ui_len - n;
        for (i = 0; i < pad; i++)
            out[p++] = ' ';
        for (i = 0; i < pad; i++)
            out[p++] = '\b';
    }
    ui_len = (int)n;
    ui_write(out, p);
}

static void ui_clear(void)
{
    char out[UI_MAXW + 4];
    size_t n = (size_t)ui_len, p = 0, i;

    if (n == 0)
        return;
    if (n > UI_MAXW)
        n = UI_MAXW;
    out[p++] = '\r';
    for (i = 0; i < n; i++)
        out[p++] = ' ';
    out[p++] = '\r';
    ui_len = 0;
    ui_write(out, p);
}

/* print the final line (clearing whatever was there) and end the line */
static void ui_final(const char *fmt, ...)
{
    char msg[1024];
    va_list ap;
    size_t n;

    va_start(ap, fmt);
    vsnprintf(msg, sizeof msg - 2, fmt, ap);
    va_end(ap);
    ui_clear();
    n = strlen(msg);
    msg[n++] = '\n';
    ui_write(msg, n);
}

/* Print "benc: message", clear the status line and record the exit code. */
static int vfailc(int code, const char *fmt, va_list ap)
{
    char msg[1024];
    int n;

    n = snprintf(msg, sizeof msg - 2, "%s: ", BENC_NAME);
    vsnprintf(msg + n, sizeof msg - 2 - (size_t)n, fmt, ap);
    ui_clear();
    n = (int)strlen(msg);
    msg[n++] = '\n';
    ui_write(msg, (size_t)n);
    g_exit = code;
    return code;
}

/* Failure with an explicit exit code. */
static int failc(int code, const char *fmt, ...)
{
    va_list ap;
    int r;

    va_start(ap, fmt);
    r = vfailc(code, fmt, ap);
    va_end(ap);
    return r;
}

/* Failure with the generic RC_ERR code (kept for internal invariants). */
static int fail(const char *fmt, ...)
{
    va_list ap;
    int r;

    va_start(ap, fmt);
    r = vfailc(RC_ERR, fmt, ap);
    va_end(ap);
    return r;
}

static int failc_errno(int code, const char *what, const char *path)
{
    return failc(code, "%s '%s': %s", what, path, strerror(errno));
}

/* ---- progress bar ------------------------------------------------- */

typedef struct {
    const char   *label;
    uint64_t      total;      /* 0 = unknown */
    uint64_t      done;
    unsigned long t0, last;
    int           bytes;      /* show sizes and speed */
} progress;

static char g_force_spin;

static void progress_draw(const progress *p)
{
    char sizes[48], rate[32], bar[UI_MAXW + 1], line[UI_MAXW * 2];
    char a[24], b[24], pctbuf[8];
    static const char spin[] = { '|', '/', '-', '\\' };
    static unsigned spin_i;
    unsigned long el = benc_now_ms() - p->t0;
    uint64_t bps = (el > 0) ? (p->done * 1000u) / el : 0;
    char sp = g_force_spin ? g_force_spin : spin[spin_i++ & 3u];
    int pct = 0, level, fill, i, bw, fixed;

    pctbuf[0] = '\0';
    if (p->total) {
        pct = (p->done >= p->total) ? 100 : (int)((p->done * 100u) / p->total);
        sprintf(pctbuf, "%3d%%", pct);
    }
    sizes[0] = rate[0] = '\0';
    if (p->bytes) {
        fmt_size(p->done, a);
        if (p->total) {
            fmt_size(p->total, b);
            sprintf(sizes, "%s/%s", a, b);
        } else {
            sprintf(sizes, "%s", a);
        }
        if (bps) {
            fmt_size(bps, a);
            sprintf(rate, "%s/s", a);
        }
    }

    /* layout: "<sp> [<bar>] <pct>% <label> <sizes>  <rate>"
     * drop optional parts (rate, sizes, bar) until the line fits. */
    for (level = 0; level < 4; level++) {
        int use_rate  = level < 1 && rate[0];
        int use_sizes = level < 2 && sizes[0];
        int use_bar   = level < 3 && p->total;

        fixed = 2;  /* spinner + space */
        if (use_bar)
            fixed += 3;  /* " [" + "]" */
        if (pctbuf[0])
            fixed += (int)strlen(pctbuf) + 1;
        fixed += (int)strlen(p->label);
        if (use_sizes)
            fixed += 1 + (int)strlen(sizes);
        if (use_rate)
            fixed += 2 + (int)strlen(rate);
        bw = ui_w - fixed;

        if (use_bar) {
            if (bw < 10)
                continue;
            if (bw > 24)
                bw = 24;
            fill = (pct * bw) / 100;
            for (i = 0; i < bw; i++)
                bar[i] = (i < fill) ? '=' : ' ';
            if (fill > 0)
                bar[fill - 1] = '>';
            bar[bw] = '\0';
        } else if (fixed > ui_w && level < 3) {
            continue;
        }

        sprintf(line, "%c ", sp);
        if (use_bar)
            sprintf(line + strlen(line), "[%s] ", bar);
        if (pctbuf[0])
            sprintf(line + strlen(line), "%s ", pctbuf);
        sprintf(line + strlen(line), "%s", p->label);
        if (use_sizes)
            sprintf(line + strlen(line), " %s", sizes);
        if (use_rate)
            sprintf(line + strlen(line), "  %s", rate);
        break;
    }
    ui_draw(line);
}

/* finalize the current live line: keep it visible and move to a fresh row.
 * does not erase the line, so completed phases stay on screen. */
static void progress_end(void)
{
    if (!ui_live || ui_len == 0)
        return;
    ui_write("\n", 1);
    ui_len = 0;
}

/* force the bar to its final state (100% when the total is known) and then
 * end the line, leaving the completed bar visible above the next message. */
static void progress_finish(progress *p)
{
    if (!ui_live)
        return;
    if (p->total && p->done < p->total)
        p->done = p->total;
    g_force_spin = '-';
    progress_draw(p);
    g_force_spin = 0;
    progress_end();
}

static void progress_begin(progress *p, const char *label, uint64_t total,
                           int bytes)
{
    progress_end();
    p->label = label;
    p->total = total;
    p->done = 0;
    p->bytes = bytes;
    p->t0 = p->last = benc_now_ms();
    if (ui_live)
        progress_draw(p);
}

static void progress_set(progress *p, uint64_t done)
{
    unsigned long t;

    p->done = done;
    if (!ui_live)
        return;
    t = benc_now_ms();
    if (t - p->last < BENC_PROGRESS_MS)
        return;
    p->last = t;
    progress_draw(p);
}

/* ------------------------------------------------------------------ */
/* SHA-256, HMAC-SHA256, PBKDF2                                        */
/* ------------------------------------------------------------------ */

static const uint32_t sha256_k[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu,
    0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u, 0xd807aa98u, 0x12835b01u,
    0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u,
    0xc19bf174u, 0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau, 0x983e5152u,
    0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u,
    0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu,
    0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u,
    0xd6990624u, 0xf40e3585u, 0x106aa070u, 0x19a4c116u, 0x1e376c08u,
    0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu,
    0x682e6ff3u, 0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

static const uint32_t sha256_iv[8] = {
    0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
    0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u
};

#define ROR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define SH_CH(x, y, z)  ((z) ^ ((x) & ((y) ^ (z))))
#define SH_MAJ(x, y, z) (((x) & (y)) | ((z) & ((x) | (y))))
#define SH_S0(x) (ROR32(x, 2) ^ ROR32(x, 13) ^ ROR32(x, 22))
#define SH_S1(x) (ROR32(x, 6) ^ ROR32(x, 11) ^ ROR32(x, 25))
#define SH_s0(x) (ROR32(x, 7) ^ ROR32(x, 18) ^ ((x) >> 3))
#define SH_s1(x) (ROR32(x, 17) ^ ROR32(x, 19) ^ ((x) >> 10))

#define SH_RND(a, b, c, d, e, f, g, h, i)                               \
    do {                                                                 \
        uint32_t t1_ = (h) + SH_S1(e) + SH_CH(e, f, g) + sha256_k[i] + w[i]; \
        uint32_t t2_ = SH_S0(a) + SH_MAJ(a, b, c);                       \
        (d) += t1_;                                                      \
        (h) = t1_ + t2_;                                                 \
    } while (0)

/* one compression; blk holds the 16 big-endian message words */
static void sha256_core(uint32_t st[8], const uint32_t blk[16])
{
    uint32_t w[64];
    uint32_t a, b, c, d, e, f, g, h;
    int i;

    for (i = 0; i < 16; i++)
        w[i] = blk[i];
    for (i = 16; i < 64; i++)
        w[i] = SH_s1(w[i - 2]) + w[i - 7] + SH_s0(w[i - 15]) + w[i - 16];

    a = st[0]; b = st[1]; c = st[2]; d = st[3];
    e = st[4]; f = st[5]; g = st[6]; h = st[7];
    for (i = 0; i < 64; i += 8) {
        SH_RND(a, b, c, d, e, f, g, h, i);
        SH_RND(h, a, b, c, d, e, f, g, i + 1);
        SH_RND(g, h, a, b, c, d, e, f, i + 2);
        SH_RND(f, g, h, a, b, c, d, e, i + 3);
        SH_RND(e, f, g, h, a, b, c, d, i + 4);
        SH_RND(d, e, f, g, h, a, b, c, i + 5);
        SH_RND(c, d, e, f, g, h, a, b, i + 6);
        SH_RND(b, c, d, e, f, g, h, a, i + 7);
    }
    st[0] += a; st[1] += b; st[2] += c; st[3] += d;
    st[4] += e; st[5] += f; st[6] += g; st[7] += h;
    benc_wipe(w, sizeof w);
}

static uint32_t be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void put_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static void sha256_block(uint32_t st[8], const uint8_t *p)
{
    uint32_t blk[16];
    int i;

    for (i = 0; i < 16; i++)
        blk[i] = be32(p + 4 * i);
    sha256_core(st, blk);
}

typedef struct {
    uint32_t h[8];
    uint64_t total;
    uint8_t  buf[64];
    size_t   blen;
} sha256_ctx;

static void sha256_init(sha256_ctx *c)
{
    memcpy(c->h, sha256_iv, sizeof c->h);
    c->total = 0;
    c->blen = 0;
}

static void sha256_update(sha256_ctx *c, const void *data, size_t len)
{
    const uint8_t *p = (const uint8_t *)data;

    c->total += len;
    if (c->blen) {
        size_t take = 64 - c->blen;
        if (take > len)
            take = len;
        memcpy(c->buf + c->blen, p, take);
        c->blen += take;
        p += take;
        len -= take;
        if (c->blen < 64)
            return;
        sha256_block(c->h, c->buf);
        c->blen = 0;
    }
    while (len >= 64) {
        sha256_block(c->h, p);
        p += 64;
        len -= 64;
    }
    if (len) {
        memcpy(c->buf, p, len);
        c->blen = len;
    }
}

static void sha256_final(sha256_ctx *c, uint8_t out[32])
{
    uint64_t bits = c->total * 8u;
    int i;

    c->buf[c->blen++] = 0x80;
    if (c->blen > 56) {
        memset(c->buf + c->blen, 0, 64 - c->blen);
        sha256_block(c->h, c->buf);
        c->blen = 0;
    }
    memset(c->buf + c->blen, 0, 56 - c->blen);
    for (i = 0; i < 8; i++)
        c->buf[56 + i] = (uint8_t)(bits >> (56 - 8 * i));
    sha256_block(c->h, c->buf);
    for (i = 0; i < 8; i++)
        put_be32(out + 4 * i, c->h[i]);
    benc_wipe(c, sizeof *c);
}

/* HMAC with both key-schedule states precomputed */
typedef struct {
    sha256_ctx in;
    uint32_t   ost[8];
} hmac_ctx;

static void hmac_init(hmac_ctx *h, const uint8_t *key, size_t keylen)
{
    uint8_t k[64], pad[64];
    size_t i;

    memset(k, 0, sizeof k);
    if (keylen > 64) {
        sha256_ctx t;
        sha256_init(&t);
        sha256_update(&t, key, keylen);
        sha256_final(&t, k);
    } else if (keylen) {
        memcpy(k, key, keylen);
    }
    for (i = 0; i < 64; i++)
        pad[i] = (uint8_t)(k[i] ^ 0x36);
    sha256_init(&h->in);
    sha256_update(&h->in, pad, 64);
    for (i = 0; i < 64; i++)
        pad[i] = (uint8_t)(k[i] ^ 0x5c);
    memcpy(h->ost, sha256_iv, sizeof h->ost);
    sha256_block(h->ost, pad);
    benc_wipe(k, sizeof k);
    benc_wipe(pad, sizeof pad);
}

static void hmac_update(hmac_ctx *h, const void *data, size_t len)
{
    sha256_update(&h->in, data, len);
}

static void hmac_final(hmac_ctx *h, uint8_t out[32])
{
    uint8_t ih[32];
    sha256_ctx o;

    sha256_final(&h->in, ih);
    memcpy(o.h, h->ost, sizeof o.h);
    o.total = 64;
    o.blen = 0;
    sha256_update(&o, ih, 32);
    sha256_final(&o, out);
    benc_wipe(ih, sizeof ih);
    benc_wipe(h, sizeof *h);
}

/* PBKDF2-HMAC-SHA256.  The per-iteration work is exactly two compression
 * calls on word arrays: no contexts, no byte conversion, no padding code. */
static void pbkdf2_sha256(const uint8_t *pw, size_t pwlen,
                          const uint8_t *salt, size_t saltlen,
                          unsigned long iters, uint8_t *out, size_t outlen,
                          progress *pg)
{
    hmac_ctx base, h;
    uint32_t blk[16], u[8], t[8], st[8];
    uint8_t  tmp[32], ctr[4];
    uint64_t total = (uint64_t)iters * ((outlen + 31) / 32), done = 0;
    uint32_t block = 1;
    size_t off = 0;
    int k;

    hmac_init(&base, pw, pwlen);
    if (pg)
        pg->total = total;

    while (off < outlen) {
        unsigned long it;
        size_t take = outlen - off;

        put_be32(ctr, block);
        h = base;
        hmac_update(&h, salt, saltlen);
        hmac_update(&h, ctr, 4);
        hmac_final(&h, tmp);
        for (k = 0; k < 8; k++)
            t[k] = u[k] = be32(tmp + 4 * k);

        for (k = 8; k < 15; k++)
            blk[k] = 0;
        blk[8] = 0x80000000u;
        blk[15] = (64u + 32u) * 8u;

        for (it = 1; it < iters; it++) {
            memcpy(blk, u, 32);
            memcpy(st, base.in.h, 32);
            sha256_core(st, blk);
            memcpy(blk, st, 32);
            memcpy(st, base.ost, 32);
            sha256_core(st, blk);
            for (k = 0; k < 8; k++) {
                u[k] = st[k];
                t[k] ^= st[k];
            }
            if (pg && (it & 127u) == 0)
                progress_set(pg, done + it);
        }
        done += iters;

        for (k = 0; k < 8; k++)
            put_be32(tmp + 4 * k, t[k]);
        if (take > 32)
            take = 32;
        memcpy(out + off, tmp, take);
        off += take;
        block++;
    }
    benc_wipe(&base, sizeof base);
    benc_wipe(&h, sizeof h);
    benc_wipe(blk, sizeof blk);
    benc_wipe(u, sizeof u);
    benc_wipe(t, sizeof t);
    benc_wipe(st, sizeof st);
    benc_wipe(tmp, sizeof tmp);
}

/* HKDF-SHA256 (RFC 5869).  Extract+Expand in one call:
 *   prk   = HMAC-SHA256(salt, ikm)
 *   okm   = HKDF-Expand(prk, info, okm_len)
 *
 * Returns 0 on success, -1 if okm_len > 255 * BENC_KEY_LEN.
 */
static int hkdf_sha256(const uint8_t *ikm, size_t ikm_len,
                       const uint8_t *salt, size_t salt_len,
                       const uint8_t *info, size_t info_len,
                       uint8_t *okm, size_t okm_len)
{
    hmac_ctx base;
    uint8_t prk[BENC_KEY_LEN];
    uint8_t t[BENC_KEY_LEN];
    size_t off = 0;
    uint8_t counter = 1;

    if (okm_len > 255 * BENC_KEY_LEN)
        return -1;

    /* Extract: prk = HMAC-SHA256(salt, ikm) */
    hmac_init(&base, salt, salt_len);
    hmac_update(&base, ikm, ikm_len);
    hmac_final(&base, prk);

    /* Expand: OKM = T(1) || T(2) || ... where
     *   T(i) = HMAC-SHA256(prk, T(i-1) || info || INT(i)) */
    while (off < okm_len) {
        hmac_ctx h;
        size_t take;

        hmac_init(&h, prk, BENC_KEY_LEN);
        if (off > 0)
            hmac_update(&h, t, BENC_KEY_LEN);
        hmac_update(&h, info, info_len);
        hmac_update(&h, &counter, 1);
        hmac_final(&h, t);

        take = okm_len - off;
        if (take > BENC_KEY_LEN)
            take = BENC_KEY_LEN;
        memcpy(okm + off, t, take);
        off += take;
        counter++;
    }

    benc_wipe(prk, sizeof prk);
    benc_wipe(t, sizeof t);
    benc_wipe(&base, sizeof base);
    return 0;
}

static int ct_equal(const uint8_t *a, const uint8_t *b, size_t n)
{
    uint8_t d = 0;
    size_t i;

    for (i = 0; i < n; i++)
        d |= (uint8_t)(a[i] ^ b[i]);
    return d == 0;
}

/* ------------------------------------------------------------------ */
/* ChaCha20                                                            */
/* ------------------------------------------------------------------ */

#define ROTL32(v, n) (((v) << (n)) | ((v) >> (32 - (n))))
#define QR(a, b, c, d)                                  \
    do {                                                \
        a += b; d ^= a; d = ROTL32(d, 16);              \
        c += d; b ^= c; b = ROTL32(b, 12);              \
        a += b; d ^= a; d = ROTL32(d, 8);               \
        c += d; b ^= c; b = ROTL32(b, 7);               \
    } while (0)

static uint32_t le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void put_le32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static void chacha20_block(uint32_t out[16], const uint32_t in[16])
{
    uint32_t x0 = in[0], x1 = in[1], x2 = in[2], x3 = in[3];
    uint32_t x4 = in[4], x5 = in[5], x6 = in[6], x7 = in[7];
    uint32_t x8 = in[8], x9 = in[9], x10 = in[10], x11 = in[11];
    uint32_t x12 = in[12], x13 = in[13], x14 = in[14], x15 = in[15];
    int i;

    for (i = 0; i < 10; i++) {
        QR(x0, x4, x8,  x12);
        QR(x1, x5, x9,  x13);
        QR(x2, x6, x10, x14);
        QR(x3, x7, x11, x15);
        QR(x0, x5, x10, x15);
        QR(x1, x6, x11, x12);
        QR(x2, x7, x8,  x13);
        QR(x3, x4, x9,  x14);
    }
    out[0] = x0 + in[0];   out[1] = x1 + in[1];   out[2] = x2 + in[2];
    out[3] = x3 + in[3];   out[4] = x4 + in[4];   out[5] = x5 + in[5];
    out[6] = x6 + in[6];   out[7] = x7 + in[7];   out[8] = x8 + in[8];
    out[9] = x9 + in[9];   out[10] = x10 + in[10]; out[11] = x11 + in[11];
    out[12] = x12 + in[12]; out[13] = x13 + in[13]; out[14] = x14 + in[14];
    out[15] = x15 + in[15];
}

typedef struct {
    uint32_t st[16];
    uint8_t  ks[64];
    size_t   pos;            /* 64 = keystream buffer empty */
} chacha20_ctx;

static void chacha20_init(chacha20_ctx *c, const uint8_t key[32],
                          const uint8_t nonce[8])
{
    int i;

    c->st[0] = 0x61707865u; c->st[1] = 0x3320646eu;
    c->st[2] = 0x79622d32u; c->st[3] = 0x6b206574u;
    for (i = 0; i < 8; i++)
        c->st[4 + i] = le32(key + 4 * i);
    c->st[12] = 0;
    c->st[13] = 0;
    c->st[14] = le32(nonce);
    c->st[15] = le32(nonce + 4);
    c->pos = 64;
}

static void chacha20_advance(chacha20_ctx *c)
{
    if (++c->st[12] == 0)
        ++c->st[13];
}

static void chacha20_xor(chacha20_ctx *c, uint8_t *d, size_t n)
{
    uint32_t x[16];
    int i;

    while (n && c->pos < 64) {
        *d++ ^= c->ks[c->pos++];
        n--;
    }
    while (n >= 64) {
        chacha20_block(x, c->st);
        chacha20_advance(c);
        {
            uint32_t block[16];
            memcpy(block, d, 64);
            for (i = 0; i < 16; i++)
                block[i] ^= x[i];
            memcpy(d, block, 64);
        }
        d += 64;
        n -= 64;
    }
    if (n) {
        chacha20_block(x, c->st);
        chacha20_advance(c);
        for (i = 0; i < 16; i++)
            put_le32(c->ks + 4 * i, x[i]);
        c->pos = 0;
        while (n--)
            *d++ ^= c->ks[c->pos++];
    }
    benc_wipe(x, sizeof x);
}

/* ------------------------------------------------------------------ */
/* base64                                                              */
/* ------------------------------------------------------------------ */

static const char b64_alpha[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* >= 0 value, -1 invalid, -2 whitespace, -3 '=' */
static signed char b64_tbl[256];

static void b64_init(void)
{
    int i;

    if (b64_tbl[(unsigned char)'A'] == 0 && b64_tbl[(unsigned char)'B'] == 1)
        return;
    for (i = 0; i < 256; i++)
        b64_tbl[i] = -1;
    for (i = 0; i < 64; i++)
        b64_tbl[(unsigned char)b64_alpha[i]] = (signed char)i;
    b64_tbl[' '] = b64_tbl['\t'] = b64_tbl['\r'] = b64_tbl['\n'] = -2;
    b64_tbl['\v'] = b64_tbl['\f'] = -2;
    b64_tbl['='] = -3;
}

/* one 3 byte group -> 4 characters */
#define B64_GROUP(dst, s)                                               \
    do {                                                                \
        uint32_t v_ = ((uint32_t)(s)[0] << 16) | ((uint32_t)(s)[1] << 8) | \
                      (uint32_t)(s)[2];                                 \
        (dst)[0] = b64_alpha[(v_ >> 18) & 63];                          \
        (dst)[1] = b64_alpha[(v_ >> 12) & 63];                          \
        (dst)[2] = b64_alpha[(v_ >> 6) & 63];                           \
        (dst)[3] = b64_alpha[v_ & 63];                                  \
    } while (0)

/* encode to one string without newline; returns 0 or -1 if cap is too small */
static int b64_encode_string(const uint8_t *d, size_t n, char *out, size_t cap)
{
    size_t i = 0, o = 0;

    if (cap < 4 * ((n + 2) / 3) + 1)
        return -1;
    for (; i + 3 <= n; i += 3, o += 4)
        B64_GROUP(out + o, d + i);
    if (n - i == 1) {
        uint8_t t[3];
        t[0] = d[i]; t[1] = 0; t[2] = 0;
        B64_GROUP(out + o, t);
        out[o + 2] = out[o + 3] = '=';
        o += 4;
    } else if (n - i == 2) {
        uint8_t t[3];
        t[0] = d[i]; t[1] = d[i + 1]; t[2] = 0;
        B64_GROUP(out + o, t);
        out[o + 3] = '=';
        o += 4;
    }
    out[o] = '\0';
    return 0;
}

/* ---- line wrapping encoder writing to a FILE ---------------------- */

typedef struct {
    FILE    *fp;
    uint8_t  carry[BENC_B64_BLOCK];
    size_t   cn;
    char    *ob;
    size_t   ob_blocks;
    int      err;
} b64_w;

static int b64_w_init(b64_w *w, FILE *fp)
{
    memset(w, 0, sizeof *w);
    w->fp = fp;
    w->ob_blocks = BENC_CHUNK / BENC_B64_BLOCK + 2;
    w->ob = (char *)malloc(w->ob_blocks * (BENC_B64_COLS + 1));
    return w->ob ? 0 : -1;
}

static void b64_w_blocks(b64_w *w, const uint8_t *src, size_t nblocks)
{
    while (nblocks && !w->err) {
        size_t m = nblocks < w->ob_blocks ? nblocks : w->ob_blocks;
        char *o = w->ob;
        size_t b, j;

        for (b = 0; b < m; b++, src += BENC_B64_BLOCK) {
            for (j = 0; j < BENC_B64_BLOCK; j += 3, o += 4)
                B64_GROUP(o, src + j);
            *o++ = '\n';
        }
        if (fwrite(w->ob, 1, (size_t)(o - w->ob), w->fp) != (size_t)(o - w->ob))
            w->err = 1;
        nblocks -= m;
    }
}

static int b64_w_put(b64_w *w, const uint8_t *d, size_t n)
{
    if (w->cn) {
        size_t take = BENC_B64_BLOCK - w->cn;
        if (take > n)
            take = n;
        memcpy(w->carry + w->cn, d, take);
        w->cn += take;
        d += take;
        n -= take;
        if (w->cn == BENC_B64_BLOCK) {
            b64_w_blocks(w, w->carry, 1);
            w->cn = 0;
        }
    }
    if (n >= BENC_B64_BLOCK) {
        size_t nb = n / BENC_B64_BLOCK;
        b64_w_blocks(w, d, nb);
        d += nb * BENC_B64_BLOCK;
        n -= nb * BENC_B64_BLOCK;
    }
    if (n) {
        memcpy(w->carry, d, n);
        w->cn = n;
    }
    return w->err ? -1 : 0;
}

static int b64_w_close(b64_w *w)
{
    if (w->cn && !w->err) {
        char line[BENC_B64_COLS + 2];
        size_t m;

        b64_encode_string(w->carry, w->cn, line, sizeof line);
        m = strlen(line);
        line[m++] = '\n';
        if (fwrite(line, 1, m, w->fp) != m)
            w->err = 1;
        w->cn = 0;
    }
    free(w->ob);
    w->ob = NULL;
    return w->err ? -1 : 0;
}

/* ---- streaming decoder -------------------------------------------- */

typedef int (*b64_sink)(void *ctx, uint8_t *data, size_t len);

typedef struct {
    b64_sink sink;
    void    *ctx;
    uint32_t acc;
    int      n;              /* sextets in acc */
    int      pad;            /* 0 none, 1 one '=' after 2 sextets, 2 done */
    uint8_t  obuf[BENC_OBUF];
    size_t   olen;
} b64_dec;

static int b64_dec_flush(b64_dec *d)
{
    int r = 0;

    if (d->olen) {
        r = d->sink(d->ctx, d->obuf, d->olen);
        d->olen = 0;
    }
    return r;
}

static int b64_dec_feed(b64_dec *d, const uint8_t *s, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++) {
        int v = b64_tbl[s[i]];

        if (v >= 0) {
            if (d->pad)
                return -1;
            d->acc = (d->acc << 6) | (uint32_t)v;
            if (++d->n == 4) {
                if (d->olen + 3 > sizeof d->obuf && b64_dec_flush(d))
                    return -1;
                d->obuf[d->olen++] = (uint8_t)(d->acc >> 16);
                d->obuf[d->olen++] = (uint8_t)(d->acc >> 8);
                d->obuf[d->olen++] = (uint8_t)d->acc;
                d->n = 0;
                d->acc = 0;
            }
        } else if (v == -2) {
            continue;
        } else if (v == -3) {
            if (d->n == 2 && d->pad == 0) {
                d->pad = 1;
            } else if (d->n == 2 && d->pad == 1) {
                if (d->olen + 1 > sizeof d->obuf && b64_dec_flush(d))
                    return -1;
                d->obuf[d->olen++] = (uint8_t)(d->acc >> 4);
                d->pad = 2;
                d->n = 0;
            } else if (d->n == 3 && d->pad == 0) {
                if (d->olen + 2 > sizeof d->obuf && b64_dec_flush(d))
                    return -1;
                d->obuf[d->olen++] = (uint8_t)(d->acc >> 10);
                d->obuf[d->olen++] = (uint8_t)(d->acc >> 2);
                d->pad = 2;
                d->n = 0;
            } else {
                return -1;
            }
        } else {
            return -1;
        }
    }
    return 0;
}

static int b64_dec_finish(b64_dec *d)
{
    if (d->n != 0 || d->pad == 1)
        return -1;
    return b64_dec_flush(d);
}

/* decode a short string (header fields) */
static int b64_decode(const char *s, uint8_t *out, size_t cap, size_t *outlen)
{
    b64_dec *d;
    size_t len = strlen(s);
    int r = -1;

    /* the decoder buffers into obuf, so a short field must fit there whole */
    if (len > 4 * BENC_MAX_NAME)
        return -1;
    d = (b64_dec *)calloc(1, sizeof *d);
    if (!d)
        return -1;
    /* decode into d->obuf only; no sink needed for short input */
    if (b64_dec_feed(d, (const uint8_t *)s, len) == 0 &&
        d->n == 0 && d->pad != 1 && d->olen <= cap) {
        memcpy(out, d->obuf, d->olen);
        *outlen = d->olen;
        r = 0;
    }
    free(d);
    return r;
}

/* ------------------------------------------------------------------ */
/* random bytes                                                        */
/* ------------------------------------------------------------------ */

static int benc_random_weak;

#if !BENC_WINDOWS && !BENC_POSIX

/* DOS and other targets without an OS entropy source: a SHA-256 pool fed
 * with timers, addresses and (see entropy_event) the timing of every
 * key press while the password is typed. */
static uint8_t       pool[32];
static unsigned long pool_ctr;

static void pool_mix(const void *p, size_t n)
{
    sha256_ctx c;

    sha256_init(&c);
    sha256_update(&c, pool, sizeof pool);
    sha256_update(&c, p, n);
    sha256_final(&c, pool);
}

#if defined(__GNUC__) && (defined(__i386__) || defined(__ia16__)) && \
    !defined(BENC_NO_PIT)
static unsigned pit_read(void)
{
    unsigned char lo, hi;

    __asm__ volatile ("outb %%al, $0x43" : : "a"((unsigned char)0));
    __asm__ volatile ("inb $0x40, %%al\n\tmovb %%al, %0" : "=m"(lo) : : "al");
    __asm__ volatile ("inb $0x40, %%al\n\tmovb %%al, %0" : "=m"(hi) : : "al");
    return ((unsigned)hi << 8) | lo;
}
#else
static unsigned pit_read(void) { return 0; }
#endif

static void entropy_event(void)
{
    unsigned long s[5];

    s[0] = (unsigned long)clock();
    s[1] = (unsigned long)time(NULL);
    s[2] = (unsigned long)pit_read();
#if defined(__DJGPP__)
    s[3] = (unsigned long)uclock();
#else
    s[3] = 0;
#endif
    s[4] = ++pool_ctr;
    pool_mix(s, sizeof s);
}
#else
static void entropy_event(void) { }
#endif

int benc_random(uint8_t *buf, size_t len)
{
#if BENC_WINDOWS
    typedef BOOLEAN (WINAPI *rtlgenrandom_fn)(PVOID, ULONG);
    static rtlgenrandom_fn fn;
    static int tried;

    if (!tried) {
        HMODULE m = LoadLibraryA("advapi32.dll");
        if (m)
            fn = (rtlgenrandom_fn)(void *)GetProcAddress(m, "SystemFunction036");
        tried = 1;
    }
    if (!fn)
        return -1;
    while (len) {
        ULONG n = len > 65536u ? 65536u : (ULONG)len;
        if (!fn(buf, n))
            return -1;
        buf += n;
        len -= n;
    }
    return 0;
#elif BENC_POSIX
    FILE *fp = fopen("/dev/urandom", "rb");
    size_t got;

    if (!fp)
        return -1;
    got = fread(buf, 1, len, fp);
    fclose(fp);
    return got == len ? 0 : -1;
#else
    size_t off = 0;
    int i;

    for (i = 0; i < 8; i++)
        entropy_event();
    while (off < len) {
        sha256_ctx c;
        uint8_t blk[32];
        size_t take = len - off > 32 ? 32 : len - off;

        sha256_init(&c);
        sha256_update(&c, pool, sizeof pool);
        sha256_update(&c, &pool_ctr, sizeof pool_ctr);
        sha256_final(&c, blk);
        pool_ctr++;
        memcpy(buf + off, blk, take);
        off += take;
        entropy_event();
    }
    benc_random_weak = 1;
    return 0;
#endif
}

/* ------------------------------------------------------------------ */
/* container header                                                    */
/* ------------------------------------------------------------------ */

typedef struct {
    unsigned version;
    unsigned long iterations;
    uint8_t  salt[BENC_SALT_LEN];
    uint8_t  nonce[BENC_NONCE_LEN];
    char     name[BENC_MAX_NAME + 1];
    size_t   name_len;
    uint64_t size;          /* bytes fed to the cipher (after compression) */
    int      size_known;
    int      comp;          /* COMP_* */
    int      level;
    int      threads;
    int      archive;       /* payload is a tar archive of a directory */
    /* Post-quantum fields (container format v5+) */
    int      mode;          /* 0=password, 1=pq-only, 2=hybrid */
    int      kem_alg;       /* 0=none, 1=ml-kem-768 */
    uint8_t  kem_pub_key[BENC_KEM_PUBLIC_KEY_LEN];
    size_t   kem_pub_key_len;
    uint8_t  kem_ct[BENC_KEM_CIPHERTEXT_LEN];
    size_t   kem_ct_len;
} benc_header;

typedef struct {
    char salt[32], nonce[16], name[4 * ((BENC_MAX_NAME + 2) / 3) + 8];
    char iters[24], size[24], level[16], threads[16], input[8];
    char mode[16], kem[32];
    char kem_pub_key[4 * ((BENC_KEM_PUBLIC_KEY_LEN + 2) / 3) + 8];
    char kem_ct[4 * ((BENC_KEM_CIPHERTEXT_LEN + 2) / 3) + 8];
} hdr_text;

static int header_encode(const benc_header *h, hdr_text *t)
{
    if (b64_encode_string(h->salt, BENC_SALT_LEN, t->salt, sizeof t->salt) ||
        b64_encode_string(h->nonce, BENC_NONCE_LEN, t->nonce, sizeof t->nonce) ||
        b64_encode_string((const uint8_t *)h->name, h->name_len, t->name,
                          sizeof t->name))
        return -1;
    u64_to_dec((uint64_t)h->iterations, t->iters);
    u64_to_dec((uint64_t)(h->level < 0 ? 0 : h->level), t->level);
    u64_to_dec((uint64_t)(h->threads < 0 ? 0 : h->threads), t->threads);
    strcpy(t->input, h->archive ? "tar" : "file");
    if (h->mode == 0)
        strcpy(t->mode, "password");
    else if (h->mode == 1)
        strcpy(t->mode, "pq");
    else
        strcpy(t->mode, "hybrid");
    if (h->kem_alg == 1)
        strcpy(t->kem, "ml-kem-768");
    else
        strcpy(t->kem, "none");
    if (h->kem_pub_key_len > 0)
        b64_encode_string(h->kem_pub_key, h->kem_pub_key_len, t->kem_pub_key,
                          sizeof t->kem_pub_key);
    else
        t->kem_pub_key[0] = '\0';
    if (h->kem_ct_len > 0)
        b64_encode_string(h->kem_ct, h->kem_ct_len, t->kem_ct,
                          sizeof t->kem_ct);
    else
        t->kem_ct[0] = '\0';
    if (h->size_known)
        u64_to_dec(h->size, t->size);
    else
        strcpy(t->size, "-");
    return 0;
}

/* the exact byte string covered by the MAC in front of the ciphertext */
static int header_canonical(const benc_header *h, char *out, size_t cap)
{
    hdr_text t;
    int r;

    if (header_encode(h, &t))
        return -1;
    if (h->version <= BENC_FMT_LEGACY)
        r = snprintf(out, cap, "benc|%u|%s|%s|%s|%s|%s|%s\n",
                     BENC_FMT_LEGACY, BENC_KDF_NAME, t.iters, t.salt, t.nonce,
                     t.name, t.size);
    else if (h->version == BENC_FMT_V4)
        r = snprintf(out, cap,
                     "benc|%u|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s\n",
                     h->version, BENC_KDF_NAME, t.iters, BENC_CIPHER_NAME,
                     BENC_MAC_NAME, comp_specs[h->comp].name, t.level,
                     t.threads, t.input, t.salt, t.nonce, t.name, t.size);
    else
        r = snprintf(out, cap,
                     "benc|%u|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s\n",
                     h->version, BENC_KDF_NAME, t.iters, BENC_CIPHER_NAME,
                     BENC_MAC_NAME, comp_specs[h->comp].name, t.level,
                     t.threads, t.input, t.salt, t.nonce, t.name, t.size,
                     t.mode, t.kem, t.kem_pub_key, t.kem_ct);
    return (r < 0 || (size_t)r >= cap) ? -1 : 0;
}

static int write_header(FILE *fp, const benc_header *h)
{
    hdr_text t;

    if (header_encode(h, &t))
        return -1;
    if (h->version <= BENC_FMT_LEGACY)
        return fprintf(fp,
                       "%s\nVersion: %u\nKDF: %s\nIterations: %s\nCipher: %s\n"
                       "MAC: %s\nSalt: %s\nNonce: %s\nName: %s\nSize: %s\n%s\n",
                       BENC_BEGIN_FILE, BENC_FMT_LEGACY, BENC_KDF_NAME, t.iters,
                       BENC_CIPHER_NAME, BENC_MAC_NAME, t.salt, t.nonce, t.name,
                       t.size, BENC_BEGIN_DATA) < 0 ? -1 : 0;
    if (h->version == BENC_FMT_V4)
        return fprintf(fp,
                   "%s\nVersion: %u\nKDF: %s\nIterations: %s\nCipher: %s\n"
                   "MAC: %s\nCompression: %s\nCompression-Level: %s\n"
                   "Compression-Threads: %s\nInput: %s\nSalt: %s\nNonce: %s\n"
                   "Name: %s\nSize: %s\n%s\n",
                   BENC_BEGIN_FILE, h->version, BENC_KDF_NAME, t.iters,
                   BENC_CIPHER_NAME, BENC_MAC_NAME, comp_specs[h->comp].name,
                   t.level, t.threads, t.input, t.salt, t.nonce, t.name,
                   t.size, BENC_BEGIN_DATA) < 0 ? -1 : 0;
    return fprintf(fp,
                   "%s\nVersion: %u\nKDF: %s\nIterations: %s\nCipher: %s\n"
                   "MAC: %s\nCompression: %s\nCompression-Level: %s\n"
                   "Compression-Threads: %s\nInput: %s\nMode: %s\nKEM: %s\n"
                   "KEM-Public-Key: %s\nKEM-Ciphertext: %s\n"
                   "Salt: %s\nNonce: %s\nName: %s\nSize: %s\n%s\n",
                   BENC_BEGIN_FILE, h->version, BENC_KDF_NAME, t.iters,
                   BENC_CIPHER_NAME, BENC_MAC_NAME, comp_specs[h->comp].name,
                   t.level, t.threads, t.input, t.mode, t.kem,
                   t.kem_pub_key, t.kem_ct,
                   t.salt, t.nonce, t.name, t.size,
                   BENC_BEGIN_DATA) < 0 ? -1 : 0;
}

/* Base64 is case sensitive and its last character may carry unused bits.
 * Re-encoding proves the text is the only spelling of those bytes, so no
 * header byte can change without changing the authenticated header. */
static int b64_is_canonical(const char *text, const uint8_t *raw, size_t n)
{
    char buf[4 * ((BENC_MAX_NAME + 2) / 3) + 8];

    if (n > BENC_MAX_NAME)
        return 0;
    if (b64_encode_string(raw, n, buf, sizeof buf))
        return 0;
    return strcmp(buf, text) == 0;
}

/* 1 = line read, 0 = clean EOF, -2 = line too long */
static int read_line(FILE *fp, char *buf, size_t cap)
{
    size_t n;

    if (!fgets(buf, (int)cap, fp))
        return 0;
    n = strlen(buf);
    if (n && buf[n - 1] == '\n') {
        buf[--n] = '\0';
    } else if (n + 1 >= cap) {
        int ch;
        while ((ch = fgetc(fp)) != EOF && ch != '\n')
            ;
        return -2;
    }
    while (n && buf[n - 1] == '\r')
        buf[--n] = '\0';
    return 1;
}

#define SEEN_VERSION    (1UL << 0)
#define SEEN_KDF        (1UL << 1)
#define SEEN_ITER       (1UL << 2)
#define SEEN_CIPHER     (1UL << 3)
#define SEEN_MAC        (1UL << 4)
#define SEEN_SALT       (1UL << 5)
#define SEEN_NONCE      (1UL << 6)
#define SEEN_NAME       (1UL << 7)
#define SEEN_SIZE       (1UL << 8)
#define SEEN_COMP       (1UL << 9)
#define SEEN_LEVEL      (1UL << 10)
#define SEEN_THREADS    (1UL << 11)
#define SEEN_INPUT      (1UL << 12)
#define SEEN_MODE       (1UL << 13)
#define SEEN_KEM         (1UL << 14)
#define SEEN_KEM_PUB_KEY (1UL << 15)
#define SEEN_KEM_CT      (1UL << 16)
#define SEEN_REQUIRED    (SEEN_VERSION | SEEN_KDF | SEEN_ITER | SEEN_CIPHER | \
                          SEEN_MAC | SEEN_SALT | SEEN_NONCE)
#define SEEN_V4_REQUIRED (SEEN_COMP | SEEN_LEVEL | SEEN_THREADS | SEEN_INPUT)
#define SEEN_V5_REQUIRED (SEEN_REQUIRED | SEEN_MODE)

/* on success the stream is positioned at the first line of the body */
static int parse_header(FILE *fp, benc_header *h)
{
    char line[8192];
    unsigned long seen = 0;
    uint64_t v;
    int r;

    memset(h, 0, sizeof *h);
    r = read_line(fp, line, sizeof line);
    if (r != 1 || strcmp(line, BENC_BEGIN_FILE) != 0)
        return failc(RC_FORMAT, "not a benc file (missing begin marker)");

    for (;;) {
        char *colon, *key, *val;
        unsigned long bit;

        r = read_line(fp, line, sizeof line);
        if (r == 0)
            return failc(RC_FORMAT, "unexpected end of file inside header");
        if (r < 0)
            return failc(RC_FORMAT, "header line too long");
        if (strcmp(line, BENC_BEGIN_DATA) == 0)
            break;
        colon = strchr(line, ':');
        if (!colon)
            return failc(RC_FORMAT, "malformed header line");
        *colon = '\0';
        key = str_trim(line);
        val = str_trim(colon + 1);

        if      (strcmp(key, "Version") == 0)    bit = SEEN_VERSION;
        else if (strcmp(key, "KDF") == 0)        bit = SEEN_KDF;
        else if (strcmp(key, "Iterations") == 0) bit = SEEN_ITER;
        else if (strcmp(key, "Cipher") == 0)     bit = SEEN_CIPHER;
        else if (strcmp(key, "MAC") == 0)        bit = SEEN_MAC;
        else if (strcmp(key, "Salt") == 0)       bit = SEEN_SALT;
        else if (strcmp(key, "Nonce") == 0)      bit = SEEN_NONCE;
        else if (strcmp(key, "Name") == 0)       bit = SEEN_NAME;
        else if (strcmp(key, "Size") == 0)       bit = SEEN_SIZE;
        else if (strcmp(key, "Compression") == 0)         bit = SEEN_COMP;
        else if (strcmp(key, "Compression-Level") == 0)   bit = SEEN_LEVEL;
        else if (strcmp(key, "Compression-Threads") == 0) bit = SEEN_THREADS;
        else if (strcmp(key, "Input") == 0)               bit = SEEN_INPUT;
        else if (strcmp(key, "Mode") == 0)                bit = SEEN_MODE;
        else if (strcmp(key, "KEM") == 0)                 bit = SEEN_KEM;
        else if (strcmp(key, "KEM-Public-Key") == 0)      bit = SEEN_KEM_PUB_KEY;
        else if (strcmp(key, "KEM-Ciphertext") == 0)      bit = SEEN_KEM_CT;
        else return failc(RC_FORMAT, "unknown header field");
        if (seen & bit)
            return failc(RC_FORMAT, "duplicate header field");
        seen |= bit;

        switch (bit) {
        case SEEN_VERSION:
            if (dec_to_u64(val, &v) || v < BENC_FMT_LEGACY ||
                v > BENC_FMT_VERSION)
                return failc(RC_UNSUPPORTED, "unsupported container version");
            h->version = (unsigned)v;
            break;
        case SEEN_KDF:
            if (strcmp(val, BENC_KDF_NAME) != 0)
                return failc(RC_UNSUPPORTED, "unsupported key derivation function");
            break;
        case SEEN_ITER:
            if (dec_to_u64(val, &v) || v == 0 || v > BENC_MAX_ITER)
                return failc(RC_FORMAT, "invalid iteration count");
            h->iterations = (unsigned long)v;
            break;
        case SEEN_CIPHER:
            if (strcmp(val, BENC_CIPHER_NAME) != 0)
                return failc(RC_UNSUPPORTED, "unsupported cipher");
            break;
        case SEEN_MAC:
            if (strcmp(val, BENC_MAC_NAME) != 0)
                return failc(RC_UNSUPPORTED, "unsupported authenticator");
            break;
        case SEEN_SALT: {
            size_t n;
            if (b64_decode(val, h->salt, sizeof h->salt, &n) ||
                n != BENC_SALT_LEN || !b64_is_canonical(val, h->salt, n))
                return failc(RC_FORMAT, "invalid salt");
            break;
        }
        case SEEN_NONCE: {
            size_t n;
            if (b64_decode(val, h->nonce, sizeof h->nonce, &n) ||
                n != BENC_NONCE_LEN || !b64_is_canonical(val, h->nonce, n))
                return failc(RC_FORMAT, "invalid nonce");
            break;
        }
        case SEEN_NAME: {
            size_t n;
            if (b64_decode(val, (uint8_t *)h->name, BENC_MAX_NAME, &n) ||
                !b64_is_canonical(val, (const uint8_t *)h->name, n))
                return failc(RC_FORMAT, "invalid name field");
            h->name[n] = '\0';
            h->name_len = n;
            break;
        }
        case SEEN_COMP: {
            int id = comp_lookup(val);
            if (id < 0)
                return failc(RC_UNSUPPORTED, "unsupported compression method '%s'", val);
            h->comp = id;
            break;
        }
        case SEEN_LEVEL:
            if (dec_to_u64(val, &v) || v > 22)
                return failc(RC_FORMAT, "invalid compression level");
            h->level = (int)v;
            break;
        case SEEN_THREADS:
            if (dec_to_u64(val, &v) || v > BENC_MAX_THREADS)
                return failc(RC_FORMAT, "invalid thread count");
            h->threads = (int)v;
            break;
        case SEEN_INPUT:
            if (strcmp(val, "tar") == 0)
                h->archive = 1;
            else if (strcmp(val, "file") != 0)
                return failc(RC_UNSUPPORTED, "unsupported input kind");
            break;
        case SEEN_SIZE:
            if (strcmp(val, "-") == 0) {
                h->size_known = 0;
            } else {
                if (dec_to_u64(val, &v))
                    return failc(RC_FORMAT, "invalid size field");
                h->size = v;
                h->size_known = 1;
            }
            break;
        case SEEN_MODE:
            if (strcmp(val, "password") == 0)
                h->mode = 0;
            else if (strcmp(val, "pq") == 0)
                h->mode = 1;
            else if (strcmp(val, "hybrid") == 0)
                h->mode = 2;
            else
                return failc(RC_UNSUPPORTED, "unknown output mode '%s'", val);
            break;
        case SEEN_KEM:
            if (strcmp(val, "none") == 0)
                h->kem_alg = 0;
            else if (strcmp(val, "ml-kem-768") == 0)
                h->kem_alg = 1;
            else
                return failc(RC_UNSUPPORTED, "unsupported KEM '%s'", val);
            break;
        case SEEN_KEM_PUB_KEY: {
            size_t n;
            if (b64_decode(val, h->kem_pub_key, sizeof h->kem_pub_key, &n) ||
                n > BENC_KEM_PUBLIC_KEY_LEN)
                return failc(RC_FORMAT, "invalid KEM public key");
            h->kem_pub_key_len = n;
            break;
        }
        case SEEN_KEM_CT: {
            size_t n;
            if (b64_decode(val, h->kem_ct, sizeof h->kem_ct, &n) ||
                n > BENC_KEM_CIPHERTEXT_LEN)
                return failc(RC_FORMAT, "invalid KEM ciphertext");
            h->kem_ct_len = n;
            break;
        }
        }
    }
    if ((seen & SEEN_REQUIRED) != SEEN_REQUIRED)
        return failc(RC_FORMAT, "incomplete header");
    if (h->version > BENC_FMT_LEGACY) {
        unsigned long required = SEEN_V4_REQUIRED;
        if (h->version >= BENC_FMT_VERSION)
            required |= SEEN_V5_REQUIRED;
        if ((seen & required) != required)
            return failc(RC_FORMAT, "incomplete header");
    }
    if (h->version <= BENC_FMT_LEGACY) {
        h->comp = COMP_NONE;
        h->level = 0;
        h->threads = 0;
        h->archive = 0;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* container body reader                                               */
/* ------------------------------------------------------------------ */

/* Reads base64 text up to the end-of-data marker and checks the footer.
 * base: bytes of the file already consumed (for the progress display). */
static int read_body(FILE *fp, b64_sink sink, void *ctx, progress *pg,
                     uint64_t base)
{
    b64_dec *d = (b64_dec *)calloc(1, sizeof *d);
    uint8_t *buf = (uint8_t *)malloc(BENC_RBUF);
    char tail[160];
    size_t tlen = 0;
    uint64_t consumed = base;
    int at_bol = 1, in_tail = 0, rc = 1;
    char *l1, *l2, *nl;

    if (!d || !buf) {
        rc = failc(RC_NOMEM, "out of memory");
        goto out;
    }
    d->sink = sink;
    d->ctx = ctx;

    for (;;) {
        size_t n = fread(buf, 1, BENC_RBUF, fp), i = 0;

        if (n == 0) {
            if (in_tail)
                break;
            rc = failc(RC_FORMAT, ferror(fp) ? "read error" :
                      "unexpected end of file inside data block");
            goto out;
        }
        consumed += n;
        if (pg)
            progress_set(pg, consumed);

        while (i < n) {
            const uint8_t *nlp;
            size_t seg;

            if (in_tail) {
                size_t take = n - i;
                if (take > sizeof tail - 1 - tlen)
                    take = sizeof tail - 1 - tlen;
                memcpy(tail + tlen, buf + i, take);
                tlen += take;
                break;
            }
            if (at_bol) {
                if (buf[i] == '-') {
                    in_tail = 1;
                    continue;
                }
                at_bol = 0;
            }
            nlp = (const uint8_t *)memchr(buf + i, '\n', n - i);
            seg = nlp ? (size_t)(nlp - (buf + i)) : n - i;
            if (b64_dec_feed(d, buf + i, seg)) {
                rc = failc(RC_FORMAT, "invalid base64 data");
                goto out;
            }
            if (nlp) {
                at_bol = 1;
                i += seg + 1;
            } else {
                i = n;
            }
        }
        if (in_tail && tlen >= sizeof tail - 1)
            break;
    }

    if (b64_dec_finish(d)) {
        rc = failc(RC_FORMAT, "truncated base64 data");
        goto out;
    }
    tail[tlen] = '\0';
    l1 = tail;
    nl = strchr(l1, '\n');
    if (!nl) {
        rc = failc(RC_FORMAT, "malformed end-of-data marker");
        goto out;
    }
    *nl = '\0';
    l2 = nl + 1;
    if (strcmp(str_trim(l1), BENC_END_DATA) != 0) {
        rc = failc(RC_FORMAT, "malformed end-of-data marker");
        goto out;
    }
    nl = strchr(l2, '\n');
    if (nl)
        *nl = '\0';
    if (strcmp(str_trim(l2), BENC_END_FILE) != 0) {
        rc = failc(RC_FORMAT, "missing end-of-file marker");
        goto out;
    }
    rc = 0;
out:
    free(d);
    free(buf);
    return rc;
}

/* pass 1 sink: MAC everything except the trailing tag */
typedef struct {
    hmac_ctx *mac;
    uint8_t   hold[BENC_TAG_LEN];
    size_t    hlen;
    uint64_t  total;
} verify_ctx;

static int verify_push(void *vctx, uint8_t *data, size_t len)
{
    verify_ctx *v = (verify_ctx *)vctx;
    size_t emit;

    v->total += len;
    if (v->hlen + len <= BENC_TAG_LEN) {
        memcpy(v->hold + v->hlen, data, len);
        v->hlen += len;
        return 0;
    }
    emit = v->hlen + len - BENC_TAG_LEN;
    if (emit <= v->hlen) {
        hmac_update(v->mac, v->hold, emit);
        memmove(v->hold, v->hold + emit, v->hlen - emit);
        v->hlen -= emit;
        memcpy(v->hold + v->hlen, data, len);
        v->hlen += len;
    } else {
        size_t from_data = emit - v->hlen;
        hmac_update(v->mac, v->hold, v->hlen);
        hmac_update(v->mac, data, from_data);
        memcpy(v->hold, data + from_data, BENC_TAG_LEN);
        v->hlen = BENC_TAG_LEN;
    }
    return 0;
}

/* pass 2 sink: decrypt and write the ciphertext part */
typedef struct {
    chacha20_ctx *cc;
    FILE         *fp;
    uint64_t      remaining;
} plain_ctx;

static int plain_push(void *vctx, uint8_t *data, size_t len)
{
    plain_ctx *p = (plain_ctx *)vctx;
    size_t take = (uint64_t)len > p->remaining ? (size_t)p->remaining : len;

    if (take) {
        chacha20_xor(p->cc, data, take);
        if (fwrite(data, 1, take, p->fp) != take)
            return -1;
        p->remaining -= take;
    }
    return 0;
}

static int count_push(void *vctx, uint8_t *data, size_t len)
{
    (void)data;
    *(uint64_t *)vctx += len;
    return 0;
}

/* ------------------------------------------------------------------ */
/* files and paths                                                     */
/* ------------------------------------------------------------------ */

static int file_exists(const char *path)
{
    FILE *fp = fopen(path, "rb");

    if (fp) {
        fclose(fp);
        return 1;
    }
    return 0;
}

/* devices and pipes cannot be replaced atomically: write to them directly */
static int is_regular_file(const char *path)
{
#if BENC_WINDOWS
    DWORD a = GetFileAttributesA(path);
    return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
#elif BENC_POSIX
    struct stat st;
    return stat(path, &st) == 0 && S_ISREG(st.st_mode);
#else
    (void)path;
    return 1;
#endif
}

static int is_directory(const char *path)
{
#if BENC_WINDOWS
    DWORD a = GetFileAttributesA(path);
    return a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY);
#elif BENC_POSIX
    struct stat st;
    return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
#else
    (void)path;
    return 0;
#endif
}

static int same_file(const char *a, const char *b)
{
#if BENC_POSIX
    struct stat sa, sb;
    if (stat(a, &sa) == 0 && stat(b, &sb) == 0)
        return sa.st_dev == sb.st_dev && sa.st_ino == sb.st_ino;
    return strcmp(a, b) == 0;
#elif BENC_WINDOWS || BENC_DOS
    return ci_equal(a, b);
#else
    return strcmp(a, b) == 0;
#endif
}

static int stream_size(FILE *fp, uint64_t *size)
{
    benc_off_t cur = benc_ftell(fp), end;

    if (cur < 0 || benc_fseek(fp, 0, SEEK_END) != 0)
        return -1;
    end = benc_ftell(fp);
    if (end < 0 || benc_fseek(fp, cur, SEEK_SET) != 0)
        return -1;
    *size = (uint64_t)end;
    return 0;
}

#if BENC_POSIX
static int copy_file(const char *from, const char *to)
{
    FILE *in = fopen(from, "rb");
    FILE *out;
    unsigned char buf[BENC_COPY_BUF];
    size_t n;

    if (!in)
        return -1;
    out = fopen(to, "wb");
    if (!out) {
        fclose(in);
        return -1;
    }
    while ((n = fread(buf, 1, sizeof buf, in)) > 0) {
        if (fwrite(buf, 1, n, out) != n) {
            fclose(in);
            fclose(out);
            return -1;
        }
    }
    if (ferror(in)) {
        fclose(in);
        fclose(out);
        return -1;
    }
    if (fclose(out) != 0) {
        fclose(in);
        return -1;
    }
    fclose(in);
    return 0;
}
#endif

static int rename_over(const char *from, const char *to)
{
#if BENC_POSIX
    if (rename(from, to) == 0)
        return 0;
    /* staging lives in RAM (/dev/shm) but the target is on disk: copy */
    if (copy_file(from, to) == 0) {
        remove(from);
        return 0;
    }
    return -1;
#else
    remove(to);                      /* rename() cannot overwrite here */
    return rename(from, to);
#endif
}

static char *xstrdup_cat(const char *a, size_t alen, const char *b)
{
    size_t bl = strlen(b);
    char *p = (char *)malloc(alen + bl + 1);

    if (!p)
        return NULL;
    memcpy(p, a, alen);
    memcpy(p + alen, b, bl + 1);
    return p;
}

#if BENC_DOS
/* DOS file names are 8.3: replace the extension instead of appending */
static size_t stem_len(const char *path)
{
    const char *b = base_name(path), *dot = strrchr(b, '.');

    return dot && dot != b ? (size_t)(dot - path) : strlen(path);
}
#endif

static char *benc_nosep_dup(const char *path)
{
    size_t n = strlen(path);
    while (n > 1 && is_sep(path[n - 1]))
        n--;
    {
        char *out = (char *)malloc(n + 1);
        if (!out)
            return NULL;
        memcpy(out, path, n);
        out[n] = '\0';
        return out;
    }
}

static char *default_output_name(const char *in, const char *ext)
{
    char *t = benc_nosep_dup(in);
    char *r;
#if BENC_DOS
    r = t ? xstrdup_cat(t, stem_len(t), ext) : NULL;
#else
    r = t ? xstrdup_cat(t, strlen(t), ext) : NULL;
#endif
    free(t);
    return r;
}

static char *default_encrypt_output(const char *in)
{
    return default_output_name(in,
#if BENC_DOS
                               ".BCT");
#else
                               ".bct");
#endif
}

static char *default_binary_output(const char *in)
{
    return default_output_name(in,
#if BENC_DOS
                               ".BBC");
#else
                               ".bcb");
#endif
}

static char *default_decrypt_output(const char *in)
{
    size_t n = strlen(in);

    if (n > 4 && ci_equal(in + n - 4, ".bct"))
        return xstrdup_cat(in, n - 4, "");
    if (n > 4 && ci_equal(in + n - 4, ".bcb"))
        return xstrdup_cat(in, n - 4, "");
    if (n > 5 && ci_equal(in + n - 5, ".benc"))
        return xstrdup_cat(in, n - 5, "");
#if BENC_DOS
    return xstrdup_cat(in, stem_len(in), ".DEC");
#else
    return xstrdup_cat(in, n, ".dec");
#endif
}

/* output path inside the directory of 'in' using the stored file name */
static char *stored_name_output(const char *in, const char *stored)
{
    const char *safe = base_name(stored);
    size_t dlen = (size_t)(base_name(in) - in);

    if (!*safe || strcmp(safe, ".") == 0 || strcmp(safe, "..") == 0)
        return NULL;
    return xstrdup_cat(in, dlen, safe);
}

/* RAM-backed temporary directory: /dev/shm on POSIX, the OS temp dir on
 * Windows/DOS.  All staged temporary files are created here so sensitive
 * plaintext never lands on a (recoverable) disk location. */
static const char *ram_temp_dir(void)
{
#if BENC_WINDOWS
    static char buf[512];
    DWORD n;

    n = GetTempPathA((DWORD)sizeof buf, buf);
    if (n > 0 && (size_t)n < sizeof buf)
        return buf;
    return "C:\\Windows\\Temp";
#elif BENC_DOS
    return "/tmp";
#else
    return "/dev/shm";
#endif
}

/* interrupt handling: restore the terminal, drop the half written file */
static char g_tmp[1024];

/* temporary plaintext staging files (tar archive, compressed payload) */
#define BENC_MAX_STAGE 2
static char g_stage[BENC_MAX_STAGE][1024];

static void stage_forget(void)
{
    int i;

    for (i = 0; i < BENC_MAX_STAGE; i++) {
        if (!g_stage[i][0])
            continue;
#if BENC_POSIX
        unlink(g_stage[i]);
#else
        remove(g_stage[i]);
#endif
        g_stage[i][0] = '\0';
    }
}

static void stage_remember(const char *p)
{
    int i;

    for (i = 0; i < BENC_MAX_STAGE; i++) {
        if (!g_stage[i][0]) {
            if (strlen(p) < sizeof g_stage[i])
                strcpy(g_stage[i], p);
            return;
        }
    }
}
#if BENC_POSIX
static struct termios g_tio;
static volatile int g_tio_saved;
#endif

#if !defined(__ia16__)
static void on_signal(int sig)
{
    char out[UI_MAXW + 4];
    int n = ui_len, i, p = 0;

#if BENC_POSIX
    if (g_tio_saved)
        tcsetattr(0, TCSAFLUSH, &g_tio);
#endif
    if (g_tmp[0]) {
#if BENC_POSIX
        unlink(g_tmp);
#else
        remove(g_tmp);
#endif
    }
    stage_forget();
    if (n > 0 && n <= UI_MAXW) {
        out[p++] = '\r';
        for (i = 0; i < n; i++)
            out[p++] = ' ';
        out[p++] = '\r';
#if BENC_POSIX
        (void)!write(2, out, (size_t)p);
#else
        fwrite(out, 1, (size_t)p, stderr);
#endif
    }
    signal(sig, SIG_DFL);
    raise(sig);
}

static void install_signals(void)
{
#ifdef SIGINT
    signal(SIGINT, on_signal);
#endif
#ifdef SIGTERM
    signal(SIGTERM, on_signal);
#endif
#ifdef SIGHUP
    signal(SIGHUP, on_signal);
#endif
}
#else
static void install_signals(void) { }
#endif

static void set_tmp(const char *p)
{
    if (!p)
        g_tmp[0] = '\0';
    else if (strlen(p) < sizeof g_tmp)
        strcpy(g_tmp, p);
}

/* ------------------------------------------------------------------ */
/* password input                                                      */
/* ------------------------------------------------------------------ */

typedef struct {
    const char *password;        /* -p */
    const char *password_file;   /* -P */
    const char *output;
    unsigned long iterations;
    int force, use_header_name, no_name, quiet;
    int binout;                  /* --binout: write a tight binary container */
    int compress;                /* COMP_* */
    int level;                   /* -1 = the codec default */
    long threads;                /* 0 = all cores / backend default */
    /* Post-quantum */
    int kem_mode;                /* 0=password, 1=pq-only, 2=hybrid */
    const char *kem_pub_key;    /* path to KEM public key file (encrypt) */
    const char *kem_secret_key; /* path to KEM secret key file (decrypt) */
    int keygen;                 /* --keygen flag */
    const char *keygen_output;  /* output path for --keygen */
} opts;

/* read one key press without echo; -1 on EOF */
static int kb_getc(void)
{
#if BENC_WINDOWS
    return _getch();
#elif BENC_POSIX
    unsigned char c;
    return read(0, &c, 1) == 1 ? (int)c : -1;
#elif defined(__ia16__)
    int ch;
    __asm__ volatile ("int $0x21" : "=a"(ch) : "a"(0x0800));
    return ch & 0xFF;
#else
    return getch();
#endif
}

/* interactive line editor on the status line.
 * returns length (> 0), 0 for an empty entry, -1 aborted, -2 too long */
static int read_secret(char *buf, size_t cap)
{
    size_t n = 0;
    int typed = 0, shown = 0, too_long = 0, c;

#if BENC_POSIX
    struct termios nt;
    if (tcgetattr(0, &g_tio) == 0) {
        nt = g_tio;
        nt.c_lflag &= (tcflag_t)~(ECHO | ICANON | IEXTEN);
        nt.c_cc[VMIN] = 1;
        nt.c_cc[VTIME] = 0;
        if (tcsetattr(0, TCSAFLUSH, &nt) == 0)
            g_tio_saved = 1;
    }
#endif
    for (;;) {
        c = kb_getc();
        entropy_event();
        if (c < 0) {
            if (n == 0) {
                n = (size_t)-1;
                goto done;
            }
            break;
        }
        if (c == '\r' || c == '\n')
            break;
        if (c == 3 || (c == 4 && n == 0)) {        /* Ctrl-C / Ctrl-D */
            n = (size_t)-1;
            goto done;
        }
        if (c == 8 || c == 127) {                   /* backspace */
            if (n) {
                while (n && ((unsigned char)buf[n - 1] & 0xC0) == 0x80)
                    n--;
                n--;
                typed--;
                if (typed < shown) {
                    ui_write("\b \b", 3);
                    ui_len--;
                    shown--;
                }
            } else if (too_long) {
                too_long = 0;
            }
            continue;
        }
        if (c == 21 || c == 27) {                   /* Ctrl-U / Esc: clear */
            while (shown > 0) {
                ui_write("\b \b", 3);
                ui_len--;
                shown--;
            }
            n = 0;
            typed = 0;
            too_long = 0;
#if BENC_POSIX
            if (c == 27) {                          /* swallow ESC [ x */
                int c2 = kb_getc();
                if (c2 == '[' || c2 == 'O') {
                    int c3;
                    do { c3 = kb_getc(); } while (c3 >= 0x20 && c3 < 0x40);
                }
            }
#endif
            continue;
        }
        if (c == 0 || c == 224) {                   /* DOS/Win function key */
#if !BENC_POSIX
            (void)kb_getc();
#endif
            continue;
        }
        if (c < 32)
            continue;
        if (n + 1 >= cap) {
            too_long = 1;
            continue;
        }
        buf[n++] = (char)c;
        if (((unsigned)c & 0xC0) != 0x80) {         /* new character */
            typed++;
            if (ui_len < ui_w) {
                ui_write("*", 1);
                ui_len++;
                shown++;
            }
        }
    }
done:
#if BENC_POSIX
    if (g_tio_saved) {
        tcsetattr(0, TCSAFLUSH, &g_tio);
        g_tio_saved = 0;
    }
#endif
    ui_clear();                  /* Enter never moves to a new line */
    if (n == (size_t)-1)
        return -1;
    buf[n] = '\0';
    if (too_long)
        return -2;
    return (int)n;
}

/* Reads the first line of fp into buf, without its line ending.
 * returns the length, 0 for an empty line, -1 on EOF/error, -2 if the line
 * does not fit (the rest of it is discarded). */
static int read_password_line(FILE *fp, char *buf, size_t cap)
{
    size_t n;

    if (!fgets(buf, (int)cap, fp))
        return -1;
    n = strlen(buf);
    if (n + 1 >= cap && buf[n - 1] != '\n') {
        int ch;
        while ((ch = fgetc(fp)) != EOF && ch != '\n')
            ;
        return -2;
    }
    while (n && (buf[n - 1] == '\n' || buf[n - 1] == '\r'))
        buf[--n] = '\0';
    return (int)n;
}

static int prompt_secret(const char *prompt, char *buf, size_t cap)
{
    int r;

    ui_draw(prompt);
    r = read_secret(buf, cap);
    if (r == -1)
        return failc(RC_PASSWORD, "aborted");
    if (r == -2)
        return failc(RC_PASSWORD, "password too long (maximum %d bytes)", BENC_MAX_PASSWORD - 1);
    return r == 0 ? 1 : 0;       /* 1 = empty */
}

/* Obtains the password.  lead is a short reason shown in front of the
 * prompt when the question is asked again ("Wrong password. ").
 * returns 0 ok, 1 failure (message already shown). *interactive tells the
 * caller whether asking again makes sense. */
static int get_password(const opts *o, char *buf, size_t cap, int confirm,
                        const char *lead, int *interactive)
{
    *interactive = 0;
    if (o->password) {
        size_t n = strlen(o->password);
        if (n == 0)
            return failc(RC_PASSWORD, "empty password");
        if (n + 1 > cap)
            return failc(RC_PASSWORD, "password too long");
        memcpy(buf, o->password, n + 1);
        return 0;
    }
    if (o->password_file) {
        FILE *fp = fopen(o->password_file, "rb");
        int r;

        if (!fp)
            return failc_errno(RC_PASSWORD, "cannot open password file", o->password_file);
        r = read_password_line(fp, buf, cap);
        fclose(fp);
        if (r == -2)
            return failc(RC_PASSWORD, "password too long");
        if (r <= 0)
            return failc(RC_PASSWORD, "password file is empty");
        return 0;
    }
    if (!benc_isatty(0)) {
        int r = read_password_line(stdin, buf, cap);

        if (r == -1)
            return failc(RC_PASSWORD, "no password supplied");
        if (r == -2)
            return failc(RC_PASSWORD, "password too long");
        if (r == 0)
            return failc(RC_PASSWORD, "empty password");
        return 0;
    }

    *interactive = 1;
    {
        char again[BENC_MAX_PASSWORD + 1];
        char prompt[64];
        int tries, r;

        for (tries = 0; tries < BENC_MAX_TRIES; tries++) {
            snprintf(prompt, sizeof prompt, "%sPassword: ", lead);
            r = prompt_secret(prompt, buf, cap);
            if (r < 0)
                return 1;
            if (r == 1) {
                lead = "Empty password. ";
                continue;
            }
            if (!confirm)
                return 0;
            r = prompt_secret("Repeat password: ", again, sizeof again);
            if (r < 0)
                return 1;
            if (r == 0 && strcmp(buf, again) == 0) {
                benc_wipe(again, sizeof again);
                return 0;
            }
            benc_wipe(again, sizeof again);
            lead = "Passwords differ. ";
        }
        return failc(RC_PASSWORD, "too many attempts");
    }
}

/* ------------------------------------------------------------------ */
/* compression and directory archiving                                 */
/* ------------------------------------------------------------------ */

/* Directories are archived with tar.  The archive, and any ordinary input
 * file, is then compressed before it is encrypted.  Supported compression
 * methods are built in (lzma2/zstd/none); staged plaintext is created
 * 0600 and removed when the job ends. */

/* A private temporary file next to the output.  0600 where the platform
 * allows it, because it holds plaintext. */
static char *stage_path(const char *fname, const char *tag)
{
    const char *d = ram_temp_dir();
    const char *b = base_name(fname);
    size_t blen = strlen(b);
    size_t need = strlen(d) + strlen(tag) + blen + 48;
    char *p = (char *)malloc(need);
    unsigned tries = 0;

    if (!p)
        return NULL;
    for (;;) {
        snprintf(p, need, "%s/benc-%s-%s-%u.part", d, tag, b, tries++);
        if (!file_exists(p))
            break;
        if (tries > 1000) {
            free(p);
            return NULL;
        }
    }
#if BENC_POSIX
    {
        int fd = open(p, O_WRONLY | O_CREAT | O_EXCL, 0600);
        if (fd < 0) {
            free(p);
            return NULL;
        }
        close(fd);
    }
#else
    {
        FILE *fp = fopen(p, "wb");
        if (!fp) {
            free(p);
            return NULL;
        }
        fclose(fp);
    }
#endif
    stage_remember(p);
    return p;
}

/* Progress callback shared by the native codecs and the tar packer: adopt a
 * byte total the first time it is known, then feed the common bar. */
static void stage_progress_cb(unsigned long long done, unsigned long long total,
                              void *ctx)
{
    progress *pg = (progress *)ctx;

    if (pg->total == 0 && total > 0) {
        pg->total = (uint64_t)total;
        if (ui_live)
            progress_draw(pg);
        pg->last = benc_now_ms();
    }
    progress_set(pg, (uint64_t)done);
    if (pg->total && done >= pg->total)
        progress_set(pg, pg->total);
}

/* Run the in-process compression backend.  decode=0 compresses src -> dst,
 * decode=1 decompresses.  Only the built-in methods may be selected. */
static int run_codec(int comp, int level, int threads,
                     const char *src, const char *dst, int decode)
{
    progress pg;
    int rc;

    if (comp == COMP_NONE)
        return 0;
    progress_begin(&pg, decode ? "Decompressing" : "Compressing", 0, 1);
    if (comp == COMP_LZMA2)
        rc = decode ? benc_lzma2_decode(src, dst, stage_progress_cb, &pg)
                    : benc_lzma2_encode(src, dst, level, threads,
                                        stage_progress_cb, &pg);
    else if (comp == COMP_ZSTD)
        rc = decode ? benc_zstd_decode(src, dst, stage_progress_cb, &pg)
                    : benc_zstd_encode(src, dst, level, threads,
                                       stage_progress_cb, &pg);
    else
        rc = failc(RC_CODEC, "unsupported compression method");
    progress_finish(&pg);
    return rc;
}

/* Directory archiving: tar stores the directory itself, so extraction
 * recreates it under the chosen output path. */
static int split_dir(const char *path, char *dir, size_t dcap,
                     char *name, size_t ncap)
{
    size_t n = strlen(path), cut, d;

    while (n > 1 && is_sep(path[n - 1]))
        n--;
    cut = n;
    while (cut > 0 && !is_sep(path[cut - 1]))
        cut--;
    if (n == cut || n - cut >= ncap)
        return -1;
    memcpy(name, path + cut, n - cut);
    name[n - cut] = '\0';
    d = cut;
    while (d > 0 && is_sep(path[d - 1]))
        d--;
    if (d == 0) {
        if (dcap < 2)
            return -1;
        strcpy(dir, cut ? "/" : ".");
    } else {
        if (d >= dcap)
            return -1;
        memcpy(dir, path, d);
        dir[d] = '\0';
    }
    return 0;
}

static int make_tar(const char *dir, const char *name, const char *dst,
                    benc_tar_progress_fn cb, void *cb_ctx)
{
    return benc_tar_create(dir, name, dst, cb, cb_ctx);
}

static int extract_tar(const char *src, const char *dest,
                       benc_tar_progress_fn cb, void *cb_ctx)
{
    return benc_tar_extract(src, dest, cb, cb_ctx);
}

static int make_directory(const char *path)
{
    if (is_directory(path))
        return 0;
    if (file_exists(path))
        return failc(RC_CODEC, "'%s' exists and is not a directory", path);
#if BENC_WINDOWS
    if (_mkdir(path) != 0 && !is_directory(path))
        return failc_errno(RC_OUTPUT, "cannot create directory", path);
#elif BENC_POSIX
    if (mkdir(path, 0777) != 0 && !is_directory(path))
        return failc_errno(RC_OUTPUT, "cannot create directory", path);
#else
    return failc(RC_CODEC, "cannot create directory '%s' on this platform", path);
#endif
    return 0;
}

/* Recursively copy a directory tree (src must be a directory).  Used to move
 * extracted archive contents out of the RAM staging area onto the final
 * (disk) destination without leaking plaintext to disk in between. */
static int copy_tree(const char *src, const char *dst)
{
#if BENC_POSIX
    DIR *d = opendir(src);
    struct dirent *e;
    struct stat st;
    char sp[4096], dp[4096];

    if (!d)
        return -1;
    if (mkdir(dst, 0777) != 0 && errno != EEXIST)
        return -1;
    while ((e = readdir(d)) != NULL) {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, ".."))
            continue;
        snprintf(sp, sizeof sp, "%s/%s", src, e->d_name);
        snprintf(dp, sizeof dp, "%s/%s", dst, e->d_name);
        if (lstat(sp, &st) != 0) {
            closedir(d);
            return -1;
        }
        if (S_ISDIR(st.st_mode)) {
            if (copy_tree(sp, dp) != 0) {
                closedir(d);
                return -1;
            }
        } else if (S_ISLNK(st.st_mode)) {
            char target[4096];
            ssize_t n = readlink(sp, target, sizeof target - 1);
            if (n < 0) {
                closedir(d);
                return -1;
            }
            target[n] = '\0';
            remove(dp);
            if (symlink(target, dp) != 0) {
                closedir(d);
                return -1;
            }
        } else {
            if (copy_file(sp, dp) != 0) {
                closedir(d);
                return -1;
            }
        }
    }
    closedir(d);
    return 0;
#else
    (void)src; (void)dst;
    return -1;
#endif
}

/* ------------------------------------------------------------------ */
/* encrypt / decrypt                                                   */
/* ------------------------------------------------------------------ */

/* Derive the 64 byte file key (cipher key || MAC key) for a container. */
static void derive_file_key(const char *pw, const benc_header *h,
                            const uint8_t *ss, size_t ss_len,
                            uint8_t out[2 * BENC_KEY_LEN], progress *pg)
{
    uint8_t master[64];
    uint8_t final_key[2 * BENC_KEY_LEN];

    pbkdf2_sha256((const uint8_t *)pw, strlen(pw), h->salt, BENC_SALT_LEN,
                  h->iterations, master, sizeof master, pg);

    if (h->mode > 0 && ss && ss_len > 0) {
        uint8_t prk[BENC_KEY_LEN];
        static const uint8_t hkdf_info[] = "benc v1.3 hybrid key v1";

        if (hkdf_sha256(ss, ss_len, master, sizeof master, hkdf_info,
                       sizeof hkdf_info - 1, prk, BENC_KEY_LEN) == 0 &&
            hkdf_sha256(prk, BENC_KEY_LEN, NULL, 0, hkdf_info,
                        sizeof hkdf_info - 1, final_key, sizeof final_key) == 0) {
            memcpy(out, final_key, sizeof final_key);
            benc_wipe(prk, sizeof prk);
            benc_wipe(final_key, sizeof final_key);
            benc_wipe(master, sizeof master);
            return;
        }
    }

    memcpy(out, master, sizeof master);
    benc_wipe(master, sizeof master);
}

static void derive_keys(const char *pw, const benc_header *h,
                        uint8_t enc_key[BENC_KEY_LEN],
                        uint8_t mac_key[BENC_KEY_LEN], progress *pg,
                        const uint8_t *ss, size_t ss_len)
{
    uint8_t key[2 * BENC_KEY_LEN];

    derive_file_key(pw, h, ss, ss_len, key, pg);
    memcpy(enc_key, key, BENC_KEY_LEN);
    memcpy(mac_key, key + BENC_KEY_LEN, BENC_KEY_LEN);
    benc_wipe(key, sizeof key);
}

static FILE *open_output(const char *out_path, char **tmp, int *direct)
{
    FILE *fp;

    *direct = file_exists(out_path) && !is_regular_file(out_path);
    *tmp = NULL;
    if (*direct)
        return fopen(out_path, "wb");
    *tmp = stage_path(out_path, "out");
    if (!*tmp) {
        errno = ENOMEM;
        return NULL;
    }
    fp = fopen(*tmp, "wb");
    if (fp)
        set_tmp(*tmp);
    return fp;
}

static int check_output(const char *in_path, const char *out_path, const opts *o)
{
    if (same_file(in_path, out_path))
        return failc(RC_INPUT, "input and output are the same file");
    if (!o->force && file_exists(out_path) && is_regular_file(out_path))
        return failc(RC_OUTPUT, "output file '%s' already exists (use -f to overwrite)",
                    out_path);
    return 0;
}

/* Flush, close and move a finished output file into place.  On success the
 * caller's FILE pointer is cleared and the temporary path is forgotten; on
 * failure the message is already printed and the temporary file is left for
 * the caller's cleanup. */
static int commit_output(FILE **outp, char *tmp, int direct,
                         const char *out_path)
{
    FILE *out = *outp;

    if (fflush(out) != 0) {
        failc(RC_OUTPUT, "cannot write output");
        return -1;
    }
    if (fclose(out) != 0) {
        *outp = NULL;
        failc(RC_OUTPUT, "cannot close output");
        return -1;
    }
    *outp = NULL;
    if (!direct && rename_over(tmp, out_path) != 0) {
        failc_errno(RC_OUTPUT, "cannot create output", out_path);
        return -1;
    }
    set_tmp(NULL);
    return 0;
}

/* final status line for a finished job (or a cleared line with --quiet) */
static void report_result(const opts *o, const char *verb,
                          const char *in_path, const char *out_path,
                          uint64_t bytes, unsigned long t0, const char *note)
{
    char sz[24], tm[24];

    if (o->quiet) {
        ui_clear();
        return;
    }
    fmt_size(bytes, sz);
    fmt_secs(benc_now_ms() - t0, tm);
    ui_final("%s %s -> %s  (%s, %s)%s", verb, in_path, out_path, sz, tm, note);
}

static int stage_payload(const char *in_path, const char *out_path,
                         int comp, int level, int threads,
                         char *namebuf, size_t ncap, char *dirbuf, size_t dcap,
                         char **staged, const char **src, int *archive)
{
    progress pg;

    *archive = 0;
    if (is_directory(in_path)) {
        if (split_dir(in_path, dirbuf, dcap, namebuf, ncap)) {
            failc(RC_INPUT, "cannot use '%s' as input", in_path);
            return -1;
        }
        staged[0] = stage_path(out_path, "tar");
        if (!staged[0]) {
            failc(RC_OUTPUT, "cannot create a temporary file next to '%s'", out_path);
            return -1;
        }
        progress_begin(&pg, "Packing", 0, 1);
        int mrc = make_tar(dirbuf, namebuf, staged[0], stage_progress_cb, &pg);
        if (mrc) {
            progress_finish(&pg);
            remove(staged[0]);
            free(staged[0]);
            staged[0] = NULL;
            failc(RC_CODEC, "cannot pack directory '%s'", in_path);
            return -1;
        }
        progress_finish(&pg);
        *src = staged[0];
        *archive = 1;
    } else {
        *src = in_path;
    }
    if (comp != COMP_NONE) {
        staged[1] = stage_path(out_path, "cmp");
        if (!staged[1]) {
            if (*archive) {
                remove(*src);
                free((void *)*src);
                staged[0] = NULL;
            }
            failc(RC_OUTPUT, "cannot create a temporary file next to '%s'", out_path);
            return -1;
        }
        if (run_codec(comp, level, threads, *src, staged[1], 0)) {
            remove(staged[1]);
            free(staged[1]);
            staged[1] = NULL;
            if (*archive) {
                remove(*src);
                free((void *)*src);
                staged[0] = NULL;
            }
            return -1;
        }
        *src = staged[1];
    }
    return 0;
}

static int cmd_encrypt(const char *in_path, const char *out_path, const opts *o)
{
    FILE *in = NULL, *out = NULL;
    char *tmp = NULL;
    char *staged[2] = { NULL, NULL };
    const char *src = in_path, *name;
    char dirbuf[1024], namebuf[512];
    benc_header h;
    uint8_t enc_key[BENC_KEY_LEN], mac_key[BENC_KEY_LEN], tag[BENC_TAG_LEN];
    char pw[BENC_MAX_PASSWORD + 1], canon[8192];
    uint8_t *buf = NULL;
    hmac_ctx mac;
    chacha20_ctx cc;
    b64_w w;
    progress pg;
    uint64_t done = 0;
    unsigned long t0 = benc_now_ms();
    int rc = RC_ERR, direct = 0, inter, w_ok = 0, archive = 0;
    int comp = o->compress, level, threads;
    size_t n;

    memset(&h, 0, sizeof h);
    memset(pw, 0, sizeof pw);
    memset(&cc, 0, sizeof cc);
    if (comp < 0 || comp >= COMP_COUNT)
        comp = COMP_NONE;
    {
        int cr = check_output(in_path, out_path, o);
        if (cr)
            return g_exit ? g_exit : cr;
    }
    level = o->level >= 0 ? o->level : comp_specs[comp].def_level;
    threads = o->threads > BENC_MAX_THREADS ? BENC_MAX_THREADS
                                            : (int)o->threads;
    if (threads < 0)
        threads = 0;
    if (comp_specs[comp].max_level &&
        (level < comp_specs[comp].min_level ||
         level > comp_specs[comp].max_level))
        return failc(RC_USAGE, "%s compression levels are %d..%d", comp_specs[comp].name,
                    comp_specs[comp].min_level, comp_specs[comp].max_level);
    if (o->kem_pub_key && !o->kem_mode) {
        /* pq-only mode: no password required */
        pw[0] = '\0';
        inter = 0;
    } else if (o->kem_pub_key) {
        /* hybrid mode: password + KEM */
        int pr = get_password(o, pw, sizeof pw, 1, "", &inter);
        if (pr)
            return g_exit ? g_exit : pr;
    } else {
        int pr = get_password(o, pw, sizeof pw, 1, "", &inter);
        if (pr)
            return g_exit ? g_exit : pr;
    }

    name = base_name(in_path);
    {
        int _sp_rc = stage_payload(in_path, out_path, comp, level, threads, namebuf,
                      sizeof namebuf, dirbuf, sizeof dirbuf, staged, &src,
                      &archive);
        if (_sp_rc) goto done;
    }

    if (archive)
        name = namebuf;

    in = fopen(src, "rb");
    if (!in) {
        failc_errno(RC_INPUT, "cannot open input", src);
        goto done;
    }
    h.version = BENC_FMT_VERSION;
    h.comp = comp;
    h.level = level;
    h.threads = threads;
    h.archive = archive;
    h.iterations = o->iterations;
    if (o->no_name) {
        h.name_len = 0;
    } else {
        h.name_len = strlen(name);
        if (h.name_len > BENC_MAX_NAME)
            h.name_len = BENC_MAX_NAME;
        memcpy(h.name, name, h.name_len);
    }
    h.size_known = (stream_size(in, &h.size) == 0);

    h.mode = o->kem_pub_key ? (o->kem_mode ? o->kem_mode : 1) : 0;
    if (o->kem_pub_key) {
        FILE *kf = fopen(o->kem_pub_key, "rb");
        uint8_t pk[BENC_KEM_PUBLIC_KEY_LEN];
        size_t pklen = 0, nread;
        benc_kem *kem = benc_kem_new("ml-kem-768");
        uint8_t ct[BENC_KEM_CIPHERTEXT_LEN], ss[BENC_KEM_SHARED_SECRET_LEN];
        size_t ctlen, sslen;
        if (!kf || !kem) {
            if (kf) fclose(kf);
            if (kem) benc_kem_free(kem);
            return failc(RC_INPUT, "cannot open KEM public key");
        }
        nread = fread(pk, 1, sizeof pk, kf);
        fclose(kf);
        pklen = nread;
        h.kem_alg = 1;
        memcpy(h.kem_pub_key, pk, pklen);
        h.kem_pub_key_len = pklen;
        if (benc_kem_encapsulate(kem, ct, &ctlen, ss, &sslen, pk, pklen)) {
            benc_kem_free(kem);
            return failc(RC_ERR, "KEM encapsulation failed");
        }
        memcpy(h.kem_ct, ct, ctlen);
        h.kem_ct_len = ctlen;
        /* store ss temporarily in a static-ish way: derive later. We'll pass ss via a global. */
        /* Use a file-scope buffer */
        memcpy(g_kem_ss, ss, sslen);
        g_kem_ss_len = sslen;
        benc_kem_free(kem);
    }

    if (benc_random(h.salt, sizeof h.salt) || benc_random(h.nonce, sizeof h.nonce)) {
        fail("no source of random bytes available");
        goto done;
    }
    if (header_canonical(&h, canon, sizeof canon)) {
        fail("internal error building header");
        goto done;
    }

    progress_begin(&pg, "Deriving key", 0, 0);
    derive_keys(pw, &h, enc_key, mac_key, &pg, o->kem_pub_key ? g_kem_ss : NULL, o->kem_pub_key ? g_kem_ss_len : 0);
    progress_finish(&pg);
    benc_wipe(pw, sizeof pw);

    buf = (uint8_t *)malloc(BENC_CHUNK);
    if (!buf) {
        failc(RC_NOMEM, "out of memory");
        goto done;
    }
    out = open_output(out_path, &tmp, &direct);
    if (!out) {
        failc_errno(RC_OUTPUT, "cannot create output", tmp ? tmp : out_path);
        goto done;
    }
    if (o->binout) {
        {
            size_t clen = strlen(canon);
            if (fwrite(canon, 1, clen, out) != clen) {
                failc(RC_OUTPUT, "cannot write output");
                goto done;
            }
        }
    } else {
        if (write_header(out, &h) || b64_w_init(&w, out)) {
            failc(RC_OUTPUT, "cannot write header");
            goto done;
        }
        w_ok = 1;
    }

    hmac_init(&mac, mac_key, BENC_KEY_LEN);
    hmac_update(&mac, canon, strlen(canon));
    chacha20_init(&cc, enc_key, h.nonce);

    progress_begin(&pg, "Encrypting", h.size_known ? h.size : 0, 1);
    while ((n = fread(buf, 1, BENC_CHUNK, in)) > 0) {
        chacha20_xor(&cc, buf, n);
        hmac_update(&mac, buf, n);
        if (o->binout) {
            if (fwrite(buf, 1, n, out) != n) {
                failc(RC_OUTPUT, "cannot write output");
                goto done;
            }
        } else if (b64_w_put(&w, buf, n)) {
            failc(RC_OUTPUT, "cannot write output");
            goto done;
        }
        done += n;
        progress_set(&pg, done);
    }
    if (ferror(in)) {
        failc_errno(RC_INPUT, "cannot read input", in_path);
        goto done;
    }
    if (h.size_known && done != h.size) {
        failc(RC_INPUT, "input file changed while it was being read");
        goto done;
    }
    hmac_final(&mac, tag);
    if (o->binout) {
        if (fwrite(tag, 1, sizeof tag, out) != sizeof tag) {
            failc(RC_OUTPUT, "cannot write output");
            goto done;
        }
        w_ok = 0;
    } else {
        if (b64_w_put(&w, tag, sizeof tag) || b64_w_close(&w)) {
            w_ok = 0;
            failc(RC_OUTPUT, "cannot write output");
            goto done;
        }
        w_ok = 0;
        if (fprintf(out, "%s\n%s\n", BENC_END_DATA, BENC_END_FILE) < 0) {
            failc(RC_OUTPUT, "cannot write output");
            goto done;
        }
    }
    if (commit_output(&out, tmp, direct, out_path))
        goto done;
    progress_finish(&pg);
    report_result(o, "Encrypted", in_path, out_path, done, t0,
                  benc_random_weak ? "  [weak random source]" : "");
    rc = RC_OK;

done:
    if (w_ok)
        b64_w_close(&w);
    benc_wipe(pw, sizeof pw);
    benc_wipe(enc_key, sizeof enc_key);
    benc_wipe(mac_key, sizeof mac_key);
    benc_wipe(tag, sizeof tag);
    benc_wipe(canon, sizeof canon);
    benc_wipe(&cc, sizeof cc);
    if (out)
        fclose(out);
    if (in)
        fclose(in);
    if (buf) {
        benc_wipe(buf, BENC_CHUNK);
        free(buf);
    }
    if (rc != RC_OK && tmp) {
        remove(tmp);
        set_tmp(NULL);
    }
    free(tmp);
    {
        int i;
        for (i = 0; i < 2; i++) {
            if (staged[i]) {
                remove(staged[i]);
                free(staged[i]);
            }
        }
    }
    stage_forget();
    if (rc == RC_ERR && g_exit)
        rc = g_exit;
    return rc;
}

/* Shared verification tail: finish HMAC, compare the tag, and report the
 * ciphertext length.  Returns RC_OK, RC_AUTH or RC_ERR. */
static int verify_auth(hmac_ctx *mac, verify_ctx *ver, progress *pg,
                       uint64_t *cipher_len)
{
    uint8_t computed[BENC_TAG_LEN];

    if (ver->total < BENC_TAG_LEN || ver->hlen != BENC_TAG_LEN) {
        progress_finish(pg);
        return failc(RC_FORMAT, "file is truncated");
    }
    hmac_final(mac, computed);
    if (!ct_equal(computed, ver->hold, BENC_TAG_LEN)) {
        progress_finish(pg);
        benc_wipe(computed, sizeof computed);
        return RC_AUTH;
    }
    benc_wipe(computed, sizeof computed);
    progress_finish(pg);
    *cipher_len = ver->total - BENC_TAG_LEN;
    return RC_OK;
}

/* pass 1: authenticate the whole file.  RC_OK, RC_AUTH or RC_ERR */
static int verify_pass(FILE *in, const benc_header *h, const char *canon,
                       const uint8_t *mac_key, uint64_t body_bytes,
                       uint64_t hdr_end, uint64_t *cipher_len)
{
    hmac_ctx mac;
    verify_ctx ver;
    int r;
    progress pg;

    hmac_init(&mac, mac_key, BENC_KEY_LEN);
    hmac_update(&mac, canon, strlen(canon));
    memset(&ver, 0, sizeof ver);
    ver.mac = &mac;

    progress_begin(&pg, "Verifying", body_bytes + hdr_end, 1);
    if (read_body(in, verify_push, &ver, &pg, hdr_end))
        return RC_ERR;
    r = verify_auth(&mac, &ver, &pg, cipher_len);
    if (r != RC_OK)
        return r;
    if (h->size_known && h->size != *cipher_len)
        return failc(RC_FORMAT, "file is truncated");
    return RC_OK;
}

/* Binary container layout: canonical header line || ciphertext || tag. */
static int verify_bin(FILE *in, const char *canon, size_t clen,
                      const uint8_t *mac_key, uint64_t body_bytes,
                      uint64_t *cipher_len)
{
    hmac_ctx mac;
    verify_ctx ver;
    uint8_t buf[BENC_CHUNK];
    uint64_t remaining = body_bytes;
    progress pg;

    hmac_init(&mac, mac_key, BENC_KEY_LEN);
    hmac_update(&mac, canon, clen);
    memset(&ver, 0, sizeof ver);
    ver.mac = &mac;
    progress_begin(&pg, "Verifying", body_bytes, 1);
    while (remaining > 0) {
        size_t n = (size_t)(remaining > BENC_CHUNK ? BENC_CHUNK : remaining);
        if (fread(buf, 1, n, in) != n) {
            progress_finish(&pg);
            return failc(RC_FORMAT, "file is truncated");
        }
        if (verify_push(&ver, buf, n)) {
            progress_finish(&pg);
            return RC_ERR;
        }
        remaining -= n;
    }
    return verify_auth(&mac, &ver, &pg, cipher_len);
}

static int decrypt_unpack_archive(const char *tar, const char *in_path,
                                  const char *out_path, const benc_header *h,
                                  const opts *o, unsigned long t0,
                                  uint64_t cipher_len)
{
    char *xdir = NULL;
    char *childp = NULL;
    char child[BENC_MAX_NAME + 2];
    size_t clen;
    progress pg;

    xdir = (char *)malloc(strlen(ram_temp_dir()) + 64);
    if (!xdir) {
        failc(RC_NOMEM, "out of memory");
        return -1;
    }
    snprintf(xdir, strlen(ram_temp_dir()) + 64, "%s/benc-dir-%u",
             ram_temp_dir(), (unsigned)benc_now_ms());
    if (make_directory(xdir))
        goto out;
    progress_begin(&pg, "Unpacking", 0, 1);
    if (extract_tar(tar, xdir, stage_progress_cb, &pg)) {
        progress_finish(&pg);
        failc(RC_CODEC, "cannot unpack directory archive");
        goto out;
    }
    progress_finish(&pg);
    clen = h->name_len;
    if (clen > BENC_MAX_NAME)
        clen = BENC_MAX_NAME;
    if (clen > (int)sizeof child - 1)
        clen = (int)sizeof child - 1;
    memcpy(child, h->name, clen);
    child[clen] = '\0';
    childp = (char *)malloc(strlen(xdir) + clen + 2);
    if (!childp) {
        failc(RC_NOMEM, "out of memory");
        goto out;
    }
    sprintf(childp, "%s/%s", xdir, child);
    if (copy_tree(childp, out_path) != 0) {
        free(childp);
        free(xdir);
        failc_errno(RC_OUTPUT, "cannot create output", out_path);
        return -1;
    }
    free(childp);
#if BENC_POSIX
    {
        char rmcmd[8192];
        int r;
        snprintf(rmcmd, sizeof rmcmd, "rm -rf '%s'", xdir);
        r = system(rmcmd);
        (void)r;
    }
#elif BENC_WINDOWS
    _rmdir(xdir);
#else
    remove(xdir);
#endif
    free(xdir);
    report_result(o, "Extracted", in_path, out_path, cipher_len, t0, "");
    return 0;

out:
    free(xdir);
    return -1;
}

/* Parse a canonical binary-container header line: "benc|<ver>|...|<size>\n".
 * Field order matches the ASCII header text; salt/nonce/name are base64. */
static int parse_canonical(const char *s, benc_header *h)
{
    char buf[2048];
    char *fields[16];
    size_t flen[16];
    int ntok = 0;
    char *p;
    unsigned long seen = 0;
    uint64_t v;
    int rc;

    memset(h, 0, sizeof *h);
    rc = snprintf(buf, sizeof buf, "%s", s);
    if (rc < 0 || (size_t)rc >= sizeof buf)
        return -1;
    {
        size_t bn = strlen(buf);
        while (bn > 0 && (buf[bn - 1] == '\n' || buf[bn - 1] == '\r'))
            buf[--bn] = '\0';
    }
    p = buf;
    while (ntok < 16) {
        char *bar = strchr(p, '|');
        if (bar)
            *bar = '\0';
        fields[ntok] = p;
        flen[ntok] = (size_t)strlen(p);
        ntok++;
        if (!bar)
            break;
        p = bar + 1;
    }
    if (ntok < 2 || strcmp(fields[0], "benc") != 0)
        return -1;
    if (flen[1] >= 16)
        return -1;
    {
        char ver_s[16];
        ver_s[0] = '\0';
        memcpy(ver_s, fields[1], flen[1]);
        ver_s[flen[1]] = '\0';
        if (dec_to_u64(ver_s, &v) || v < BENC_FMT_LEGACY || v > BENC_FMT_VERSION)
            return -1;
        h->version = (unsigned)v;
    }
    if (h->version > BENC_FMT_LEGACY) {
        /* v4 field order: ver|kdf|iters|cipher|mac|comp|level|threads|input|
         *                 salt|nonce|name|size */
        if (ntok < 14) return -1;
        if (strcmp(fields[2], BENC_KDF_NAME) != 0) return -1;
        if (seen & SEEN_VERSION) return -1;
        seen |= SEEN_VERSION;
        if (dec_to_u64(fields[3], &v) || v == 0 || v > BENC_MAX_ITER)
            return -1;
        h->iterations = (unsigned long)v;
        if (seen & SEEN_KDF) return -1;
        seen |= SEEN_KDF;
        if (seen & SEEN_ITER) return -1;
        seen |= SEEN_ITER;
        if (strcmp(fields[4], BENC_CIPHER_NAME) != 0) return -1;
        if (seen & SEEN_CIPHER) return -1;
        seen |= SEEN_CIPHER;
        if (strcmp(fields[5], BENC_MAC_NAME) != 0) return -1;
        if (seen & SEEN_MAC) return -1;
        seen |= SEEN_MAC;
        if (seen & SEEN_COMP) return -1;
        seen |= SEEN_COMP;
        {
            int id = comp_lookup(fields[6]);
            if (id < 0) return -1;
            h->comp = id;
        }
        if (seen & SEEN_LEVEL) return -1;
        seen |= SEEN_LEVEL;
        if (dec_to_u64(fields[7], &v) || v > 22) return -1;
        h->level = (int)v;
        if (seen & SEEN_THREADS) return -1;
        seen |= SEEN_THREADS;
        if (dec_to_u64(fields[8], &v) || v > BENC_MAX_THREADS) return -1;
        h->threads = (int)v;
        if (seen & SEEN_INPUT) return -1;
        seen |= SEEN_INPUT;
        if (strcmp(fields[9], "tar") == 0)
            h->archive = 1;
        else if (strcmp(fields[9], "file") != 0)
            return -1;
        if (seen & SEEN_SALT) return -1;
        seen |= SEEN_SALT;
        {
            size_t n;
            if (b64_decode(fields[10], h->salt, sizeof h->salt, &n) ||
                n != BENC_SALT_LEN || !b64_is_canonical(fields[10], h->salt, n))
                return -1;
        }
        if (seen & SEEN_NONCE) return -1;
        seen |= SEEN_NONCE;
        {
            size_t n;
            if (b64_decode(fields[11], h->nonce, sizeof h->nonce, &n) ||
                n != BENC_NONCE_LEN || !b64_is_canonical(fields[11], h->nonce, n))
                return -1;
        }
        if (seen & SEEN_NAME) return -1;
        seen |= SEEN_NAME;
        {
            size_t n;
            if (b64_decode(fields[12], (uint8_t *)h->name, BENC_MAX_NAME, &n) ||
                !b64_is_canonical(fields[12], (const uint8_t *)h->name, n))
                return -1;
            h->name[n] = '\0';
            h->name_len = n;
        }
        if (seen & SEEN_SIZE) return -1;
        seen |= SEEN_SIZE;
        if (strcmp(fields[13], "-") != 0) {
            if (dec_to_u64(fields[13], &v))
                return -1;
            h->size = v;
            h->size_known = 1;
        }
    } else {
        /* legacy field order: ver|kdf|iters|salt|nonce|name|size */
        if (ntok < 8) return -1;
        if (strcmp(fields[2], BENC_KDF_NAME) != 0) return -1;
        if (seen & SEEN_VERSION) return -1;
        seen |= SEEN_VERSION;
        if (dec_to_u64(fields[3], &v) || v == 0 || v > BENC_MAX_ITER)
            return -1;
        h->iterations = (unsigned long)v;
        if (seen & SEEN_KDF) return -1;
        seen |= SEEN_KDF;
        if (seen & SEEN_ITER) return -1;
        seen |= SEEN_ITER;
        if (seen & SEEN_SALT) return -1;
        seen |= SEEN_SALT;
        {
            size_t n;
            if (b64_decode(fields[4], h->salt, sizeof h->salt, &n) ||
                n != BENC_SALT_LEN || !b64_is_canonical(fields[4], h->salt, n))
                return -1;
        }
        if (seen & SEEN_NONCE) return -1;
        seen |= SEEN_NONCE;
        {
            size_t n;
            if (b64_decode(fields[5], h->nonce, sizeof h->nonce, &n) ||
                n != BENC_NONCE_LEN || !b64_is_canonical(fields[5], h->nonce, n))
                return -1;
        }
        if (seen & SEEN_NAME) return -1;
        seen |= SEEN_NAME;
        {
            size_t n;
            if (b64_decode(fields[6], (uint8_t *)h->name, BENC_MAX_NAME, &n) ||
                !b64_is_canonical(fields[6], (const uint8_t *)h->name, n))
                return -1;
            h->name[n] = '\0';
            h->name_len = n;
        }
        if (seen & SEEN_SIZE) return -1;
        seen |= SEEN_SIZE;
        if (strcmp(fields[7], "-") != 0) {
            if (dec_to_u64(fields[7], &v))
                return -1;
            h->size = v;
            h->size_known = 1;
        }
    }
    if ((seen & SEEN_REQUIRED) != SEEN_REQUIRED)
        return -1;
    if (h->version > BENC_FMT_LEGACY &&
        (seen & SEEN_V4_REQUIRED) != SEEN_V4_REQUIRED)
        return -1;
    if (h->version <= BENC_FMT_LEGACY) {
        h->comp = COMP_NONE;
        h->level = 0;
        h->threads = 0;
        h->archive = 0;
    }
    return 0;
}

static int cmd_decrypt(const char *in_path, const char *out_path, const opts *o)
{
    FILE *in = NULL, *out = NULL;
    char *tmp = NULL, *mid = NULL, *unz = NULL;
    benc_header h;
    uint8_t enc_key[BENC_KEY_LEN], mac_key[BENC_KEY_LEN];
    char pw[BENC_MAX_PASSWORD + 1], canon[8192];
    const char *lead = "";
    chacha20_ctx cc;
    plain_ctx plain;
    progress pg;
    uint64_t cipher_len = 0, fsize = 0, hdr_end;
    unsigned long t0 = benc_now_ms();
    int rc = RC_ERR, direct = 0, inter = 0, tries, r, post, bin = 0;

    memset(&h, 0, sizeof h);
    memset(pw, 0, sizeof pw);
    memset(&cc, 0, sizeof cc);
    {
        int cr = check_output(in_path, out_path, o);
        if (cr)
            return g_exit ? g_exit : cr;
    }

    in = fopen(in_path, "rb");
    if (!in) {
        failc_errno(RC_INPUT, "cannot open input", in_path);
        goto done;
    }
    {
        char head[8];
        size_t hn = fread(head, 1, sizeof head, in);
        if (hn >= 4 && memcmp(head, "benc|", 4) == 0) {
            bin = 1;
            char canon_bin[2048];
            size_t cn = 0;
            int ch, got = 0;
            benc_fseek(in, 0, SEEK_SET);
            while (!got) {
                ch = fgetc(in);
                if (ch == EOF)
                    break;
                if (ch == '\n') {
                    got = 1;
                    break;
                }
                if (cn < sizeof canon_bin - 1)
                    canon_bin[cn++] = (char)ch;
            }
            canon_bin[cn] = '\0';
            if (parse_canonical(canon_bin, &h)) {
                failc(RC_FORMAT, "invalid binary container header");
                goto done;
            }
            memcpy(canon, canon_bin, cn + 1);
        } else {
            benc_fseek(in, 0, SEEK_SET);
            if (parse_header(in, &h))
                goto done;
        }
    }
    if (h.archive && !o->force && is_directory(out_path)) {
        failc(RC_OUTPUT, "output directory '%s' already exists (use -f to overwrite)",
             out_path);
        goto done;
    }
    hdr_end = (uint64_t)benc_ftell(in);
    if (stream_size(in, &fsize) != 0 || fsize < hdr_end)
        fsize = hdr_end;
    if (header_canonical(&h, canon, sizeof canon)) {
        fail("internal error building header");
        goto done;
    }

    if (o->kem_secret_key) {
        FILE *kf = fopen(o->kem_secret_key, "rb");
        uint8_t sk[BENC_KEM_SECRET_KEY_LEN];
        size_t sklen, nread;
        benc_kem *kem = benc_kem_new("ml-kem-768");
        uint8_t ss[BENC_KEM_SHARED_SECRET_LEN];
        size_t sslen;
        if (!kf || !kem) {
            if (kf) fclose(kf);
            if (kem) benc_kem_free(kem);
            return failc(RC_INPUT, "cannot open KEM secret key");
        }
        nread = fread(sk, 1, sizeof sk, kf);
        fclose(kf);
        sklen = nread;
        if (benc_kem_decapsulate(kem, ss, &sslen, h.kem_ct, h.kem_ct_len, sk, sklen)) {
            benc_kem_free(kem);
            return failc(RC_AUTH, "wrong key, or the file has been modified");
        }
        memcpy(g_kem_ss, ss, sslen);
        g_kem_ss_len = sslen;
        benc_kem_free(kem);
        if (h.mode == 2) {
            int pr = get_password(o, pw, sizeof pw, 0, lead, &inter);
            if (pr) goto done;
        } else {
            pw[0] = '\0';
        }
        progress_begin(&pg, "Deriving key", 0, 0);
        derive_keys(pw, &h, enc_key, mac_key, &pg, g_kem_ss, g_kem_ss_len);
        progress_finish(&pg);
        /* verify */
        if (bin)
            r = verify_bin(in, canon, (size_t)strlen(canon), mac_key, fsize - hdr_end, &cipher_len);
        else
            r = verify_pass(in, &h, canon, mac_key, fsize - hdr_end, hdr_end, &cipher_len);
        if (r != RC_OK) {
            rc = r;
            failc(r, "wrong key, or the file has been modified");
            goto done;
        }
        tries = BENC_MAX_TRIES; /* skip loop */
    } else {
    for (tries = 0; tries < BENC_MAX_TRIES; tries++) {
        if (get_password(o, pw, sizeof pw, 0, lead, &inter))
            goto done;
        progress_begin(&pg, "Deriving key", 0, 0);
        derive_keys(pw, &h, enc_key, mac_key, &pg, NULL, 0);
        progress_finish(&pg);
        benc_wipe(pw, sizeof pw);

        if (bin)
            r = verify_bin(in, canon, (size_t)strlen(canon), mac_key,
                           fsize - hdr_end, &cipher_len);
        else
            r = verify_pass(in, &h, canon, mac_key, fsize - hdr_end, hdr_end,
                            &cipher_len);
        if (r == RC_OK)
            break;
        if (r == RC_AUTH) {
            if (inter && tries + 1 < BENC_MAX_TRIES &&
                benc_fseek(in, (benc_off_t)hdr_end, SEEK_SET) == 0) {
                lead = "Wrong password. ";
                continue;
            }
            rc = RC_AUTH;
            failc(RC_AUTH, "wrong password, or the file has been modified");
        }
        goto done;
    }
    if (!o->kem_secret_key) {
    if (tries == BENC_MAX_TRIES)
        goto done;
    }
    }

    /* pass 2: decrypt */
    if (benc_fseek(in, (benc_off_t)hdr_end, SEEK_SET) != 0) {
        failc(RC_INPUT, "cannot rewind input");
        goto done;
    }
    post = (h.comp != COMP_NONE || h.archive);
    if (post) {
        mid = stage_path(out_path, "dec");
        if (!mid) {
            failc(RC_OUTPUT, "cannot create a temporary file next to '%s'", out_path);
            goto done;
        }
        out = fopen(mid, "wb");
        if (!out) {
            failc_errno(RC_OUTPUT, "cannot create temporary file", mid);
            goto done;
        }
    } else {
        out = open_output(out_path, &tmp, &direct);
        if (!out) {
            failc_errno(RC_OUTPUT, "cannot create output", tmp ? tmp : out_path);
            goto done;
        }
    }
    chacha20_init(&cc, enc_key, h.nonce);
    plain.cc = &cc;
    plain.fp = out;
    plain.remaining = cipher_len;

    progress_begin(&pg, "Decrypting", fsize, 1);
    if (bin) {
        uint8_t dbuf[BENC_CHUNK];
        uint64_t rem = cipher_len;

        if (benc_fseek(in, (benc_off_t)hdr_end, SEEK_SET) != 0) {
            failc(RC_INPUT, "cannot rewind input");
            goto done;
        }
        while (rem > 0) {
            size_t n = (size_t)(rem > BENC_CHUNK ? BENC_CHUNK : rem);
            if (fread(dbuf, 1, n, in) != n) {
                failc(RC_FORMAT, "file is truncated");
                goto done;
            }
            if (plain_push(&plain, dbuf, n)) {
                failc(RC_OUTPUT, "cannot write output");
                goto done;
            }
            rem -= n;
        }
        if (plain.remaining != 0) {
            failc(RC_FORMAT, "file is truncated");
            goto done;
        }
    } else if (read_body(in, plain_push, &plain, &pg, hdr_end)) {
        goto done;
    }
    progress_finish(&pg);
    if (!post) {
        if (commit_output(&out, tmp, direct, out_path))
            goto done;
        report_result(o, "Decrypted", in_path, out_path, cipher_len, t0, "");
        rc = RC_OK;
        goto done;
    }

    /* staged plaintext: decompress, then unpack or rename into place */
    if (fclose(out) != 0) {
        out = NULL;
        failc(RC_OUTPUT, "cannot write output");
        goto done;
    }
    out = NULL;
    {
        const char *payload = mid;

        if (h.comp != COMP_NONE) {
            unz = stage_path(out_path, "unz");
            if (!unz) {
                failc(RC_OUTPUT, "cannot create a temporary file next to '%s'", out_path);
                goto done;
            }
            if (run_codec(h.comp, 0, h.threads, mid, unz, 1))
                goto done;
            payload = unz;
        }
        if (h.archive) {
            if (decrypt_unpack_archive(payload, in_path, out_path, &h, o, t0,
                                      cipher_len))
                goto done;
        } else {
            if (rename_over(payload, out_path) != 0) {
                failc_errno(RC_OUTPUT, "cannot create output", out_path);
                goto done;
            }
            report_result(o, "Decrypted", in_path, out_path, cipher_len, t0,
                          "");
        }
    }
    rc = RC_OK;

done:
    benc_wipe(pw, sizeof pw);
    benc_wipe(enc_key, sizeof enc_key);
    benc_wipe(mac_key, sizeof mac_key);
    benc_wipe(canon, sizeof canon);
    benc_wipe(&cc, sizeof cc);
    if (out)
        fclose(out);
    if (in)
        fclose(in);
    if (rc != RC_OK && tmp) {
        remove(tmp);
        set_tmp(NULL);
    }
    free(tmp);
    if (mid) {
        remove(mid);
        free(mid);
    }
    if (unz) {
        remove(unz);
        free(unz);
    }
    stage_forget();
    if (rc == RC_ERR && g_exit)
        rc = g_exit;
    return rc;
}

/* ------------------------------------------------------------------ */
/* info                                                                */
/* ------------------------------------------------------------------ */

static int cmd_info(const char *path)
{
    FILE *in = fopen(path, "rb");
    benc_header h;
    uint64_t body = 0;
    char num[24];
    char canon_bin[2048];
    int bin = 0;

    if (!in)
        return failc_errno(RC_INPUT, "cannot open input", path);
    {
        char head[8];
        size_t hn = fread(head, 1, sizeof head, in);
        if (hn >= 4 && memcmp(head, "benc|", 4) == 0) {
            bin = 1;
            size_t cn = 0;
            int ch, got = 0;
            benc_fseek(in, 0, SEEK_SET);
            while (!got) {
                ch = fgetc(in);
                if (ch == EOF)
                    break;
                if (ch == '\n') {
                    got = 1;
                    break;
                }
                if (cn < sizeof canon_bin - 1)
                    canon_bin[cn++] = (char)ch;
            }
            canon_bin[cn] = '\0';
            if (parse_canonical(canon_bin, &h)) {
                fclose(in);
                return failc(RC_FORMAT, "invalid binary container header");
            }
        } else {
            benc_fseek(in, 0, SEEK_SET);
            if (parse_header(in, &h)) {
                fclose(in);
                return g_exit ? g_exit : RC_FORMAT;
            }
        }
    }
    if (bin) {
        /* binary container: body is the rest of the file (payload + tag) */
        uint64_t fsize = 0;
        uint64_t hdr_end = (uint64_t)benc_ftell(in);
        if (stream_size(in, &fsize) == 0 && fsize >= hdr_end)
            body = fsize - hdr_end;
        else
            body = 0;
    } else {
        if (read_body(in, count_push, &body, NULL, 0)) {
            fclose(in);
            return failc(RC_FORMAT, "not a benc file (missing begin marker)");
        }
    }
    fclose(in);

    printf("File:            %s\n", path);
    printf("Format version:  %u\n", h.version);
    u64_to_dec((uint64_t)h.iterations, num);
    printf("KDF:             %s, %s iterations\n", BENC_KDF_NAME, num);
    printf("Cipher:          %s\n", BENC_CIPHER_NAME);
    printf("MAC:             %s\n", BENC_MAC_NAME);
    printf("Compression:     %s\n", comp_specs[h.comp].name);
    if (h.version > BENC_FMT_LEGACY) {
        printf("Compression level: %d\n", h.level);
        if (h.threads > 0)
            printf("Compression threads: %d\n", h.threads);
        else
            printf("Compression threads: auto (all cores)\n");
        printf("Input:           %s\n",
               h.archive ? "directory archive (tar)" : "file");
    }
    printf("Original name:   %s\n", h.name_len ? h.name : "(not stored)");
    if (h.size_known) {
        u64_to_dec(h.size, num);
        if (h.version > BENC_FMT_LEGACY)
            printf("Stored size:     %s bytes (plaintext after compression)\n",
                   num);
        else
            printf("Original size:   %s bytes\n", num);
    } else {
        printf("Original size:   (not stored)\n");
    }
    if (body >= BENC_TAG_LEN) {
        u64_to_dec(body - BENC_TAG_LEN, num);
        printf("Ciphertext size: %s bytes\n", num);
    }
    return RC_OK;
}

/* ------------------------------------------------------------------ */
/* self test (one updating status line)                                */
/* ------------------------------------------------------------------ */

static void hex(const uint8_t *p, size_t n, char *out)
{
    static const char d[] = "0123456789abcdef";
    size_t i;

    for (i = 0; i < n; i++) {
        out[2 * i] = d[p[i] >> 4];
        out[2 * i + 1] = d[p[i] & 15];
    }
    out[2 * n] = '\0';
}

static int g_fails, g_tests;

static void check(const char *name, int ok)
{
    char line[96];

    g_tests++;
    if (!ok) {
        g_fails++;
        ui_final("selftest: FAIL %s", name);
        return;
    }
    snprintf(line, sizeof line, "selftest: %s ok", name);
    ui_draw(line);
}

static void check_hex(const char *name, const uint8_t *got, size_t n,
                      const char *want)
{
    char h[200];

    hex(got, n, h);
    check(name, strcmp(h, want) == 0);
}

static int run_selftest(void)
{
    uint8_t d[64], big[200];
    size_t i;

    b64_init();
    {
        sha256_ctx s;
        sha256_init(&s);
        sha256_update(&s, "abc", 3);
        sha256_final(&s, d);
        check_hex("sha256 abc", d, 32,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        sha256_init(&s);
        sha256_final(&s, d);
        check_hex("sha256 empty", d, 32,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        sha256_init(&s);
        sha256_update(&s, "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", 56);
        sha256_final(&s, d);
        check_hex("sha256 56 bytes", d, 32,
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
        /* chunked updates must equal one shot */
        for (i = 0; i < sizeof big; i++)
            big[i] = (uint8_t)i;
        sha256_init(&s);
        sha256_update(&s, big, 1);
        sha256_update(&s, big + 1, 70);
        sha256_update(&s, big + 71, 129);
        sha256_final(&s, d);
        {
            uint8_t e[32];
            sha256_init(&s);
            sha256_update(&s, big, sizeof big);
            sha256_final(&s, e);
            check("sha256 chunking", memcmp(d, e, 32) == 0);
        }
    }
    {
        uint8_t key[131];
        memset(key, 0x0b, 20);
        {
            hmac_ctx h;
            hmac_init(&h, key, 20);
            hmac_update(&h, "Hi There", 8);
            hmac_final(&h, d);
            check_hex("hmac-sha256 rfc4231 #1", d, 32,
                "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
            hmac_init(&h, (const uint8_t *)"Jefe", 4);
            hmac_update(&h, "what do ya want for nothing?", 28);
            hmac_final(&h, d);
            check_hex("hmac-sha256 rfc4231 #2", d, 32,
                "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
            memset(key, 0xaa, sizeof key);
            hmac_init(&h, key, sizeof key);
            hmac_update(&h, "Test Using Larger Than Block-Size Key - Hash Key First", 54);
            hmac_final(&h, d);
            check_hex("hmac-sha256 long key", d, 32,
                "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");
        }
    }
    pbkdf2_sha256((const uint8_t *)"password", 8, (const uint8_t *)"salt", 4, 1, d, 32, NULL);
    check_hex("pbkdf2 c=1", d, 32,
        "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b");
    pbkdf2_sha256((const uint8_t *)"password", 8, (const uint8_t *)"salt", 4, 2, d, 32, NULL);
    check_hex("pbkdf2 c=2", d, 32,
        "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43");
    pbkdf2_sha256((const uint8_t *)"password", 8, (const uint8_t *)"salt", 4, 4096, d, 32, NULL);
    check_hex("pbkdf2 c=4096", d, 32,
        "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a");
    pbkdf2_sha256((const uint8_t *)"password", 8, (const uint8_t *)"salt", 4, 3, d, 64, NULL);
    check_hex("pbkdf2 64 byte output", d, 64,
        "ad35240ac683febfaf3cd49d845473fbbbaa2437f5f82d5a415ae00ac76c6bfc"
        "cf9a9b8d6d2fe4a1e700c4460b040dbed692c1cb85a747f35588c08930fcfc41");
    {
        uint8_t pw[100];
        memset(pw, 'p', sizeof pw);
        pbkdf2_sha256(pw, sizeof pw, (const uint8_t *)"0123456789abcdef", 16, 5, d, 64, NULL);
        check_hex("pbkdf2 long password", d, 64,
            "b698ed05c59f66835863739b755a39662f03ef345b7803fd46cb24903d70a09c"
            "d3b10e51fb0cc454b047a29f308c8257c086355df17482ed54d113549db01213");
    }
    {
        uint32_t st[16], out[16];
        static const uint32_t expect[16] = {
            0xe4e7f110u, 0x15593bd1u, 0x1fdd0f50u, 0xc47120a3u,
            0xc7f4d1c7u, 0x0368c033u, 0x9aaa2204u, 0x4e6cd4c3u,
            0x466482d2u, 0x09aa9f07u, 0x05d7c214u, 0xa2028bd9u,
            0xd19c12b5u, 0xb94e16deu, 0xe883d0cbu, 0x4e3c50a2u
        };
        int ok = 1;
        st[0] = 0x61707865u; st[1] = 0x3320646eu;
        st[2] = 0x79622d32u; st[3] = 0x6b206574u;
        for (i = 0; i < 8; i++)
            st[4 + i] = 0x03020100u + (uint32_t)i * 0x04040404u;
        st[12] = 1u; st[13] = 0x09000000u; st[14] = 0x4a000000u; st[15] = 0u;
        chacha20_block(out, st);
        for (i = 0; i < 16; i++)
            if (out[i] != expect[i])
                ok = 0;
        check("chacha20 rfc7539 block", ok);
    }
    {
        uint8_t key[32], nonce[8], a[300], b[300];
        chacha20_ctx c1, c2;
        size_t off = 0;
        static const size_t steps[] = { 1, 63, 64, 65, 3, 100, 4 };

        for (i = 0; i < 32; i++)
            key[i] = (uint8_t)(i * 7);
        for (i = 0; i < 8; i++)
            nonce[i] = (uint8_t)(i + 1);
        memset(a, 0, sizeof a);
        memset(b, 0, sizeof b);
        chacha20_init(&c1, key, nonce);
        chacha20_xor(&c1, a, sizeof a);
        chacha20_init(&c2, key, nonce);
        for (i = 0; off < sizeof b; i++) {
            size_t s = steps[i % (sizeof steps / sizeof steps[0])];
            if (s > sizeof b - off)
                s = sizeof b - off;
            chacha20_xor(&c2, b + off, s);
            off += s;
        }
        check("chacha20 odd chunk sizes", memcmp(a, b, sizeof a) == 0);
    }
    {
        static const struct { const char *p, *e; } v[] = {
            { "", "" }, { "f", "Zg==" }, { "fo", "Zm8=" }, { "foo", "Zm9v" },
            { "foob", "Zm9vYg==" }, { "fooba", "Zm9vYmE=" },
            { "foobar", "Zm9vYmFy" }
        };
        int ok = 1;
        char enc[32];
        uint8_t dec[32];
        size_t n;

        for (i = 0; i < sizeof v / sizeof v[0]; i++) {
            if (b64_encode_string((const uint8_t *)v[i].p, strlen(v[i].p), enc,
                                  sizeof enc) || strcmp(enc, v[i].e) != 0)
                ok = 0;
            if (b64_decode(v[i].e, dec, sizeof dec, &n) || n != strlen(v[i].p) ||
                memcmp(dec, v[i].p, n) != 0)
                ok = 0;
        }
        if (!b64_decode("Zg=", dec, sizeof dec, &n)) ok = 0;
        if (!b64_decode("Zg==Zg==", dec, sizeof dec, &n)) ok = 0;
        if (!b64_decode("Z!==", dec, sizeof dec, &n)) ok = 0;
        check("base64 rfc4648", ok);
    }
    if (g_fails) {
        ui_final("selftest: %d of %d tests FAILED", g_fails, g_tests);
        return RC_SELFTEST;
    }
    ui_final("selftest: all %d tests passed", g_tests);
    return 0;
}

/* ------------------------------------------------------------------ */
/* command line                                                        */
/* ------------------------------------------------------------------ */

static void usage(FILE *fp)
{
    fprintf(fp,
        "%s %s - portable password based file encryption\n"
        "\n"
        "Usage:\n"
        "  %s [options] <input> [output]        encrypt or decrypt (auto)\n"
        "  %s encrypt [options] <input> [output]\n"
        "  %s decrypt [options] <input> [output]\n"
        "  %s info <file>\n"
        "  %s selftest\n"
        "\n"
        "Commands:\n"
        "  (no command)       Detect by the BENC header and do the right thing\n"
        "  encrypt, enc, e    Encrypt <input> into a text file (default %s)\n"
        "  decrypt, dec, d    Decrypt a benc text file (default %s)\n"
        "  info               Show container header (password not required)\n"
        "  selftest           Run built-in cryptographic self tests\n"
        "\n"
        "Options:\n"
        "  -o, --output FILE      Write the result to FILE\n"
        "  -p, --password PASS    Use PASS (insecure: visible in process list)\n"
        "  -P, --password-file F  Read the password from the first line of F\n"
        "  -i, --iterations N     PBKDF2 iterations (default %lu)\n"
        "  -c, --compress NAME    Compress before encrypting: lzma2 (default),\n"
        "                         zstd, none\n"
        "      --no-compress      Same as --compress none\n"
        "  -b, --binout           Write a tight binary container (default)\n"
        "  -t, --textout          Write the ASCII text/base64 container instead\n"
        "  -l, --level N          Compression level (codec default when omitted)\n"
        "  -T, --threads N        Worker threads for the compressor (0 = all)\n"
        "  -f, --force            Overwrite an existing output file\n"
        "  -n, --use-header-name  On decrypt, restore the stored file name\n"
        "  -q, --quiet            No progress and no result message\n"
        "  -h, --help             Show this help\n"
        "  -v, --version          Show version\n"
        "\n"
        "A directory is packed into a tar archive before it is encrypted, and\n"
        "unpacked again after decryption.  Compression uses the built-in\n"
        "native codec (lzma2 or zstd).\n"
        "\n"
        "While working the program uses a single terminal line for the\n"
        "password prompt, progress and result.\n"
        "\n"
        "Container format:\n"
        "  PBKDF2-HMAC-SHA256 keys, ChaCha20 encryption, HMAC-SHA256 tag.\n"
        "  The output is a plain ASCII text file (.bct) or a tight binary\n"
        "  container (.bcb with --binout).\n",
        BENC_NAME, BENC_VERSION, BENC_NAME, BENC_NAME, BENC_NAME, BENC_NAME,
        BENC_NAME,
#if BENC_DOS
        "<input>.BCT", "the stored name",
#else
        "<input>.bct", "strips .bct",
#endif
        BENC_DEFAULT_ITER);
}

static int parse_iter(const char *s, unsigned long *out)
{
    uint64_t v;

    if (dec_to_u64(s, &v) || v == 0 || v > BENC_MAX_ITER)
        return failc(RC_USAGE, "invalid iteration count");
    *out = (unsigned long)v;
    return 0;
}

/* returns 0 ok, 1 error, 2 handled (help/version) */
static int parse_options(int argc, char **argv, int start, opts *o,
                         const char **pos, int *npos)
{
    int i;

    *npos = 0;
    for (i = start; i < argc; i++) {
        const char *a = argv[i];
        const char *val = NULL;
        char name[32];
        size_t nl;

        if (strcmp(a, "--") == 0) {
            for (i++; i < argc; i++)
                if (*npos < 4)
                    pos[(*npos)++] = argv[i];
            break;
        }
        if (a[0] != '-' || a[1] == '\0') {
            if (*npos >= 4)
                return failc(RC_USAGE, "too many arguments");
            pos[(*npos)++] = a;
            continue;
        }
        /* split --name=value */
        nl = strcspn(a, "=");
        if (a[1] == '-' && a[nl] == '=') {
            if (nl >= sizeof name)
                return failc(RC_USAGE, "unknown option '%s'", a);
            memcpy(name, a, nl);
            name[nl] = '\0';
            val = a + nl + 1;
            a = name;
        }
#define NEED_VALUE()                                                   \
        do {                                                           \
            if (!val) {                                                \
                if (++i >= argc)                                       \
                    return failc(RC_USAGE, "missing value for %s", a);            \
                val = argv[i];                                         \
            }                                                          \
        } while (0)

        if (!strcmp(a, "-o") || !strcmp(a, "--output")) {
            NEED_VALUE(); o->output = val;
        } else if (!strcmp(a, "-p") || !strcmp(a, "--password")) {
            NEED_VALUE(); o->password = val;
        } else if (!strcmp(a, "-P") || !strcmp(a, "--password-file")) {
            NEED_VALUE(); o->password_file = val;
        } else if (!strcmp(a, "-i") || !strcmp(a, "--iterations")) {
            NEED_VALUE();
            if (parse_iter(val, &o->iterations))
                return 1;
        } else if (!strcmp(a, "-c") || !strcmp(a, "--compress") ||
                   !strcmp(a, "--compression")) {
            int id;
            NEED_VALUE();
            id = comp_lookup(val);
            if (id < 0)
                return failc(RC_USAGE, "unknown compression '%s' (lzma2, zstd, none)",
                            val);
            o->compress = id;
        } else if (!strcmp(a, "--no-compress")) {
            o->compress = COMP_NONE;
        } else if (!strcmp(a, "-b") || !strcmp(a, "-B") || !strcmp(a, "--binout")) {
            o->binout = 1;
        } else if (!strcmp(a, "-t") || !strcmp(a, "--textout")) {
            o->binout = 0;
        } else if (!strcmp(a, "-l") || !strcmp(a, "--level")) {
            uint64_t lv;
            NEED_VALUE();
            if (dec_to_u64(val, &lv) || lv > 22)
                return failc(RC_USAGE, "invalid compression level");
            o->level = (int)lv;
        } else if (!strcmp(a, "-T") || !strcmp(a, "--threads")) {
            uint64_t th;
            NEED_VALUE();
            if (dec_to_u64(val, &th) || th > BENC_MAX_THREADS)
                return failc(RC_USAGE, "invalid thread count");
            o->threads = (long)th;
        } else if (!strcmp(a, "-f") || !strcmp(a, "--force")) {
            o->force = 1;
        } else if (!strcmp(a, "-n") || !strcmp(a, "--use-header-name")) {
            o->use_header_name = 1;
        } else if (!strcmp(a, "--no-name")) {
            o->no_name = 1;
        } else if (!strcmp(a, "-k") || !strcmp(a, "--kem")) {
            NEED_VALUE();
            o->kem_pub_key = val;
        } else if (!strcmp(a, "--key")) {
            NEED_VALUE();
            o->kem_secret_key = val;
        } else if (!strcmp(a, "--hybrid")) {
            o->kem_mode = 2;
        } else if (!strcmp(a, "--keygen")) {
            o->keygen = 1;
        } else if (!strcmp(a, "-q") || !strcmp(a, "--quiet")) {
            o->quiet = 1;
        } else if (!strcmp(a, "-h") || !strcmp(a, "--help")) {
            usage(stdout);
            return 2;
        } else if (!strcmp(a, "-v") || !strcmp(a, "--version")) {
            printf("%s %s\n", BENC_NAME, BENC_VERSION);
            return 2;
        } else {
            return failc(RC_USAGE, "unknown option '%s'", a);
        }
#undef NEED_VALUE
    }
    return 0;
}

/* 1 = text BENC container, 2 = binary BENC container, 0 = not a container,
 * -1 = unreadable */
static int detect_container(const char *path)
{
    FILE *fp = fopen(path, "rb");
    char line[64];
    int r;

    if (!fp)
        return -1;
    {
        char head[8];
        size_t hn = fread(head, 1, sizeof head, fp);
        if (hn >= 4 && memcmp(head, "benc|", 4) == 0) {
            fclose(fp);
            return 2;
        }
        if (benc_fseek(fp, 0, SEEK_SET) != 0) {
            fclose(fp);
            return -1;
        }
    }
    r = read_line(fp, line, sizeof line);
    fclose(fp);
    return r == 1 && strcmp(line, BENC_BEGIN_FILE) == 0;
}

typedef enum { C_AUTO, C_ENC, C_DEC, C_INFO, C_TEST, C_HELP } cmd_t;

static cmd_t resolve_command(const char *s, int *consumed)
{
    *consumed = 1;
    if (!strcmp(s, "encrypt") || !strcmp(s, "enc") || !strcmp(s, "e")) return C_ENC;
    if (!strcmp(s, "decrypt") || !strcmp(s, "dec") || !strcmp(s, "d")) return C_DEC;
    if (!strcmp(s, "info")) return C_INFO;
    if (!strcmp(s, "selftest")) return C_TEST;
    if (!strcmp(s, "help")) return C_HELP;
    *consumed = 0;
    return C_AUTO;
}

int main(int argc, char **argv)
{
    const char *pos[4];
    const char *in_path, *out_path;
    char *allocated = NULL;
    opts o;
    cmd_t cmd = C_AUTO;
    int npos = 0, consumed = 0, rc, mode_dec = 0, i;

    b64_init();
    g_exit = 0;
    if (argc < 2) {
        usage(stderr);
        return RC_USAGE;
    }
    for (i = 1; i < argc; i++)
        if (!strcmp(argv[i], "-q") || !strcmp(argv[i], "--quiet"))
            break;
    ui_init(i < argc);
    install_signals();

    cmd = resolve_command(argv[1], &consumed);
    if (cmd == C_HELP) {
        usage(stdout);
        return 0;
    }
    if (cmd == C_TEST)
        return run_selftest();

    memset(&o, 0, sizeof o);
    o.iterations = BENC_DEFAULT_ITER;
    o.compress = COMP_LZMA2;
    o.level = -1;
    o.threads = 0;
    o.binout = 1;
    rc = parse_options(argc, argv, 1 + consumed, &o, pos, &npos);
    if (rc == 2)
        return 0;
    if (rc)
        return g_exit ? g_exit : RC_USAGE;
    ui_init(o.quiet);

    if (o.keygen) {
        const char *base = o.output ? o.output : "kem";
        benc_kem *kem = benc_kem_new("ml-kem-768");
        uint8_t pk[BENC_KEM_PUBLIC_KEY_LEN], sk[BENC_KEM_SECRET_KEY_LEN];
        size_t pklen, sklen;
        char path[1024];
        FILE *f;
        if (!kem) return failc(RC_UNSUPPORTED, "KEM not available");
        if (benc_kem_keypair(kem, pk, &pklen, sk, &sklen)) {
            benc_kem_free(kem);
            return failc(RC_ERR, "key generation failed");
        }
        snprintf(path, sizeof path, "%s.pub", base);
        f = fopen(path, "wb");
        if (f) { fwrite(pk,1,pklen,f); fclose(f); }
        snprintf(path, sizeof path, "%s.priv", base);
        f = fopen(path, "wb");
        if (f) { fwrite(sk,1,sklen,f); fclose(f); }
        benc_kem_free(kem);
        printf("Generated key pair: %s.pub / %s.priv\n", base, base);
        return RC_OK;
    }

    if (cmd == C_INFO) {
        if (npos != 1)
            return failc(RC_USAGE, "info requires exactly one file");
        return cmd_info(pos[0]);
    }
    if (npos < 1 || npos > 2)
        return failc(RC_USAGE, cmd == C_AUTO ? "expected <input> [output]"
                                  : "expected <input> [output] after the command");
    in_path = pos[0];
    if (o.output && npos == 2)
        return failc(RC_USAGE, "output given twice");
    out_path = o.output ? o.output : (npos == 2 ? pos[1] : NULL);

    if (cmd == C_AUTO) {
        int is_ctr = detect_container(in_path);
        if (is_ctr < 0)
            return failc_errno(RC_INPUT, "cannot open input", in_path);
        mode_dec = (is_ctr == 1 || is_ctr == 2);
    } else {
        mode_dec = (cmd == C_DEC);
    }

    if (!out_path) {
        if (!mode_dec) {
            allocated = o.binout ? default_binary_output(in_path)
                                 : default_encrypt_output(in_path);
        } else {
            benc_header probe;
            FILE *fp;

            if (o.use_header_name
#if BENC_DOS
                || 1
#endif
                ) {
                fp = fopen(in_path, "rb");
                if (!fp)
                    return failc_errno(RC_INPUT, "cannot open input", in_path);
                if (parse_header(fp, &probe)) {
                    fclose(fp);
                    return g_exit ? g_exit : RC_FORMAT;
                }
                fclose(fp);
                if (probe.name_len)
                    allocated = stored_name_output(in_path, probe.name);
            }
            if (!allocated)
                allocated = default_decrypt_output(in_path);
        }
        if (!allocated)
            return failc(RC_NOMEM, "out of memory");
        out_path = allocated;
    }

    rc = mode_dec ? cmd_decrypt(in_path, out_path, &o)
                  : cmd_encrypt(in_path, out_path, &o);
    free(allocated);
    return rc;
}
