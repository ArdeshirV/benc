/* benc_platform.h - platform abstraction layer for benc */

#ifndef BENC_PLATFORM_H
#define BENC_PLATFORM_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ---------------------------------------------------------------- */
/* feature macros                                                    */
/* ---------------------------------------------------------------- */

#if defined(_WIN32)
#  define BENC_WINDOWS 1
#  define BENC_POSIX   0
#  define BENC_DOS     0
#elif defined(__DJGPP__) || defined(__MSDOS__) || defined(_DOS) || defined(__ia16__)
#  define BENC_WINDOWS 0
#  define BENC_POSIX   0
#  define BENC_DOS     1
#else
#  define BENC_WINDOWS 0
#  define BENC_POSIX   1
#  define BENC_DOS     0
#endif

#if BENC_WINDOWS
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#  include <io.h>
#  include <fcntl.h>
#elif BENC_POSIX
#  include <unistd.h>
#  include <sys/types.h>
#  include <sys/stat.h>
#  include <sys/time.h>
#  include <sys/ioctl.h>
#  include <sys/wait.h>
#  include <fcntl.h>
#  include <dirent.h>
#  include <termios.h>
#elif BENC_DOS
#  include <unistd.h>
#endif

/* ---------------------------------------------------------------- */
/* integer types                                                     */
/* ---------------------------------------------------------------- */

#if BENC_WINDOWS
typedef __int64 benc_off_t;
#  define benc_fseek(fp, off, wh) _fseeki64((fp), (off), (wh))
#  define benc_ftell(fp)          _ftelli64(fp)
#elif BENC_POSIX
typedef off_t benc_off_t;
#  define benc_fseek(fp, off, wh) fseeko((fp), (benc_off_t)(off), (wh))
#  define benc_ftell(fp)          ((benc_off_t)ftello(fp))
#else
typedef long benc_off_t;
#  define benc_fseek(fp, off, wh) fseek((fp), (long)(off), (wh))
#  define benc_ftell(fp)          ((benc_off_t)ftell(fp))
#endif

/* ---------------------------------------------------------------- */
/* time                                                              */
/* ---------------------------------------------------------------- */

static inline unsigned long benc_now_ms(void)
{
#if BENC_WINDOWS
    return (unsigned long)GetTickCount();
#elif BENC_POSIX
    struct timeval tv;
    if (gettimeofday(&tv, NULL) != 0)
        return 0;
    return (unsigned long)tv.tv_sec * 1000ul + (unsigned long)(tv.tv_usec / 1000);
#elif BENC_DOS
    return (unsigned long)((unsigned long)clock() * 1000ul / (unsigned long)CLOCKS_PER_SEC);
#else
    return (unsigned long)time(NULL) * 1000ul;
#endif
}

/* ---------------------------------------------------------------- */
/* terminal                                                          */
/* ---------------------------------------------------------------- */

static inline int benc_isatty(int fd)
{
#if BENC_WINDOWS
    return _isatty(fd);
#else
    return isatty(fd);
#endif
}

static inline int benc_get_terminal_width(void)
{
#if BENC_WINDOWS
    CONSOLE_SCREEN_BUFFER_INFO ci;
    if (GetConsoleScreenBufferInfo(GetStdHandle(STD_ERROR_HANDLE), &ci))
        return ci.srWindow.Right - ci.srWindow.Left + 1;
    return 0;
#elif BENC_POSIX
    int w = 0;
#ifdef TIOCGWINSZ
    struct winsize ws;
    if (ioctl(2, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0)
        w = ws.ws_col;
#endif
    if (w <= 0) {
        const char *c = getenv("COLUMNS");
        if (c)
            w = atoi(c);
    }
    return w;
#else
    return 0;
#endif
}

/* ---------------------------------------------------------------- */
/* random bytes                                                       */
/* ---------------------------------------------------------------- */

int benc_random(uint8_t *buf, size_t len);

/* ---------------------------------------------------------------- */
/* file operations                                                    */
/* ---------------------------------------------------------------- */

static inline int benc_file_exists(const char *path)
{
    FILE *fp = fopen(path, "rb");
    if (fp) {
        fclose(fp);
        return 1;
    }
    return 0;
}

static inline int benc_is_regular_file(const char *path)
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

static inline int benc_is_directory(const char *path)
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

static inline int benc_same_file(const char *a, const char *b)
{
#if BENC_POSIX
    struct stat sa, sb;
    if (stat(a, &sa) == 0 && stat(b, &sb) == 0)
        return sa.st_dev == sb.st_dev && sa.st_ino == sb.st_ino;
    return strcmp(a, b) == 0;
#else
    return strcmp(a, b) == 0;
#endif
}

static inline int benc_stream_size(FILE *fp, uint64_t *size)
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

/* ---------------------------------------------------------------- */
/* path utilities                                                     */
/* ---------------------------------------------------------------- */

static inline int benc_is_sep(char c)
{
    return c == '/' || c == '\\';
}

static inline const char *benc_base_name(const char *path)
{
    const char *p, *b = path;
    for (p = path; *p; p++)
        if (benc_is_sep(*p))
            b = p + 1;
    return b;
}

/* ---------------------------------------------------------------- */
/* temporary files                                                    */
/* ---------------------------------------------------------------- */

const char *benc_ram_temp_dir(void);

static int benc_copy_file(const char *from, const char *to);

static inline int benc_rename_over(const char *from, const char *to)
{
#if BENC_WINDOWS || !BENC_POSIX
    remove(to);
    return rename(from, to);
#else
    if (rename(from, to) == 0)
        return 0;
    /* staging lives in RAM (/dev/shm) but the target is on disk: copy */
    if (benc_copy_file(from, to) == 0) {
        remove(from);
        return 0;
    }
    return -1;
#endif
}

#if BENC_POSIX
static int benc_copy_file(const char *from, const char *to)
{
    FILE *in = fopen(from, "rb");
    FILE *out;
    unsigned char buf[65536];
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

/* ---------------------------------------------------------------- */
/* signals (POSIX only)                                               */
/* ---------------------------------------------------------------- */

#if BENC_POSIX
void benc_install_signals(void);
void benc_save_terminal(void);
void benc_restore_terminal(void);
#else
static inline void benc_install_signals(void) { }
static inline void benc_save_terminal(void) { }
static inline void benc_restore_terminal(void) { }
#endif

/* ---------------------------------------------------------------- */
/* secure memory wipe                                                 */
/* ---------------------------------------------------------------- */

static inline void benc_wipe(void *p, size_t n)
{
    volatile uint8_t *q = (volatile uint8_t *)p;
    while (n--)
        *q++ = 0;
}

/* ---------------------------------------------------------------- */
/* endian helpers                                                     */
/* ---------------------------------------------------------------- */

static inline uint32_t benc_be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static inline void benc_put_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static inline uint32_t benc_le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static inline void benc_put_le32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v;
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

#endif /* BENC_PLATFORM_H */
