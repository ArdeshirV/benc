/* benc_tar.c - self contained tar create/extract for benc directory payloads. */

#if !defined(_WIN32) && !defined(__DJGPP__) && !defined(__MSDOS__) && \
    !defined(_DOS)
#  ifndef _POSIX_C_SOURCE
#    define _POSIX_C_SOURCE 200809L
#  endif
#  define BC_TAR_POSIX 1
#endif

#include "benc_tar.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#if defined(BC_TAR_POSIX)
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>

#define BC_TAR_BLOCK 512
#define BC_TAR_NAME_MAX 1024

static int tar_header_write(FILE *out, const char *name, size_t size, int typeflag,
                            const char *linkname)
{
    char h[512];
    unsigned long sum = 0;
    int i;

    memset(h, 0, sizeof h);
    {
        size_t n = strlen(name);
        if (n > 100)
            n = 100;
        memcpy(h, name, n);
    }
    if (linkname && linkname[0]) {
        size_t n = strlen(linkname);
        if (n > 100)
            return -1;
        memcpy(h + 157, linkname, n);
    }
    snprintf(h + 100, 8, "%07o", 0755);
    snprintf(h + 108, 8, "%07o", 0);
    snprintf(h + 116, 8, "%07o", 0);
    snprintf(h + 124, 12, "%011o", (unsigned)(size & 0777777777777UL));
    snprintf(h + 136, 12, "%011o", (unsigned)time(NULL));
    snprintf(h + 148, 8, "%06o", 0);
    h[156] = (char)typeflag;
    memcpy(h + 257, "ustar", 5);
    h[262] = '0';
    for (i = 0; i < 512; i++) {
        unsigned char c = (i >= 148 && i < 156) ? (unsigned char)' '
                          : (unsigned char)h[i];
        sum += c;
    }
    snprintf(h + 148, 8, "%06o", (unsigned)sum);
    if (fwrite(h, 1, 512, out) != 512)
        return -1;
    return 0;
}

static int tar_write_pad(FILE *out, size_t size)
{
    size_t rem = (size_t)((512 - (size % 512)) % 512);
    unsigned char z[512];
    memset(z, 0, sizeof z);
    while (rem > 0) {
        size_t n = rem > sizeof z ? sizeof z : rem;
        if (fwrite(z, 1, n, out) != n)
            return -1;
        rem -= n;
    }
    return 0;
}

static int tar_is_dot_entry(const char *name)
{
    return name[0] == '.' &&
           (name[1] == '\0' || (name[1] == '.' && name[2] == '\0'));
}

static int tar_add_file(const char *fsname, const char *arcname, FILE *out,
                        benc_tar_progress_fn cb, void *cb_ctx,
                        unsigned long long *done, unsigned long long total)
{
    FILE *f = fopen(fsname, "rb");
    struct stat st;
    unsigned char buf[4096];
    size_t rem;

    if (!f)
        return -1;
    if (fstat(fileno(f), &st) != 0) {
        fclose(f);
        return -1;
    }
    if (tar_header_write(out, arcname, (size_t)st.st_size, '0', NULL) != 0) {
        fclose(f);
        return -1;
    }
    *done += 512;
    if (cb)
        cb(*done, total, cb_ctx);
    rem = (size_t)st.st_size;
    while (rem > 0) {
        size_t n = rem > sizeof buf ? sizeof buf : rem;
        if (fread(buf, 1, n, f) != n) {
            fclose(f);
            return -1;
        }
        if (fwrite(buf, 1, n, out) != n) {
            fclose(f);
            return -1;
        }
        rem -= n;
        *done += n;
        if (cb)
            cb(*done, total, cb_ctx);
    }
    fclose(f);
    {
        size_t pad = (size_t)((512 - ((size_t)st.st_size % 512)) % 512);
        if (tar_write_pad(out, (size_t)st.st_size) != 0)
            return -1;
        *done += pad;
        if (cb)
            cb(*done, total, cb_ctx);
    }
    return 0;
}

static int tar_add_symlink(const char *fsname, const char *arcname, FILE *out,
                           benc_tar_progress_fn cb, void *cb_ctx,
                           unsigned long long *done, unsigned long long total)
{
    char target[BC_TAR_NAME_MAX];
    ssize_t n = readlink(fsname, target, sizeof target - 1);

    if (n < 0)
        return -1;
    target[n] = '\0';
    if (tar_header_write(out, arcname, 0, '2', target) != 0)
        return -1;
    *done += 512;
    if (cb)
        cb(*done, total, cb_ctx);
    return 0;
}

static int tar_add_dir(const char *fsdir, const char *arcname, FILE *out,
                       benc_tar_progress_fn cb, void *cb_ctx,
                       unsigned long long *done, unsigned long long total)
{
    DIR *d = opendir(fsdir);
    struct dirent *e;
    int rc = 0;

    if (!d)
        return -1;
    if (tar_header_write(out, arcname, 0, '5', NULL) != 0) {
        closedir(d);
        return -1;
    }
    *done += 512;
    if (cb)
        cb(*done, total, cb_ctx);
    while ((e = readdir(d)) != NULL) {
        char child[4096];
        char childarc[BC_TAR_NAME_MAX];
        struct stat st;

        if (tar_is_dot_entry(e->d_name))
            continue;
        snprintf(child, sizeof child, "%s/%s", fsdir, e->d_name);
        snprintf(childarc, sizeof childarc, "%s%s", arcname, e->d_name);
        if (lstat(child, &st) != 0) {
            rc = -1;
            break;
        }
        if (S_ISDIR(st.st_mode)) {
            char sub[BC_TAR_NAME_MAX + 2];
            snprintf(sub, sizeof sub, "%s/", childarc);
            rc = tar_add_dir(child, sub, out, cb, cb_ctx, done, total);
        } else if (S_ISREG(st.st_mode)) {
            rc = tar_add_file(child, childarc, out, cb, cb_ctx, done, total);
        } else if (S_ISLNK(st.st_mode)) {
            rc = tar_add_symlink(child, childarc, out, cb, cb_ctx, done, total);
        } else {
            /* FIFOs, sockets and device nodes have no tar representation here:
             * skip them instead of aborting the whole archive. */
        }
        if (rc)
            break;
    }
    closedir(d);
    return rc;
}

/* first pass: compute the total tar size so the progress bar can show a
 * percentage while packing.  returns 0 on success. */
static int tar_add_file_size(const char *fsname, unsigned long long *total)
{
    struct stat st;

    if (stat(fsname, &st) != 0)
        return -1;
    if (!S_ISREG(st.st_mode))
        return -1;
    *total += 512;
    *total += (unsigned long long)st.st_size;
    *total += (512 - ((unsigned long long)st.st_size % 512)) % 512;
    return 0;
}

static int tar_add_dir_size(const char *fsdir, unsigned long long *total)
{
    DIR *d = opendir(fsdir);
    struct dirent *e;
    int rc = 0;

    if (!d)
        return -1;
    *total += 512;
    while ((e = readdir(d)) != NULL) {
        char child[4096];
        struct stat st;

        if (tar_is_dot_entry(e->d_name))
            continue;
        snprintf(child, sizeof child, "%s/%s", fsdir, e->d_name);
        if (lstat(child, &st) != 0) {
            rc = -1;
            break;
        }
        if (S_ISDIR(st.st_mode))
            rc = tar_add_dir_size(child, total);
        else if (S_ISREG(st.st_mode))
            rc = tar_add_file_size(child, total);
        else if (S_ISLNK(st.st_mode))
            *total += 512;
        else {
            /* special file types are skipped by tar_add_dir too */
        }
        if (rc)
            break;
    }
    closedir(d);
    return rc;
}

int benc_tar_create(const char *dir, const char *name, const char *dst,
                    benc_tar_progress_fn cb, void *cb_ctx)
{
    char fsroot[4096];
    char arcroot[BC_TAR_NAME_MAX];
    FILE *out;
    unsigned char z[1024];
    unsigned long long done = 0;
    unsigned long long total = 0;
    int have_total = 0;

    {
        size_t dlen = strlen(dir);
        int need_sep = (dlen > 0 && dir[dlen - 1] != '/') ? 1 : 0;
        int n = snprintf(fsroot, sizeof fsroot, "%s%s%s", dir, need_sep ? "/" : "",
                         name);
        if (n < 0 || (size_t)n >= sizeof fsroot)
            return -1;
    }
    if (snprintf(arcroot, sizeof arcroot, "%s/", name) >= (int)sizeof arcroot)
        return -1;

    /* first pass: compute the total tar size for the progress bar */
    total = 1024;  /* two zero blocks terminating the archive */
    if (tar_add_dir_size(fsroot, &total) == 0)
        have_total = 1;
    else
        total = 0;
    if (cb)
        cb(0, have_total ? total : 0, cb_ctx);

    out = fopen(dst, "wb");
    if (!out)
        return -1;
    {
        int rc = tar_add_dir(fsroot, arcroot, out, cb, cb_ctx, &done,
                             have_total ? total : 0);
        if (rc != 0) {
            fclose(out);
            return -1;
        }
    }
    memset(z, 0, sizeof z);
    if (fwrite(z, 1, sizeof z, out) != sizeof z) {
        fclose(out);
        return -1;
    }
    done += sizeof z;
    if (cb)
        cb(done, have_total ? total : 0, cb_ctx);
    if (fclose(out) != 0)
        return -1;
    return 0;
}

static int benc_mkdir_p(const char *path)
{
    char tmp[4096];
    size_t len;
    char *p;

    if (snprintf(tmp, sizeof tmp, "%s", path) >= (int)sizeof tmp)
        return -1;
    len = strlen(tmp);
    while (len > 1 && tmp[len - 1] == '/')
        tmp[--len] = '\0';
    for (p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(tmp, 0777) != 0 && errno != EEXIST)
                return -1;
            *p = '/';
        }
    }
    if (mkdir(tmp, 0777) != 0 && errno != EEXIST)
        return -1;
    return 0;
}

int benc_tar_extract(const char *src, const char *dest,
                     benc_tar_progress_fn cb, void *cb_ctx)
{
    FILE *f = fopen(src, "rb");
    char *in = NULL;
    long fsz;
    size_t len;
    size_t pos = 0;

    if (!f)
        return -1;
    if (fseek(f, 0, SEEK_END) != 0)
        return -1;
    fsz = ftell(f);
    if (fsz < 0)
        return -1;
    if (fseek(f, 0, SEEK_SET) != 0)
        return -1;
    len = (size_t)fsz;
    in = (char *)malloc(len + 1);
    if (!in)
        return -1;
    if (len > 0 && fread(in, 1, len, f) != len)
        return -1;
    fclose(f);
    in[len] = '\0';
    if (cb)
        cb(0, (unsigned long long)len, cb_ctx);

    while (pos + BC_TAR_BLOCK <= len) {
        unsigned char *h = (unsigned char *)in + pos;
        size_t i;
        int allzero = 1;
        int typeflag;
        size_t size = 0;
        char name[BC_TAR_NAME_MAX];
        char full[4096];
        char dirp[4096];
        char *slash = NULL;
        size_t flen;

        for (i = 0; i < BC_TAR_BLOCK; i++) {
            if (h[i] != 0) {
                allzero = 0;
                break;
            }
        }
        if (allzero)
            break;
        memcpy(name, h, 100);
        name[100] = '\0';
        {
            char prefix[156];
            size_t pn = 0;
            char combined[BC_TAR_NAME_MAX];
            int n2;
            memcpy(prefix, h + 345, 155);
            prefix[155] = '\0';
            while (pn < 155 && prefix[pn] != '\0')
                pn++;
            prefix[pn] = '\0';
            if (pn > 0) {
                n2 = snprintf(combined, sizeof combined, "%s/%s", prefix, name);
                if (n2 < 0 || (size_t)n2 >= sizeof combined)
                    return -1;
                snprintf(name, sizeof name, "%s", combined);
            }
        }
        typeflag = (int)h[156];
        {
            size_t off = 124;
            size_t v = 0;
            int any = 0;
            for (i = 0; i < 12; i++) {
                char c = (char)h[off + i];
                if (c >= '0' && c <= '7') {
                    v = v * 8 + (size_t)(c - '0');
                    any = 1;
                } else {
                    break;
                }
            }
            size = any ? v : 0;
        }
        /* --- security: reject traversal / absolute / NUL names --- */
        {
            size_t ni;
            /* reject embedded NUL */
            for (ni = 0; ni < BC_TAR_NAME_MAX && name[ni]; ni++) {}
            /* name must not contain NUL bytes (already C-string, but check prefix) */
            if (strlen(name) >= BC_TAR_NAME_MAX - 1)
                return -1;
            /* reject absolute */
            if (name[0] == '/' || name[0] == '\\')
                return -1;
            /* reject drive letter (Windows) */
            if (strlen(name) >= 2 && name[1] == ':')
                return -1;
            /* reject any component that is ".." or empty */
            {
                char tmp[BC_TAR_NAME_MAX];
                char *tok;
                snprintf(tmp, sizeof tmp, "%s", name);
                tok = strtok(tmp, "/");
                while (tok) {
                    if (tok[0] == '\0' || (tok[0]=='.' && tok[1]=='.' && tok[2]=='\0'))
                        return -1;
                    tok = strtok(NULL, "/");
                }
            }
        }
        if (snprintf(full, sizeof full, "%s/%s", dest, name) >= (int)sizeof full)
            return -1;
        if (typeflag == '5') {
            if (benc_mkdir_p(full) != 0)
                return -1;
        } else if (typeflag == '0' || typeflag == 0 || typeflag == '2') {
            flen = strlen(full);
            if (flen >= sizeof dirp)
                return -1;
            memcpy(dirp, full, flen + 1);
            slash = strrchr(dirp, '/');
            if (slash && slash != dirp) {
                *slash = '\0';
                if (benc_mkdir_p(dirp) != 0)
                    return -1;
                *slash = '/';
            }
            if (typeflag == '2') {
                /* refuse symlinks entirely (security: symlink escape) */
                free(in);
                return -1;
            } else {
                if (size > len - pos - BC_TAR_BLOCK) {
                    free(in);
                    return -1;
                }
                {
                    FILE *of = fopen(full, "wb");
                    size_t rem = size;
                    unsigned char *odata = (unsigned char *)in + pos + BC_TAR_BLOCK;
                    if (!of)
                        return -1;
                    while (rem > 0) {
                        size_t n = rem > 4096 ? 4096 : rem;
                        if (fwrite(odata, 1, n, of) != n)
                            return -1;
                        odata += n;
                        rem -= n;
                    }
                    if (fclose(of) != 0)
                        return -1;
                }
            }
        } else {
            return -1;
        }
        pos += BC_TAR_BLOCK + (((size + 511) / 512) * 512);
        if (cb)
            cb((unsigned long long)pos, (unsigned long long)len, cb_ctx);
    }
    if (cb)
        cb((unsigned long long)len, (unsigned long long)len, cb_ctx);
    free(in);
    return 0;
}
#else
int benc_tar_create(const char *dir, const char *name, const char *dst,
                    benc_tar_progress_fn cb, void *cb_ctx)
{
    (void)dir;
    (void)name;
    (void)dst;
    (void)cb;
    (void)cb_ctx;
    return -1;
}

int benc_tar_extract(const char *src, const char *dest,
                     benc_tar_progress_fn cb, void *cb_ctx)
{
    (void)src;
    (void)dest;
    (void)cb;
    (void)cb_ctx;
    return -1;
}
#endif
