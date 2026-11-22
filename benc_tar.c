/* benc_tar.c - self contained tar create/extract for benc directory payloads. */

#if !defined(_WIN32) && !defined(__DJGPP__) && !defined(__MSDOS__) && \
    !defined(_DOS)
#  ifndef _POSIX_C_SOURCE
#    define _POSIX_C_SOURCE 200809L
#  endif
#endif

#include "benc_tar.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#if defined(BENC_POSIX)
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <time.h>
#include <errno.h>

#define BC_TAR_BLOCK 512
#define BC_TAR_NAME_MAX 1024

static int tar_header_write(FILE *out, const char *name, size_t size, int typeflag)
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

static int tar_add_file(const char *fsname, const char *arcname, FILE *out)
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
    if (tar_header_write(out, arcname, (size_t)st.st_size, '0') != 0) {
        fclose(f);
        return -1;
    }
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
    }
    fclose(f);
    return tar_write_pad(out, (size_t)st.st_size);
}

static int tar_add_dir(const char *fsdir, const char *arcname, FILE *out)
{
    DIR *d = opendir(fsdir);
    struct dirent *e;
    int rc = 0;

    if (!d)
        return -1;
    if (tar_header_write(out, arcname, 0, '5') != 0) {
        closedir(d);
        return -1;
    }
    while ((e = readdir(d)) != NULL) {
        char child[4096];
        char childarc[BC_TAR_NAME_MAX];
        struct stat st;

        if (e->d_name[0] == '.' && (e->d_name[1] == '\0' ||
                                   (e->d_name[1] == '.' && e->d_name[2] == '\0')))
            continue;
        snprintf(child, sizeof child, "%s/%s", fsdir, e->d_name);
        snprintf(childarc, sizeof childarc, "%s%s", arcname, e->d_name);
        if (stat(child, &st) != 0) {
            rc = -1;
            break;
        }
        if (S_ISDIR(st.st_mode)) {
            char sub[BC_TAR_NAME_MAX + 2];
            snprintf(sub, sizeof sub, "%s/", childarc);
            rc = tar_add_dir(child, sub, out);
        } else if (S_ISREG(st.st_mode)) {
            rc = tar_add_file(child, childarc, out);
        } else {
            rc = -1;
            break;
        }
        if (rc)
            break;
    }
    closedir(d);
    return rc;
}

int benc_tar_create(const char *dir, const char *name, const char *dst)
{
    char fsroot[4096];
    char arcroot[BC_TAR_NAME_MAX];
    FILE *out;
    unsigned char z[1024];


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
    out = fopen(dst, "wb");
    if (!out)
        return -1;
    {
        int rc = tar_add_dir(fsroot, arcroot, out);
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

int benc_tar_extract(const char *src, const char *dest)
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
            size_t n = 0;
            while (n < 100 && name[n] != '\0')
                n++;
            name[n] = '\0';
        }
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
        if (snprintf(full, sizeof full, "%s/%s", dest, name) >= (int)sizeof full)
            return -1;
        if (typeflag == '5') {
            if (benc_mkdir_p(full) != 0)
                return -1;
        } else if (typeflag == '0' || typeflag == 0) {
            flen = strlen(full);
            if (flen >= sizeof dirp)
                return -1;
            memcpy(dirp, full, flen + 1);
            slash = dirp;
            while (*slash) {
                if (*slash == '/')
                    break;
                slash++;
            }
            if (slash != dirp) {
                *slash = '\0';
                if (benc_mkdir_p(dirp) != 0)
                    return -1;
                *slash = '/';
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
        } else {
            return -1;
        }
        pos += BC_TAR_BLOCK + (((size + 511) / 512) * 512);
    }
    free(in);
    return 0;
}
#else
int benc_tar_create(const char *dir, const char *name, const char *dst)
{
    (void)dir;
    (void)name;
    (void)dst;
    return -1;
}

int benc_tar_extract(const char *src, const char *dest)
{
    (void)src;
    (void)dest;
    return -1;
}
#endif
