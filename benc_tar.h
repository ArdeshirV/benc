#ifndef BENC_TAR_H
#define BENC_TAR_H

/* Minimal built-in tar (create + extract) for directory payloads.
 * No external library or command line tool is used. */
int benc_tar_create(const char *dir, const char *name, const char *dst);
int benc_tar_extract(const char *src, const char *dest);

#endif
