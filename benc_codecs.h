#ifndef BENC_CODECS_H
#define BENC_CODECS_H

int benc_lzma2_encode(const char *src, const char *dst, int preset, int threads);
int benc_lzma2_decode(const char *src, const char *dst);
int benc_zstd_encode(const char *src, const char *dst, int level, int threads);
int benc_zstd_decode(const char *src, const char *dst);

#endif
