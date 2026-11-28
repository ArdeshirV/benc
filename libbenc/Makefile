# Standalone libbenc build
VERSION := $(shell cat VERSION)
CC ?= cc
CFLAGS ?= -O2 -std=c99 -Wall -Wextra -Wpedantic -Werror -Iinclude -Isrc -Ivendor/kyber
AR ?= ar
RANLIB ?= ranlib

SRCS = src/crypto/sha256.c src/crypto/hmac.c src/crypto/pbkdf2.c \
       src/crypto/hkdf.c src/crypto/chacha20.c src/crypto/ctutil.c src/crypto/wipe.c \
       src/codec/lzma2.c src/codec/zstd.c src/codec/codec.c \
       src/container/header.c src/container/b64.c src/container/encrypt.c src/container/decrypt.c src/container/info.c \
       src/archive/tar_mem.c \
       src/kem/kem.c \
       src/platform/rng_linux.c src/platform/rng_generic.c \
       src/fs/fs_common.c src/fs/fs_posix.c \
       src/selftest.c src/alloc.c src/status.c src/version.c src/license.c \
       vendor/kyber/kem.c vendor/kyber/indcpa.c vendor/kyber/polyvec.c vendor/kyber/poly.c \
       vendor/kyber/ntt.c vendor/kyber/reduce.c vendor/kyber/cbd.c vendor/kyber/verify.c \
       vendor/kyber/fips202.c vendor/kyber/symmetric-shake.c vendor/kyber/randombytes.c

# For now, just a placeholder - copy from root
all:
	@echo "libbenc Makefile placeholder - copy sources from parent"
	@echo "VERSION=$(VERSION)"

library:
	@echo "make library: not yet implemented (skeleton)"
	@mkdir -p dist/libbenc/include/benc dist/libbenc/lib
	@cp include/benc/*.h dist/libbenc/include/benc/
	@echo "done (skeleton)"

clean:
	rm -rf dist build
