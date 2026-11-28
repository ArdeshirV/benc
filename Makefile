# Root Makefile - builds libbenc then benc CLI
CC ?= cc
CFLAGS ?= -O2 -std=c99 -Wall -Wextra -Wpedantic -Ilibbenc/include -Ilibbenc/include/benc -Ilibbenc/src
LDFLAGS ?=
LDLIBS ?=

LIBBENC_SRCS = libbenc/src/benc.c libbenc/src/benc_codecs.c libbenc/src/benc_tar.c \
               libbenc/src/benc_kem.c libbenc/include/benc/benc_platform.h \
               vendor/kyber/kem.c vendor/kyber/indcpa.c \
               vendor/kyber/polyvec.c vendor/kyber/poly.c \
               vendor/kyber/ntt.c vendor/kyber/reduce.c \
               vendor/kyber/cbd.c vendor/kyber/verify.c \
               vendor/kyber/fips202.c vendor/kyber/symmetric-shake.c \
               vendor/kyber/randombytes.c

BENC_SRCS = benc/src/main.c

all: benc-cli

libbenc/libbenc.a: $(LIBBENC_SRCS)
	@mkdir -p libbenc/build
	$(CC) $(CFLAGS) -c libbenc/src/benc.c -o libbenc/build/benc.o
	$(CC) $(CFLAGS) -c libbenc/src/benc_codecs.c -o libbenc/build/benc_codecs.o
	$(CC) $(CFLAGS) -c libbenc/src/benc_tar.c -o libbenc/build/benc_tar.o
	$(CC) $(CFLAGS) -c libbenc/src/benc_kem.c -o libbenc/build/benc_kem.o
	$(CC) $(CFLAGS) -c vendor/kyber/kem.c -o libbenc/build/kyber_kem.o
	$(CC) $(CFLAGS) -c vendor/kyber/indcpa.c -o libbenc/build/kyber_indcpa.o
	$(CC) $(CFLAGS) -c vendor/kyber/polyvec.c -o libbenc/build/kyber_polyvec.o
	$(CC) $(CFLAGS) -c vendor/kyber/poly.c -o libbenc/build/kyber_poly.o
	$(CC) $(CFLAGS) -c vendor/kyber/ntt.c -o libbenc/build/kyber_ntt.o
	$(CC) $(CFLAGS) -c vendor/kyber/reduce.c -o libbenc/build/kyber_reduce.o
	$(CC) $(CFLAGS) -c vendor/kyber/cbd.c -o libbenc/build/kyber_cbd.o
	$(CC) $(CFLAGS) -c vendor/kyber/verify.c -o libbenc/build/kyber_verify.o
	$(CC) $(CFLAGS) -c vendor/kyber/fips202.c -o libbenc/build/kyber_fips202.o
	$(CC) $(CFLAGS) -c vendor/kyber/symmetric-shake.c -o libbenc/build/kyber_symmetric.o
	$(CC) $(CFLAGS) -c vendor/kyber/randombytes.c -o libbenc/build/kyber_randombytes.o
	ar rcs $@ libbenc/build/*.o

benc-cli: libbenc/libbenc.a benc/src/main.c
	$(CC) $(CFLAGS) -Ilibbenc/include -o benc-cli benc/src/main.c -Llibbenc -lbenc $(LDFLAGS) $(LDLIBS)

clean:
	rm -f benc libbenc/libbenc.a
	rm -rf libbenc/build

test: benc-cli
	sh tests/run_tests.sh ./benc-cli

.PHONY: all clean test
