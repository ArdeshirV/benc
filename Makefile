# Root Makefile - builds libbenc then benc CLI
CC ?= cc
CFLAGS ?= -O2 -std=c99 -Wall -Wextra -Wpedantic -Ilibbenc/include -Ilibbenc/include/benc -Ilibbenc/src
LDFLAGS ?=
LDLIBS ?=

LIBBENC_SRCS = libbenc/src/benc.c libbenc/src/benc_codecs.c libbenc/src/benc_tar.c \
               libbenc/src/benc_kem.c libbenc/include/benc/benc_platform.h \
               libbenc/vendor/kyber/kem.c libbenc/vendor/kyber/indcpa.c \
               libbenc/vendor/kyber/polyvec.c libbenc/vendor/kyber/poly.c \
               libbenc/vendor/kyber/ntt.c libbenc/vendor/kyber/reduce.c \
               libbenc/vendor/kyber/cbd.c libbenc/vendor/kyber/verify.c \
               libbenc/vendor/kyber/fips202.c libbenc/vendor/kyber/symmetric-shake.c \
               libbenc/vendor/kyber/randombytes.c

BENC_SRCS = cli/src/main.c

all: benc

native-optimized:
	$(MAKE) CFLAGS="-O3 -march=native -std=c99 -Wall -Wextra -Wpedantic -Ilibbenc/include -Ilibbenc/include/benc -Ilibbenc/src"

libbenc/libbenc.a: $(LIBBENC_SRCS)
	@mkdir -p libbenc/build
	@mkdir -p libbenc/build
	$(CC) $(CFLAGS) -c libbenc/src/benc.c -o libbenc/build/benc.o
	$(CC) $(CFLAGS) -c libbenc/src/benc_codecs.c -o libbenc/build/benc_codecs.o
	$(CC) $(CFLAGS) -c libbenc/src/benc_tar.c -o libbenc/build/benc_tar.o
	$(CC) $(CFLAGS) -c libbenc/src/benc_kem.c -o libbenc/build/benc_kem.o
	$(CC) $(CFLAGS) -c libbenc/vendor/kyber/kem.c -o libbenc/build/kyber_kem.o
	$(CC) $(CFLAGS) -c libbenc/vendor/kyber/indcpa.c -o libbenc/build/kyber_indcpa.o
	$(CC) $(CFLAGS) -c libbenc/vendor/kyber/polyvec.c -o libbenc/build/kyber_polyvec.o
	$(CC) $(CFLAGS) -c libbenc/vendor/kyber/poly.c -o libbenc/build/kyber_poly.o
	$(CC) $(CFLAGS) -c libbenc/vendor/kyber/ntt.c -o libbenc/build/kyber_ntt.o
	$(CC) $(CFLAGS) -c libbenc/vendor/kyber/reduce.c -o libbenc/build/kyber_reduce.o
	$(CC) $(CFLAGS) -c libbenc/vendor/kyber/cbd.c -o libbenc/build/kyber_cbd.o
	$(CC) $(CFLAGS) -c libbenc/vendor/kyber/verify.c -o libbenc/build/kyber_verify.o
	$(CC) $(CFLAGS) -c libbenc/vendor/kyber/fips202.c -o libbenc/build/kyber_fips202.o
	$(CC) $(CFLAGS) -c libbenc/vendor/kyber/symmetric-shake.c -o libbenc/build/kyber_symmetric.o
	$(CC) $(CFLAGS) -c libbenc/vendor/kyber/randombytes.c -o libbenc/build/kyber_randombytes.o
	ar rcs $@ libbenc/build/*.o

benc: libbenc/libbenc.a cli/src/main.c
	$(CC) $(CFLAGS) -Ilibbenc/include -o benc cli/src/main.c -Llibbenc -lbenc $(LDFLAGS) $(LDLIBS)

clean:
	rm -f benc libbenc/libbenc.a
	rm -rf libbenc/build

test: benc
	sh tests/run_tests.sh ./benc

.PHONY: all clean test native-optimized
