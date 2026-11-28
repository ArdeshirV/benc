VERSION := $(shell cat VERSION)
CC ?= cc
CFLAGS ?= -O2 -std=c99 -Wall -Wextra -Wpedantic -Iinclude -Iinclude/benc -Isrc
AR ?= ar

VENDOR = ../vendor/kyber

SRCS = src/benc.c src/benc_codecs.c src/benc_tar.c src/benc_kem.c \
       $(VENDOR)/kem.c $(VENDOR)/indcpa.c $(VENDOR)/polyvec.c $(VENDOR)/poly.c \
       $(VENDOR)/ntt.c $(VENDOR)/reduce.c $(VENDOR)/cbd.c $(VENDOR)/verify.c \
       $(VENDOR)/fips202.c $(VENDOR)/symmetric-shake.c $(VENDOR)/randombytes.c

all: libbenc.a

libbenc.a: $(SRCS)
	$(CC) $(CFLAGS) -c src/benc.c -o src/benc.o
	$(CC) $(CFLAGS) -c src/benc_codecs.c -o src/benc_codecs.o
	$(CC) $(CFLAGS) -c src/benc_tar.c -o src/benc_tar.o
	$(CC) $(CFLAGS) -c src/benc_kem.c -o src/benc_kem.o
	$(CC) $(CFLAGS) -c $(VENDOR)/kem.c -o $(VENDOR)/kem.o
	$(CC) $(CFLAGS) -c $(VENDOR)/indcpa.c -o $(VENDOR)/indcpa.o
	$(CC) $(CFLAGS) -c $(VENDOR)/polyvec.c -o $(VENDOR)/polyvec.o
	$(CC) $(CFLAGS) -c $(VENDOR)/poly.c -o $(VENDOR)/poly.o
	$(CC) $(CFLAGS) -c $(VENDOR)/ntt.c -o $(VENDOR)/ntt.o
	$(CC) $(CFLAGS) -c $(VENDOR)/reduce.c -o $(VENDOR)/reduce.o
	$(CC) $(CFLAGS) -c $(VENDOR)/cbd.c -o $(VENDOR)/cbd.o
	$(CC) $(CFLAGS) -c $(VENDOR)/verify.c -o $(VENDOR)/verify.o
	$(CC) $(CFLAGS) -c $(VENDOR)/fips202.c -o $(VENDOR)/fips202.o
	$(CC) $(CFLAGS) -c $(VENDOR)/symmetric-shake.c -o $(VENDOR)/symmetric-shake.o
	$(CC) $(CFLAGS) -c $(VENDOR)/randombytes.c -o $(VENDOR)/randombytes.o
	ar rcs $@ src/benc.o src/benc_codecs.o src/benc_tar.o src/benc_kem.o $(VENDOR)/kem.o $(VENDOR)/indcpa.o $(VENDOR)/polyvec.o $(VENDOR)/poly.o $(VENDOR)/ntt.o $(VENDOR)/reduce.o $(VENDOR)/cbd.o $(VENDOR)/verify.o $(VENDOR)/fips202.o $(VENDOR)/symmetric-shake.o $(VENDOR)/randombytes.o

clean:
	rm -f src/*.o $(VENDOR)/*.o libbenc.a

.PHONY: all clean
