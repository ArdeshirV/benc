# ---------------------------------------------------------------------------
# benc - small C codebase, many platforms
#
#   make                  build for the machine you are on        (./benc)
#   make linux            Linux (host arch)   -> build/linux/benc
#   make linux-386        Linux i386          -> build/linux-386/benc
#   make linux-amd64      Linux x86_64        -> build/linux-amd64/benc
#   make linux-arm        Linux armhf         -> build/linux-arm/benc
#   make linux-arm64      Linux aarch64       -> build/linux-arm64/benc
#   make macos            macOS (host arch)   -> build/macos/benc
#   make macos-amd64      macOS x86_64        -> build/macos-amd64/benc
#   make macos-arm64      macOS arm64         -> build/macos-arm64/benc
#   make macos-universal  macOS arm64 + amd64 -> build/macos-universal/benc
#   make termux           Termux/Android      -> build/termux/benc
#   make termux-arm64     Termux/Android arm64 -> build/termux-arm64/benc
#   make bsd              *BSD (host arch)    -> build/bsd/benc
#   make bsd-386          *BSD i386           -> build/bsd-386/benc
#   make bsd-amd64        *BSD x86_64         -> build/bsd-amd64/benc
#   make bsd-arm          *BSD arm            -> build/bsd-arm/benc
#   make bsd-arm64        *BSD aarch64        -> build/bsd-arm64/benc
#   make windows          Windows x64 + x86   -> build/windows-*/benc.exe
#   make windows-amd64    Windows x86_64      -> build/windows-amd64/benc.exe
#   make windows-386      Windows i686        -> build/windows-386/benc.exe
#   make windows-arm      Windows arm32       -> build/windows-arm/benc.exe
#   make windows-arm64    Windows arm64       -> build/windows-arm64/benc.exe
#   make dos              MS-DOS (DJGPP)      -> build/dos/benc.exe
#   make all-platforms    build every platform whose toolchain is installed
#   make check            show which toolchains were detected
#   make test             run the test suite with the native build
#   make nace-drex        optional Nace Drex client -> build/nace/nace-drex
#   make install          install the native binary into $(PREFIX)/bin
#   make clean            remove all build products
#   make optimized          host-specific optimized build (-march=native) -> ./benc
#
# Cross builds use freely available toolchains:
#   Debian/Ubuntu : apt install gcc-mingw-w64-x86-64 gcc-mingw-w64-i686
#                   apt install gcc-multilib gcc-arm-linux-gnueabihf \
#                   gcc-aarch64-linux-gnu gcc-x86-64-linux-gnu-gcc
#                   apt install djgpp  (or build DJGPP from source)
#   macOS -> arm/amd64: osxcross, then MACOS_ARM64_CC=o64-clang
#   Linux -> Termux: Android NDK, then TERMUX_CC=aarch64-linux-android21-clang
#
# Every variable can be overridden, e.g.
#   make windows WIN64_CC=/opt/mingw/bin/x86_64-w64-mingw32-gcc
#   make linux-arm64 LINUX_ARM64_CC=aarch64-linux-gnu-gcc
#   make CFLAGS="-O3 -march=native"   (host-specific optimization)
# ---------------------------------------------------------------------------

APP     := benc
SRC     := benc.c benc_codecs.c benc_tar.c
HDRS    := benc_platform.h benc_codecs.h benc_tar.h
BUILD   := build

CC       ?= cc
CFLAGS   ?= -O3
WARN     := -std=c99 -Wall -Wextra -Wpedantic
LDFLAGS  ?=
LDLIBS   ?=
PREFIX   ?= /usr/local
STATIC   ?= 0

ifeq ($(DEBUG),1)
  CFLAGS := -O0 -g3
endif

# --------------------------------------------------------------- host ----
ifeq ($(OS),Windows_NT)
  HOST := windows
else
  HOST_OS   := $(shell uname -s 2>/dev/null)
  HOST_ARCH := $(shell uname -m 2>/dev/null)
  ifeq ($(HOST_OS),Darwin)
    HOST := macos
  else
    ifneq (,$(findstring MINGW,$(HOST_OS)))
      HOST := windows
    else
      ifneq (,$(findstring MSYS,$(HOST_OS)))
        HOST := windows
      else
        ifneq (,$(findstring CYGWIN,$(HOST_OS)))
          HOST := windows
        else
          ifneq (,$(findstring Linux,$(HOST_OS)))
            HOST := linux
          else
            ifneq (,$(findstring BSD,$(HOST_OS)))
              HOST := bsd
            else
              ifneq (,$(findstring GNU/kFreeBSD,$(HOST_OS)))
                HOST := bsd
              else
                ifneq (,$(findstring SunOS,$(HOST_OS)))
                  HOST := solaris
                else
                  HOST := unknown
                endif
              endif
            endif
          endif
        endif
      endif
    endif
  endif
  ifeq ($(HOST),linux)
    ifneq (,$(findstring com.termux,$(PREFIX)))
      HOST := termux
    endif
  endif
endif

# uname may be missing (DOS) - fall back to the compiler target triple
ifeq ($(HOST),unknown)
  TARGET_TRIPLET := $(shell $(CC) -dumpmachine 2>/dev/null)
  ifneq (,$(findstring msdosdjgpp,$(TARGET_TRIPLET)))
    HOST := dos
  endif
  ifneq (,$(findstring mingw,$(TARGET_TRIPLET)))
    HOST := windows
  endif
endif

ifeq ($(filter windows dos,$(HOST)),)
  EXE :=
else
  EXE := .exe
endif
ifeq ($(HOST),windows)
  LDLIBS += -lbcrypt
endif

# ------------------------------------------------------- cross compilers --
WIN64_CC   ?= x86_64-w64-mingw32-gcc
WIN32_CC   ?= i686-w64-mingw32-gcc
WINARM_CC  ?= arm-w64-mingw32-gcc
WINARM64_CC ?= aarch64-w64-mingw32-gcc
DOS_CC     ?= ia16-elf-gcc
ifeq ($(findstring ia16,$(DOS_CC)),ia16)
  DOS_EXTRA ?= -mcmodel=medium
else
  DOS_EXTRA ?=
endif
MACOS_CC      ?= $(if $(shell command -v o64-clang 2>/dev/null),o64-clang,)
MACOS_AMD64_CC ?= $(if $(shell command -v x86_64-apple-darwin24.1-clang 2>/dev/null),x86_64-apple-darwin24.1-clang,)
MACOS_ARM64_CC ?= $(if $(shell command -v aarch64-apple-darwin24.1-clang 2>/dev/null),aarch64-apple-darwin24.1-clang,)
TERMUX_CC  ?= $(if $(shell command -v aarch64-linux-android21-clang 2>/dev/null),aarch64-linux-android21-clang,)
LINUX_CC   ?=
LINUX_386_CC   ?= i686-linux-gnu-gcc
LINUX_AMD64_CC ?= x86_64-linux-gnu-gcc
LINUX_ARM_CC   ?= arm-linux-gnueabihf-gcc
LINUX_ARM64_CC ?= aarch64-linux-gnu-gcc
BSD_CC     ?=
BSD_386_CC   ?= i386-unknown-freebsd-gcc
BSD_AMD64_CC ?= x86_64-unknown-freebsd-gcc
BSD_ARM_CC   ?= arm-unknown-freebsd-gcc
BSD_ARM64_CC ?= aarch64-unknown-freebsd-gcc

ifeq ($(STATIC),1)
  ifneq (,$(filter linux termux bsd solaris,$(HOST)))
    LDFLAGS += -static
  endif
endif

# ------------------------------------------------------------- targets ----
.PHONY: all native optimized linux linux-386 linux-amd64 linux-arm linux-arm64 macos macos-amd64 macos-arm64 \
        macos-universal termux termux-arm64 bsd bsd-386 bsd-amd64 bsd-arm bsd-arm64 solaris windows windows-amd64 \
        windows-386 windows-arm windows-arm64 windows-msvc dos all-platforms check test \
        nace-drex install clean distclean help

all: native

# Fail with a clear message if the single source file is missing, instead of
# a cryptic "No rule to make target".  Only installed when benc.c really is
# absent, so a forced build (-B) never replaces the real recipe.
ifeq ($(wildcard $(SRC)),)
$(SRC):
	@echo "error: $(SRC) is missing; restore the benc source before building" >&2
	@exit 1
endif

native: $(APP)$(EXE)

optimized: CFLAGS += -march=native
optimized: $(APP)$(EXE)

$(APP)$(EXE): $(SRC) $(HDRS)
	$(CC) $(CFLAGS) $(WARN) -DBENC_POSIX -o $@ $(SRC) $(LDFLAGS) $(LDLIBS)

# --------------------------------------------------------------- linux ----
linux:
ifneq (,$(filter linux termux,$(HOST)))
	@mkdir -p $(BUILD)/linux
	$(CC) $(CFLAGS) $(WARN) -o $(BUILD)/linux/$(APP) $(SRC) $(LDFLAGS) $(LDLIBS)
else ifneq ($(LINUX_CC),)
	@mkdir -p $(BUILD)/linux
	$(LINUX_CC) $(CFLAGS) $(WARN) -o $(BUILD)/linux/$(APP) $(SRC) $(LDFLAGS) $(LDLIBS)
else
	@echo "linux: run this on Linux, or set LINUX_CC to a Linux cross compiler" >&2
	@exit 1
endif

# ----------------------------------------------------------- linux-386 -----
linux-386:
ifneq (,$(filter i386 i686,$(HOST_ARCH)))
	@mkdir -p $(BUILD)/linux-386
	$(CC) $(CFLAGS) $(WARN) -o $(BUILD)/linux-386/$(APP) $(SRC) $(LDFLAGS) $(LDLIBS)
else ifneq ($(LINUX_386_CC),)
	@command -v $(LINUX_386_CC) >/dev/null 2>&1 || { \
	  echo "linux-386: $(LINUX_386_CC) not found." >&2; \
	  echo "  Debian/Ubuntu: sudo apt install gcc-multilib" >&2; \
	  echo "  or set LINUX_386_CC=/path/to/i686-linux-gnu-gcc" >&2; exit 1; }
	@mkdir -p $(BUILD)/linux-386
	$(LINUX_386_CC) $(CFLAGS) $(WARN) -o $(BUILD)/linux-386/$(APP) $(SRC) $(LDFLAGS) $(LDLIBS)
else
	@echo "linux-386: run this on i386/i686 Linux, or set LINUX_386_CC" >&2
	@exit 1
endif

# --------------------------------------------------------- linux-amd64 -----
linux-amd64:
ifneq (,$(filter x86_64 amd64,$(HOST_ARCH)))
	@mkdir -p $(BUILD)/linux-amd64
	$(CC) $(CFLAGS) $(WARN) -o $(BUILD)/linux-amd64/$(APP) $(SRC) $(LDFLAGS) $(LDLIBS)
else ifneq ($(LINUX_AMD64_CC),)
	@command -v $(LINUX_AMD64_CC) >/dev/null 2>&1 || { \
	  echo "linux-amd64: $(LINUX_AMD64_CC) not found." >&2; \
	  echo "  Debian/Ubuntu: sudo apt install gcc-x86-64-linux-gnu-gcc" >&2; \
	  echo "  or set LINUX_AMD64_CC=/path/to/x86_64-linux-gnu-gcc" >&2; exit 1; }
	@mkdir -p $(BUILD)/linux-amd64
	$(LINUX_AMD64_CC) $(CFLAGS) $(WARN) -o $(BUILD)/linux-amd64/$(APP) $(SRC) $(LDFLAGS) $(LDLIBS)
else
	@echo "linux-amd64: run this on x86_64 Linux, or set LINUX_AMD64_CC" >&2
	@exit 1
endif

# ------------------------------------------------------------ linux-arm ------
linux-arm:
ifneq (,$(filter arm armv% armhf,$(HOST_ARCH)))
	@mkdir -p $(BUILD)/linux-arm
	$(CC) $(CFLAGS) $(WARN) -o $(BUILD)/linux-arm/$(APP) $(SRC) $(LDFLAGS) $(LDLIBS)
else ifneq ($(LINUX_ARM_CC),)
	@command -v $(LINUX_ARM_CC) >/dev/null 2>&1 || { \
	  echo "linux-arm: $(LINUX_ARM_CC) not found." >&2; \
	  echo "  Debian/Ubuntu: sudo apt install gcc-arm-linux-gnueabihf" >&2; \
	  echo "  or set LINUX_ARM_CC=/path/to/arm-linux-gnueabihf-gcc" >&2; exit 1; }
	@mkdir -p $(BUILD)/linux-arm
	$(LINUX_ARM_CC) $(CFLAGS) $(WARN) -o $(BUILD)/linux-arm/$(APP) $(SRC) $(LDFLAGS) $(LDLIBS)
else
	@echo "linux-arm: run this on arm Linux, or set LINUX_ARM_CC" >&2
	@exit 1
endif

# ---------------------------------------------------------- linux-arm64 ------
linux-arm64:
ifneq (,$(filter aarch64 arm64,$(HOST_ARCH)))
	@mkdir -p $(BUILD)/linux-arm64
	$(CC) $(CFLAGS) $(WARN) -o $(BUILD)/linux-arm64/$(APP) $(SRC) $(LDFLAGS) $(LDLIBS)
else ifneq ($(LINUX_ARM64_CC),)
	@command -v $(LINUX_ARM64_CC) >/dev/null 2>&1 || { \
	  echo "linux-arm64: $(LINUX_ARM64_CC) not found." >&2; \
	  echo "  Debian/Ubuntu: sudo apt install gcc-aarch64-linux-gnu" >&2; \
	  echo "  or set LINUX_ARM64_CC=/path/to/aarch64-linux-gnu-gcc" >&2; exit 1; }
	@mkdir -p $(BUILD)/linux-arm64
	$(LINUX_ARM64_CC) $(CFLAGS) $(WARN) -o $(BUILD)/linux-arm64/$(APP) $(SRC) $(LDFLAGS) $(LDLIBS)
else
	@echo "linux-arm64: run this on aarch64 Linux, or set LINUX_ARM64_CC" >&2
	@exit 1
endif

# --------------------------------------------------------------- macos ----
macos:
ifeq ($(HOST),macos)
	@mkdir -p $(BUILD)/macos
	$(CC) $(CFLAGS) $(WARN) -o $(BUILD)/macos/$(APP) $(SRC) $(LDFLAGS) $(LDLIBS)
else ifneq ($(MACOS_CC),)
	@mkdir -p $(BUILD)/macos
	$(MACOS_CC) $(CFLAGS) $(WARN) -o $(BUILD)/macos/$(APP) $(SRC) $(LDFLAGS) $(LDLIBS)
else
	@echo "macos: run this on macOS, or set MACOS_CC (osxcross, e.g. MACOS_CC=o64-clang)" >&2
	@exit 1
endif

# ---------------------------------------------------------- macos-amd64 ------
macos-amd64:
ifeq ($(HOST),macos)
	@mkdir -p $(BUILD)/macos-amd64
	$(CC) $(CFLAGS) $(WARN) -o $(BUILD)/macos-amd64/$(APP) $(SRC) $(LDFLAGS) $(LDLIBS)
else ifneq ($(MACOS_AMD64_CC),)
	@command -v $(MACOS_AMD64_CC) >/dev/null 2>&1 || { \
	  echo "macos-amd64: $(MACOS_AMD64_CC) not found." >&2; \
	  echo "  macOS -> amd64: osxcross, set MACOS_AMD64_CC=x86_64-apple-darwin21-clang" >&2; \
	  echo "  or set MACOS_AMD64_CC=o64-clang" >&2; exit 1; }
	@mkdir -p $(BUILD)/macos-amd64
	$(MACOS_AMD64_CC) $(CFLAGS) $(WARN) -o $(BUILD)/macos-amd64/$(APP) $(SRC) $(LDFLAGS) $(LDLIBS)
else
	@echo "macos-amd64: run this on macOS, or set MACOS_AMD64_CC (osxcross)" >&2
	@exit 1
endif

# ---------------------------------------------------------- macos-arm64 ------
macos-arm64:
ifeq ($(HOST),macos)
	@mkdir -p $(BUILD)/macos-arm64
	$(CC) $(CFLAGS) $(WARN) -o $(BUILD)/macos-arm64/$(APP) $(SRC) $(LDFLAGS) $(LDLIBS)
else ifneq ($(MACOS_ARM64_CC),)
	@command -v $(MACOS_ARM64_CC) >/dev/null 2>&1 || { \
	  echo "macos-arm64: $(MACOS_ARM64_CC) not found." >&2; \
	  echo "  macOS -> arm64: osxcross, set MACOS_ARM64_CC=aarch64-apple-darwin21-clang" >&2; \
	  echo "  or set MACOS_ARM64_CC=o64-clang" >&2; exit 1; }
	@mkdir -p $(BUILD)/macos-arm64
	$(MACOS_ARM64_CC) $(CFLAGS) $(WARN) -o $(BUILD)/macos-arm64/$(APP) $(SRC) $(LDFLAGS) $(LDLIBS)
else
	@echo "macos-arm64: run this on macOS, or set MACOS_ARM64_CC (osxcross)" >&2
	@exit 1
endif

# ---------------------------------------------------------- macos-universal --
# macOS universal binary: arm64 + amd64 slices (requires the Xcode CLT for lipo).
macos-universal:
	$(MAKE) macos-arm64
	$(MAKE) macos-amd64
	@command -v lipo >/dev/null 2>&1 || { \
	  echo "macos-universal: lipo not found." >&2; \
	  echo "  install the Xcode Command Line Tools: xcode-select --install" >&2; \
	  exit 1; }
	@mkdir -p $(BUILD)/macos-universal
	@lipo -create $(BUILD)/macos-arm64/$(APP) $(BUILD)/macos-amd64/$(APP) \
	    -output $(BUILD)/macos-universal/$(APP)

# -------------------------------------------------------------- termux ----
termux:
ifeq ($(HOST),termux)
	@mkdir -p $(BUILD)/termux
	$(CC) $(CFLAGS) $(WARN) -o $(BUILD)/termux/$(APP) $(SRC) $(LDFLAGS) $(LDLIBS)
else ifneq ($(TERMUX_CC),)
	@mkdir -p $(BUILD)/termux
	$(TERMUX_CC) $(CFLAGS) $(WARN) -o $(BUILD)/termux/$(APP) $(SRC) $(LDFLAGS) $(LDLIBS)
else
	@echo "termux: run this in Termux, or set TERMUX_CC (Android NDK clang," >&2
	@echo "        e.g. TERMUX_CC=aarch64-linux-android21-clang)" >&2
	@exit 1
endif

# ---------------------------------------------------------- termux-arm64 ----
termux-arm64:
ifeq ($(HOST),termux)
	@mkdir -p $(BUILD)/termux-arm64
	$(CC) $(CFLAGS) $(WARN) -o $(BUILD)/termux-arm64/$(APP) $(SRC) $(LDFLAGS) $(LDLIBS)
else ifneq ($(TERMUX_CC),)
	@command -v $(TERMUX_CC) >/dev/null 2>&1 || { \
	  echo "termux-arm64: $(TERMUX_CC) not found." >&2; \
	  echo "  install the Android NDK clang, or set TERMUX_CC=/path/to/aarch64-linux-android21-clang" >&2; \
	  echo "  or set TERMUX_CC=aarch64-linux-android21-clang" >&2; \
	  exit 1; }
	@mkdir -p $(BUILD)/termux-arm64
	$(TERMUX_CC) $(CFLAGS) $(WARN) -o $(BUILD)/termux-arm64/$(APP) $(SRC) $(LDFLAGS) $(LDLIBS)
else
	@echo "termux-arm64: run this in Termux, or set TERMUX_CC (Android NDK clang," >&2
	@echo "        e.g. TERMUX_CC=aarch64-linux-android21-clang)" >&2
	@exit 1
endif

# ----------------------------------------------------------------- bsd ----
bsd:
ifeq ($(HOST),bsd)
	@mkdir -p $(BUILD)/bsd
	$(CC) $(CFLAGS) $(WARN) -o $(BUILD)/bsd/$(APP) $(SRC) $(LDFLAGS) $(LDLIBS)
else ifneq ($(BSD_CC),)
	@mkdir -p $(BUILD)/bsd
	$(BSD_CC) $(CFLAGS) $(WARN) -o $(BUILD)/bsd/$(APP) $(SRC) $(LDFLAGS) $(LDLIBS)
else
	@echo "bsd: run this on FreeBSD/OpenBSD/NetBSD, or set BSD_CC" >&2
	@exit 1
endif

# ------------------------------------------------------------ bsd-386 -------
bsd-386:
ifeq ($(HOST),bsd)
	@mkdir -p $(BUILD)/bsd-386
	$(CC) $(CFLAGS) $(WARN) -o $(BUILD)/bsd-386/$(APP) $(SRC) $(LDFLAGS) $(LDLIBS)
else ifneq ($(BSD_386_CC),)
	@command -v $(BSD_386_CC) >/dev/null 2>&1 || { \
	  echo "bsd-386: $(BSD_386_CC) not found." >&2; \
	  echo "  set BSD_386_CC to a *BSD i386 cross compiler" >&2; exit 1; }
	@mkdir -p $(BUILD)/bsd-386
	$(BSD_386_CC) $(CFLAGS) $(WARN) -o $(BUILD)/bsd-386/$(APP) $(SRC) $(LDFLAGS) $(LDLIBS)
else
	@echo "bsd-386: run this on *BSD, or set BSD_386_CC" >&2
	@exit 1
endif

# ----------------------------------------------------------- bsd-amd64 ------
bsd-amd64:
ifeq ($(HOST),bsd)
	@mkdir -p $(BUILD)/bsd-amd64
	$(CC) $(CFLAGS) $(WARN) -o $(BUILD)/bsd-amd64/$(APP) $(SRC) $(LDFLAGS) $(LDLIBS)
else ifneq ($(BSD_AMD64_CC),)
	@command -v $(BSD_AMD64_CC) >/dev/null 2>&1 || { \
	  echo "bsd-amd64: $(BSD_AMD64_CC) not found." >&2; \
	  echo "  set BSD_AMD64_CC to a *BSD x86_64 cross compiler" >&2; exit 1; }
	@mkdir -p $(BUILD)/bsd-amd64
	$(BSD_AMD64_CC) $(CFLAGS) $(WARN) -o $(BUILD)/bsd-amd64/$(APP) $(SRC) $(LDFLAGS) $(LDLIBS)
else
	@echo "bsd-amd64: run this on *BSD, or set BSD_AMD64_CC" >&2
	@exit 1
endif

# -------------------------------------------------------------- bsd-arm ------
bsd-arm:
ifeq ($(HOST),bsd)
	@mkdir -p $(BUILD)/bsd-arm
	$(CC) $(CFLAGS) $(WARN) -o $(BUILD)/bsd-arm/$(APP) $(SRC) $(LDFLAGS) $(LDLIBS)
else ifneq ($(BSD_ARM_CC),)
	@command -v $(BSD_ARM_CC) >/dev/null 2>&1 || { \
	  echo "bsd-arm: $(BSD_ARM_CC) not found." >&2; \
	  echo "  set BSD_ARM_CC to a *BSD arm cross compiler" >&2; exit 1; }
	@mkdir -p $(BUILD)/bsd-arm
	$(BSD_ARM_CC) $(CFLAGS) $(WARN) -o $(BUILD)/bsd-arm/$(APP) $(SRC) $(LDFLAGS) $(LDLIBS)
else
	@echo "bsd-arm: run this on *BSD, or set BSD_ARM_CC" >&2
	@exit 1
endif

# ----------------------------------------------------------- bsd-arm64 ------
bsd-arm64:
ifeq ($(HOST),bsd)
	@mkdir -p $(BUILD)/bsd-arm64
	$(CC) $(CFLAGS) $(WARN) -o $(BUILD)/bsd-arm64/$(APP) $(SRC) $(LDFLAGS) $(LDLIBS)
else ifneq ($(BSD_ARM64_CC),)
	@command -v $(BSD_ARM64_CC) >/dev/null 2>&1 || { \
	  echo "bsd-arm64: $(BSD_ARM64_CC) not found." >&2; \
	  echo "  set BSD_ARM64_CC to a *BSD aarch64 cross compiler" >&2; exit 1; }
	@mkdir -p $(BUILD)/bsd-arm64
	$(BSD_ARM64_CC) $(CFLAGS) $(WARN) -o $(BUILD)/bsd-arm64/$(APP) $(SRC) $(LDFLAGS) $(LDLIBS)
else
	@echo "bsd-arm64: run this on *BSD, or set BSD_ARM64_CC" >&2
	@exit 1
endif

solaris: bsd

# ------------------------------------------------------------- windows ----
windows: windows-amd64 windows-386

windows-amd64:
ifeq ($(HOST),windows)
	@echo "windows-amd64: the host is Windows, use 'make' for a native build"
else
	@command -v $(WIN64_CC) >/dev/null 2>&1 || { \
	  echo "windows-amd64: $(WIN64_CC) not found." >&2; \
	  echo "  Debian/Ubuntu: sudo apt install gcc-mingw-w64-x86-64" >&2; \
	  echo "  or set WIN64_CC=/path/to/x86_64-w64-mingw32-gcc" >&2; exit 1; }
	@mkdir -p $(BUILD)/windows-amd64
	$(WIN64_CC) $(CFLAGS) $(WARN) -o $(BUILD)/windows-amd64/$(APP).exe \
	    $(SRC) $(LDFLAGS) -lbcrypt $(if $(filter 1,$(STATIC)),-static,)
endif

windows-386:
ifeq ($(HOST),windows)
	@echo "windows-386: the host is Windows, use 'make' for a native build"
else
	@command -v $(WIN32_CC) >/dev/null 2>&1 || { \
	  echo "windows-386: $(WIN32_CC) not found." >&2; \
	  echo "  Debian/Ubuntu: sudo apt install gcc-mingw-w64-i686" >&2; \
	  echo "  or set WIN32_CC=/path/to/i686-w64-mingw32-gcc" >&2; exit 1; }
	@mkdir -p $(BUILD)/windows-386
	$(WIN32_CC) $(CFLAGS) $(WARN) -o $(BUILD)/windows-386/$(APP).exe \
	    $(SRC) $(LDFLAGS) -lbcrypt $(if $(filter 1,$(STATIC)),-static,)
endif

# ------------------------------------------------------------ windows-arm ----
windows-arm:
ifeq ($(HOST),windows)
	@echo "windows-arm: the host is Windows, use 'make' for a native build"
else
	@command -v $(WINARM_CC) >/dev/null 2>&1 || { \
	  echo "windows-arm: $(WINARM_CC) not found." >&2; \
	  echo "  set WINARM_CC=/path/to/arm-w64-mingw32-gcc" >&2; exit 1; }
	@mkdir -p $(BUILD)/windows-arm
	$(WINARM_CC) $(CFLAGS) $(WARN) -o $(BUILD)/windows-arm/$(APP).exe \
	    $(SRC) $(LDFLAGS) -lbcrypt $(if $(filter 1,$(STATIC)),-static,)
endif

# ---------------------------------------------------------- windows-arm64 ----
windows-arm64:
ifeq ($(HOST),windows)
	@echo "windows-arm64: the host is Windows, use 'make' for a native build"
else
	@command -v $(WINARM64_CC) >/dev/null 2>&1 || { \
	  echo "windows-arm64: $(WINARM64_CC) not found." >&2; \
	  echo "  set WINARM64_CC=/path/to/aarch64-w64-mingw32-gcc" >&2; exit 1; }
	@mkdir -p $(BUILD)/windows-arm64
	$(WINARM64_CC) $(CFLAGS) $(WARN) -o $(BUILD)/windows-arm64/$(APP).exe \
	    $(SRC) $(LDFLAGS) -lbcrypt $(if $(filter 1,$(STATIC)),-static,)
endif

# Build with MSVC from a "Developer Command Prompt for VS" that also has GNU
# make on PATH.  (Plain nmake uses the same command line.)
windows-msvc:
	cl /nologo /O2 /W3 $(SRC) /link bcrypt.lib

# --------------------------------------------------------------- dos ------
dos:
ifeq ($(HOST),windows)
	@echo "dos: build with DJGPP on DOS, or cross build from Linux with DOS_CC" >&2
	@exit 1
else
	@command -v $(DOS_CC) >/dev/null 2>&1 || { \
	  echo "dos: $(DOS_CC) not found." >&2; \
	  echo "  install DJGPP and put its bin directory on PATH," >&2; \
	  echo "  or set DOS_CC=/path/to/i586-pc-msdosdjgpp-gcc" >&2; exit 1; }
	@mkdir -p $(BUILD)/dos
	$(DOS_CC) $(CFLAGS) $(WARN) $(DOS_EXTRA) -o $(BUILD)/dos/$(APP).exe $(SRC) $(LDFLAGS)
endif

# -------------------------------------------------------- every platform --
all-platforms:
ifneq (,$(filter windows dos,$(HOST)))
	@echo "all-platforms is meant for Unix-like hosts; use 'make' here."
else
	@echo "building every platform whose toolchain is installed"
	@logs=$$(mktemp -d 2>/dev/null || echo ./.benc-logs); mkdir -p "$$logs"; \
	built=0; skipped=0; failed=0; \
	for p in linux linux-386 linux-amd64 linux-arm linux-arm64 macos macos-amd64 macos-arm64 \
	    termux termux-arm64 bsd bsd-386 bsd-amd64 bsd-arm bsd-arm64 windows-amd64 windows-386 \
	    windows-arm windows-arm64 dos; do \
	    printf '  %-16s ' "$$p"; \
	    if $(MAKE) --no-print-directory $$p >"$$logs/$$p.log" 2>&1; then \
	        echo built; built=$$((built + 1)); \
	    elif grep -qiE 'not found|toolchain|install |set [A-Z_]+_CC|run this (on|in)|meant for Unix|djgpp|osxcross|mingw|android ndk' "$$logs/$$p.log"; then \
	        echo "skipped (toolchain not available)"; skipped=$$((skipped + 1)); \
	    else \
	        echo "FAILED"; failed=$$((failed + 1)); \
	        sed 's/^/      | /' "$$logs/$$p.log"; \
	    fi; \
	done; \
	echo; \
	echo "$$built built, $$skipped skipped, $$failed failed"; \
	if [ -d $(BUILD) ]; then \
	    echo; echo "artifacts:"; \
	    find $(BUILD) -type f \( -name '$(APP)' -o -name '$(APP).exe' \) \
	        -exec ls -l {} \; | sed 's/^/  /'; \
	fi; \
	rm -rf "$$logs"; \
	if [ $$failed -ne 0 ]; then \
	    echo; echo "all-platforms: $$failed target(s) failed" >&2; exit 1; \
	fi
endif

check:
	@echo "host          : $(HOST) ($(HOST_ARCH))"
	@echo "native cc     : $(CC)"
	@printf '%-14s: %s\n' "windows-amd64" "$(if $(shell command -v $(WIN64_CC) 2>/dev/null),$(WIN64_CC),not found)"
	@printf '%-14s: %s\n' "windows-386"   "$(if $(shell command -v $(WIN32_CC) 2>/dev/null),$(WIN32_CC),not found)"
	@printf '%-14s: %s\n' "dos"           "$(if $(shell command -v $(DOS_CC) 2>/dev/null),$(DOS_CC),not found)"
	@printf '%-14s: %s\n' "macos"         "$(if $(MACOS_CC),$(MACOS_CC),$(if $(filter macos,$(HOST)),native cc,not found))"
	@printf '%-14s: %s\n' "termux"        "$(if $(TERMUX_CC),$(TERMUX_CC),not found)"
	@printf '%-14s: %s\n' "termux-arm64"   "$(if $(TERMUX_CC),$(TERMUX_CC),not found)"
	@printf '%-14s: %s\n' "bsd"           "$(if $(BSD_CC),$(BSD_CC),not found)"
	@printf '%-14s: %s\n' "linux-386"     "$(if $(LINUX_386_CC),$(LINUX_386_CC),not set)"
	@printf '%-14s: %s\n' "linux-amd64"   "$(if $(LINUX_AMD64_CC),$(LINUX_AMD64_CC),not set)"
	@printf '%-14s: %s\n' "linux-arm"     "$(if $(LINUX_ARM_CC),$(LINUX_ARM_CC),not set)"
	@printf '%-14s: %s\n' "linux-arm64"   "$(if $(LINUX_ARM64_CC),$(LINUX_ARM64_CC),not set)"
	@printf '%-14s: %s\n' "macos-amd64"   "$(if $(MACOS_AMD64_CC),$(MACOS_AMD64_CC),not set)"
	@printf '%-14s: %s\n' "macos-arm64"   "$(if $(MACOS_ARM64_CC),$(MACOS_ARM64_CC),not set)"
	@printf '%-14s: %s\n' "bsd-386"       "$(if $(BSD_386_CC),$(BSD_386_CC),not set)"
	@printf '%-14s: %s\n' "bsd-amd64"     "$(if $(BSD_AMD64_CC),$(BSD_AMD64_CC),not set)"
	@printf '%-14s: %s\n' "bsd-arm"       "$(if $(BSD_ARM_CC),$(BSD_ARM_CC),not set)"
	@printf '%-14s: %s\n' "bsd-arm64"     "$(if $(BSD_ARM64_CC),$(BSD_ARM64_CC),not set)"
	@printf '%-14s: %s\n' "windows-arm"   "$(if $(WINARM_CC),$(WINARM_CC),not set)"
	@printf '%-14s: %s\n' "windows-arm64" "$(if $(WINARM64_CC),$(WINARM64_CC),not set)"

# ---------------------------------------------------------------- nace ----
# Optional decision-routing helper.  Unlike benc it needs OpenSSL and a POSIX
# socket API, so it has its own binary and is never part of `make all` or the
# platform targets.
NACE_DREX       := $(BUILD)/nace/nace-drex
NACE_DREX_SRC   := nace_drex.c nace_drex_cli.c
NACE_DREX_HDR   := nace_drex.h
NACE_DREX_LDLIBS ?= -lssl -lcrypto

nace-drex: $(NACE_DREX)

$(NACE_DREX): $(NACE_DREX_SRC) $(NACE_DREX_HDR)
	@mkdir -p $(BUILD)/nace
	$(CC) $(CFLAGS) $(WARN) -o $@ $(NACE_DREX_SRC) $(NACE_DREX_LDLIBS)

# --------------------------------------------------------------- tests ----
test: native
	sh tests/run_tests.sh ./$(APP)$(EXE)

# ------------------------------------------------------------- install ----
install: native
	@mkdir -p $(DESTDIR)$(PREFIX)/bin
	install -m 755 $(APP)$(EXE) $(DESTDIR)$(PREFIX)/bin/$(APP)$(EXE)

# --------------------------------------------------------------- clean ----
clean:
	rm -rf $(BUILD)
	rm -f $(APP) $(APP).exe *.o

distclean: clean

help:
	@sed -n '2,33p' Makefile | sed 's|^# \{0,1\}||; s|\$$(PREFIX)|$(PREFIX)|g'
