# benc

Small C program that turns any file or directory into an encrypted
ASCII text file and back again, using one password. The container
is always a plain text file (7-bit ASCII, base64 body), so it travels safely
through e-mail, chat, USB sticks, line-based editors, version control and
printers. Payloads are compressed before they are encrypted (LZMA2 by
default, or Zstd) and decompressed after decryption. Only the built-in
native codecs are accepted: `lzma2` (default), `zstd` and `none`.

```
$ benc notes.pdf
Password:
Repeat password:
Encrypted notes.pdf -> notes.pdf.benc

$ benc notes.pdf.benc
Password:
Decrypted notes.pdf.benc -> notes.pdf

$ benc photos/                    # a directory is packed into a tar first
Encrypted photos -> photos.benc
$ benc photos.benc                # ... and unpacked again afterwards
Decrypted photos.benc -> photos
```

Encryption is self-contained: SHA-256, HMAC, PBKDF2, ChaCha20, base64 and
the container parser are all implemented in `benc.c`, with no OpenSSL,
libsodium or other crypto library required. Compression is implemented in
the same source tree (`benc_codecs.c`): both LZMA2 and Zstd are fully native,
so no library and no command line tool is needed. That is what makes the
code portable enough to run on DOS, Windows, macOS, Linux and Termux.

## Usage

```
benc [options] <input> [output]        encrypt or decrypt (auto)
benc encrypt [options] <input> [output]
benc decrypt [options] <input> [output]
benc info <file>
benc selftest
benc --help
benc --version
```

Default output names:

* `encrypt` -> `<input>.benc`
* `decrypt` -> input with `.benc` removed, or `<input>.dec` if there is none

Options:

| Option | Meaning |
| --- | --- |
| `-o, --output FILE` | write the result to `FILE` |
| `-p, --password PASS` | supply the password on the command line |
| `-P, --password-file F` | read the password from the first line of `F` |
| `-i, --iterations N` | PBKDF2 iteration count for new files (default 210000) |
| `-c, --compress NAME` | `lzma2` (default), `zstd`, `none` |
| `--no-compress` | same as `--compress none` |
| `-l, --level N` | compression level (codec default when omitted) |
| `-T, --threads N` | worker threads for the compressor (`0` = all cores) |
| `-f, --force` | overwrite an existing output file |
| `-n, --use-header-name` | on decrypt, restore the original file name |
| `--no-name` | on encrypt, don't store the original file name |
| `-q, --quiet` | suppress informational messages |

If no command is given, benc detects the container by its header and encrypts
or decrypts accordingly. If stdin is a terminal the password is read without
echo and asked twice when encrypting. If stdin is a pipe (scripts, CI) a line
is read from it:

```
printf 'secret\nsecret\n' | benc encrypt -f backup.tar
```

`-p` is convenient for scripts but exposes the password in the process list;
prefer the prompt, a pipe, or `--password-file`.

`-i` only affects newly created containers. Decryption always uses the
iteration count stored in the file.

## Compression and directories

A directory given as input is packed with `tar` (storing the directory itself,
so it is recreated on decrypt), then compressed, then encrypted. On decrypt the
payload is decrypted, decompressed and unpacked into a new directory.

The payload is compressed by default with LZMA2; `-c/--compress zstd` selects
Zstd and `--no-compress` (or `-c none`) turns compression off. Tune with
`-l/--level` and `-T/--threads`:

```
benc -c zstd -l 19 -T 8 project/       # zstd level 19 on 8 threads
benc --no-compress -p secret notes.txt
benc -c lzma notes.txt                  # alias for the default lzma2
```

| Codec | Levels | Threads | Backend |
| --- | --- | --- | --- |
| `lzma2` (default) | 0-9 (6) | `-T` (accepted) | built in (`benc_codecs.c`) |
| `zstd` | 1-19 (3) | `-T` (accepted) | built in (`benc_codecs.c`) |
| `none` | - | no | built in (no compression) |

Both codecs run inside `benc_codecs.c`; no library or command line tool is
involved. The LZMA2 stream is byte-compatible with the one produced by the
`xz` tool, and Zstd output is a standard Zstd frame readable by the `zstd`
tool.

With `-T 0` (the default) thread-aware codecs use every core. The chosen codec,
level and thread count are stored in the authenticated header, so `benc info`
shows them without the password.

### 16-bit DOS

The DOS build is 16-bit: `size_t` holds 16 bits and a single object cannot
exceed 64 KiB, which is less than the compression tables need. The codecs
degrade instead of failing:

* Zstd stores **raw (uncompressed) blocks**. The frames are still standard
  Zstd and decode normally with the `zstd` tool or with this program on any
  other platform. A Zstd frame that uses compressed blocks (for example from
  a container made on a PC) cannot be decompressed on DOS and is rejected
  with an error.
* LZMA2 always emits valid chunks. When the match finder does not fit it
  writes uncompressed chunks, so the result is larger but still
  `xz`-compatible, and compressed LZMA2 streams from other platforms
  decompress normally.
* The 16-bit heap is under 64 KiB in total, so only small payloads work: in
  testing a 20 KB file round-tripped while a 60 KB one failed before
  compression started.

Compress and encrypt large inputs on a 32-bit or 64-bit platform.

## Container format

```
-----BEGIN BENC FILE-----
Version: 4
KDF: PBKDF2-HMAC-SHA256
Iterations: 210000
Cipher: ChaCha20
MAC: HMAC-SHA256
Compression: lzma2
Compression-Level: 6
Compression-Threads: 0
Input: file
Salt: <base64>
Nonce: <base64>
Name: <base64>
Size: <bytes or ->
-----BEGIN BENC DATA-----
<base64 body>
-----END BENC DATA-----
-----END BENC FILE-----
```

* `Salt` is 16 random bytes, `Nonce` 8 random bytes, both fresh for every
  file.
* `Name` is the base64 encoded base name of the source (file or directory),
  `Size` the number of bytes handed to the cipher after compression (`-` when
  the platform cannot determine it).
* `Compression` names the codec, `Compression-Level` its level,
  `Compression-Threads` the requested worker count (`0` = all cores).
  `Input` is `tar` when the payload is a packed directory, otherwise `file`.
* Version 1 containers (no compression fields) are still read and decrypted.
* Versions 2 and 3 are not produced by this tool: they belong to a different
  container lineage (PBKDF2-HMAC-SHA256+SHAKE256, ChaCha20-Cascade-512,
  KMAC256) and are rejected by `parse_header` with an
  "unsupported key derivation function" error.  New containers are written as
  version 4 to avoid colliding with the version 2/3 fixtures shipped in
  `tests/data/`.
* The body is the payload, encrypted, followed by a 32-byte tag, base64
  encoded in 64-character lines.

Key schedule:

```
key  = PBKDF2-HMAC-SHA256(password, salt, iterations, 32)
tag  = HMAC-SHA256(key, canonical_header || ciphertext)
```

The compression fields sit in the canonical header, so changing the recorded
codec, level or input kind invalidates the tag just like changing the salt.

## Security notes

* **Confidentiality**: ChaCha20 with a 256-bit key and a fresh nonce per file.
* **Integrity**: encrypt-then-MAC. The tag covers the entire header (salt,
  nonce, KDF parameters, name, size) and every ciphertext byte. Changing any
  character makes decryption fail.
* **No partial plaintext**: the whole container is authenticated *before* the
  output file is created. A wrong password or a modified file leaves no
  plaintext behind. Compressed payloads are decrypted and decompressed into
  private (0600) temporary files that are removed afterwards, and deleted by
  the interrupt handler.
* **Password handling**: passwords are never stored. Keys are wiped from memory
  after use.
* The original file name and size sit in the container header and are covered
  by the tag, but they are *not* secret: `benc info` shows them without the
  password. The size is always visible because it sets the payload length.
* Randomness comes from `/dev/urandom` on POSIX systems and `BCryptGenRandom`
  on Windows. Plain DOS has no OS entropy source: the fallback mixes the clock
  and addresses into a SHA-256 generator and prints a warning. Treat containers
  created on DOS as weaker and re-encrypt them on a modern system.
* All temporary files (the tar archive of a directory, the compressed
  payload and the staged output) are created on the OS RAM disk (`/dev/shm`
  on Linux, the temp directory on Windows, `/tmp` on DOS) so sensitive
  plaintext never lands on recoverable disk storage. The final result is
  moved into place only after it has been fully written.
* DOS has no `kill`/`raise`, so Ctrl-C / abort cleanup (restoring the terminal,
  removing a half-written temp file) is disabled there; an interrupted run may
  leave a temporary file behind.
* A wrong password and a tampered file both produce the same error on purpose.
* This is a compact, auditable implementation, not a substitute for `age` or
  `gpg` in high-assurance environments.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | success |
| 1 | usage error, I/O error, or malformed container |
| 2 | authentication failure (wrong password or modified file) |

## Build

The Makefile knows how to build for every supported platform and prints a
clear message when a toolchain is missing.

```
make                  # native build, produces ./benc
make linux            # -> build/linux/benc
make linux-386        # -> build/linux-386/benc
make linux-amd64      # -> build/linux-amd64/benc
make linux-arm        # -> build/linux-arm/benc
make linux-arm64      # -> build/linux-arm64/benc
make macos            # -> build/macos/benc
make macos-amd64      # -> build/macos-amd64/benc
make macos-arm64      # -> build/macos-arm64/benc
make termux           # -> build/termux/benc
make bsd              # -> build/bsd/benc
make bsd-386          # -> build/bsd-386/benc
make bsd-amd64        # -> build/bsd-amd64/benc
make bsd-arm          # -> build/bsd-arm/benc
make bsd-arm64        # -> build/bsd-arm64/benc
make windows          # -> build/windows-amd64/benc.exe + build/windows-386/benc.exe
make windows-amd64    # -> build/windows-amd64/benc.exe
make windows-386      # -> build/windows-386/benc.exe
make windows-arm      # -> build/windows-arm/benc.exe
make windows-arm64    # -> build/windows-arm64/benc.exe
make dos              # -> build/dos/benc.exe
make all-platforms    # build every platform whose toolchain is installed
make check            # show which toolchains were detected
make test             # run the test suite with the native build
make install          # install into $(PREFIX)/bin (default /usr/local)
make help
```

Cross compilers are picked up automatically when they are on `PATH`; override
any of them on the command line:

| Target | Toolchain variable | Debian/Ubuntu package |
| --- | --- | --- |
| `windows-amd64` | `WIN64_CC` (x86_64-w64-mingw32-gcc) | `gcc-mingw-w64-x86-64` |
| `windows-386` | `WIN32_CC` (i686-w64-mingw32-gcc) | `gcc-mingw-w64-i686` |
| `dos` | `DOS_CC` (ia16-elf-gcc) | ia16-elf-gcc |
| `macos` | `MACOS_CC` (osxcross `o64-clang`) | osxcross |
| `termux` | `TERMUX_CC` (aarch64-linux-android21-clang) | Android NDK |
| `linux` from a non-Linux host | `LINUX_CC` | any Linux cross gcc |

Examples:

```
make windows WIN64_CC=/opt/mingw/bin/x86_64-w64-mingw32-gcc
make termux TERMUX_CC=$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android21-clang
make linux STATIC=1          # fully static binary, handy for old distros
make DEBUG=1                 # -O0 -g3
```

Without `make`, a direct build is always available:

| Platform | Command |
| --- | --- |
| Linux, macOS, Termux, *BSD | `cc -std=c99 -O2 -o benc benc.c benc_codecs.c benc_tar.c` |
| Windows, MSVC | `cl /O2 /W3 benc.c benc_codecs.c benc_tar.c bcrypt.lib /Fe:benc.exe` |
| Windows, MinGW | `gcc -std=c99 -O2 -o benc.exe benc.c benc_codecs.c benc_tar.c -lbcrypt` |
| DOS, ia16 | `ia16-elf-gcc -std=c99 -O2 -mcmodel=medium -o benc.exe benc.c benc_codecs.c benc_tar.c` |

Only a C99 compiler is needed; all three source files are compiled together. The DOS build targets 16-bit x86 with the
medium memory model (`-mcmodel=medium`); the default tiny model is too small.
Because `size_t` is 16 bits there, Zstd payloads are stored uncompressed and
only small files fit in memory; see [16-bit DOS](#16-bit-dos).

## Files

```
benc.c               CLI, container format and encryption core
benc_codecs.c        native LZMA2 and Zstd codecs
benc_tar.c           built-in tar for directory payloads
Makefile             cross-platform build
tests/run_tests.sh   end-to-end test suite (make test)
tests/data/          compatibility fixtures (version 2 and 3 lineage)
```

## License

MIT License. See `LICENSE` for details.