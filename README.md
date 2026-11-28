<div align="center">

<img src="img/benc.png" alt="benc logo" width="160" />

# 🔐 benc

**Tiny, dependency-free file & directory encryption — one password, one file.**

<i>Binary-tight by default · ASCII-safe on request · Everywhere</i>

<p>
  <img alt="C99" src="https://img.shields.io/badge/language-C99-2b6cb0?style=for-the-badge&logo=c&logoColor=white" />
  <img alt="no dependencies" src="https://img.shields.io/badge/dependencies-none-38a169?style=for-the-badge" />
  <img alt="platforms" src="https://img.shields.io/badge/platforms-Windows%20·%20macOS%20·%20Linux%20·%20BSD%20·%20Termux-805ad5?style=for-the-badge" />
  <img alt="license" src="https://img.shields.io/badge/license-MIT-718096?style=for-the-badge" />
</p>

<sub>ChaCha20 · HMAC-SHA256 · PBKDF2 · LZMA2 · Zstd — all implemented in-tree</sub>

</div>

## 🔐 Technical Summary

> **benc** is a dependency-free C99 CLI that encrypts any file or directory with one password into a single portable container (binary `.bcb` by default, ASCII `.bct` on request), using **PBKDF2-HMAC-SHA256 → ChaCha20 → HMAC-SHA256** (encrypt-then-MAC) with LZMA2/Zstd compression, and supports **post-quantum Kyber-768** encapsulation with hybrid password+KEM key derivation via HKDF-SHA256 (container format v5). It builds and runs on **Windows, Linux, macOS, and FreeBSD** with **no runtime dependencies at all** — the pq-crystals Kyber-768 reference implementation is vendored in-tree.

> 📦 **libbenc is a fully independent library.** Everything benc does — encryption,
> decryption, compression, container format, tar, and post-quantum KEM — lives in
> **libbenc**, a self-contained C99 library with no external dependencies. The
> `benc` executable is just a thin CLI layer on top of it. You can link libbenc
> into your own C or C++ programs and use every capability on RAM buffers and
> strings, without ever touching the CLI. See [🧩 Using libbenc in your own C++
> code](#using-libbenc) and the [📚 libbenc API Reference](#libbenc-api).

---

## 📖 Table of contents

- [✨ What is benc?](#what-is-benc)
- [⚡ Quick start](#quick-start)
- [🧭 Usage](#usage)
- [🔑 Passwords & stdin](#passwords-stdin)
- [🗜️ Compression & directories](#compression-directories)
- [📜 Container format](#container-format)
- [🌌 Post-quantum container (version 5)](#post-quantum-container-v5)
- [🛡️ Security notes](#security-notes)
- [🚦 Exit codes](#exit-codes)
- [🏗️ Build](#build)
- [🗂️ Files](#files)
- [⚖️ License](#license)

---

<a id="what-is-benc"></a>
## ✨ What is benc?

`benc` turns **any file or directory** into a single encrypted container — and
back again — protected by one password. Payloads are compressed *before*
encryption (LZMA2 by default, or Zstd) and decompressed *after* decryption.

The default output is a **tight binary container**. Pass `--textout` to get a
**7-bit ASCII** container instead, which travels safely through e-mail, chat,
USB sticks, line-based editors, version control and printers. A binary file is
recognised by its magic and decrypted transparently.

<div align="center">

| 🎯 One password | 🧊 Zero dependencies | 🌍 Everywhere | 🧾 Text-safe |
|:---:|:---:|:---:|:---:|
| encrypt & decrypt files **and** folders | crypto + codecs in-tree | Windows → macOS → Linux → BSD → Termux | ASCII/base64 containers on demand |

</div>

> 🧬 **Self-contained by design.** SHA-256, HMAC, PBKDF2, ChaCha20, base64, the
> container parser **and** both LZMA2 and Zstd codecs live in this source tree.
> No OpenSSL, no libsodium, no `xz`/`zstd` binaries — just a C99 compiler. That
> is what lets the same code run on a low-end box and a modern Mac.

---

<a id="quick-start"></a>
## ⚡ Quick start

```console
$ benc notes.pdf
Password:
Repeat password:
Encrypted notes.pdf -> notes.pdf.bcb  (16 B, 0.2 s)

$ benc notes.pdf.bcb
Password:
Decrypted notes.pdf.bcb -> notes.pdf  (16 B, 0.2 s)

$ benc --textout notes.pdf
Password:
Repeat password:
Encrypted notes.pdf -> notes.pdf.bct  (16 B, 0.2 s)

$ benc --textout notes.pdf.bct
Password:
Decrypted notes.pdf.bct -> notes.pdf  (16 B, 0.2 s)

$ benc photos/                    # a directory is packed into a tar first
Password:
Repeat password:
Encrypted photos/ -> photos.bcb  (159 B, 0.2 s)

$ benc photos.bcb                  # ... and unpacked again afterwards
Password:
Extracted photos.bcb -> photos  (159 B, 0.2 s)
```

**Everything benc can do:**

```console
benc -c zstd -l 19 -T 8 notes.pdf         # compress with zstd level 19 on 8 threads
benc --no-compress -p secret notes.pdf   # store without compression
benc -i 1000 backup.tar                   # PBKDF2 iterations for new containers
benc -b notes.pdf                         # force binary container
benc -t notes.pdf                         # force ASCII text container
benc -n notes.pdf.bcb                    # restore the stored file name on decrypt
```

**Post-quantum (container format version 5, tool version 1.9.0):**

```console
$ benc --keygen --output kem                     # generate a Kyber-768 key pair (kem.pub / kem.priv)
$ benc --kem kem.pub notes.pdf                 # encrypt to a post-quantum recipient
$ benc --key kem.priv notes.pdf.bcb          # decrypt with the recipient private key

$ benc --hybrid --kem kem.pub notes.pdf      # hybrid: password master + KEM shared secret
$ benc --key kem.priv notes.pdf.bcb --hybrid # hybrid: decrypt with password + private key
```

> ℹ️ Sizes and timings vary with the input and machine. The default output is
> the binary `.bcb` container; `--textout` selects the ASCII `.bct` container.
> The interaction line is the only terminal output: the single status line is
> cleared and redrawn in place while a job runs, and the final result is printed
> once the job finishes.

---

<a id="usage"></a>
## 🧭 Usage

```console
benc [options] <input> [output]        encrypt or decrypt (auto)
benc encrypt [options] <input> [output]         # aliases: enc, e
benc decrypt [options] <input> [output]         # aliases: dec, d
benc info <file>
benc selftest
benc --help
benc --version
```

**Default output names**

- 🔒 `encrypt` → `<input>.bcb` (binary container, **default**), or `<input>.bct`
  with `--textout` (text container)
- 🔓 `decrypt` → input with `.bct` / `.bcb` (or legacy `.benc`) removed, or
  `<input>.dec` if none matches
- 📁 a directory keeps the same naming; encrypt reports it as `dir/` and decrypt
  reports `Extracted …`

If no command is given, `benc` detects the container by its header and encrypts
or decrypts accordingly.

### ⚙️ Options

| Option | Meaning |
| :--- | :--- |
| `-o, --output FILE` | write the result to `FILE` |
| `-p, --password PASS` | supply the password on the command line |
| `-P, --password-file F` | read the password from the first line of `F` |
| `-i, --iterations N` | PBKDF2 iteration count for new files (default `210000`) |
| `-c, --compress NAME` | `lzma2` (default), `zstd`, `none` |
| `--no-compress` | same as `--compress none` |
| `-b, --binout` | write a tight binary container (**default**) |
| `-t, --textout` | write the ASCII text/base64 container instead |
| `-l, --level N` | compression level (codec default when omitted) |
| `-T, --threads N` | worker threads for the compressor (`0` = all cores) |
| `-f, --force` | overwrite an existing output file |
| `-n, --use-header-name` | on decrypt, restore the original file name |
| `--no-name` | on encrypt, don't store the original file name |
| `-q, --quiet` | suppress progress and result messages |
| `-h, --help` | show the help text |
| `-v, --version` | show the version |
| `-k, --kem FILE` | post-quantum public key file (encrypt, Kyber-768) |
| `--key FILE` | post-quantum private key file (decrypt) |
| `--hybrid` | derive the file key via HKDF from password master + KEM shared secret |
| `--keygen` | generate a Kyber-768 key pair (output base from `--output`, default `kem`) |

---

<a id="passwords-stdin"></a>
## 🔑 Passwords & stdin

If **stdin is a terminal**, the password is read without echo and asked twice
when encrypting. If **stdin is a pipe** (scripts, CI), a single line is read:

```console
printf 'secret\nsecret\n' | benc encrypt -f backup.tar
```

> ⚠️ `-p` is convenient for scripts but exposes the password in the process
> list. Prefer the prompt, a pipe, or `--password-file`.

> ℹ️ `-i` only affects **newly created** containers. Decryption always uses the
> iteration count stored inside the file.

---

<a id="compression-directories"></a>
## 🗜️ Compression & directories

A directory given as input is packed with `tar` (storing the directory itself,
so it is recreated on decrypt), then compressed, then encrypted. On decrypt the
payload is decrypted, decompressed and unpacked into a new directory.

The payload is compressed with **LZMA2** by default; `-c/--compress zstd`
selects Zstd and `--no-compress` (or `-c none`) turns compression off. Tune
with `-l/--level` and `-T/--threads`:

```console
benc -c zstd -l 19 -T 8 project/       # zstd level 19 on 8 threads
benc --no-compress -p secret notes.txt
benc -c lzma notes.txt                 # alias for the default lzma2
```

| Codec | Levels | Threads | Backend |
| :--- | :--- | :--- | :--- |
| 🧱 `lzma2` (default) | `0-9` (`6`) | `-T` (accepted) | built in (`benc_codecs.c`) |
| ⚡ `zstd` | `1-19` (`3`) | `-T` (accepted) | built in (`benc_codecs.c`) |
| 🚫 `none` | — | no | built in (no compression) |

Both codecs run inside `benc_codecs.c`; no library or command line tool is
involved. The LZMA2 stream is byte-compatible with the `xz` tool, and Zstd
output is a standard Zstd frame readable by the `zstd` tool.

With `-T 0` (the default) thread-aware codecs use every core. The chosen codec,
level and thread count are stored in the authenticated header, so `benc info`
shows them **without the password**.

---

<a id="container-format"></a>
## 📜 Container format

```text
-----BEGIN BENC FILE-----
Version: 5
KDF: PBKDF2-HMAC-SHA256
Iterations: 210000
Cipher: ChaCha20
MAC: HMAC-SHA256
Compression: lzma2
Compression-Level: 6
Compression-Threads: 0
Input: file
Mode: password
KEM: none
KEM-Public-Key: <base64 or empty>
KEM-Ciphertext: <base64 or empty>
Salt: <base64>
Nonce: <base64>
Name: <base64>
Size: <bytes or ->
-----BEGIN BENC DATA-----
<base64 body>
-----END BENC DATA-----
-----END BENC FILE-----
```

- 🧂 `Salt` is 16 random bytes, `Nonce` 8 random bytes — both fresh for every file.
- 🏷️ `Name` is the base64-encoded base name of the source (file or directory);
  `Size` is the number of bytes handed to the cipher after compression (`-` when
  the platform cannot determine it).
- 🗜️ `Compression` names the codec, `Compression-Level` its level,
  `Compression-Threads` the requested worker count (`0` = all cores).
  `Input` is `tar` for a packed directory, otherwise `file`.
- 🕰️ **Version 1** containers (no compression fields) are still read and decrypted.
- 🧾 **Version 4** containers (the previous format) are still read and decrypted.
- 🚫 **Versions 2 and 3** are not produced by this tool: they belong to a
  different container lineage (PBKDF2-HMAC-SHA256+SHAKE256, ChaCha20-Cascade-512,
  KMAC256) and are rejected by `parse_header` with an *unsupported key
  derivation function* error.
- 📦 **Version 5** is the current container format written by tool version
  **1.9.0**: it extends the version 4 field order with the post-quantum fields
  `Mode`, `KEM`, `KEM-Public-Key` and `KEM-Ciphertext`. Older version 1 and 4
  containers are still readable.
- 📦 The body is the payload, encrypted, followed by a 32-byte tag, base64
  encoded in 64-character lines.

### 🧊 Binary container (`-b` / `--binout`, default)

The default output is the tight binary container: the canonical header line,
then the encrypted payload, then the 32-byte tag — all raw bytes. With
`--textout` the output is instead the ASCII text/base64 container (7-bit ASCII,
base64 body). The binary form starts with the canonical header magic
(`benc|<version>|...`) and is detected and decrypted transparently.

**Key schedule**

```text
key = PBKDF2-HMAC-SHA256(password, salt, iterations, 64)   # enc key = first 32, mac key = second 32
tag = HMAC-SHA256(mac_key, canonical_header || ciphertext)
```

For post-quantum containers (`Mode: pq` or `Mode: hybrid`) the file key is
derived through HKDF-SHA256 on top of the PBKDF2 master secret and the KEM shared
secret:

```text
prk = HKDF-Extract(salt = <pbkdf2 master secret>, ikm = <kem shared secret>)
key = HKDF-Expand(prk, info = "benc v1.3 hybrid key v1", length = 64)
     # -> enc_key[32] || mac_key[32]
```

The compression fields sit in the canonical header, so changing the recorded
codec, level or input kind invalidates the tag just like changing the salt.

---

<a id="post-quantum-container-v5"></a>
## 🌌 Post-quantum container (version 5)

Version **5** — written by tool version **1.9.0** — extends the version 4 header
with three post-quantum fields:

```text
Mode: password        # password based (default), pq-only, hybrid
KEM: none             # no KEM, or ml-kem-768
KEM-Public-Key: <base64>    # KEM public key, base64 encoded
KEM-Ciphertext: <base64>   # KEM encapsulated ciphertext, base64 encoded
```

- 🔐 `Mode: password` is the default and keeps the version 4 key schedule
  (PBKDF2-HMAC-SHA256 master split into cipher key and MAC key).
- 🔒 `Mode: pq` selects post-quantum key encapsulation for the payload key.
- 🔗 `Mode: hybrid` mixes the password master secret and the KEM shared secret
  with HKDF-SHA256 to derive the file key (see *Key schedule* above).

The KEM public key and ciphertext are base64 in the header and are covered by
the HMAC tag like every other authenticated header field. The matching command
line options are `--kem`, `--key`, `--hybrid` and `--keygen`.

> ℹ️ Kyber-768 is the official pq-crystals reference implementation, vendored
> under `vendor/kyber/` (public domain / Apache-2.0) and wrapped by
> `benc_kem.c` — no external library is required and the post-quantum options
> are always available. This is the Kyber round-3 encoding that ML-KEM-768 is
> based on, not the final FIPS 203 KDF, so keys are not interchangeable with
> other ML-KEM implementations. The password-based path remains the
> recommended, fully-verified mode.

---

<a id="security-notes"></a>
## 🛡️ Security notes

| Property | Detail |
| :--- | :--- |
| 🔐 **Confidentiality** | ChaCha20 with a 256-bit key and a fresh nonce per file. |
| 🧾 **Integrity** | Encrypt-then-MAC. The tag covers the entire header (salt, nonce, KDF parameters, name, size) and every ciphertext byte. Changing any character makes decryption fail. |
| 🫥 **No partial plaintext** | The whole container is authenticated *before* the output file is created. A wrong password or a modified file leaves no plaintext behind. Compressed payloads are decrypted and decompressed into private (`0600`) temporary files that are removed afterwards and by the interrupt handler. |
| 🗝️ **Password handling** | Passwords are never stored. Keys are wiped from memory after use. |
| 👁️ **Metadata** | Original file name and size live in the header and are covered by the tag, but are **not secret**: `benc info` shows them without the password. The size is always visible because it sets the payload length. |
| 🎲 **Randomness** | `/dev/urandom` on POSIX, `BCryptGenRandom` on Windows.  |
| 🧹 **Temp files** | The tar archive, compressed payload and staged output live on the OS RAM disk (`/dev/shm` on Linux, temp dir on Windows), so plaintext never lands on recoverable disk. The result is moved into place only after it is fully written. |
| 🕵️ **Indistinguishable errors** | A wrong password and a tampered file produce the same error on purpose. |

> 🧪 This is a compact, auditable implementation — **not** a substitute for
> `age` or `gpg` in high-assurance environments.

---

<a id="exit-codes"></a>
## 🚦 Exit codes

`benc` returns a specific, stable exit code for each failure class so scripts
can react without parsing messages.

| Code | Meaning |
| :---: | :--- |
| `0` | ✅ success |
| `1` | ⚠️ unspecified error (e.g. internal failure or weak-random path) |
| `2` | 🔑 authentication failure: wrong password or tampered container |
| `3` | 🧭 usage error: bad/unknown option, missing or extra arguments |
| `4` | 📥 input error: input cannot be opened or read, or input == output |
| `5` | 📤 output error: cannot create/write output, or it exists without `-f` |
| `6` | 📜 format error: not a benc file, malformed header, bad base64, truncated |
| `7` | 🚫 unsupported container: version, KDF, cipher, authenticator or codec |
| `8` | 💥 out of memory |
| `9` | 🗝️ password problem: missing, empty, too long or too many attempts |
| `10` | 🗜️ compression/decompression failure, or directory pack/unpack failure |
| `11` | 🧪 built-in self-test (`benc selftest`) reported failures |

A run interrupted by a signal keeps the conventional shell status of
`128 + signal` (for example `130` for `SIGINT`), after cleaning up any
half-written output.

---

<a id="using-libbenc"></a>
## 🧩 Using `libbenc` in your own C++ code

`benc` is built on top of **libbenc**, a self-contained, dependency-free C99
library. You can link it into your own C or C++ programs.

### 1. Get the library

```console
make library              # builds dist/libbenc/  (static + shared)
make library TYPE=static  # static only
make library TYPE=shared  # shared only
```

The distribution contains only:

```text
dist/libbenc/
├── include/benc/
│   ├── benc.h
│   ├── benc_export.h
│   └── benc_version.h
└── lib/
    ├── libbenc.a
    └── libbenc.so  (or .dylib / .dll)
```

### 2. Include and link

```cpp
#include <benc/benc.h>
#include <cstdio>
#include <cstring>

int main() {
    const char *msg = "hello, libbenc";
    const char *pw  = "correct horse battery staple";

    benc_encrypt_opts eo;
    benc_encrypt_opts_init(&eo);
    eo.password = reinterpret_cast<const uint8_t *>(pw);
    eo.password_len = std::strlen(pw);
    eo.compression = BENC_COMP_ZSTD;

    benc_buf ct = BENC_BUF_INIT, pt = BENC_BUF_INIT;
    benc_status s = benc_encrypt(
        reinterpret_cast<const uint8_t *>(msg), std::strlen(msg), &eo, &ct);
    if (s != BENC_OK) {
        std::fprintf(stderr, "encrypt: %s\n", benc_strerror(s));
        return 1;
    }

    benc_decrypt_opts dopt;
    benc_decrypt_opts_init(&dopt);
    dopt.password = reinterpret_cast<const uint8_t *>(pw);
    dopt.password_len = std::strlen(pw);
    s = benc_decrypt(ct.data, ct.len, &dopt, &pt, nullptr);
    if (s != BENC_OK) {
        benc_buf_free(&ct);
        std::fprintf(stderr, "decrypt: %s\n", benc_strerror(s));
        return 2;
    }

    std::printf("%.*s\n", (int)pt.len, reinterpret_cast<const char *>(pt.data));
    benc_buf_free(&ct);
    benc_buf_free_secure(&pt);
    return 0;
}
```

### 3. Compile

```console
# static link (self-contained executable)
g++ -std=c++17 -O2 -I dist/libbenc/include example.cpp dist/libbenc/lib/libbenc.a -o example

# dynamic link
g++ -std=c++17 -O2 -I dist/libbenc/include example.cpp -L dist/libbenc/lib -lbenc -o example
export LD_LIBRARY_PATH=dist/libbenc/lib:$LD_LIBRARY_PATH
./example
```

### 4. CMake

```cmake
find_package(libbenc REQUIRED)
target_link_libraries(myapp PRIVATE libbenc::libbenc)
```

### Notes for C++ users

- `benc_buf` is a plain C struct; free it with `benc_buf_free()` /
  `benc_buf_free_secure()` (the latter zeroises secret plaintext).
- All functions return `benc_status` (negative on failure); use
  `benc_strerror()` for a human-readable message.
- The library is **thread-safe**: independent operations may run concurrently
  with no shared mutable state and no locks.
- No global state, no hidden configuration — pass `benc_env`/`benc_limits`
  explicitly (or `NULL` for defaults).
- The library never throws; it only returns status codes.

---

---

<a id="libbenc-api"></a>
## 📚 libbenc API Reference

All functions are declared in `<benc/benc.h>` (and `<benc/benc_fs.h>` for
filesystem helpers). Everything is C99, `extern "C"`-safe, and thread-safe.

### Status codes

| Constant | Value | Meaning |
| :--- | :---: | :--- |
| `BENC_OK` | 0 | success |
| `BENC_E_INTERNAL` | -1 | internal error |
| `BENC_E_AUTH` | -2 | wrong password/key or tampered container |
| `BENC_E_INVALID_ARG` | -3 | bad argument / option / struct |
| `BENC_E_INPUT` | -4 | input unreadable |
| `BENC_E_OUTPUT` | -5 | output not writable / exists without force |
| `BENC_E_FORMAT` | -6 | not a benc container / malformed / truncated |
| `BENC_E_UNSUPPORTED` | -7 | unsupported version / KDF / cipher / codec |
| `BENC_E_NOMEM` | -8 | out of memory |
| `BENC_E_PASSWORD` | -9 | missing / empty / too long password |
| `BENC_E_CODEC` | -10 | (de)compression or tar failure |
| `BENC_E_SELFTEST` | -11 | built-in self-test failure |
| `BENC_E_CANCELLED` | -12 | cancelled by callback |
| `BENC_E_LIMIT` | -13 | size / entry limit exceeded |
| `BENC_E_RANDOM` | -14 | entropy source unavailable |
| `BENC_E_BUFFER_TOO_SMALL` | -15 | caller buffer too small |

### Constants

| Constant | Value | Description |
| :--- | :--- | :--- |
| `BENC_KEM_PUBLIC_KEY_LEN` | 1184 | Kyber-768 public key size |
| `BENC_KEM_SECRET_KEY_LEN` | 2400 | Kyber-768 secret key size |
| `BENC_KEM_CIPHERTEXT_LEN` | 1088 | Kyber-768 ciphertext size |
| `BENC_KEM_SHARED_SECRET_LEN` | 32 | shared secret size |
| `BENC_UNLIMITED` | `UINT64_MAX` | no limit |

### Enums

```c
benc_comp:    BENC_COMP_NONE (0), BENC_COMP_LZMA2 (1), BENC_COMP_ZSTD (2)
benc_format:  BENC_FMT_BINARY (0, .bcb), BENC_FMT_TEXT (1, .bct)
benc_mode:    BENC_MODE_PASSWORD (0), BENC_MODE_PQ (1), BENC_MODE_HYBRID (2)
```

### Core types

```c
typedef struct benc_buf {
    uint8_t *data; size_t len, cap;
    void (*free_fn)(void*, void*, size_t); void *free_ctx;
} benc_buf;
#define BENC_BUF_INIT {0,0,0,0,0}

typedef struct benc_env {          /* allocator + randomness (all optional) */
    uint32_t struct_size, flags;
    void *(*alloc)(void*, size_t);
    void *(*realloc)(void*, void*, size_t, size_t);
    void (*free)(void*, void*, size_t);
    void *alloc_ctx;
    int  (*random)(void*, uint8_t*, size_t);  /* 0 = ok */
    void *random_ctx;
} benc_env;

typedef struct benc_limits {       /* 0 = safe default, BENC_UNLIMITED = no limit */
    uint32_t struct_size, flags;
    uint64_t max_input_bytes;     /* default 1 GiB */
    uint64_t max_output_bytes;    /* default 1 GiB (decompression-bomb guard) */
    uint32_t max_iterations;      /* default 10,000,000 */
    uint32_t max_tar_entries;     /* default 1,000,000 */
    uint32_t max_path_len;        /* default 4096 */
} benc_limits;

typedef int (*benc_progress_fn)(uint64_t done, uint64_t total, void *user);
/* non-zero return cancels the operation (BENC_E_CANCELLED) */
```

### One-shot RAM API

```c
benc_status benc_encrypt(const uint8_t *in, size_t in_len,
                        const benc_encrypt_opts *opts, benc_buf *out);
benc_status benc_decrypt(const uint8_t *in, size_t in_len,
                        const benc_decrypt_opts *opts, benc_buf *out, void *info);
size_t      benc_encrypt_bound(size_t in_len, const benc_encrypt_opts *opts);
benc_status benc_encrypt_into(const uint8_t *in, size_t in_len,
    const benc_encrypt_opts *opts, uint8_t *out, size_t out_cap, size_t *out_len);
benc_status benc_decrypt_into(const uint8_t *in, size_t in_len,
    const benc_decrypt_opts *opts, uint8_t *out, size_t out_cap,
    size_t *out_len, void *info);
```

### Options

```c
typedef struct benc_encrypt_opts {
    uint32_t struct_size, flags;
    const benc_env    *env;
    const benc_limits *limits;
    const uint8_t *password;  size_t password_len;
    uint32_t iterations;               /* 0 = 210000 */
    benc_comp compression;  int32_t level;  int32_t threads;
    benc_format format;  benc_mode mode;
    const uint8_t *kem_public_key;  size_t kem_public_key_len;
    const char *name;  size_t name_len;
    benc_progress_fn progress;  void *progress_user;
} benc_encrypt_opts;

typedef struct benc_decrypt_opts {
    uint32_t struct_size, flags;
    const benc_env    *env;
    const benc_limits *limits;
    const uint8_t *password;  size_t password_len;
    const uint8_t *kem_secret_key;  size_t kem_secret_key_len;
    benc_progress_fn progress;  void *progress_user;
} benc_decrypt_opts;
```

### String convenience

```c
benc_status benc_encrypt_string(const char *plaintext, const char *password,
    const benc_encrypt_opts *opts, benc_buf *out);   /* always emits text container */
benc_status benc_decrypt_string(const char *container, const char *password,
    benc_buf *out);
```

### Compression only

```c
benc_status benc_compress(const void *env, int comp, int level, int threads,
    const uint8_t *in, size_t in_len, benc_buf *out, void *limits,
    benc_progress_fn progress, void *user);
benc_status benc_decompress(const void *env, int comp,
    const uint8_t *in, size_t in_len, benc_buf *out, void *limits,
    benc_progress_fn progress, void *user);
```

### Inspection

```c
benc_status benc_container_info(const uint8_t *in, size_t in_len, void *info);
benc_status benc_container_verify(const uint8_t *in, size_t in_len,
    const benc_decrypt_opts *opts);   /* authenticate only, write nothing */
```

### Tar in RAM

```c
benc_status benc_tar_read(const void *env, const uint8_t *tar, size_t len,
    int (*visit)(const void*, void*), void *user, void *limits);
```

### Keys

```c
benc_status benc_kem_keygen(const void *env,
    uint8_t pk[BENC_KEM_PUBLIC_KEY_LEN], uint8_t sk[BENC_KEM_SECRET_KEY_LEN]);
benc_status benc_kem_encapsulate(const void *env, uint8_t *ct, size_t *ctlen,
    uint8_t *ss, size_t *sslen, const uint8_t *pk, size_t pklen);
benc_status benc_kem_decapsulate(const void *env, uint8_t *ss, size_t *sslen,
    const uint8_t *ct, size_t ctlen, const uint8_t *sk, size_t sklen);
benc_status benc_kem_fingerprint(const uint8_t pk[BENC_KEM_PUBLIC_KEY_LEN],
    char out_hex[17]);
```

### Utilities

```c
benc_status benc_selftest(char *report, size_t cap, size_t *report_len);
void        benc_zeroize(void *p, size_t n);
const char *benc_version(void);
uint32_t    benc_abi_version(void);
const char *benc_strerror(benc_status s);
int         benc_status_to_exit_code(benc_status s, int cancelled_by_signal);
const char *benc_license(void);
void        benc_buf_free(benc_buf *b);
void        benc_buf_free_secure(benc_buf *b);
void        benc_env_init(benc_env *e);
void        benc_limits_init(benc_limits *l);
void        benc_encrypt_opts_init(benc_encrypt_opts *o);
void        benc_decrypt_opts_init(benc_decrypt_opts *o);
```

### Filesystem module (`benc_fs.h`, `WITH_FS=1`)

```c
benc_status benc_encrypt_file(const char *in, const char *out,
    const benc_encrypt_opts *opts, const void *fs_opts);
benc_status benc_decrypt_file(const char *in, const char *out,
    const benc_decrypt_opts *opts, const void *fs_opts);
benc_status benc_encrypt_dir(const char *dir, const char *out,
    const benc_encrypt_opts *opts, const void *fs_opts);
benc_status benc_decrypt_dir(const char *in, const char *dest,
    const benc_decrypt_opts *opts, const void *fs_opts);
```

### Environment variables

| Variable | Meaning |
| :--- | :--- |
| `BENC_PASSWORD_FILE` | read password from this file |
| `BENC_TMPDIR` | staging directory for temp files |
| `BENC_THREADS` | worker threads for compression |
| `NO_COLOR` | disable color/progress output |

---

---

<a id="build"></a>
## 🏗️ Build

The Makefile knows how to build for every supported platform and prints a clear
message when a toolchain is missing.

```console
make                  # native build, produces ./benc (alias for `make native`)
make native           # native build, produces ./benc
make native-optimized # native build with -march=native (host CPU tuning) -> ./benc
make linux            # -> build/linux/benc
make linux-386        # -> build/linux-386/benc
make linux-amd64      # -> build/linux-amd64/benc
make linux-arm        # -> build/linux-arm/benc
make linux-arm64      # -> build/linux-arm64/benc
make macos            # -> build/macos/benc
make macos-amd64      # -> build/macos-amd64/benc
make macos-arm64      # -> build/macos-arm64/benc
make macos-universal  # macOS universal, arm64 + amd64 -> build/macos-universal/benc
make termux           # -> build/termux/benc
make termux-arm64     # -> build/termux-arm64/benc
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
make windows-msvc     # build with MSVC (cl) from a VS developer prompt
make nace-drex        # optional Nace Drex client -> build/nace/nace-drex
make all-platforms    # build every platform whose toolchain is installed
make check            # show which toolchains were detected
make test             # run the test suite with the native build
make install          # install into $(PREFIX)/bin (default /usr/local)
make clean            # remove all build products
make distclean        # same as clean
make help             # show this target list
```

> ⚡ `make native-optimized` appends `-march=native`, tuning the binary for the
> CPU it was built on. It may not run on older or different processors — use
> plain `make` for a portable binary.

> 🪟 The Windows executables embed the application icon (`img/benc.ico`) and a
> version resource through `benc.rc`, compiled with `windres` (from
> `binutils-mingw-w64`) and linked into every `windows-*` build.

> 🧩 `make nace-drex` builds the optional Nace Drex helper from `nace_drex*.c`.
> Those sources are not part of this repository, so the target only works when
> you provide them.

### 🧰 Cross toolchains

Cross compilers are picked up automatically when they are on `PATH`; override
any of them on the command line.

| Target | Toolchain variable | Debian/Ubuntu package |
| :--- | :--- | :--- |
| `windows-amd64` | `WIN64_CC` (`x86_64-w64-mingw32-gcc`) | `gcc-mingw-w64-x86-64` |
| `windows-386` | `WIN32_CC` (`i686-w64-mingw32-gcc`) | `gcc-mingw-w64-i686` |
| `macos` | `MACOS_CC` (osxcross `o64-clang`) | osxcross |
| `termux` | `TERMUX_CC` (`aarch64-linux-android21-clang`) | Android NDK |
| `linux` from a non-Linux host | `LINUX_CC` | any Linux cross gcc |

```console
make windows WIN64_CC=/opt/mingw/bin/x86_64-w64-mingw32-gcc
make termux TERMUX_CC=$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android21-clang
make linux STATIC=1          # fully static binary, handy for old distros
make DEBUG=1                 # -O0 -g3
```

### 🧱 Direct build (no make)

| Platform | Command |
| :--- | :--- |
| Linux, macOS, Termux, *BSD | `cc -std=c99 -O2 -o benc benc.c benc_codecs.c benc_tar.c` |
| Windows, MSVC | `cl /O2 /W3 benc.c benc_codecs.c benc_tar.c bcrypt.lib /Fe:benc.exe` |
| Windows, MinGW | `gcc -std=c99 -O2 -o benc.exe benc.c benc_codecs.c benc_tar.c -lbcrypt` |

Only a C99 compiler is needed; all three source files are compiled together. The
the default tiny model is too small. Because `size_t` is 16 bits there, Zstd
payloads are stored uncompressed and only small files fit in memory — see

---

<a id="files"></a>
## 🗂️ Files

```text
benc.c               CLI, container format and encryption core
benc_platform.h      platform abstraction layer (OS, tty, file, path, entropy)
benc_kem.c           Kyber-768 adapter over the vendored reference implementation
benc_kem.h           KEM public interface
benc_codecs.c        native LZMA2 and Zstd codecs
benc_codecs.h        codec interface
benc_tar.c           built-in tar for directory payloads
benc_tar.h           tar interface
benc.rc              Windows resource script (icon + version info)
img/benc.ico         Windows application icon
img/benc.png         project icon used in this README
Makefile             cross-platform build
tests/run_tests.sh   end-to-end test suite (make test)
tests/data/          compatibility fixtures (version 2 and 3 lineage)
```

---

<a id="license"></a>
## ⚖️ License

MIT License. See [`LICENSE`](LICENSE) for details.

<div align="center"><sub>Made with love and a stubborn refusal to link an external library.</sub></div>
