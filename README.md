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

**Post-quantum (container format version 5, tool version 1.7.0):**

```console
$ benc --keygen --kem ml-kem-768 --output kem    # generate an ML-KEM-768 key pair
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
| `-k, --kem FILE` | post-quantum public key file (encrypt, ML-KEM-768) |
| `--key FILE` | post-quantum private key file (decrypt) |
| `--hybrid` | derive the file key via HKDF from password master + KEM shared secret |
| `--keygen FILE` | generate a new ML-KEM-768 public/private key pair |

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
  **1.7.0**: it extends the version 4 field order with the post-quantum fields
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

Version **5** — written by tool version **1.7.0** — extends the version 4 header
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
