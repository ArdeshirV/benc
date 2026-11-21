# benc

Single-file, dependency-free C program that turns any file into an encrypted
ASCII text file and back again, using one password. The container is always a
plain text file (7-bit ASCII, base64 body), so it travels safely through
e-mail, chat, USB sticks, line-based editors, version control and printers.

```
$ benc notes.pdf
Password:
Repeat password:
Encrypted notes.pdf -> notes.pdf.benc

$ benc notes.pdf.benc
Password:
Decrypted notes.pdf.benc -> notes.pdf
```

No OpenSSL, libsodium or any other library is required. Everything (SHA-256,
SHA-3/SHAKE256, HMAC, KMAC256, PBKDF2, ChaCha20, base64 and the container
parser) is implemented in `benc.c`. That is what makes it possible to run the
same code on DOS, Windows, macOS, Linux and Termux.

## Build

The Makefile knows how to build for every supported platform and prints a
clear message when a toolchain is missing.

```
make                  # native build, produces ./benc
make linux            # -> build/linux/benc
make macos            # -> build/macos/benc
make termux           # -> build/termux/benc
make bsd              # -> build/bsd/benc
make windows          # -> build/windows-amd64/benc.exe + build/windows-386/benc.exe
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

Without `make`, the single-file build is always available:

| Platform | Command |
| --- | --- |
| Linux, macOS, Termux, *BSD | `cc -std=c99 -O2 -o benc benc.c` |
| Windows, MSVC | `cl /O2 /W3 benc.c bcrypt.lib /Fe:benc.exe` |
| Windows, MinGW | `gcc -std=c99 -O2 -o benc.exe benc.c -lbcrypt` |
| DOS, ia16 | `ia16-elf-gcc -std=c99 -O2 -mcmodel=medium -o benc.exe benc.c` |

Only a C99 compiler is needed. The DOS build targets 16-bit x86 with the
medium memory model (`-mcmodel=medium`); the default tiny model is too small.

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
| `-f, --force` | overwrite an existing output file |
| `-n, --use-header-name` | on decrypt, restore the original file name |
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

## Decision routing with Nace Drex (optional)

`nace-drex` is a companion tool, not part of `benc`: it sends one case state and
typed questions to the [Nace Drex](https://console.nace.ai/docs/drex/quickstart)
decision API (`POST /v1/systemone`, model `drex-latest`) and routes the case on
the calibrated probability of every option. `benc` itself never links a network
or crypto library; this tool needs OpenSSL and a POSIX socket API.

```
make nace-drex
export NACE_API_KEY="nace_sk_..."      # from console.nace.ai -> API Keys

./build/nace/nace-drex --state "Help! My payouts have been failing for 3 days." \
    --noul is_urgent="Does this convey urgency?" \
    --choice team="Which team should handle this?" \
    --option payments="Payouts, charges, or refunds" \
    --option support="General questions and how-to"
```

```
drex-latest  request req_...  6.8 ms  tokens 63/86
is_urgent        noul    p(yes)=0.8401 p(no)=0.1599  -> yes
team             choice  payments=0.9227 support=0.0296  -> payments
```

`--threshold P` (default 0.5) is the probability an option needs before it is
acted on; an answer that clears nothing is printed as undecided and the tool
exits 2, so a script can send that case to a human instead. `--score ID=TEXT`
with `--level` asks an ordered question, `--state-file` or stdin replaces
`--state`, `--model` picks another model, and `--json` prints the raw response.
The key is only ever read from `NACE_API_KEY` (see `.env.example`), and exit
codes are 0 decided, 2 below the threshold, 1 usage, network or API error.

## Container format

```
-----BEGIN BENC FILE-----
Version: 1
KDF: PBKDF2-HMAC-SHA256
Iterations: 210000
Cipher: ChaCha20
MAC: HMAC-SHA256
Salt: <base64>
Nonce: <base64>
Name: <base64>
Size: <bytes or ->
-----BEGIN BENC DATA-----
<base64 body>
-----END BENC DATA-----
-----END BENC FILE-----
```

* `Salt` is 32 random bytes, `Nonce` 16 random bytes, both fresh for every
  file.
* `Name` is the base64 encoded base name of the source file, `Size` its length
  in bytes (`-` when the platform cannot determine it).
* The body is the plaintext, encrypted, followed by a 32-byte tag, base64
  encoded in 64-character lines.

Key schedule:

```
key  = PBKDF2-HMAC-SHA256(password, salt, iterations, 32)
tag  = HMAC-SHA256(key, canonical_header || ciphertext)
```

## Security notes

* **Confidentiality**: ChaCha20 with a 256-bit key and a fresh nonce per file.
* **Integrity**: encrypt-then-MAC. The tag covers the entire header (salt,
  nonce, KDF parameters, name, size) and every ciphertext byte. Changing any
  character makes decryption fail.
* **No partial plaintext**: the whole container is authenticated *before* the
  output file is created. A wrong password or a modified file leaves no
  plaintext behind.
* **Password handling**: passwords are never stored. Keys are wiped from memory
  after use.
* The original file name and size sit in the container header and are covered
  by the tag, but they are *not* secret: `benc info` shows them without the
  password. The size is always visible because it sets the payload length.
* Randomness comes from `/dev/urandom` on POSIX systems and `BCryptGenRandom`
  on Windows. Plain DOS has no OS entropy source: the fallback mixes the clock
  and addresses into a SHA-256 generator and prints a warning. Treat containers
  created on DOS as weaker and re-encrypt them on a modern system.
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

## Files

```
benc.c               the whole program
nace_drex.c, .h      optional Nace Drex decision client (OpenSSL + POSIX)
nace_drex_cli.c      the nace-drex command line front end
Makefile             cross-platform build
tests/run_tests.sh   end-to-end test suite (make test)
tests/data/          version 2 compatibility fixture
```
