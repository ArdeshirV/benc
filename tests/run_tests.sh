#!/bin/sh
# benc test suite.  Usage: sh tests/run_tests.sh [path-to-benc]
set -u

BENC=${1:-./benc}
FAILED=0
PASSED=0

if [ ! -x "$BENC" ]; then
    echo "error: '$BENC' is not executable" >&2
    exit 1
fi
case "$BENC" in
    /*) ;;
    *) BENC=$(pwd)/${BENC#./} ;;
esac

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
WORK=$(mktemp -d 2>/dev/null || echo "./benc-test-$$")
mkdir -p "$WORK"
trap 'rm -rf "$WORK"' EXIT INT TERM

PW='correct horse battery staple'

ok()  { PASSED=$((PASSED + 1)); printf 'ok   %s\n' "$1"; }
bad() { FAILED=$((FAILED + 1)); printf 'FAIL %s\n' "$1"; }

expect_rc() { # name expected actual
    if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (expected exit $2, got $3)"; fi
}

expect_file_missing() {
    if [ -e "$2" ]; then bad "$1 (file '$2' should not exist)"; else ok "$1"; fi
}

expect_same() {
    if cmp -s "$2" "$3"; then ok "$1"; else bad "$1 (contents differ)"; fi
}

echo "== self tests =="
if "$BENC" selftest >"$WORK/selftest.log" 2>&1; then
    ok "built-in self tests"
else
    bad "built-in self tests"
    cat "$WORK/selftest.log"
fi

echo "== round trips =="
: > "$WORK/empty.bin"
printf 'x' > "$WORK/one.bin"
printf 'hello, world\n' > "$WORK/text.txt"
printf 'a\r\nb\r\nc\r\n' > "$WORK/crlf.txt"
head -c 4096 /dev/urandom > "$WORK/rand4k.bin" 2>/dev/null || : > "$WORK/rand4k.bin"
head -c 1048576 /dev/urandom > "$WORK/rand1m.bin" 2>/dev/null || : > "$WORK/rand1m.bin"
: > "$WORK/nulbytes.bin"
i=0
while [ $i -lt 512 ]; do printf '\000' >> "$WORK/nulbytes.bin"; i=$((i + 1)); done

for f in empty.bin one.bin text.txt crlf.txt rand4k.bin rand1m.bin nulbytes.bin; do
    "$BENC" encrypt -q -f --textout -p "$PW" "$WORK/$f" >/dev/null 2>&1
    if [ ! -f "$WORK/$f.bct" ]; then
        bad "encrypt $f (no output produced)"
        continue
    fi
    "$BENC" decrypt -q -p "$PW" "$WORK/$f.bct" -o "$WORK/$f.out" >/dev/null 2>&1
    expect_same "round trip $f" "$WORK/$f" "$WORK/$f.out"
done

echo "== output is text =="
if LC_ALL=C grep -q '[^[:print:][:space:]]' "$WORK/text.txt.bct"; then
    bad "container is plain text"
else
    ok "container is plain text"
fi

if head -1 "$WORK/text.txt.bct" | grep -q 'BEGIN BENC FILE'; then
    ok "container has a readable header"
else
    bad "container has a readable header"
fi

echo "== binary container (-b) =="
"$BENC" encrypt -q -f -b -p "$PW" "$WORK/text.txt" -o "$WORK/bin.txt.bcb" >/dev/null 2>&1
if [ -f "$WORK/bin.txt.bcb" ]; then
    ok "binary output produced"
else
    bad "binary output produced"
fi
if head -c 5 "$WORK/bin.txt.bcb" | grep -q '^benc'; then
    ok "binary output starts with the container magic"
else
    bad "binary output starts with the container magic"
fi
"$BENC" decrypt -q -f -p "$PW" "$WORK/bin.txt.bcb" -o "$WORK/bin.txt.out" >/dev/null 2>&1
expect_same "binary round trip text.txt" "$WORK/text.txt" "$WORK/bin.txt.out"
"$BENC" encrypt -q -f -t -p "$PW" "$WORK/text.txt" -o "$WORK/t.txt.bct" >/dev/null 2>&1
if head -1 "$WORK/t.txt.bct" | grep -q 'BEGIN BENC FILE'; then
    ok "-t writes the text container"
else
    bad "-t writes the text container"
fi

echo "== wrong password =="
"$BENC" decrypt -q -f -p 'wrong password' "$WORK/text.txt.bct" \
    -o "$WORK/wrong.out" >/dev/null 2>&1
expect_rc "wrong password is rejected" 2 $?
expect_file_missing "no plaintext written on failure" "$WORK/wrong.out"

echo "== tampering =="
cp "$WORK/text.txt.bct" "$WORK/tamper.benc"
# flip a character in the middle of the payload
awk '/BEGIN BENC DATA/ { indata = 1; print; next }
     indata && !done { c = substr($0, 3, 1); r = (c == "A") ? "B" : "A";
                       $0 = substr($0, 1, 2) r substr($0, 4); done = 1 }
     { print }' \
    "$WORK/tamper.benc" > "$WORK/tamper2.benc"
"$BENC" decrypt -q -f -p "$PW" "$WORK/tamper2.benc" \
    -o "$WORK/tamper.out" >/dev/null 2>&1
expect_rc "modified payload is rejected" 2 $?
expect_file_missing "no plaintext written for modified payload" "$WORK/tamper.out"

cp "$WORK/text.txt.bct" "$WORK/tamperh.benc"
sed 's/^Iterations: 210000$/Iterations: 210001/' "$WORK/tamperh.benc" > "$WORK/tamperh2.benc"
"$BENC" decrypt -q -f -p "$PW" "$WORK/tamperh2.benc" \
    -o "$WORK/tamperh.out" >/dev/null 2>&1
rc=$?
if [ "$rc" -ne 0 ]; then ok "modified header is rejected"; else bad "modified header is rejected"; fi

echo "== truncated input =="
SIZE=$(wc -c < "$WORK/text.txt.bct")
head -c $((SIZE - 40)) "$WORK/text.txt.bct" > "$WORK/trunc.benc"
"$BENC" decrypt -q -f -p "$PW" "$WORK/trunc.benc" -o "$WORK/trunc.out" >/dev/null 2>&1
rc=$?
if [ "$rc" -ne 0 ]; then ok "truncated container is rejected"; else bad "truncated container is rejected"; fi
expect_file_missing "no plaintext written for truncated container" "$WORK/trunc.out"

echo "== not a container =="
"$BENC" decrypt -q -f -p "$PW" "$WORK/text.txt" -o "$WORK/not.out" >/dev/null 2>&1
rc=$?
if [ "$rc" -ne 0 ]; then ok "foreign file is rejected"; else bad "foreign file is rejected"; fi

echo "== overwrite protection =="
"$BENC" encrypt -q -f --textout -p "$PW" "$WORK/text.txt" -o "$WORK/text.txt.bct" >/dev/null 2>&1
"$BENC" encrypt -q -p "$PW" "$WORK/text.txt" -o "$WORK/text.txt.bct" >/dev/null 2>&1
expect_rc "existing output requires -f" 5 $?
"$BENC" encrypt -q -f --textout -p "$PW" "$WORK/text.txt" -o "$WORK/text.txt.bct" >/dev/null 2>&1
expect_rc "force overwrites" 0 $?

echo "== randomness =="
"$BENC" encrypt -q -f -p "$PW" "$WORK/text.txt" -o "$WORK/r1.benc" >/dev/null 2>&1
"$BENC" encrypt -q -f -p "$PW" "$WORK/text.txt" -o "$WORK/r2.benc" >/dev/null 2>&1
if cmp -s "$WORK/r1.benc" "$WORK/r2.benc"; then
    bad "salt and nonce are fresh per file"
else
    ok "salt and nonce are fresh per file"
fi

echo "== metadata =="
if "$BENC" info "$WORK/text.txt.bct" | grep -q 'Original name:[[:space:]]*text.txt'; then
    ok "v4 stores the file name"
else
    bad "v4 stores the file name"
fi

"$BENC" encrypt -q -f --textout --no-name -p "$PW" "$WORK/text.txt" -o "$WORK/noname.benc" >/dev/null 2>&1
mkdir -p "$WORK/nn"
cp "$WORK/noname.benc" "$WORK/nn/x.benc"
( cd "$WORK/nn" && "$BENC" decrypt -q -f -p "$PW" -n x.benc >/dev/null 2>&1 )
if [ -f "$WORK/nn/x" ] && cmp -s "$WORK/text.txt" "$WORK/nn/x"; then
    ok "--no-name falls back to the input name"
else
    bad "--no-name falls back to the input name"
fi

mkdir -p "$WORK/sub"
cp "$WORK/text.txt.bct" "$WORK/sub/renamed.benc"
( cd "$WORK/sub" && "$BENC" decrypt -q -f -p "$PW" -n renamed.benc >/dev/null 2>&1 )
if cmp -s "$WORK/text.txt" "$WORK/sub/text.txt"; then
    ok "-n restores the stored file name"
else
    bad "-n restores the stored file name"
fi

echo "== compression =="
if "$BENC" info "$WORK/text.txt.bct" | grep -q 'Compression:[[:space:]]*lzma'; then
    ok "lzma2 is the default compression"
else
    bad "lzma2 is the default compression"
fi

for m in lzma zstd none; do
    "$BENC" encrypt -q -f --compress "$m" -p "$PW" "$WORK/text.txt" \
        -o "$WORK/c-$m.benc" >/dev/null 2>&1
    "$BENC" decrypt -q -f -p "$PW" "$WORK/c-$m.benc" -o "$WORK/c-$m.out" >/dev/null 2>&1
    expect_same "--compress $m round trip" "$WORK/text.txt" "$WORK/c-$m.out"
done

"$BENC" encrypt -q -f --textout --no-compress -p "$PW" "$WORK/text.txt" \
    -o "$WORK/c-off.benc" >/dev/null 2>&1
if "$BENC" info "$WORK/c-off.benc" | grep -q 'Compression:[[:space:]]*none'; then
    ok "--no-compress disables compression"
else
    bad "--no-compress disables compression"
fi

i=0
: > "$WORK/repeat.txt"
while [ $i -lt 400 ]; do
    printf 'the quick brown fox jumps over the lazy dog 0123456789\n' >> "$WORK/repeat.txt"
    i=$((i + 1))
done

for m in lzma zstd none; do
    "$BENC" encrypt -q -f -c "$m" -p "$PW" "$WORK/repeat.txt" \
        -o "$WORK/r-$m.benc" >/dev/null 2>&1
    "$BENC" decrypt -q -f -p "$PW" "$WORK/r-$m.benc" -o "$WORK/r-$m.out" >/dev/null 2>&1
    expect_same "large payload with $m" "$WORK/repeat.txt" "$WORK/r-$m.out"
done

"$BENC" encrypt -q -f --legacy --compress lzma -p "$PW" "$WORK/text.txt" \
    -o "$WORK/bad-legacy.benc" >/dev/null 2>&1
rc=$?
if [ "$rc" -ne 0 ]; then ok "--legacy rejects compression"; else bad "--legacy rejects compression"; fi

echo "== backwards compatibility =="
"$BENC" decrypt -q -f -p 'v2-fixture' "$SCRIPT_DIR/data/v2.benc" \
    -o "$WORK/v2.out" >/dev/null 2>&1
rc=$?
if [ "$rc" -ne 0 ]; then ok "version 2 containers are rejected"; else bad "version 2 containers are rejected"; fi
expect_file_missing "no plaintext for rejected v2 container" "$WORK/v2.out"

echo "== post quantum container =="
if "$BENC" info "$WORK/text.txt.bct" | grep -q 'Cipher:[[:space:]]*ChaCha20'; then
    ok "new containers use the ChaCha20 cipher"
else
    bad "new containers use the ChaCha20 cipher"
fi
if "$BENC" info "$WORK/text.txt.bct" | grep -q 'MAC:[[:space:]]*HMAC-SHA256'; then
    ok "new containers authenticate with HMAC-SHA256"
else
    bad "new containers authenticate with HMAC-SHA256"
fi

"$BENC" encrypt -q -f --legacy -p "$PW" "$WORK/text.txt" -o "$WORK/v1.benc" >/dev/null 2>&1
rc=$?
if [ "$rc" -ne 0 ]; then ok "--legacy is rejected"; else bad "--legacy is rejected"; fi
expect_file_missing "--legacy does not write a container" "$WORK/v1.benc"

sed 's/^Version: 4$/Version: 1/' "$WORK/text.txt.bct" > "$WORK/downgrade.benc"
"$BENC" decrypt -q -f -p "$PW" "$WORK/downgrade.benc" -o "$WORK/dg.out" >/dev/null 2>&1
rc=$?
if [ "$rc" -ne 0 ]; then ok "version downgrade is rejected"; else bad "version downgrade is rejected"; fi
expect_file_missing "no plaintext for downgraded container" "$WORK/dg.out"

echo "== password input modes =="
printf '%s\n' "$PW" > "$WORK/pw.txt"
"$BENC" decrypt -q -f -P "$WORK/pw.txt" "$WORK/text.txt.bct" \
    -o "$WORK/pwfile.out" >/dev/null 2>&1
expect_same "--password-file works" "$WORK/text.txt" "$WORK/pwfile.out"

printf '%s\n%s\n' "$PW" "$PW" | "$BENC" encrypt -q -f "$WORK/text.txt" \
    -o "$WORK/pipe.benc" >/dev/null 2>&1
printf '%s\n' "$PW" | "$BENC" decrypt -q -f "$WORK/pipe.benc" \
    -o "$WORK/pipe.out" >/dev/null 2>&1
expect_same "password from a pipe" "$WORK/text.txt" "$WORK/pipe.out"

echo "== iteration handling =="
"$BENC" encrypt -q -f -i 1000 -p "$PW" "$WORK/text.txt" -o "$WORK/fast.benc" >/dev/null 2>&1
"$BENC" decrypt -q -f -p "$PW" "$WORK/fast.benc" -o "$WORK/fast.out" >/dev/null 2>&1
expect_same "custom iteration count" "$WORK/text.txt" "$WORK/fast.out"

"$BENC" decrypt -q -f -p "$PW" "$WORK/fast.benc" -o "$WORK/x.out" --iterations 5 >/dev/null 2>&1
expect_same "iteration count comes from the header" "$WORK/text.txt" "$WORK/x.out"

echo "== rekey =="
cp "$WORK/text.txt.bct" "$WORK/rk.benc"
"$BENC" rekey -q -p "$PW" --new-password 'new password' "$WORK/rk.benc" >/dev/null 2>&1
rc=$?
if [ "$rc" -ne 0 ]; then ok "rekey is not a supported command"; else bad "rekey is not a supported command"; fi
expect_same "rekey leaves the file untouched" "$WORK/text.txt.bct" "$WORK/rk.benc"

echo "== every header byte is authenticated =="
"$BENC" encrypt -q -f --textout -i 1000 -p "$PW" "$WORK/text.txt" -o "$WORK/hdr.benc" >/dev/null 2>&1
HDR_LEN=$(awk '/BEGIN BENC DATA/ { print length_all; exit } { length_all += length($0) + 1 }' "$WORK/hdr.benc")
total=0
badflip=0
i=0
while [ "$i" -lt "$HDR_LEN" ]; do
    cp "$WORK/hdr.benc" "$WORK/flip.benc"
    byte=$(od -An -tu1 -j "$i" -N1 "$WORK/hdr.benc" | tr -d ' \n')
    new=$(( (byte + 1) % 256 ))
    printf "\\$(printf '%03o' "$new")" | dd of="$WORK/flip.benc" bs=1 seek="$i" \
        conv=notrunc status=none 2>/dev/null
    if "$BENC" decrypt -q -f -i 1000 -p "$PW" "$WORK/flip.benc" \
        -o "$WORK/flip.out" >/dev/null 2>&1; then
        badflip=$((badflip + 1))
    fi
    total=$((total + 1))
    i=$((i + 1))
done
if [ "$badflip" -eq 0 ]; then
    ok "all $total header bytes are covered by the tag"
else
    bad "$badflip of $total header byte flips were accepted"
fi

echo "== exit codes =="
"$BENC" --definitely-not-an-option >/dev/null 2>&1
expect_rc "usage error exits 3" 3 $?
"$BENC" decrypt -p "$PW" "$WORK/does-not-exist.bcb" >/dev/null 2>&1
expect_rc "missing input exits 4" 4 $?
printf 'not a benc file\n' > "$WORK/foreign.dat"
"$BENC" decrypt -p "$PW" "$WORK/foreign.dat" >/dev/null 2>&1
expect_rc "foreign container exits 6" 6 $?

echo
if [ "$FAILED" -eq 0 ]; then
    echo "all $PASSED tests passed"
    exit 0
fi
echo "$FAILED of $((PASSED + FAILED)) tests failed"
exit 1
