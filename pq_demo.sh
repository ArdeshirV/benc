#!/bin/sh
# pq_demo.sh — demonstrate benc post-quantum (ML-KEM-768) usage
# Usage: sh pq_demo.sh [path-to-benc]
set -e

BENC=${1:-./benc}
WORK=$(mktemp -d)
PW='correct horse battery staple'

echo "=== Setup ==="
printf 'hello, quantum world\n' > "$WORK/a.txt"
printf 'second file for hybrid mode\n' > "$WORK/b.txt"

echo "=== 1. Generate an ML-KEM-768 key pair ==="
# NOTE: --keygen is a flag; the algorithm is always ML-KEM-768.
# --kem is NOT used here (it takes a public-key FILE path, for encrypt).
"$BENC" --keygen --output "$WORK/kem"
ls -l "$WORK/kem.pub" "$WORK/kem.priv"

echo "=== 2. PQ-only mode (no password) ==="
"$BENC" encrypt --kem "$WORK/kem.pub" -f "$WORK/a.txt" -o "$WORK/a.pq.bcb"
"$BENC" decrypt --key "$WORK/kem.priv" -f "$WORK/a.pq.bcb" -o "$WORK/a.pq.out"
cmp "$WORK/a.txt" "$WORK/a.pq.out" && echo "PQ round-trip OK"

echo "=== 3. Hybrid mode (password + KEM shared secret via HKDF) ==="
printf '%s\n' "$PW" | "$BENC" encrypt --hybrid --kem "$WORK/kem.pub" -f "$WORK/b.txt" -o "$WORK/b.hyb.bcb"
printf '%s\n' "$PW" | "$BENC" decrypt --hybrid --key "$WORK/kem.priv" -f "$WORK/b.hyb.bcb" -o "$WORK/b.hyb.out"
cmp "$WORK/b.txt" "$WORK/b.hyb.out" && echo "Hybrid round-trip OK"

echo "=== 4. Wrong private key is rejected ==="
"$BENC" --keygen --output "$WORK/badkem" >/dev/null 2>&1
if "$BENC" decrypt --key "$WORK/badkem.priv" -f "$WORK/a.pq.bcb" -o "$WORK/a.bad.out" 2>/dev/null; then
    echo "ERROR: wrong key accepted"
    exit 1
else
    echo "Wrong key correctly rejected (exit $?)"
fi

echo "=== Done ==="
rm -rf "$WORK"
