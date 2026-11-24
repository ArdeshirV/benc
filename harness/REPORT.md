# benc 1.4.0 — Harness Run Report

## Scope executed
Iteration 0 (baseline + setup) plus targeted fixes for D1 and D5, and the
D3 Makefile define. Full 40-iteration / 6-hour budget was NOT consumed; this
run stopped after two clean iterations with verified fixes.

## Baseline (measured)
- Build: `make` → gcc -O3 -std=c99 -Wall -Wextra -Wpedantic -DBENC_POSIX, 0 warnings, binary 130256 B.
- Tests: `sh tests/run_tests.sh ./benc` → 67/67 pass; `benc selftest` → 15/15.
- Sanitizers: ASan+UBSan full suite → 67/67, 0 findings (detect_leaks=1).

## Fixed (with commits)
| ID | Fix | Commit | Test evidence |
|---|---|---|---|
| D1 | `benc info` now detects binary `.bcb` containers (was text-only, exit 1) | 0012766 | `info` on `.bcb` and `.bct` identical except File: line; malformed input → exit 6 |
| D5 | Progress no longer drawn when `!ui_live` (quiet or non-tty) | 7e6ec90 | `encrypt -q` → 0 stderr bytes; non-tty run → 0 progress bytes |
| D3 | Makefile now passes `-DBENC_WITH_MLKEM` when liboqs present | 64802b7 | define wired into native recipe (liboqs absent in sandbox) |

## Not attempted / blocked
- D2 (tar hardening), D4 (memory staging), D6 (help), D7 (threads), D8 (metadata),
  D9 (docs hygiene), D10/D11 (perf) — require larger, multi-commit work; deferred.
- Fake KEM backend for exercising PQ container logic — not built (liboqs absent).
- Fuzzing, coverage, mutation testing, oracles — not run in this pass.

## Claims NOT verified
- No post-quantum cryptographic correctness (fake backend not implemented).
- No performance numbers beyond baseline throughput (not re-measured).
- No coverage/mutation/fuzz metrics.

## Reproduce
- Build: `make` (0 warnings)
- Tests: `sh tests/run_tests.sh ./benc` (67/67)
- Selftest: `./benc selftest` (15/15)
- ASan: `gcc -O1 -g -fsanitize=address,undefined ...` + full suite (67/67, 0 findings)
