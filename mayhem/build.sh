#!/usr/bin/env bash
#
# mayhem/build.sh — build CMake's fuzzers (fuzz + standalone) and the test programs mayhem/test.sh runs.
#
# Runs inside the commit image (mayhem/Dockerfile) as `mayhem` in /mayhem. The base image
# (ghcr.io/savantenvs/base) already exports the build contract — use these, don't redefine:
#   CC, CXX             stock clang / clang++
#   LIB_FUZZING_ENGINE  -fsanitize=fuzzer   (link into each harness that has a LLVMFuzzer entry)
#   SANITIZER_FLAGS     -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer
#                       (ASan + UBSan, both set to HALT — so Mayhem catches memory AND UB defects)
#   DEBUG_FLAGS         -g -gdwarf-3   (DWARF debug info — always on for fuzz/standalone builds,
#                       independent of the sanitizer off-switch; DWARF version must be < 4)
#   RUST_DEBUG_FLAGS    -C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3
#                       (thread through RUSTFLAGS on every cargo-fuzz build)
#   GO_DEBUG_FLAGS      -gcflags=all=-N -l
#                       (thread through go build / go-fuzz-build so the linked ELF keeps symbols)
#   SRC                 /mayhem (the repo source)
#
# Contract: build EVERYTHING here — one runnable binary per fuzz harness, AND the project's test
# suite (so mayhem/test.sh only has to RUN it, never compile). Keep it ADDITIVE (build upstream as
# upstream documents; don't edit upstream files). IMPORTANT: build the PROJECT ITSELF with
# $SANITIZER_FLAGS and $DEBUG_FLAGS (not just the harness) so the fuzzed code is instrumented
# AND carries DWARF < 4 symbols — otherwise ASan/UBSan only see the harness, not the library
# you're trying to find bugs in, and backtraces won't resolve project source lines. Build the TEST
# suite with the project's NORMAL flags (a clean, independent build) so test.sh stays an honest
# functional oracle and won't false-fail on benign UB. Leave the test binary/runner where test.sh
# expects it.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) — it must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# Build knobs come from the ENVIRONMENT (overridable), with sane defaults — no if-statements,
# just parameter-expansion fallbacks. Default sanitizers are the base's ASan+UBSan (halting); override
# per build via the Dockerfile's `--build-arg SANITIZER_FLAGS="..."`.
# NB: SANITIZER_FLAGS uses `=` (no colon) on purpose — `=` only fills when the var is UNSET, so an
# explicit EMPTY value (`--build-arg SANITIZER_FLAGS=`) is honored and builds with NO sanitizers
# (useful when you want the program's natural crash / full backtrace, not an ASan report). The other
# knobs use `:=` (default on empty too). MAYHEM_JOBS sets build parallelism (falls back to nproc).
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
# DEBUG_FLAGS carries DWARF debug info INDEPENDENTLY of the sanitizer off-switch (so an empty
# SANITIZER_FLAGS still yields DWARF symbols). DWARF MUST be < 4 (Mayhem triage can't read >=4); clang-19's
# plain `-g` emits DWARF-5, so `-gdwarf-3` is explicit. Apply $DEBUG_FLAGS to the fuzz/harness/standalone
# builds (NOT the test/oracle build). Rust/Go carry the same intent via their language flags below.
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${RUST_DEBUG_FLAGS:=-C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3}"
: "${GO_DEBUG_FLAGS:=-gcflags=all=-N -l}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
# COVERAGE_FLAGS: empty by default → no effect on the normal oracle build. Set it via the Dockerfile's
# `--build-arg COVERAGE_FLAGS="-fprofile-instr-generate -fcoverage-mapping"` to instrument the TEST
# build for source-coverage measurement (how much of the project the test suite actually exercises —
# a quality signal for the oracle; complements the anti-reward-hack sabotage check). APPEND it to the
# test build's compile+link flags in step 3 (NOT the fuzz build); after `test.sh` runs, merge with
# `llvm-profdata` and report with `llvm-cov`. Empty value is honored (`=`, not `:=`).
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS RUST_DEBUG_FLAGS GO_DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

# Both build trees are named build-*: upstream's .gitignore covers /build*/, so `git clean -ffdX`
# removes them (configure state included).
B="$SRC/build-fuzz"      # sanitized + coverage-instrumented: CMakeLib, its bundled libraries, the fuzzers
T="$SRC/build-tests"     # the project's normal flags: cmake, ctest and the unit-test drivers

# Coverage instrumentation for the library code (upstream's Tests/Fuzzing/README.rst builds with
# -fsanitize=fuzzer-no-link: instrumented, without pulling the engine's main() into every executable).
: "${FUZZ_COVERAGE_FLAGS=-fsanitize=fuzzer-no-link}"
FUZZ_FLAGS="$SANITIZER_FLAGS $FUZZ_COVERAGE_FLAGS $DEBUG_FLAGS"
# The bundled C libraries call callbacks through pointers of a different function type by design
# (the generated llpkgc pkg-config parser, llpkgc_dep__internal.c:959; librhash's hash-function table,
# rhash.c:148), which UBSan's `function` check halts on for every .pc input and every script that
# hashes. Relax exactly that one check, for C only: CMake's own C++ keeps the full ASan+UBSan set.
FUZZ_C_RELAX=""
case "$SANITIZER_FLAGS" in *undefined*) FUZZ_C_RELAX="-fno-sanitize=function" ;; esac
# The 42 binaries each link all of CMakeLib statically with debug info; lld keeps that fast.
FUZZ_LD=""
command -v ld.lld >/dev/null 2>&1 && FUZZ_LD="-fuse-ld=lld"

# 0) Objects linked next to upstream's harnesses: the build-time LeakSanitizer off-switch (into every
#    executable of the fuzz tree, through CMAKE_EXE_LINKER_FLAGS) and the run-once standalone driver.
#    Written only when their content changes, so a re-run does not relink anything.
mkdir -p "$B/mayhem"
compile_c() {  # compile_c <source> <object>
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$1" -o "$2.new"
  if cmp -s "$2.new" "$2"; then rm -f "$2.new"; else mv -f "$2.new" "$2"; fi
}
compile_c "$SRC/mayhem/lsan_off.c"   "$B/mayhem/lsan_off.o"
compile_c "$STANDALONE_FUZZ_MAIN"    "$B/mayhem/standalone_main.o"

# 1) CMake itself, as OSS-Fuzz builds it (bundled libraries, no OpenSSL, no tests), with sanitizers +
#    coverage, and upstream's in-tree fuzzers (Tests/Fuzzing, -DCMake_BUILD_FUZZING=ON). Upstream's
#    Tests/Fuzzing/CMakeLists.txt takes the engine from $LIB_FUZZING_ENGINE. Release (so NDEBUG), the
#    configuration upstream fuzzes: its harnesses build project states no real run reaches and
#    upstream's own genex_eval seed compiled_files.bin fails an assert() there
#    (cmGeneratorTarget.cxx:4545) when asserts are compiled in.
mapfile -t FUZZERS < <(grep -vE '^[[:space:]]*(#|$)' "$SRC/mayhem/fuzzers.txt")
cmake -S "$SRC" -B "$B" -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_FLAGS="$FUZZ_FLAGS $FUZZ_C_RELAX" \
  -DCMAKE_CXX_FLAGS="$FUZZ_FLAGS" \
  -DCMAKE_C_FLAGS_RELEASE="-O2 -DNDEBUG" \
  -DCMAKE_CXX_FLAGS_RELEASE="-O2 -DNDEBUG" \
  -DCMAKE_EXE_LINKER_FLAGS="$FUZZ_LD $B/mayhem/lsan_off.o" \
  -DCMake_BUILD_FUZZING=ON \
  -DCMAKE_USE_SYSTEM_LIBRARIES=OFF \
  -DCMAKE_USE_OPENSSL=OFF \
  -DBUILD_TESTING=OFF \
  -DBUILD_CursesDialog=OFF -DBUILD_QtDialog=OFF
cmake --build "$B" -j"$MAYHEM_JOBS" --target "${FUZZERS[@]}"

# 2) Per harness: the libFuzzer binary /mayhem/<name> and the run-once reproducer
#    /mayhem/<name>-standalone. The reproducer is the SAME link (same objects, libraries and flags)
#    with the engine swapped for the standalone driver, so it is derived from the link command Ninja
#    holds for the target rather than restated here. `rewrite` fails loudly if upstream's link line
#    ever stops having the shape this relies on.
rewrite() {  # rewrite <text> <literal-pattern> <replacement>  → text with EVERY occurrence replaced
  case "$1" in *"$2"*) ;; *) echo "build.sh: expected '$2' in: $1" >&2; return 1 ;; esac
  printf '%s' "${1//"$2"/"$3"}"
}
link_command() { ninja -C "$B" -t commands "$1" | tail -n 1; }
run_in_tree() { (cd "$B" && bash -euo pipefail -c "$1"); }

# Harnesses of ours, from mayhem/harnesses/<name>.cxx. Each is compiled and linked with the commands
# Ninja holds for an upstream harness (<template>), so it sees exactly the flags, includes and
# libraries upstream's do. <template> is the upstream harness the variant replaces, or any upstream
# harness for a harness that has no upstream counterpart:
#   cmScriptFuzzer, cmArchiveExtractFuzzer  upstream's harnesses, with the reasons they differ in their headers
#   cmDependsJavaParserFuzzer, cmDependsCFuzzer  scanners that read project sources; not in Tests/Fuzzing
VARIANTS=(cmScriptFuzzer cmArchiveExtractFuzzer cmDependsJavaParserFuzzer cmDependsCFuzzer)
declare -A VARIANT_TEMPLATE=(
  [cmScriptFuzzer]=cmScriptFuzzer
  [cmArchiveExtractFuzzer]=cmArchiveExtractFuzzer
  [cmDependsJavaParserFuzzer]=cmGlobFuzzer
  [cmDependsCFuzzer]=cmGlobFuzzer
)
declare -A LINK_CMD    # name -> the link command (run in $B) that produces mayhem/<name>

build_variant() {  # build_variant <name>
  local name="$1" tpl="${VARIANT_TEMPLATE[$1]}"
  local obj="mayhem/$1.cxx.o" src="$SRC/mayhem/harnesses/$1.cxx" cc_cmd link
  if [ ! -e "$B/$obj" ] || [ "$src" -nt "$B/$obj" ] || [ "$B/build.ninja" -nt "$B/$obj" ]; then
    cc_cmd="$(ninja -C "$B" -t commands "$tpl" | grep -F -- "-c $SRC/Tests/Fuzzing/$tpl.cxx" | tail -n 1)"
    cc_cmd="$(rewrite "$cc_cmd" "Tests/Fuzzing/CMakeFiles/$tpl.dir/$tpl.cxx.o" "$obj")"
    cc_cmd="$(rewrite "$cc_cmd" "-c $SRC/Tests/Fuzzing/$tpl.cxx" "-c $src")"
    run_in_tree "$cc_cmd"
  fi
  link="$(link_command "$tpl")"
  link="$(rewrite "$link" "Tests/Fuzzing/CMakeFiles/$tpl.dir/$tpl.cxx.o" "$obj")"
  link="$(rewrite "$link" "Tests/Fuzzing/CMakeFiles/$tpl.dir/link.d" "mayhem/$name.link.d")"
  link="$(rewrite "$link" " -o Tests/Fuzzing/$tpl " " -o mayhem/$name ")"
  LINK_CMD[$name]="$link"
  if [ ! -e "$B/mayhem/$name" ] || [ "$B/$obj" -nt "$B/mayhem/$name" ] || [ "$B/Source/libCMakeLib.a" -nt "$B/mayhem/$name" ]; then
    run_in_tree "$link"
  fi
}
for v in "${VARIANTS[@]}"; do build_variant "$v"; done

for f in "${FUZZERS[@]}" "${VARIANTS[@]}"; do
  if [ -n "${LINK_CMD[$f]:-}" ]; then bin="$B/mayhem/$f"; link="${LINK_CMD[$f]}"; out="mayhem/$f"
  else bin="$B/Tests/Fuzzing/$f"; link="$(link_command "$f")"; out="Tests/Fuzzing/$f"; fi
  [ -x "$bin" ] || { echo "build.sh: $bin was not built" >&2; exit 1; }
  # Hard link, not a copy: six of these binaries are ~350 MB each.
  if [ ! "$bin" -ef "$SRC/$f" ]; then ln -f "$bin" "$SRC/$f" 2>/dev/null || cp -f "$bin" "$SRC/$f"; fi
  if [ ! -e "$SRC/$f-standalone" ] || [ "$bin" -nt "$SRC/$f-standalone" ]; then
    link="$(rewrite "$link" " -o $out " " -o $SRC/$f-standalone ")"
    link="$(rewrite "$link" "link.d " "standalone-link.d ")"
    # " -fsanitize=fuzzer " with both spaces: the engine, not the -fsanitize=fuzzer-no-link coverage flag.
    link="$(rewrite "$link" " $LIB_FUZZING_ENGINE " " $B/mayhem/standalone_main.o ")"
    run_in_tree "$link"
  fi
done

# 3) The test programs mayhem/test.sh runs, with the project's NORMAL flags (Release, the build type
#    upstream's bootstrap defaults to; no sanitizers), independent of the fuzz tree: cmake and ctest,
#    the CMakeLib and kwsys unit-test drivers and the two helper programs those unit tests spawn.
cmake -S "$SRC" -B "$T" -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_C_FLAGS="$COVERAGE_FLAGS" -DCMAKE_CXX_FLAGS="$COVERAGE_FLAGS" \
  -DBUILD_TESTING=ON \
  -DCMAKE_USE_SYSTEM_LIBRARIES=OFF \
  -DCMAKE_USE_OPENSSL=OFF \
  -DBUILD_CursesDialog=OFF -DBUILD_QtDialog=OFF
cmake --build "$T" -j"$MAYHEM_JOBS" --target cmake ctest \
  CMakeLibTests testUVProcessChainHelper testDebuggerNamedPipe cmsysTestsCxx cmsysTestsC

echo "build.sh: built $(( ${#FUZZERS[@]} + ${#VARIANTS[@]} )) fuzzers (+ standalone) and the test tree"
