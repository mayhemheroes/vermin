#!/usr/bin/env bash
#
# mayhem/build.sh -- build the vermin Atheris fuzz harness + its standalone reproducer,
# and prepare the project's own unittest suite. Runs inside the commit image
# (mayhem/Dockerfile) as `mayhem` in /mayhem. Python adaptation of the C/C++ template.
#
# What it does (must be idempotent + air-gapped on re-run -- SPEC item 9 / 6.5):
#   1. Populate / reuse an in-image wheelhouse under /opt/toolchains/python (HOME-independent),
#      then install atheris OFFLINE from that wheelhouse into a fixed site dir on PYTHONPATH. The
#      first (CI, online) build fills the wheelhouse; the air-gapped PATCH re-run resolves entirely
#      from it (pip --no-index --find-links). vermin itself has NO runtime deps and is consumed as
#      the editable source tree at the repo root ($SRC on PYTHONPATH), so a PATCH agent's edits
#      under vermin/ take effect with no reinstall.
#   2. Compile launcher.c -> the ELF Mayhem target `vermin_fuzzer` (Atheris is a Python script;
#      Mayhem needs an ELF cmd, and the gate needs DWARF < 4 -- hence a compiled wrapper).
#   3. Build the same launcher as the standalone (run-once) reproducer `vermin_fuzzer-standalone`.
#   4. Compile run_tests.c -> the ELF test wrapper that drives the unittest oracle.
#
# The base image exports the build contract (CC, SANITIZER_FLAGS, DEBUG_FLAGS, ...). We only need
# DEBUG_FLAGS here (the launcher is a thin C exec wrapper -- sanitizing it would just instrument the
# wrapper, not the fuzzed Python; Atheris instruments the vermin library itself at import time).
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}"
: "${MAYHEM_JOBS:=$(nproc)}"
export DEBUG_FLAGS CC MAYHEM_JOBS

SRC="${SRC:-/mayhem}"
cd "$SRC"

# -- Python toolchain caches at a FIXED, $HOME-independent prefix (SPEC item 8) --
PY_PREFIX=/opt/toolchains/python
WHEELHOUSE="$PY_PREFIX/wheelhouse"
SITE="$PY_PREFIX/site"
mkdir -p "$WHEELHOUSE" "$SITE"

PY="$(command -v python3)"

# 1) Wheelhouse: download the fuzzing runtime dependency ONCE (online). On the air-gapped re-run the
#    directory is already populated, so pip never reaches the network. atheris ships a prebuilt
#    manylinux wheel for this CPython, so no compilation is needed. vermin has NO runtime deps and
#    its tests use only the stdlib + unittest, so atheris is the only wheel we need.
PKGS=(atheris)
need_download=0
"$PY" -c "import os,glob,sys; sys.exit(0 if glob.glob(os.path.join('$WHEELHOUSE','atheris-*.whl')) else 1)" || need_download=1
if [ "$need_download" -eq 1 ]; then
  echo ">> populating wheelhouse (online) at $WHEELHOUSE"
  "$PY" -m pip download --dest "$WHEELHOUSE" "${PKGS[@]}"
else
  echo ">> wheelhouse already populated -- reusing $WHEELHOUSE (air-gapped re-run path)"
fi

# 2) Install atheris into the fixed site dir, OFFLINE from the wheelhouse. --no-index +
#    --find-links guarantees no PyPI access (works on the air-gapped re-run). Idempotent: once the
#    site dir holds atheris we SKIP the reinstall.
if "$PY" -c "import os,glob,sys; sys.exit(0 if glob.glob(os.path.join('$SITE','atheris*')) else 1)"; then
  echo ">> deps already installed in $SITE -- skipping (idempotent re-run)"
else
  echo ">> installing deps (offline) into $SITE"
  "$PY" -m pip install --no-index --find-links="$WHEELHOUSE" --target "$SITE" "${PKGS[@]}"
fi

# vermin itself stays the editable source tree at the repo root: $SRC holds the `vermin/` package,
# so $SRC on PYTHONPATH makes `import vermin` resolve to the live source (PATCH edits take effect
# with no reinstall). atheris comes from the site dir.
PYRUN="$SITE:$SRC"

# Record the site dir + interpreter for test.sh / the launcher to consume.
cat > "$PY_PREFIX/env.sh" <<EOF
export PYTHONPATH="$PYRUN\${PYTHONPATH:+:\$PYTHONPATH}"
export PYTHON_BIN="$PY"
EOF

# Sanity: the harness imports must resolve offline now.
PYTHONPATH="$PYRUN" "$PY" -c 'import atheris, vermin; print("imports OK")'

# 3) Compile the ELF launcher target + the standalone reproducer (DWARF < 4 via $DEBUG_FLAGS).
#    The launcher execs $PY on the harness; PYTHONPATH is baked into the env the binary inherits at
#    run time (the Dockerfile sets ENV PYTHONPATH), so the Python side finds atheris + vermin.
HARNESS="$SRC/mayhem/fuzz_version.py"
echo ">> compiling vermin_fuzzer (+ standalone) with DEBUG_FLAGS=$DEBUG_FLAGS"
$CC $DEBUG_FLAGS -DPYTHON="\"$PY\"" -DHARNESS="\"$HARNESS\"" \
    "$SRC/mayhem/launcher.c" -o "$SRC/vermin_fuzzer"
# The standalone reproducer is the same launcher: libFuzzer runs a single input file once when the
# harness is given a file path (no fuzzing loop), which is exactly the run-once reproducer contract.
$CC $DEBUG_FLAGS -DPYTHON="\"$PY\"" -DHARNESS="\"$HARNESS\"" \
    "$SRC/mayhem/launcher.c" -o "$SRC/vermin_fuzzer-standalone"

# 4) The unittest oracle runs through a compiled NON-system ELF wrapper so the gate's anti-reward-hack
#    sabotage check (which neuters non-system binaries to exit(0)) actually bites the suite -- a
#    test.sh that shelled straight to the system python would be spared and look reward-hackable.
$CC $DEBUG_FLAGS -DPYTHON="\"$PY\"" "$SRC/mayhem/run_tests.c" -o "$SRC/vermin_run_tests"

echo ">> build.sh complete"
ls -la "$SRC/vermin_fuzzer" "$SRC/vermin_fuzzer-standalone" "$SRC/vermin_run_tests"
