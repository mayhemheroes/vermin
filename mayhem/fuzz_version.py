#!/usr/bin/env python3
"""Atheris fuzz harness for vermin (the "parse-version" target).

vermin statically analyses Python source and reports the minimum Python
version(s) the code requires. This harness feeds arbitrary bytes (interpreted
as a unicode Python source string) through vermin's public detection API so the
parser / AST visitor / version-combination logic is exercised on hostile input.

Atheris instruments the imported vermin modules (coverage feedback), so
libFuzzer drives the analyser toward new code paths.

Run modes (driven by the compiled launcher `vermin_fuzzer` / `-standalone`):
  * fuzzing      -- `python3 fuzz_version.py [libFuzzer args]`
  * single input -- `python3 fuzz_version.py <file>` (libFuzzer runs it once)
"""
import sys
import tokenize

import atheris

# Instrument vermin (the library under test) so the fuzzer gets coverage feedback. Scope with
# include=['vermin'] rather than a bare instrument_imports(): vermin imports multiprocessing / pickle
# / signal at module load, and instrumenting those stdlib modules only adds non-target edges plus
# startup cost without exercising the analyser. vermin's parser / AST visitor / version logic (the
# real target) lives entirely in the vermin package; the ast & tokenize backends are C and cannot be
# instrumented by Atheris anyway.
with atheris.instrument_imports(include=['vermin']):
    import vermin


def TestOneInput(data: bytes) -> int:
    fdp = atheris.FuzzedDataProvider(data)
    source = fdp.ConsumeUnicodeNoSurrogates(atheris.ALL_REMAINING)
    try:
        if fdp.ConsumeBool():
            # Full pipeline: detect() parses + visits, version_strings() formats.
            vermin.version_strings(vermin.detect(source))
        else:
            # Lower-level entry: parse + visit the source directly.
            vermin.visit(source)
    except (vermin.InvalidVersionException, UnicodeDecodeError, SyntaxError,
            tokenize.TokenError):
        # Malformed / unparseable input -- expected, not a defect. vermin's comment
        # tokenizer (parser.comments) lazily iterates a generate_tokens() generator, so a
        # tokenize.TokenError (e.g. a bare CR / non-printable char) surfaces during iteration
        # and is NOT a SyntaxError -- catch it here so a hostile snippet does not abort the run.
        return -1
    except ValueError as e:
        # Embedded NUL bytes raise ValueError from the compiler; not a defect.
        if "null bytes" in str(e):
            return -1
        raise
    return 0


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
