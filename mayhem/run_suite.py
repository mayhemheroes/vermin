#!/usr/bin/env python3
"""run_suite.py -- run vermin's own unittest suites and print a machine-readable summary.

This is the behavioral oracle driver. It loads the EXACT same test suites the
project's runtests.py runs (real unittest assertions over vermin's detection
output -- known-answer min-version checks), executes them ALL in one run
(continuing past failures so the counts are complete), and prints a single line

    RESULT tests=<N> passed=<P> failed=<F> skipped=<S>

that mayhem/test.sh parses into a CTRF report. Exit status is non-zero iff any
test failed/errored, so a no-op PATCH that neuters vermin breaks the assertions
and fails the oracle (anti-reward-hacking).
"""
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

# Same suites as the project's runtests.py.
SUITES = (
    "general", "config", "arguments", "lang", "module", "builtin_classes",
    "class", "exception", "builtin_functions", "builtin_constants",
    "builtin_exceptions", "function", "constants", "decorators", "kwargs",
    "strftime_directive", "annotation", "maybe_annotations", "array_typecodes",
    "codecs_error_handlers", "codecs_encodings", "exclusions",
    "comment_exclusions", "backports", "bytes_directive", "violations",
)


def main() -> int:
    # tests/general.py::test_process_runtests_py analyses sys.argv[0] and asserts it is the
    # project test runner (runtests.py). We drive the same suites from this module, so point
    # argv[0] at the real runtests.py file the test means to inspect.
    sys.argv[0] = os.path.join(ROOT, "runtests.py")

    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    for name in SUITES:
        suite.addTests(loader.loadTestsFromName("tests." + name))

    runner = unittest.TextTestRunner(verbosity=1, buffer=True)
    result = runner.run(suite)

    total = result.testsRun
    failed = len(result.failures) + len(result.errors)
    skipped = len(getattr(result, "skipped", []))
    passed = total - failed - skipped
    print("RESULT tests=%d passed=%d failed=%d skipped=%d" % (total, passed, failed, skipped))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
