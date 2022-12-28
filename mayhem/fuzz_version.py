#! /usr/bin/env python3
import atheris
import sys
import fuzz_helpers

with atheris.instrument_imports():
  import vermin


def TestOneInput(data):
    fdp = fuzz_helpers.EnhancedFuzzedDataProvider(data)
    try:
      vermin.version_strings(vermin.detect(fdp.ConsumeRemainingString()))
    except (vermin.InvalidVersionException, UnicodeDecodeError, SyntaxError):
      return -1
    except ValueError as e:
      if 'null bytes' in str(e):
        return -1
      raise e


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
