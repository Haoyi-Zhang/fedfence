"""Compatibility alias for the current TOSEM reproduction driver.

Like reproduce_tosem.py, this runs the full local evidence campaign unless
--help is requested; --paper additionally builds and audits the paper.
"""
import sys


def main(argv=None):
    from reproduce_tosem import main as current_main
    print("reproduce.py forwards to scripts/reproduce_tosem.py", file=sys.stderr)
    return current_main(argv)


if __name__ == "__main__":
    raise SystemExit(main())
