"""
Command-line interface for the Universal Input Sanitizer.

Provides convenient entrypoints for ad-hoc usage.
"""
import sys
import argparse
from .sanitizer import sanitize_value, detect_type, language_escape

def _read_stdin() -> str:
    data = sys.stdin.read()
    return data

def sanitize_stdin(args):
    data = _read_stdin().rstrip("\n")
    kind = args.type
    detected, sanitized = sanitize_value(data, kind)
    print(f"# detected: {detected}")
    print(sanitized)
    if args.languages:
        print("\n# language literals:")
        for lang in args.languages:
            print(f"{lang}: {language_escape(sanitized, lang)}")

def sanitize_file(args):
    path = args.path
    if path == "-":
        data = _read_stdin().rstrip("\n")
    else:
        with open(path, "r", encoding="utf-8") as f:
            data = f.read()
    # for convenience, if file is JSON and user requested languages,
    # we pretty-print the sanitized JSON
    detected, sanitized = sanitize_value(data, args.type) if getattr(args, "type", None) else sanitize_value(data)
    print(f"# detected: {detected}")
    print(sanitized)
    if args.languages:
        print("\n# language literals:")
        for lang in args.languages:
            print(f"{lang}: {language_escape(sanitized, lang)}")

def main(argv=None):
    p = argparse.ArgumentParser(prog="uisanitizer", description="Universal Input Sanitizer CLI")
    sub = p.add_subparsers(dest="cmd")

    s1 = sub.add_parser("sanitize-stdin", help="Sanitize a single value from stdin")
    s1.add_argument("--type", help="Override detected type (email|phone|url|json|env|text)",
                    choices=["email", "phone", "url", "json", "env", "text"])
    s1.add_argument("--languages", nargs="*", help="Languages to print escaped literals for", default=[])
    s1.set_defaults(func=sanitize_stdin)

    s2 = sub.add_parser("sanitize-file", help="Sanitize contents of a file")
    s2.add_argument("path", help='Path to file to sanitize (use "-" to read stdin)')
    s2.add_argument("--type", help="Override detected type (email|phone|url|json|env|text)",
                    choices=["email", "phone", "url", "json", "env", "text"])
    s2.add_argument("--languages", nargs="*", help="Languages to print escaped literals for", default=[])
    s2.set_defaults(func=sanitize_file)

    args = p.parse_args(argv)
    if not hasattr(args, "func"):
        p.print_help()
        return 1
    args.func(args)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
