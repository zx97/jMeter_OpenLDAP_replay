#!/usr/bin/env python3
"""Refuse to commit data that is not anonymised.

Scans tracked (or staged) files for values that must never enter the
repository: addresses outside the documentation ranges, domain components
other than the reserved ``example.*`` ones, and e-mail or host names that are
not reserved.

Every rule here is generic on purpose -- this file carries no production
identifier, so it can stay public.  The convention it enforces is documented in
``doc/sample/README.md``:

  * domain  : ``example.com`` / ``example.org`` / ``example.net`` (RFC 2606)
  * IPv4    : ``192.0.2.0/24``, ``198.51.100.0/24``, ``203.0.113.0/24``
              (RFC 5737), plus loopback and ``0.0.0.0``

Exit status is 1 when a value has to be replaced, so it can be used as a
pre-commit hook and in CI.
"""

import argparse
import bz2
import gzip
import lzma
import os
import re
import subprocess
import sys

ALLOWED_IP_PREFIXES = ("127.", "192.0.2.", "198.51.100.", "203.0.113.")
ALLOWED_IP_EXACT = {"0.0.0.0", "255.255.255.255"}
ALLOWED_DC = {"example", "com", "org", "net", "test", "invalid", "local", "localhost"}
ALLOWED_MAIL_DOMAINS = {"example.com", "example.org", "example.net"}
ALLOWED_HOST_SUFFIXES = (".example.com", ".example.org", ".example.net")

# A four-octet address, not part of a longer dotted sequence (so LDAP OIDs such
# as 1.3.6.1.4.1... are left alone).
IPV4 = re.compile(r"(?<![\d.])((?:\d{1,3}\.){3}\d{1,3})(?![\d.])")
DC = re.compile(r"\bdc=([A-Za-z0-9-]+)")
# An e-mail whose domain ends in an alphabetic TLD; the TLD requirement keeps
# colour literals such as "#e67e22@0.95" out of the check.
MAIL = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")
# The hostname token of an RFC 3339 or classic syslog line, just before "slapd".
HOST = re.compile(
    r"^(?:\d{4}-\d\d-\d\dT\S+|[A-Z][a-z]{2}\s+\d+\s+\d\d:\d\d:\d\d)"
    r"\s+(\S+)\s+slapd\b"
)

# Files that are not log data and whose content legitimately contains external
# names (package metadata, the licence, ...).
SKIP = {"tests/package-lock.json", "LICENSE"}


def read_text(path):
    """Return the file as text, decompressing the log archives, or None."""
    low = path.lower()
    try:
        if low.endswith(".gz"):
            with gzip.open(path, "rt", encoding="utf-8", errors="replace") as fh:
                return fh.read()
        if low.endswith(".bz2"):
            with bz2.open(path, "rt", encoding="utf-8", errors="replace") as fh:
                return fh.read()
        if low.endswith(".xz"):
            with lzma.open(path, "rt", encoding="utf-8", errors="replace") as fh:
                return fh.read()
        with open(path, "rb") as fh:
            data = fh.read()
        if b"\x00" in data[:4096]:
            return None
        return data.decode("utf-8", "replace")
    except (OSError, EOFError, lzma.LZMAError):
        return None


def ip_bad(ip):
    return ip not in ALLOWED_IP_EXACT and not ip.startswith(ALLOWED_IP_PREFIXES)


def scan(path, findings):
    text = read_text(path)
    if text is None:
        return
    for lineno, line in enumerate(text.splitlines(), 1):
        for m in IPV4.finditer(line):
            ip = m.group(1)
            if ip_bad(ip):
                findings.append((path, lineno, "non-reserved IP %s" % ip))
        for m in DC.finditer(line):
            if m.group(1).lower() not in ALLOWED_DC:
                findings.append((path, lineno, "non-example domain component dc=%s"
                                 % m.group(1)))
        for m in MAIL.finditer(line):
            dom = m.group(1).lower()
            if dom not in ALLOWED_MAIL_DOMAINS:
                findings.append((path, lineno, "non-example e-mail domain %s"
                                 % m.group(1)))
        m = HOST.match(line)
        if m:
            host = m.group(1).lower()
            if "." in host and not host.endswith(ALLOWED_HOST_SUFFIXES):
                findings.append((path, lineno, "non-example host %s" % m.group(1)))


def git_lines(args):
    return subprocess.run(["git"] + args, capture_output=True,
                          text=True).stdout.splitlines()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--staged", action="store_true",
                    help="check the files staged for the next commit")
    ap.add_argument("files", nargs="*", help="check these files instead")
    args = ap.parse_args()

    if args.files:
        files = args.files
    elif args.staged:
        files = git_lines(["diff", "--cached", "--name-only", "--diff-filter=ACMR"])
    else:
        files = git_lines(["ls-files"])

    findings = []
    for path in files:
        if path in SKIP or not os.path.isfile(path):
            continue
        scan(path, findings)

    if findings:
        for path, lineno, msg in findings:
            print("%s:%d: %s" % (path, lineno, msg))
        print("\nanonymity check failed: %d value(s) must be replaced with "
              "RFC 2606 / RFC 5737 examples (see doc/sample/README.md)."
              % len(findings))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
