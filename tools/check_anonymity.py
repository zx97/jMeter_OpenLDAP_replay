#!/usr/bin/env python3
"""Refuse to commit data that is not anonymised.

Scans tracked (or staged) files for values that must never enter the
repository: addresses outside the documentation ranges, domain components
other than the reserved ``example.*`` ones, and e-mail, host, ``o=`` or ``uid=``
values that are not reserved.

Every rule here is generic on purpose -- this file carries no production
identifier, so it can stay public.  The convention it enforces is documented in
``doc/sample/README.md``:

  * domain  : ``example.com`` / ``example.org`` / ``example.net`` (RFC 2606)
  * IPv4    : ``192.0.2.0/24``, ``198.51.100.0/24``, ``203.0.113.0/24``
              (RFC 5737), plus loopback and ``0.0.0.0``

Findings are reported by file, line and rule only: the offending value is
deliberately **not echoed**, so a failed public CI log cannot itself leak the
hostname, domain or user id it refused.

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

# uid values that are clearly synthetic in this repository.  Everything else
# (a real account, an employee number, a person's login, ...) is refused.
ALLOWED_UIDS = {
    "*", "*...", "...", "a", "abc", "alice", "b", "bob", "c", "carol",
    "carol2", "d", "dave", "erin", "foo", "FOO", "NAME", "MyApplication",
    "APP_A", "APP_B", "APP_C", "u", "x", "user", "app76obody", "admin",
    "replicator", "gadmin-ap", "n/a", "svc-account", "hr-sync", "legacy-app",
    "monitor", "portal", "reporting", "jdoe", "other",
}
UID_SYNTHETIC = re.compile(r"^(?:app\d+|user\d*)$")

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
# Any hostname that ends in the real organisation's suffix, wherever it
# appears: syslog line, DN, URL, config file, comment.
INT_TLD = re.compile(
    r"(?<![A-Za-z0-9.-])(?:[A-Za-z0-9-]+\.)*int(?![A-Za-z0-9-])",
    re.IGNORECASE,
)
# An organisation attribute whose value looks like a domain name (o=<domain>).
O_DOMAIN = re.compile(r"\bo=([A-Za-z0-9.-]+\.[A-Za-z]{2,})", re.IGNORECASE)
# A bind/search account: uid=<value>.  uidNumber= is not matched (the "N"
# follows "uid" where this pattern requires "=").
UID = re.compile(r"\buid=([A-Za-z0-9._*-]+)")

# Files that are not log data and whose content legitimately contains external
# names (package metadata, the licence, ...), or the checker itself (it holds
# the rule patterns, not repository data).
SKIP = {"tests/package-lock.json", "LICENSE", "tools/check_anonymity.py"}


def open_text(path):
    """Open the file as a text stream (decompressing log archives), or None."""
    low = path.lower()
    try:
        if low.endswith(".gz"):
            return gzip.open(path, "rt", encoding="utf-8", errors="replace")
        if low.endswith(".bz2"):
            return bz2.open(path, "rt", encoding="utf-8", errors="replace")
        if low.endswith(".xz"):
            return lzma.open(path, "rt", encoding="utf-8", errors="replace")
        with open(path, "rb") as fh:
            head = fh.read(4096)
        if b"\x00" in head:
            return None
        return open(path, "r", encoding="utf-8", errors="replace")
    except (OSError, EOFError, lzma.LZMAError):
        return None


def ip_bad(ip):
    return ip not in ALLOWED_IP_EXACT and not ip.startswith(ALLOWED_IP_PREFIXES)


def uid_bad(value):
    return value not in ALLOWED_UIDS and not UID_SYNTHETIC.match(value)


def scan(path, findings, cap):
    fh = open_text(path)
    if fh is None:
        return
    with fh:
        for lineno, line in enumerate(fh, 1):
            for m in IPV4.finditer(line):
                if ip_bad(m.group(1)):
                    findings.append((path, lineno, "non-reserved IP"))
            for m in DC.finditer(line):
                if m.group(1).lower() not in ALLOWED_DC:
                    findings.append((path, lineno, "non-example domain component dc="))
            for m in MAIL.finditer(line):
                if m.group(1).lower() not in ALLOWED_MAIL_DOMAINS:
                    findings.append((path, lineno, "non-example e-mail domain"))
            m = HOST.match(line)
            if m:
                host = m.group(1).lower()
                if "." in host and not host.endswith(ALLOWED_HOST_SUFFIXES):
                    findings.append((path, lineno, "non-example host"))
            for _ in INT_TLD.finditer(line):
                findings.append((path, lineno, "non-example host"))
            for m in O_DOMAIN.finditer(line):
                dom = m.group(1).lower()
                if dom in ALLOWED_MAIL_DOMAINS:
                    continue
                if INT_TLD.fullmatch(dom):
                    continue  # already reported as a host
                findings.append((path, lineno, "non-example o= domain"))
            for m in UID.finditer(line):
                if uid_bad(m.group(1)):
                    findings.append((path, lineno, "non-example uid"))
            if cap and len(findings) >= cap:
                return


def git_lines(args):
    return subprocess.run(["git"] + args, capture_output=True,
                          text=True).stdout.splitlines()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--staged", action="store_true",
                    help="check the files staged for the next commit")
    ap.add_argument("--max-findings", type=int, default=1000,
                    help="stop after this many findings (0 = no limit)")
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
        scan(path, findings, args.max_findings)
        if args.max_findings and len(findings) >= args.max_findings:
            break

    if findings:
        seen = set()
        shown = 0
        for path, lineno, msg in findings:
            key = (path, lineno, msg)
            if key in seen:
                continue
            seen.add(key)
            print("%s:%d: %s" % (path, lineno, msg))
            shown += 1
        print("\nanonymity check failed: %d value(s) must be replaced with "
              "RFC 2606 / RFC 5737 examples (see doc/sample/README.md)."
              % shown)
        if args.max_findings and len(findings) >= args.max_findings:
            print("(stopped after %d findings)" % args.max_findings)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
