#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Manuel FLURY
#
# This file is part of jMeter_OpenLDAP_replay: replays OpenLDAP access-log
# traffic with Apache JMeter and renders an HTML dashboard. Distributed
# under the GNU Affero General Public License v3.0 (AGPL-3.0-or-later);
# see the LICENSE file for the full text.
#
# Set ONE shared password on all application accounts of the example LDAP
# instance (ou=People, dc=example,dc=org). Plain-text userPassword is sent;
# OpenLDAP hashes it automatically ({ARGON2}) if olcPPolicyClearTest has been set.
#
# Usage:
#   LDAP_ADMIN_PW='<admin pw>' ./set_passwords.sh [new_password] [passwords.csv]
#
# The optional second argument is the path of a TAB-separated
# "DN<TAB>password" table to write next to this script. It uses the same
# separator as the *.replay file (TAB) so the JSR223 loader can parse it
# with the configured separator. Defaults to ./passwords.csv.
#
# After running, replay with jMeter (5.6.x) installed locally or via flatpak:
#   jmeter -n -t replay_ldap.jmx \
#     -JREPLAY_FILE=/abs/path/sample.replay \
#     -JPASSWORD_FILE=/abs/path/passwords.csv \
#     -JLDAP_HOST=ldap.example.org \
#     -JLDAP_PORT=636 \
#     -JLDAP_USE_SSL=true \
#     -JLDAP_USE_STARTTLS=false \
#     -l results.jtl -j jmeter.log
#
# Optional environment (takes precedence over the parameter file):
#   LDAP_URI="ldaps://localhost:636"       URI of the directory
#   LDAP_ADMIN_DN="cn=Directory Manager,dc=example,dc=org"   admin DN
#   LDAP_SEARCH_BASES="ou=People,dc=example,dc=org"  search bases (space-separated)
#   PWDRESET="auto"                        pwdReset pass: auto (detect the
#                                          ppolicy overlay), true (force),
#                                          false (skip; pwdReset exists only
#                                          when ppolicy is active)
#   CONFIG_DN / CONFIG_PW                  cn=config admin credentials (env
#                                          only) used by PWDRESET=auto for a
#                                          direct probe; when absent, the
#                                          data suffix is probed instead
#   CONF_FILE="path"                       parameter file (default: ./jmeter_replay.conf)
#
# The same defaults can be edited once in jmeter_replay.conf (same
# directory) instead of editing this script.
set -euo pipefail

# Optional central parameter file (same directory as this script). It only
# sets defaults (KEY="${KEY:-default}"), so a variable already exported in
# the environment takes precedence. If the file is absent, the defaults
# below apply unchanged.
CONF_FILE="${CONF_FILE:-$(dirname "$0")/jmeter_replay.conf}"
if [ -f "$CONF_FILE" ]; then
    # shellcheck source=jmeter_replay.conf
    source "$CONF_FILE"
fi

PW="${1:-ChangeMe!}"
CSV="${2:-./passwords.csv}"

# --- Adapt to your directory (defaults from jmeter_replay.conf) --------------
H="${LDAP_URI:-ldaps://localhost:636}"
A="${LDAP_ADMIN_DN:-cn=Directory Manager,dc=example,dc=org}"
SEARCH_BASES=(${LDAP_SEARCH_BASES:-ou=People,dc=example,dc=org})
# pwdReset is provided by the ppolicy overlay and only exists when that
# overlay is active: auto = detect it, true = force the pass, false = skip.
PWDRESET="${PWDRESET:-auto}"
# CONFIG_DN/CONFIG_PW (environment only, never the parameter file) are the
# admin credentials of the cn=config suffix, used to probe it directly. When
# they are not available, the detection falls back to probing the data
# suffix with the directory admin credentials below.
W="${LDAP_ADMIN_PW:?set LDAP_ADMIN_PW}"

TMP="$(mktemp)"
trap 'rm -f "$TMP".pw "$TMP".pr' EXIT

probe_config() {
  ldapsearch -x -LLL -H "$H" -D "$CONFIG_DN" -w "$CONFIG_PW" \
    -b "cn=config" "(objectClass=olcPpolicyConfig)" dn 2>/dev/null \
    | grep -q "^dn:"
}

probe_base() {
  # Ask the data suffix for the pwdReset operational attribute: it is only
  # returned when the ppolicy overlay is active, so its absence (or an
  # unknown-attribute error) means ppolicy is not loaded.
  ldapsearch -x -LLL -H "$H" -D "$A" -w "$W" -b "${SEARCH_BASES[0]}" \
    -s one "(objectClass=*)" pwdReset 2>/dev/null | grep -q "^pwdReset:"
}

case "$PWDRESET" in
  true)  DO_PWDRESET=true ;;
  false) DO_PWDRESET=false ;;
  *)     if [ -n "${CONFIG_DN:-}" ] && [ -n "${CONFIG_PW:-}" ]; then
           probe_config && DO_PWDRESET=true || DO_PWDRESET=false
         else
           probe_base && DO_PWDRESET=true || DO_PWDRESET=false
         fi
         if [ "$DO_PWDRESET" != true ]; then
           echo "WARNING: pwdReset pass skipped (ppolicy overlay not detected);" >&2
           echo "  set PWDRESET=true to force it, or provide CONFIG_DN/CONFIG_PW" >&2
           echo "  (cn=config admin credentials) for a direct probe." >&2
         fi ;;
esac

collect_dns() {
  for b in "${SEARCH_BASES[@]}"; do
    ldapsearch -x -LLL -H "$H" -D "$A" -w "$W" -b "$b" -s one "(objectClass=*)" dn
  done | awk '/^dn: /{print $2}'
}

emit_pw_ldif() {
  collect_dns | awk -v p="$PW" '
    { print "dn: " $0
      print "changetype: modify"
      print "replace: userPassword"
      print "userPassword: " p
      print ""
    }'
}

emit_pr_ldif() {
  collect_dns | awk '
    { print "dn: " $0
      print "changetype: modify"
      print "replace: pwdReset"
      print "pwdReset: FALSE"
      print ""
    }'
}

# Two separate passes: combining userPassword + pwdReset in a single
# ModifyRequest on entries whose pwdPolicySubentry is bound to a particular
# policy triggers a server-side "wrong attributeType" without the changes
# being applied. Keeping the operations apart makes both passes idempotent
# and reliable. The pwdReset pass only runs when the ppolicy overlay is
# active (or PWDRESET=true is forced).
emit_pw_ldif  > "$TMP.pw"

ldapmodify -x -c -H "$H" -D "$A" -w "$W" -f "$TMP.pw"

if [ "$DO_PWDRESET" = true ]; then
  emit_pr_ldif  > "$TMP.pr"
  ldapmodify -x -c -H "$H" -D "$A" -w "$W" -f "$TMP.pr"
fi

rm -f "$TMP.pw" "$TMP.pr"

# Produce the TAB-separated DN<TAB>password table for the JSR223 loader.
{
  printf '# Password table used by replay_ldap.groovy for the BINDs.\n'
  printf '# Format: <distinguished name><TAB><password>\n'
  printf '# Lines starting with # are ignored.\n'
  printf '# Single shared password for all accounts.\n\n'
  for b in "${SEARCH_BASES[@]}"; do
    ldapsearch -x -LLL -H "$H" -D "$A" -w "$W" -b "$b" -s one "(objectClass=*)" dn
  done | awk -v p="$PW" '/^dn: /{printf "%s\t%s\n", $2, p}'
} > "$CSV"

echo "OK: password '$PW' set on all accounts; $CSV updated with $(grep -cv '^#\|^$' "$CSV") entries"
