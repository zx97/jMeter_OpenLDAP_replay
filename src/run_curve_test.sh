#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Manuel FLURY
#
# This file is part of jMeter_OpenLDAP_replay: replays OpenLDAP access-log
# traffic with Apache JMeter and renders an HTML dashboard. Distributed
# under the GNU Affero General Public License v3.0 (AGPL-3.0-or-later);
# see the LICENSE file for the full text.
#
# Runs the replay workload along a concurrency curve (CONCURRENCY_PROFILE)
# for a given duration, keeps host monitoring active during the run, and
# saves one report + one results file + one host-metrics CSV + the intended
# concurrency curve (concurrency_curve.csv, written by the groovy script
# next to the report).
#
# Usage:
#   ./run_curve_test.sh <outdir> <profile> <duration_s> [--host-args "LDAP_SERVERS=ldap1"] \
#                       -- <any -J arguments for jMeter>
#
# Examples:
#   # "Typical day" (camel back) test, 30 minutes, against an LDAP server:
#   ./run_curve_test.sh runs/curve_main \
#       /opt/jMeter_OpenLDAP_replay/src/concurrency_profiles/typical_day.profile \
#       1800 --host-args "LDAP_SERVERS=ldap1" -- \
#       -JLDAP_HOST=ldap.example.org -JLDAP_PORT=636 -JLDAP_USE_SSL=true \
#       -JLDAP_TRUSTSTORE=/opt/jMeter_OpenLDAP_replay/tls/truststore.jks \
#       -JLDAP_TRUSTSTORE_PASSWORD=changeit \
#       -JREPLAY_FILE=/opt/jMeter_OpenLDAP_replay/examples/sample.replay \
#       -JPASSWORD_FILE=/opt/jMeter_OpenLDAP_replay/examples/sample_passwords.csv
#
#   # "Until rupture" test: stop as soon as LDAP stops replying:
#   ... -JSTOP_ON_INFRA_ERR=true
#
# Optional environment (takes precedence over the parameter file):
#   LDAP_SERVERS="ldap1 ldap2 ldap3"   LDAP server instances monitored
#   LDAP_DISK="sda"                    LDAP data disk on the server
#   INJECTOR_DISK="nvme0n1"            results disk on the injector host
#   MONITOR_INTERVAL="2"               host_monitor sampling interval (s)
#   JMETER_CMD="jmeter"                command that runs jMeter (default:
#                                       flatpak wrapper; override for
#                                       system installs, e.g. "JMETER_CMD=jmeter")
#   CONF_FILE="path"                   parameter file (default: ./jmeter_replay.conf)
#
# The same defaults can be edited once in jmeter_replay.conf (same
# directory) instead of exporting them each time.

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

OUTDIR="${1:-${CURVE_OUTDIR:-runs/curve}}"
PROFILE="${2:-}"
DURATION_S="${3:-}"
HOST_ARGS="${HOST_ARGS:-}"
MONITOR_INTERVAL="${MONITOR_INTERVAL:-2}"
JMX="${JMX:-replay_ldap.jmx}"
# jMeter command: split the (space-separated) value from the parameter file
# or the environment into an argument array; fall back to the flatpak
# wrapper when unset.
if [ -n "${JMETER_CMD:-}" ]; then
    read -r -a JMETER_CMD <<< "$JMETER_CMD"
else
    JMETER_CMD=(
        /usr/bin/flatpak run --branch=stable --arch=x86_64
        --command=jmeter-wrapper.sh org.apache.jmeter
    )
fi

usage() {
  awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"
  exit 1
}

# Parse --host-args and the "--" separator.
JARGS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --host-args) HOST_ARGS="$2"; shift 2 ;;
    --)          shift; JARGS=("$@"); break ;;
    -h|--help)   usage ;;
    *)           shift ;; # positional outdir/profile/duration already consumed
  esac
done

if [ ${#JARGS[@]} -eq 0 ] || [ -z "$PROFILE" ] || [ -z "$DURATION_S" ]; then usage; fi
if [ ! -f "$JMX" ]; then echo "ERROR: $JMX not found (run from the jMeter directory)"; exit 1; fi
if [ ! -f "$PROFILE" ]; then echo "ERROR: profile not found: $PROFILE"; exit 1; fi

mkdir -p "$OUTDIR"
REPORT="$OUTDIR/replay_report.txt"
JTL="$OUTDIR/results.jtl"
CSV="$OUTDIR/host_metrics.csv"
JLOG="$OUTDIR/jmeter.log"

echo "==================================================================="
echo "CURVE TEST: profile=$PROFILE duration=${DURATION_S}s -> $OUTDIR"
echo "==================================================================="

# Start host monitoring for this run (background), killed after jMeter.
env ${HOST_ARGS:-} ./host_monitor.sh "$CSV" "$MONITOR_INTERVAL" &
MONITOR_PID=$!

# jMeter: do NOT pass -j (the flatpak wrapper already adds its own log),
# and do NOT pass -JREPORT_FILE/-JCONCURRENCY_PROFILE/-JTEST_DURATION_S
# inside JARGS (forced below to the run settings).
JREPORT=()
for a in "${JARGS[@]}"; do
  case "$a" in
    -JREPORT_FILE=*) ;; # override below
    -JCONCURRENCY_PROFILE=*) ;; # override below
    -JTEST_DURATION_S=*) ;; # override below
    *) JREPORT+=("$a") ;;
  esac
done
JREPORT+=("-JCONCURRENCY_PROFILE=$PROFILE" "-JTEST_DURATION_S=$DURATION_S")
JREPORT+=("-JREPORT_FILE=$REPORT")

set +e
"${JMETER_CMD[@]}" -n -t "$JMX" -l "$JTL" "${JREPORT[@]}" >"$JLOG" 2>&1
RC=$?
set -e

# Stop monitoring and wait for its last line to be flushed.
kill "$MONITOR_PID" 2>/dev/null || true
wait "$MONITOR_PID" 2>/dev/null || true

if [ $RC -ne 0 ]; then
  echo "ERROR: jMeter failed (rc=$RC), see $JLOG"
  exit 1
fi

if [ -f "$REPORT" ]; then
  grep -E "^Replay of file:|^Concurrency curve:|^Run duration:|^Total:" "$REPORT" | sed 's/^/  /'
else
  echo "  WARNING: no report file produced"
fi