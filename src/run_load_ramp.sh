#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Manuel FLURY
#
# This file is part of jMeter_OpenLDAP_replay: replays OpenLDAP access-log
# traffic with Apache JMeter and renders an HTML dashboard. Distributed
# under the GNU Affero General Public License v3.0 (AGPL-3.0-or-later);
# see the LICENSE file for the full text.
#
# Orchestrates a load ramp-up against the LDAP server: runs the replay
# workload at increasing CONCURRENCY values (1, 2, 4, ...), keeps host
# monitoring active during each run, and saves one report + one results
# file + one host-metrics CSV per step so the response times (p50/p95/p99/
# MAX) and the server resources (CPU/swap/disk I-O) can be compared as a
# function of the load.
#
# The ramp stops before the step whose CONCURRENCY broke the service
# (INFRA_ERR > 0) unless --keep-going is given.
#
# Usage:
#   ./run_load_ramp.sh [--max N] [--step N] [--loops N] [--keep-going] \
#                      [--jmx replay_ldap.jmx] [--outdir runs/] \
#                      [--host-args "LDAP_SERVERS=ldap1 LDAP_DISK=sda"] \
#                      -- <any -J arguments for jMeter>
#
# Examples:
#   ./run_load_ramp.sh -- -JLDAP_HOST=ldap.example.org -JLDAP_PORT=636 \
#       -JLDAP_USE_SSL=true -JLDAP_TRUSTSTORE=/abs/tls/truststore.jks \
#       -JLDAP_TRUSTSTORE_PASSWORD=changeit \
#       -JREPLAY_FILE=/abs/sample.replay \
#       -JPASSWORD_FILE=/abs/passwords.csv
#   LDAP_SERVERS="ldap1" ./run_load_ramp.sh --max 8 -- -JLDAP_HOST=...
#
# Optional environment (takes precedence over the parameter file):
#   LDAP_SERVERS="ldap1 ldap2 ldap3"   LDAP server instances monitored
#   LDAP_DISK="sda"                    LDAP data disk on the server
#   INJECTOR_DISK="nvme0n1"            results disk on the injector host
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

MAX="${MAX:-16}"
STEP="${STEP:-2}"
LOOPS="${LOOPS:-1}"
KEEP_GOING="${KEEP_GOING:-0}"
JMX="${JMX:-replay_ldap.jmx}"
OUTDIR="${OUTDIR:-${RAMP_OUTDIR:-runs}}"
MONITOR_INTERVAL="${MONITOR_INTERVAL:-2}"
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

# Parse --options before the "--" separator; everything after "--" is passed
# verbatim to jMeter as -J arguments.
JARGS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --max)        MAX="$2"; shift 2 ;;
    --step)       STEP="$2"; shift 2 ;;
    --loops)      LOOPS="$2"; shift 2 ;;
    --keep-going) KEEP_GOING=1; shift ;;
    --jmx)        JMX="$2"; shift 2 ;;
    --outdir)     OUTDIR="$2"; shift 2 ;;
    --host-args)  HOST_ARGS="$2"; shift 2 ;;
    --)           shift; JARGS=("$@"); break ;;
    -h|--help)    usage ;;
    *)            usage ;;
  esac
done

# The LDAP host / replay file must be supplied via the jMeter arguments.
if [ ${#JARGS[@]} -eq 0 ]; then usage; fi
if [ ! -f "$JMX" ]; then echo "ERROR: $JMX not found (run from the jMeter directory)"; exit 1; fi
mkdir -p "$OUTDIR"

# Detect the first INFRA_ERR in a report: the service is considered broken
# when LDAP stops replying (the only real error). The report line is
#   Total: X operations, Y infra error(s), peak concurrent connections: N
report_broken() {
  grep -qE "infra error\(s\), *[1-9][0-9]*" "$1"
}

C=1
while [ "$C" -le "$MAX" ]; do
  DIR="$OUTDIR/conc_$C"
  mkdir -p "$DIR"
  REPORT="$DIR/replay_report.txt"
  JTL="$DIR/results.jtl"
  CSV="$DIR/host_metrics.csv"
  JLOG="$DIR/jmeter.log"

  echo "==================================================================="
  echo "STEP concurrency=$C (loops=$LOOPS) -> $DIR"
  echo "==================================================================="

  # Start host monitoring for this step (background). It is killed after the
  # run; env overrides passed via --host-args (e.g. LDAP_SERVERS="pc") are
  # applied here, otherwise host_monitor.sh uses its own defaults.
  env ${HOST_ARGS:-} ./host_monitor.sh "$CSV" "$MONITOR_INTERVAL" &
  MONITOR_PID=$!

  # jMeter: do NOT pass -j (the flatpak wrapper already adds its own log),
  # and do NOT pass -JREPORT_FILE inside JARGS (forced below to the step dir).
  JREPORT=()
  for a in "${JARGS[@]}"; do
    case "$a" in
      -JREPORT_FILE=*) ;;  # override below
      -JREPLAY_LOOPS=*) ;; # forced below
      *) JREPORT+=("$a") ;;
    esac
  done
  JREPORT+=("-JREPLAY_LOOPS=$LOOPS" "-JCONCURRENCY=$C")
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
    # Summary line of the step (Total / peak / infra errors)
    grep -E "^Total:|METRICS BY TYPE" -A 1 "$REPORT" | head -4 | \
      sed 's/^/  /'
  else
    echo "  WARNING: no report file produced"
  fi

  # Stop the ramp when the service broke (unless --keep-going).
  if [ "$KEEP_GOING" -eq 0 ] && [ -f "$REPORT" ] && report_broken "$REPORT"; then
    echo "STOP: service broken at concurrency=$C (INFRA_ERR > 0)"
    echo "Last healthy step: concurrency=$((C / STEP > 0 ? C / STEP : 1))"
    exit 0
  fi

  C=$((C * STEP))
done

echo "Ramp finished: max concurrency=$MAX reached without breaking the service."