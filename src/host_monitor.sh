#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Manuel FLURY
#
# This file is part of jMeter_OpenLDAP_replay: replays OpenLDAP access-log
# traffic with Apache JMeter and renders an HTML dashboard. Distributed
# under the GNU Affero General Public License v3.0 (AGPL-3.0-or-later);
# see the LICENSE file for the full text.
#
# Collects host and per-process metrics every N seconds.
# Captures: per-CPU breakdown (user/sys/iowait/steal), memory (used/cached/
# available + swap), load average, per-LDAP-server CPU/RSS/LMDB, and disk I/O
# (read/write MB/s) for the LDAP data disk and the jMeter results disk.
#
# Two collection targets:
#   - the LDAP server (remote, via SSH): host-wide + one block per LDAP
#     server instance. By default the instances that together form the LDAP
#     server are monitored (ldap1, ldap2, ldap3); override with
#     LDAP_SERVERS="ldap1" to monitor a single server (simple deployment).
#   - the injector (local): the jMeter injector host + the jMeter java
#     process.
#
# The script must run on the injector host (the jMeter host) so that the
# local pidstat / ps / free commands target the right machine.
#
# Usage: ./host_monitor.sh <output.csv> [interval_seconds]
#
# Optional environment (takes precedence over the parameter file):
#   LDAP_HOST="ldap.example.org"  SSH target of the LDAP server (default)
#   LDAP_SERVERS="ldap1 ldap2 ldap3"   LDAP server instances (default)
#   LDAP_SERVERS="ldap1"          single-server deployment
#   LDAP_DISK="sda"               device holding the LDAP data
#   INJECTOR_DISK="nvme0n1"       device holding the jMeter results
#   CONF_FILE="path"              parameter file (default: ./jmeter_replay.conf)
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

CSV="${1:-host_metrics.csv}"
INTERVAL="${2:-${MONITOR_INTERVAL:-5}}"
REMOTE="${LDAP_HOST:-ldap.example.org}"

# LDAP server instances monitored on the remote host (default: the ones that
# together form the LDAP server; a simple deployment has only one).
SERVERS=(${LDAP_SERVERS:-ldap1 ldap2 ldap3})

# Disk devices used for the I/O columns. Defaults: the LDAP server keeps its
# slapd data (LMDB) on sda; the injector keeps the jMeter results on nvme0n1.
LDAP_DISK="${LDAP_DISK:-sda}"
INJECTOR_DISK="${INJECTOR_DISK:-nvme0n1}"

# Column header: shared prefix + one block per LDAP server + I/O + injector
HEADER="timestamp_utm"
HEADER+=",host_cpu_usr,host_cpu_sys,host_cpu_iowait,host_cpu_steal"
HEADER+=",host_mem_used_mb,host_mem_cached_mb,host_mem_avail_mb,host_load1"
HEADER+=",host_swap_used_mb,host_swap_total_mb"
for s in "${SERVERS[@]}"; do
    HEADER+=",slapd_${s}_cpu_usr,slapd_${s}_cpu_sys,slapd_${s}_cpu_iowait,slapd_${s}_rss_mb,slapd_${s}_lmdb_mb"
done
HEADER+=",ldap_disk_read_mbs,ldap_disk_write_mbs"
HEADER+=",injector_cpu_usr,injector_cpu_sys,injector_cpu_iowait,injector_cpu_steal,injector_mem_used_mb,injector_mem_cached_mb,injector_mem_avail_mb,injector_load1"
HEADER+=",injector_swap_used_mb,injector_swap_total_mb"
HEADER+=",injector_disk_read_mbs,injector_disk_write_mbs"
HEADER+=",jmeter_cpu_usr,jmeter_cpu_sys,jmeter_cpu_iowait,jmeter_rss_mb,jmeter_threads"
echo "$HEADER" > "$CSV"

# ---------------------------------------------------------------------------
# Generic helpers (run either via ssh or locally)
# ---------------------------------------------------------------------------

# Usage: run_local "command string"   - run on the injector
#        run_ssh   "command string"   - run on the LDAP server
run_local() { bash -c "$1"; }
run_ssh()   { ssh -T "$REMOTE" "bash -c $(printf %q "$1")"; }

# pidstat output (per pid) -> "usr,sys,iowait" aggregated
# Skip the header line, sum across all matching pids.
# $1 = target (ssh|local), $2 = pgrep filter (e.g. 'slapd_ldap1\.d')
proc_cpu() {
    local target="$1" filter="$2"
    local cmd="
        pids=\$(pgrep -f '$filter' 2>/dev/null | tr '\n' ' ')
        [ -z \"\$pids\" ] && echo '0,0,0' && exit 0
        pidstat -u -p \$pids 1 1 2>/dev/null | awk '
            NF >= 8 && \$3 ~ /^[0-9]+\$/ {
                # pidstat line: time CPU PID %usr %system %guest %wait %CPU ...
                printf \"%s,%s,%s\n\", \$4, \$5, \$7
            }
        ' | head -1
    "
    if [ "$target" = "ssh" ]; then run_ssh "$cmd"; else run_local "$cmd"; fi
}

# Process RSS in MB (sum across all matching pids).
# $1 = target (ssh|local), $2 = pgrep filter
proc_rss() {
    local target="$1" filter="$2"
    local cmd="
        pgrep -f '$filter' 2>/dev/null | while read pid; do
            awk '/VmRSS:/ {printf \"%.0f\", \$2/1024}' /proc/\$pid/status
            echo
        done | awk '{s+=\$1} END {printf \"%.0f\", s+0}'
    "
    if [ "$target" = "ssh" ]; then run_ssh "$cmd"; else run_local "$cmd"; fi
}

# Thread count of the jMeter process (single JVM in our case).
proc_threads() {
    local target="$1" filter="$2"
    local cmd="
        pids=\$(pgrep -f '$filter' 2>/dev/null | tr '\n' ' ')
        [ -z \"\$pids\" ] && echo '0' && exit 0
        echo \"\$pids\" | head -1 | while read pid; do
            ls /proc/\$pid/task 2>/dev/null | wc -l
        done
    "
    if [ "$target" = "ssh" ]; then run_ssh "$cmd"; else run_local "$cmd"; fi
}

# LMDB mmap'd size (slapd processes only — the *.mdb file is mmap'd to
# read the database and the kernel page cache holds the actual data).
# The smaps layout for each mapping is:
#   <addr range> <perms> <offset> <dev> <inode>  <path-to-mdb>
#   Size:               N kB
#   Rss:                N kB
#   ...
# We flag the mapping with `in_mdb` when the file line ends in .mdb, then
# accumulate the Size/Rss lines that follow until the next mapping.
proc_lmdb() {
    local target="$1" filter="$2"
    local cmd="
        pgrep -f '$filter' 2>/dev/null | while read pid; do
            awk '
                \$NF ~ /\\.mdb\$/ { in_mdb=1; next }
                in_mdb && /^[0-9a-f]+-[0-9a-f]+/ { in_mdb=0 }
                in_mdb && \$1 == \"Size:\" { sz  += \$2 }
                END { printf \"Size=%d\n\", sz+0 }
            ' /proc/\$pid/smaps 2>/dev/null
        done | awk -F'[= ]' '/Size/ {sz+=\$2} END {printf \"%.0f\", (sz+0)/1024}'
    "
    if [ "$target" = "ssh" ]; then run_ssh "$cmd"; else run_local "$cmd"; fi
}

# Host-wide CPU breakdown (user/sys/iowait/steal) via top -bn1.
host_cpu() {
    local target="$1"
    local cmd="
        top -bn1 | awk '/^%?Cpu/ {
            gsub(/[^0-9. ]/, \" \", \$0); print; exit
        }' | awk '{printf \"%.1f,%.1f,%.1f,%.1f\", \$1, \$3, \$5, \$8}'
    "
    if [ "$target" = "ssh" ]; then run_ssh "$cmd"; else run_local "$cmd"; fi
}

# Host-wide memory (used, cached, available) in MB.
host_mem() {
    local target="$1"
    local cmd="
        awk '
            /^MemTotal:/     { tot=\$2 }
            /^MemAvailable:/ { avl=\$2 }
            /^Cached:/       { cch=\$2 }
            /^Buffers:/      { buf=\$2 }
            END {
                used = tot - avl
                cached = cch + buf
                printf \"%.0f,%.0f,%.0f\", used/1024, cached/1024, avl/1024
            }' /proc/meminfo
    "
    if [ "$target" = "ssh" ]; then run_ssh "$cmd"; else run_local "$cmd"; fi
}

# Host-wide swap (used, total) in MB.
host_swap() {
    local target="$1"
    local cmd="
        awk '
            /^SwapTotal:/ { t=\$2 }
            /^SwapFree:/  { f=\$2 }
            END { printf \"%.0f,%.0f\", (t-f)/1024, t/1024 }
        ' /proc/meminfo
    "
    if [ "$target" = "ssh" ]; then run_ssh "$cmd"; else run_local "$cmd"; fi
}

# Load average 1 min.
host_load() {
    local target="$1"
    local cmd="awk '{print \$1}' /proc/loadavg"
    if [ "$target" = "ssh" ]; then run_ssh "$cmd"; else run_local "$cmd"; fi
}

# Disk I/O rate (read MB/s, write MB/s) for a whole block device, computed
# from /proc/diskstats (sectors read/written, 512 bytes each) sampled twice
# 1 s apart. Works on any Linux host without requiring iostat.
disk_io() {
    local target="$1" dev="$2"
    local cmd="
        r1=\$(awk -v d='$dev' '\$3==d {print \$6}' /proc/diskstats)
        w1=\$(awk -v d='$dev' '\$3==d {print \$10}' /proc/diskstats)
        sleep 1
        r2=\$(awk -v d='$dev' '\$3==d {print \$6}' /proc/diskstats)
        w2=\$(awk -v d='$dev' '\$3==d {print \$10}' /proc/diskstats)
        awk -v r1=\"\$r1\" -v r2=\"\$r2\" -v w1=\"\$w1\" -v w2=\"\$w2\" '
            BEGIN {
                printf \"%.2f,%.2f\", (r2-r1)*512/1048576, (w2-w1)*512/1048576
            }'
    "
    if [ "$target" = "ssh" ]; then run_ssh "$cmd"; else run_local "$cmd"; fi
}

# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

echo "Collecting host + per-process metrics every ${INTERVAL}s -> $CSV" >&2
echo "  remote: LDAP server (host + ${SERVERS[*]})" >&2
echo "  local : injector (host + jMeter JVM)" >&2

trap 'echo "Host monitor stopped, $(wc -l < "$CSV") samples written" >&2; exit 0' INT TERM

while true; do
    TS=$(date -u +%FT%TZ.%3N)

    # OpenLDAP (remote)
    H_CPU=$(host_cpu   ssh)
    H_MEM=$(host_mem   ssh)
    H_SWAP=$(host_swap ssh)
    H_LD=$(host_load    ssh)

    # One block per LDAP server instance (ldap1/ldap2/ldap3 by default)
    SRV=""
    sep=""
    for s in "${SERVERS[@]}"; do
        f="slapd_${s}\\.d"
        cpu=$(proc_cpu ssh "$f")
        rss=$(proc_rss ssh "$f")
        lm=$(proc_lmdb ssh "$f")
        SRV+="${sep}${cpu},${rss},${lm}"
        sep=","
    done
    LD_IO=$(disk_io ssh "$LDAP_DISK")

    # Injector host (local) — the machine running jMeter itself (the local
    # host of this script), as opposed to the remote LDAP server above.
    HE_CPU=$(host_cpu   local)
    HE_MEM=$(host_mem   local)
    HE_SWAP=$(host_swap local)
    HE_LD=$(host_load    local)
    HE_IO=$(disk_io local "$INJECTOR_DISK")
    JM_FILTER="ApacheJMeter\\|java.*jmeter"
    JM_CPU=$(proc_cpu   local "$JM_FILTER")
    JM_RSS=$(proc_rss   local "$JM_FILTER")
    JM_THR=$(proc_threads local "$JM_FILTER")

    printf "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n" \
        "$TS" "$H_CPU" "$H_MEM" "$H_LD" "$H_SWAP" \
        "$SRV" \
        "$LD_IO" \
        "$HE_CPU" "$HE_MEM" "$HE_LD" "$HE_SWAP" "$HE_IO" \
        "$JM_CPU" "$JM_RSS" "$JM_THR" >> "$CSV"
    sleep "$INTERVAL"
done
