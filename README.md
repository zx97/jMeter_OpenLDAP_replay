# jMeter_OpenLDAP_replay

**Replays recorded LDAP traffic (BIND, SEARCH, COMPARE, UNBIND, ABANDON)
against a live OpenLDAP server with Apache JMeter, measures response times
as a function of the load, and produces a self-contained HTML dashboard.**

This project is published under the **GNU Affero General Public License
v3.0 (AGPL-3.0)**. See the [LICENSE](LICENSE) file for the full text.

Current version: **1.0.0** (see [VERSION](VERSION) and the
[CHANGELOG](CHANGELOG.md) for the release history).

It is based on [slaplog](https://gitlab.com/ooo.manu.ooo/slaplog), the
replay-file generator and distributed under AGPL-3.0
(mirror at [github.com/zx97/slaplog](https://github.com/zx97/slaplog)),
and on the Apache JMeter test framework.

The source is mirrored on
[GitHub](https://github.com/zx97/jMeter_OpenLDAP_replay) and
[GitLab](https://gitlab.com/ooo.manu.ooo/jMeter_OpenLDAP_replay).

---

## What it does

- **Replays** the `BIND`, `SEARCH` (SRCH), `COMPARE` (CMP), `UNBIND` and
  `ABANDON` operations recorded in an OpenLDAP access log against a live
  LDAP server, preserving the original session ordering (one connection =
  one worker thread).
- **Verifies** the results (`returnCode` and `nentries`) against the
  expected values from the original log (informational only).
- **Measures** the response times (`AVGms`, `p50`, `p95`, `p99`, `MAXms`)
  as a function of the load.
- **Produces** a self-contained HTML dashboard with latency charts,
  throughput, queue analysis, CPU correlation, server non-response
  episodes, and per-minute breakdowns.

Two orchestration modes are provided:

| Mode | Script | Use case |
|------|--------|----------|
| **Load ramp** | `src/run_load_ramp.sh` | Find the concurrency limit: run at increasing `CONCURRENCY` (1, 2, 4, ...) and stop as soon as the service breaks. |
| **Concurrency curve** | `src/run_curve_test.sh` | Follow a time-varying target (e.g. "typical day" profile). |

---

## Repository layout

```
jMeter_OpenLDAP_replay/
├── LICENSE                  GNU AGPL-3.0
├── README.md                this file
├── VERSION                  current version
├── CHANGELOG.md             release history
├── src/                     the JMeter project
│   ├── replay_ldap.jmx          JMeter test plan
│   ├── replay_ldap.groovy       JSR223 script (the replay logic)
│   ├── report_html.py           HTML dashboard generator
│   ├── host_monitor.sh          server + injector host metrics collector
│   ├── run_curve_test.sh        concurrency-curve orchestrator
│   ├── run_load_ramp.sh         load-ramp orchestrator
│   ├── set_passwords.sh         helper to set a shared password on a directory
│   ├── jmeter_replay.conf       optional central parameter file (all defaults)
│   └── concurrency_profiles/    typical_day, until_rupture, smoke_test profiles
└── examples/
    ├── sample.replay            small sample replay file (example DNs)
    ├── sample_passwords.csv     matching example password table
    └── sample_report/html/      self-contained HTML sample report (5 pages)
```

---

## Prerequisites

What you need on the machines before running the load test:

| Software | Where | Used by |
|----------|-------|---------|
| **OpenLDAP server** with LDAPS and (optionally) the ppolicy overlay | target server | the replayed workload |
| **slaplog** | wherever you generate the replay file | step 1 (replay file generation) |
| **Apache JMeter 5.6.x** + a JRE | injector host (jMeter machine) | the replay itself; a native install or the flatpak wrapper both work |
| **OpenLDAP client tools** (`ldapsearch`, `ldapmodify`) | the machine running `set_passwords.sh` | `src/set_passwords.sh` (package: `ldap-utils` on Debian/Ubuntu, `openldap-clients` on RHEL/Fedora) |
| **Python 3** (standard library only) | injector host | `src/report_html.py` |
| **SSH client** + password-less key to the LDAP server | injector host | `src/host_monitor.sh` (it reaches the remote server over SSH) |
| **`sysstat`** (`pidstat`) and **`top`** | injector host **and** LDAP server | `src/host_monitor.sh` (per-process CPU) |
| Standard shell tools (`awk`, `grep`, `sed`, `head`, `pgrep`, `ps`, `free`, `date`, `sleep`) | injector host and LDAP server | all scripts |

`src/host_monitor.sh` must run on the **injector** host (the jMeter machine)
so that its local commands target the right machine, and it needs SSH access
to the LDAP server for the remote columns. It reads `/proc`, `/proc/*/status`,
`/proc/*/smaps`, `/proc/meminfo`, `/proc/loadavg` and `/proc/diskstats` on
both hosts, so no agent needs to be installed on the server — only the
regular SSH connection.

The default `LDAP_URI` in `src/jmeter_replay.conf` is `ldaps://localhost:636`
for the example instance; adapt it (and the `LDAP_HOST` for the host monitor)
to your real deployment.

---

## Quick start (end-to-end test)

### 1. Generate a replay file with slaplog

```bash
slaplog -o replay -q --replay-limit 0 --replay-separator tab \
    /var/log/slapd/access.log > myworkload.replay
```

Use `--replay-separator tab` to avoid collisions with the LDAP filter
OR operator `|`.

### 2. Set passwords on your directory

slapd logs do not record passwords; you must provide them yourself.
Pick one shared password for all BIND DNs and apply it:

```bash
# Adapt the search bases and the admin DN in src/jmeter_replay.conf first
LDAP_ADMIN_PW='<admin pw>' ./src/set_passwords.sh 'MyTest!Pass1' my_passwords.csv
```

The resulting `my_passwords.csv` is `DN<TAB>password`, tab-separated.

`set_passwords.sh` also runs an optional second `ldapmodify` pass that sets
`pwdReset: FALSE` to clear a previous password-expiry flag. `pwdReset` only
exists when the **ppolicy overlay** is active on the server, so the pass is
controlled by `PWDRESET` (default `auto`): `auto` detects the overlay — via
the `cn=config` suffix when the `CONFIG_DN`/`CONFIG_PW` env credentials are
provided, otherwise by probing the data suffix for the `pwdReset`
operational attribute — and skips the pass with a warning when it cannot
detect it. Set `PWDRESET=true` to force the pass, `PWDRESET=false` to skip
it unconditionally.

### 3. Run the load test

For a quick smoke test (1 → 4 → 2 → 1 over 60 s):

```bash
./src/run_curve_test.sh runs/smoke \
    src/concurrency_profiles/smoke_test.profile 60 -- \
    -JLDAP_HOST=ldap.example.org -JLDAP_PORT=636 -JLDAP_USE_SSL=true \
    -JLDAP_TRUSTSTORE=/abs/tls/truststore.jks \
    -JLDAP_TRUSTSTORE_PASSWORD=changeit \
    -JREPLAY_FILE=$PWD/myworkload.replay \
    -JPASSWORD_FILE=$PWD/my_passwords.csv
```

For a load ramp that stops when the service breaks:

```bash
./src/run_load_ramp.sh --max 16 --step 2 --keep-going -- \
    -JLDAP_HOST=ldap.example.org -JLDAP_PORT=636 -JLDAP_USE_SSL=true \
    -JLDAP_TRUSTSTORE=/abs/tls/truststore.jks \
    -JLDAP_TRUSTSTORE_PASSWORD=changeit \
    -JREPLAY_FILE=$PWD/myworkload.replay \
    -JPASSWORD_FILE=$PWD/my_passwords.csv
```

Each step (or the single curve step) produces:

- `runs/<name>/replay_report.txt` — textual metrics report
- `runs/<name>/results.jtl` — JMeter samples (CSV)
- `runs/<name>/host_metrics.csv` — server + injector host metrics
- `runs/<name>/concurrency_curve.csv` — intended (elapsed, target) pairs

### 4. Generate the HTML dashboard

```bash
# Single page (per step)
python3 src/report_html.py runs/<name>/replay_report.txt \
    -o html/conc_<N>.html \
    --host-metrics runs/<name>/host_metrics.csv \
    --jtl runs/<name>/results.jtl \
    --steps 1,2,4,8,16,120

# Full family (recommended) — generate the master index, the
# comparison page, and one page per step
for n in 1 2 4 8 16 120; do
    python3 src/report_html.py runs/<name>/replay_report.txt \
        -o html/conc_$n.html \
        --host-metrics runs/<name>/host_metrics.csv \
        --jtl runs/<name>/results.jtl --steps 1,2,4,8,16,120
    python3 src/report_html.py runs/<name>/replay_report.txt \
        -o html/injector_conc_$n.html \
        --host-metrics runs/<name>/host_metrics.csv \
        --jtl runs/<name>/results.jtl --steps 1,2,4,8,16,120 --injector
done
python3 src/report_html.py --master runs/<name> -o html/index.html
python3 src/report_html.py --compare runs/<name> -o html/compare.html
```

The dashboard is self-contained (charts are inline SVG, no JavaScript
framework dependency, no CDN). It can be opened directly from the
filesystem with `file://` or served statically.

---

## What the dashboard contains

### Per-step page (`conc_<N>.html`)

- **Summary** — totals, throughput, peak concurrent connections,
  infra errors.
- **Metrics by type** — per-operation-type response times (AVG, p50, p95,
  p99, MAX) for BIND, SRCH, CMP, UNBIND and ABANDON.
- **All operations combined** — transactions/s, average latency, concurrent
  connections over time.
- **Queue analysis** — latency percentiles grouped by load quartile
  (Q1..Q4) to detect queueing.
- **Behaviour over time (per minute)** — operations / latency timeline.
- **Latency / CPU correlation** — overlays TPS, p99 latency and slapd CPU.
- **Server resources** — per-instance slapd CPU/RSS/LMDB size, host CPU/
  memory/swap/load, disk I/O.
- **Server non-response episodes** — periods where LDAP stopped replying
  for several seconds, with the baseline ops/bucket for context. These
  are server-side stalls (CPU drops to 0), not client-side JVM GC pauses
  (a GC freeze would leave the server CPU busy).
- **Infra errors** — any operation that did not receive a reply from LDAP.

### Compare page (`compare.html`)

Multi-concurrency overview: for each `CONCURRENCY` step, one row in the
latency tables and one toggleable line in the over-time charts, so you
can compare the impact of raising the load at a glance.

### Injector page (`injector_conc_<N>.html`)

Focuses on the JMeter injector host: injector CPU, memory, swap, load,
disk I/O, and jMeter JVM consumption. Use this page to verify the
injector itself is not the bottleneck.

---

## Configuring the host monitor

`src/host_monitor.sh` collects per-CPU breakdown (user/sys/iowait/steal),
memory, swap, load average, per-LDAP-instance slapd metrics, disk I/O
(for both the LDAP data disk and the injector results disk), and the
jMeter JVM metrics.

The collected columns are:

| Column group | Default names | Override via |
|--------------|---------------|--------------|
| Host-wide | `host_*` | (always the same) |
| Per LDAP instance | `slapd_<name>_cpu_usr/sys/iowait`, `slapd_<name>_rss_mb`, `slapd_<name>_lmdb_mb` | `LDAP_SERVERS="ldap1 ldap2 ldap3"` (space-separated) |
| Injector host | `injector_*` | (always the same; renamed via `INJECTOR_PREFIX`) |
| jMeter JVM | `jmeter_*` | (always the same) |

All defaults come from the central parameter file `src/jmeter_replay.conf`;
each value can still be overridden per run with an environment variable of
the same name (the environment wins over the file, which wins over the
built-in default). The values used by the host monitor are:

| Variable | Default (in `jmeter_replay.conf`) | Purpose |
|----------|---------|---------|
| `LDAP_HOST` | `ldap.example.org` | SSH target of the LDAP server |
| `LDAP_SERVERS` | `ldap1 ldap2 ldap3` | LDAP instances to monitor on the server |
| `LDAP_DISK` | `sda` | Block device holding the LDAP data |
| `INJECTOR_DISK` | `nvme0n1` | Block device holding the jMeter results on the injector host |
| `MONITOR_INTERVAL` | `2` | Sampling interval (seconds) used by the orchestrators |

The script must run on the **injector** host (the jMeter machine) — the
local `pidstat`/`ps`/`free` commands target the local machine.

---

## Customizing display labels in `report_html.py`

`src/report_html.py` reads four parameters (environment variable, then the
central `src/jmeter_replay.conf` file, then the built-in default) that
control the display labels of the dashboard:

| Parameter | Default | Purpose |
|-----------|---------|---------|
| `LDAP_HOST_LABEL` | `LDAP server` | Label of the LDAP server in titles/charts |
| `INJECTOR_HOST_LABEL` | `injector host` | Label of the injector host in titles/charts |
| `INJECTOR_PREFIX` | `injector` | Matches `host_metrics` columns `injector_*` |
| `SLAPD_PREFIX` | `slapd` | Matches `host_metrics` columns `slapd_<inst>_*` |

Edit them in `jmeter_replay.conf` to brand the report for your own LDAP /
injector hostnames (e.g. `LDAP_HOST_LABEL="ldap1"`,
`INJECTOR_HOST_LABEL="injector"`). The CSV column prefixes
(`slapd_<name>_cpu_usr` and `injector_cpu_usr`) must match the
corresponding `host_monitor.sh` settings.

---

## Example: the included sample report

`examples/sample_report/html/` contains five HTML pages that
demonstrate the dashboard on a synthetic replay of 29 operations spread
over ~60 seconds, scaled up to a stress run of 93 971 operations over
16 minutes.

Open `examples/sample_report/html/index.html` in a browser to navigate
the family:

- `index.html` — master index with links to the step pages
- `conc_120.html` — the load-step page (peak concurrency 120)
- `injector_conc_120.html` — the injector-host page
- `compare.html` — the comparison page
- `fidelity_conc_120.html` — the replay-vs-log fidelity check

The sample uses the included `examples/sample.replay` (7 BINDs, 10 SRCHs,
4 CMPs, 7 UNBINDs and 1 ABANDON against `dc=example,dc=org`) as a
starting point — replace it with your own replay file for a real test.

---

## Limitations

- **Only BIND, SRCH, CMP, UNBIND and ABANDON are replayed** — other LDAP
  operations (ADD, MOD, DEL, EXT, ...) are parsed from the replay file
  and counted but not replayed.
- You must supply passwords via `PASSWORD_FILE` or `LDAP_DEFAULT_PASSWORD`.
- Replays run each search under the DN that bound the connection earlier;
  the `LDAP_SYSTEM_DN` is used when the replay must break the
  connection-bound identity.
- **Comparison is informational** — `MATCHED` / `MISMATCHED` is shown
  in the fidelity page but is not the goal of the test.

---

## License

Copyright (C) 2026 Manuel FLURY.

This program is free software: you can redistribute it and/or modify it
under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or (at
your option) any later version. See [LICENSE](LICENSE) for the full text.

The replay file format is defined by [slaplog](https://gitlab.com/ooo.manu.ooo/slaplog),
the replay-file generator distributed under AGPL-3.0 ([github mirror](https://github.com/zx97/slaplog)).
