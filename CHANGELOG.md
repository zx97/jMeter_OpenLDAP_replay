# Changelog

All notable changes to **jMeter_OpenLDAP_replay** are documented in this
file. The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

The project is distributed under the **GNU Affero General Public License
v3.0 (AGPL-3.0)** — see the [LICENSE](LICENSE) file for the full text.

## [1.0.0] - 2026-08-17

### Added

- Initial public release of the replay toolchain:
  - `src/replay_ldap.jmx` — Apache JMeter test plan.
  - `src/replay_ldap.groovy` — JSR223 replay script: replays the BIND,
    SRCH, CMP, UNBIND and ABANDON operations of a `*.replay` file
    (slaplog format) against a live OpenLDAP server, preserving the
    original session ordering, and verifies the results (`returnCode`
    and `nentries`) against the expected values.
  - `src/report_html.py` — self-contained HTML dashboard generator
    (latency, throughput, queue analysis, CPU correlation, server
    non-response episodes, per-minute breakdowns).
  - `src/host_monitor.sh` — server + injector host metrics collector.
  - `src/run_curve_test.sh` — concurrency-curve orchestrator.
  - `src/run_load_ramp.sh` — load-ramp orchestrator.
  - `src/set_passwords.sh` — helper to set a shared password on a
    directory.
  - `src/concurrency_profiles/` — `smoke_test`, `typical_day` and
    `until_rupture` concurrency profiles.
- `examples/sample.replay` — small anonymized replay file (example DNs).
- `examples/sample_passwords.csv` — matching example password table.
- `examples/sample_report/html/` — self-contained HTML sample report
  (5 pages), generated with this project.

[1.0.0]: https://github.com/zx97/jMeter_OpenLDAP_replay/releases/tag/v1.0.0
