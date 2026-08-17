# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Manuel FLURY
#
# This file is part of jMeter_OpenLDAP_replay: replays OpenLDAP access-log
# traffic with Apache JMeter and renders an HTML dashboard. Distributed
# under the GNU Affero General Public License v3.0 (AGPL-3.0-or-later);
# see the LICENSE file for the full text.
#
# Typical day on the LDAP server - "camel back" workload curve.
# Two humps: first ~09:00, second ~13:30.
#
# Format: <time> <concurrency>
#   time can be:
#     - HH:MM  : time of day (day clock). The whole day is compressed into
#                TEST_DURATION_S when it is set; otherwise scaled by
#                TIME_SCALE (seconds of test per day-minute, default 1).
#     - number : seconds from the start of the test.
# Between the points the target concurrency is ramped linearly, so a ramp-up,
# a plateau, a ramp-down, a dip and a second hump are all expressible.
#
# Usage example (30 minute test):
#   -JCONCURRENCY_PROFILE=/opt/jMeter_OpenLDAP_replay/src/concurrency_profiles/typical_day.profile \
#   -JTEST_DURATION_S=1800
#
# The day below (00:00 -> 23:00 = 1380 minutes) compressed into 1800 s gives
# a scale of ~1.30 s per day-minute: the 09:00 hump lands ~11.7 min into the
# test and the 13:30 hump ~17.6 min.
00:00 1
05:00 1
06:00 2
07:00 4
08:00 8
09:00 16      # first hump (morning peak)
09:30 16
10:30 12
11:30 8
12:00 4       # lunch dip
13:00 8
13:30 16      # second hump (afternoon peak)
14:00 16
15:00 12
16:00 8
17:00 6
18:00 3
20:00 2
23:00 1