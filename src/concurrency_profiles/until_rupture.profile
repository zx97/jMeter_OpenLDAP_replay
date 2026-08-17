# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 Manuel FLURY
#
# This file is part of jMeter_OpenLDAP_replay: replays OpenLDAP access-log
# traffic with Apache JMeter and renders an HTML dashboard. Distributed
# under the GNU Affero General Public License v3.0 (AGPL-3.0-or-later);
# see the LICENSE file for the full text.
#
# "Until rupture" profile (seconds from test start).
# The concurrency ramps up continuously; the run stops as soon as
# STOP_ON_INFRA_ERR=true observes LDAP stop replying, recording the exact
# point of rupture. TEST_DURATION_S acts as a safety cap.
0 1
60 4
120 8
180 16
240 24
300 32
360 40
420 48
480 56
540 64
600 72
660 80
720 88
780 96
840 104
900 112
960 120