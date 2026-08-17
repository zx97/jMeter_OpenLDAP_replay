//
// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 Manuel FLURY
//
// This file is part of jMeter_OpenLDAP_replay: replays OpenLDAP access-log
// traffic with Apache JMeter and renders an HTML dashboard. Distributed
// under the GNU Affero General Public License v3.0 (AGPL-3.0-or-later);
// see the LICENSE file for the full text.
//
// ============================================================================
//  Replays the LDAP operations (BIND, SRCH, CMP, UNBIND, ABANDON) of a
//  *.replay file generated from an OpenLDAP (slapd) log, and verifies the
//  results.
//
//  Expected format per line (separator '|'):
//    timestamp|conn|op|type|base|filter|attrs|scope|deref|binddn|authcid|authzid|err|etime|qtime|nentries|text
//
//  Format semantics:
//    - timestamp : time of the operation in the original log
//    - conn      : LDAP connection identifier (links the lines together)
//    - op        : position of the operation WITHIN the connection (replay order)
//    - type      : operation type (BIND, SRCH, CMP, UNBIND, ABANDON; other
//                  types are silently ignored)
//    - following columns: parameters of the operation type, as well as the
//      RESULT obtained in the original log (err = LDAP return code,
//      nentries = number of returned entries, etime/qtime = timings)
//      for comparison via jMeter.
//
//  Replay rules:
//    - Lines sharing the same conn are replayed over a SINGLE LDAP connection,
//      in op order, to reproduce the state (authentication, session) of the
//      original connection.
//    - BIND    -> simple bind with the DN + password (passwords.csv or default).
//    - SRCH    -> search with base/filter/attrs/scope/deref, then verification
//                 of the return code (err) and the number of entries (nentries).
//                 If an 18th column contains the expected DNs (comma separated,
//                 sorted), the content is also compared.
//    - CMP     -> LDAP compare: tests that `base` has `filter=attr:value`
//                 (RFC 4515 assertion). Result codes: 0 = compare-true,
//                 5 = compare-false, anything else is an error.
//    - UNBIND  -> graceful disconnect. Any op on the same conn after UNBIND
//                 is skipped.
//    - ABANDON -> fire-and-forget. The filter column carries the numeric
//                 message id of the operation to cancel. No result is
//                 expected.
//    - A SRCH or CMP on a connection already authenticated by a previous BIND
//      of the same conn reuses that identity; otherwise it is anonymous, or
//      uses a system bind if LDAP_SYSTEM_DN is set.
//
//  Dependency: UnboundID LDAP SDK (bundled with JMeter for the LDAP sampler).
//  JMeter variables used (with default values):
//    REPLAY_FILE, REPLAY_SEPARATOR (| or tab/comma), PASSWORD_FILE,
//    LDAP_DEFAULT_PASSWORD,
//    LDAP_HOST, LDAP_PORT, LDAP_USE_SSL, LDAP_USE_STARTTLS,
//    LDAP_SYSTEM_DN, LDAP_SYSTEM_PASSWORD,
//    PACING_MODE (none|delta|sorted), PACING_CAP_MS, COMPARE_DNS,
//    REPLAY_START / REPLAY_END (ISO-8601, empty = whole file),
//    REPLAY_LOOPS (repeat the replay N times to increase the load),
//    REPORT_FILE (path of the metrics report)
//
//  Purpose of the collected metrics:
//    - reach the limit of the server: repeat the workload (REPLAY_LOOPS),
//      monitor the throughput (ops/s) and the success rate under load;
//    - observe the behaviour vs the load: latency percentiles (p50/p95/p99),
//      min/max, and per-minute buckets showing ops/errors/latency over time;
//    - replay a particular period: filter the file with REPLAY_START/END to
//      reproduce an incident in a controlled environment.
//
//  IMPORTANT NOTE: generate the replay with an unambiguous separator
//  (recommended: tab) because '|' is also the OR operator of LDAP
//  filters:  slaplog -o replay --replay-separator tab <log> > out.replay
// ============================================================================
//

import com.unboundid.ldap.sdk.*
import org.apache.jmeter.samplers.SampleResult as SRClass
import java.time.Instant
import java.time.Duration
import java.time.format.DateTimeParseException

// JMeter 5.x binds the current sample as "SampleResult" (capital S).
def sampleResult = SampleResult

// ---------------------------------------------------------------------------
// 1. Configuration (read from JMeter variables / properties)
// ---------------------------------------------------------------------------
// JMeter -J flags set *properties* (props), while the UDV block of the
// TestPlan sets *variables* (vars). To honour both shapes, prefer the
// property (which the CLI can override) and fall back to the UDV.
def conf = { String name, String dflt ->
    String p = props.get(name)
    if (p != null && !p.toString().isEmpty()) return p.toString()
    p = vars.get(name)
    return (p != null && !p.toString().isEmpty()) ? p : dflt
}

String replayPath  = conf("REPLAY_FILE",           "sample.replay")
String passPath    = conf("PASSWORD_FILE",         "")
String defaultPass = conf("LDAP_DEFAULT_PASSWORD", "")

// Separator of the replay file. Possible values: "|" (default), "tab", "comma",
// or any other literal string.
String sepRaw = (vars.get("REPLAY_SEPARATOR") ?: "|").toLowerCase()
String sep
switch (sepRaw) {
    case "tab":
        sep = "\t"
        break
    case "comma":
        sep = ","
        break
    default:
        sep = sepRaw
        break
}

String  host    = conf("LDAP_HOST",          "localhost")
int     port    = Integer.parseInt(conf("LDAP_PORT", "389"))
boolean useSSL  = Boolean.parseBoolean(conf("LDAP_USE_SSL",       "false"))
boolean useTLS  = Boolean.parseBoolean(conf("LDAP_USE_STARTTLS",  "false"))

// Optional trust store for LDAPS. Set LDAP_TRUSTSTORE (e.g.
// /path/to/truststore.jks) and LDAP_TRUSTSTORE_PASSWORD (default "changeit")
// to have the script trust a private CA during the handshake.  When unset
// the SSL verifier is TrustAll (verification disabled); this is fine for
// reproductions against a private infrastructure but should never be used
// against the open Internet.
String truststorePath = conf("LDAP_TRUSTSTORE",          "")
String truststorePw   = conf("LDAP_TRUSTSTORE_PASSWORD", "changeit")

String sysDn = conf("LDAP_SYSTEM_DN",         "")
String sysPw = conf("LDAP_SYSTEM_PASSWORD",   "")

// Pacing modes:
//   "none"   -> as fast as possible
//   "delta"  -> respect the timestamp gaps of the file (file order)
//   "sorted" -> sort by timestamp first, then respect the gaps
String pacingMode = conf("PACING_MODE", "none").toLowerCase()
long   pacingCap  = Long.parseLong(vars.get("PACING_CAP_MS") ?: "10000")
boolean compareDns = Boolean.parseBoolean(vars.get("COMPARE_DNS") ?: "false")
// Optional path of a detailed textual metrics report written at the end of
// the run. Empty = no file, the metrics remain in the parent sample response.
String reportFile = conf("REPORT_FILE", "")

// Time-range filter (ISO-8601, e.g. 2026-05-27T17:00:00Z). Empty = whole file.
// Useful to replay a particular period and reproduce an incident in a
// controlled environment.
String replayStart = conf("REPLAY_START", "")
String replayEnd   = conf("REPLAY_END",   "")

// Number of times the workload is repeated (default 1). Increase it to raise
// the load and probe the limit the server can sustain.
int loops = Integer.parseInt(conf("REPLAY_LOOPS", "1"))
if (loops < 1) loops = 1

// Number of LDAP connections kept open simultaneously (default 1).
// 1 = sequential replay (historical behaviour). > 1 = parallel replay:
// `concurrency` worker threads, each replaying one connection of the file at
// a time, so the session state of each connection is still preserved while
// the load (number of simultaneous connections) rises toward the concurrency
// of the original log. The load-test report correlates the response times
// with the peak number of simultaneous connections actually reached.
int concurrency = Integer.parseInt(conf("CONCURRENCY", "1"))
if (concurrency < 1) concurrency = 1

int total = 0
// "passed" counts the operations for which LDAP actually replied (network
// and connection are healthy). It does NOT imply the reply matches the log:
// a wrong password or a missing entry still counts as passed because the
// server did its job. Use `matched` for the fidelity check.
int passed = 0
// "matched" counts the operations whose LDAP reply matches what the log
// recorded (result code, number of entries, optionally DNS list).
int matched = 0
// "infraErr" counts the operations for which LDAP did NOT reply at all
// (SSL handshake failure, connection timeout, refused, ...). This is the
// only situation that is reported as an error in the final report.
int infraErr = 0
int ignored = 0
// Concurrency of the replay: the number of LDAP connections open at the same
// time (the "load" applied to the server). With the sequential replay this
// stays at 1; a parallel replay (CONCURRENCY > 1) raises it. The peak value
// is what the load-test report correlates with the response times.
int peakConcurrent = 0
int activeConns = 0
List<String> infraFailures = []
List<String> fidelityFailures = []

// Metrics collected during the replay and included in the final report:
//   per operation type: counters (total/ok/ko), latency and mismatches
//   between the original log (expected) and the replay (actual):
//     errMismatch  : LDAP result code differs
//     countMismatch: number of returned entries differs
//     dnsMismatch  : returned DNS list differs (only if COMPARE_DNS=true)
Map<String, Map> metrics = [:]

// Concurrency curve driver (optional, replaces the fixed CONCURRENCY pool):
//   CONCURRENCY_PROFILE : text file describing the number of simultaneous
//     connections as a function of time. One point per line, "#" = comment:
//     "<time> <concurrency>" where time is either seconds from the start of
//     the test (e.g. "300 16") or a time of day HH:MM (e.g. "09:00 16")
//     modelling a typical day; between the points the target concurrency is
//     ramped linearly (ramp-up / hold / ramp-down / second hump ...). With
//     HH:MM times the whole day is compressed into TEST_DURATION_S, or
//     scaled by TIME_SCALE (seconds of test per day-minute, default 1).
//   TEST_DURATION_S    : total duration of the test in seconds (e.g. 1800
//     for half an hour). The replay workload is repeated in a loop to fill
//     the duration; without a profile this holds CONCURRENCY constant.
boolean curveMode = false
String profilePath = conf("CONCURRENCY_PROFILE", "")
double durationSec = 0.0
double timeScale = 1.0
// Stop the curve early as soon as an infrastructure error is observed
// (LDAP stopped replying). Useful for a dedicated "until rupture" run: the
// test then records the exact point where the service broke.
boolean stopOnInfraErr = Boolean.parseBoolean(conf("STOP_ON_INFRA_ERR", "false"))
try {
    if (conf("TEST_DURATION_S", "")) durationSec = Double.parseDouble(conf("TEST_DURATION_S", ""))
    if (conf("TIME_SCALE", "")) timeScale = Double.parseDouble(conf("TIME_SCALE", ""))
} catch (NumberFormatException e) {
    infraFailures << "Invalid TEST_DURATION_S/TIME_SCALE (must be numbers): " + e.getMessage()
}

// ---------------------------------------------------------------------------
// 2. Helpers
// ---------------------------------------------------------------------------
def toInt = { String s, int dflt ->
    if (s == null || s.isEmpty()) return dflt
    try { return Integer.parseInt(s) } catch (NumberFormatException e) { return dflt }
}

// Returns the p-th percentile (0..100) of a sorted list of longs.
def percentile = { List<Long> sorted, double p ->
    if (sorted == null || sorted.isEmpty()) return 0L
    int idx = (int) Math.ceil(p / 100.0 * sorted.size()) - 1
    if (idx < 0) idx = 0
    if (idx >= sorted.size()) idx = sorted.size() - 1
    return sorted[idx]
}

def scopeOf = { String s ->
    switch (s) {
        case "base": return SearchScope.BASE
        case "one":  return SearchScope.ONE
        default:     return SearchScope.SUB
    }
}

def derefOf = { String s ->
    switch (s) {
        case "1": return DereferencePolicy.SEARCHING
        case "2": return DereferencePolicy.FINDING
        case "3": return DereferencePolicy.ALWAYS
        default:  return DereferencePolicy.NEVER
    }
}

// Returns a fresh metrics entry for one operation type.
def newMetric = {
    [ total: 0, replayed: 0, matched: 0, mismatched: 0, notReplayed: 0, infraErr: 0,
      errMismatch: 0, countMismatch: 0, dnsMismatch: 0,
      latMin: Long.MAX_VALUE, latMax: 0L, latSum: 0L,
      latList: [] as List<Long>,      // all latencies, for percentiles
      buckets: [:] as Map<String, Map> ]  // per-minute buckets
}

// Whole-run figures (throughput, duration) are accumulated separately.
long runStartMs = System.currentTimeMillis()

// ---------------------------------------------------------------------------
// 3. Read the password table (dn|password, lines starting with # ignored)
// ---------------------------------------------------------------------------
Map<String, String> passMap = [:]
if (passPath) {
    File pf = new File(passPath)
    if (pf.exists()) {
        pf.eachLine { line ->
            if (line && !line.startsWith("#")) {
                String[] a = line.split(sep, -1)
                if (a.length >= 2 && a[0].trim()) {
                    passMap[a[0].trim()] = a[1].trim()
                }
            }
        }
    } else {
        infraFailures << "Password file not found: " + passPath
    }
}

// ---------------------------------------------------------------------------
// 4. Read the replay file
// ---------------------------------------------------------------------------
File replayFile = new File(replayPath)
if (!replayFile.exists()) {
    sampleResult.setSuccessful(false)
    sampleResult.setResponseMessage("Replay file not found: " + replayPath)
    return
}

List<Map> ops = []
replayFile.eachLine { line, lineNo ->
    String[] p = line.split(sep, -1)            // -1 : keep the empty fields
    if (p.length < 4) return
    if (p[3].trim().equalsIgnoreCase("type")) return   // header line
    String type = p[3].trim()
    if (type != "BIND" && type != "SRCH" && type != "CMP" && type != "UNBIND" && type != "ABANDON") return       // other types ignored
    // Lines whose field count differs from the format (17) are ignored
    // (may happen if the chosen separator appears inside an LDAP filter,
    // e.g. '|' with the OR operator). Use --replay-separator tab instead.
    if (p.length != 17) {
        ignored++
        return
    }
    // Time-range filter: keep only the operations within [replayStart, replayEnd]
    // (lexicographic comparison on the ISO-8601 timestamp).
    String ts = p[0].trim()
    if (replayStart && ts < replayStart) return
    if (replayEnd   && ts > replayEnd)   return
    ops << [
        ts          : ts,
        conn        : p[1].trim(),
        op          : p[2].trim(),
        type        : type,
        base        : p[ 4].trim(),
        filter      : p[ 5].trim(),
        attrs       : p[ 6].trim(),
        scope       : p[ 7].trim(),
        deref       : p[ 8].trim(),
        binddn      : p[ 9].trim(),
        err         : p[12].trim(),
        etime       : p[13].trim(),
        qtime       : p[14].trim(),
        nentries    : p[15].trim(),
        expectedDns : p.length > 17 ? p[17].trim() : ""   // optional 18th column
    ]
}

// Group by connection (conn): lines sharing the same conn are linked and
// replayed together; the global order of connections follows the order of
// appearance in the file (or the timestamp of the first op if mode "sorted").
Map<String, List<Map>> byConn = [:]
List<String> connOrder = []
ops.each { op ->
    if (!byConn.containsKey(op.conn)) {
        byConn[op.conn] = []
        connOrder << op.conn
    }
    byConn[op.conn] << op
}
// Within each connection, strict sort by op (position in the connection).
byConn.each { k, v -> v.sort { a, b -> toInt(a.op, 0).compareTo(toInt(b.op, 0)) } }

if (pacingMode == "sorted") {
    connOrder = connOrder.sort { ca, cb ->
        Instant.parse(byConn[ca][0].ts).compareTo(Instant.parse(byConn[cb][0].ts))
    }
}

// ---------------------------------------------------------------------------
// 5. LDAP connection
// ---------------------------------------------------------------------------
// In UnboundID LDAP SDK 7.x LDAPConnectionOptions lost setUseSSL(boolean):
// LDAPS is now obtained by passing an SSLSocketFactory (or SSLSocketVerifier)
// to LDAPConnectionOptions / the LDAPConnection constructor. StartTLS is
// still available as a per-connection method but needs an SSLUtil argument
// since v6+.
import java.security.KeyStore
import com.unboundid.util.ssl.SSLUtil
import com.unboundid.util.ssl.TrustAllSSLSocketVerifier
import com.unboundid.util.ssl.HostNameSSLSocketVerifier

// Build a JSSE TrustManager that trusts every certificate contained in
// `truststorePath` (a JKS file). Returns null when the path is blank: a
// null TrustManager in SSLUtil means "default JVM trust" (the public CAs).
def buildTrustManager = {
    if (!truststorePath) {
        return null
    }
    // Use the (File, char[], String, boolean) 4-arg constructor; using a
    // 2-arg form triggers Groovy dynamic dispatch which fails to pick the
    // correct overload.
    return new com.unboundid.util.ssl.TrustStoreTrustManager(
        new File(truststorePath),
        truststorePw.toCharArray(),
        "JKS",
        false)
}

def buildSslFactory = {
    SSLUtil ssl = new SSLUtil((javax.net.ssl.TrustManager) buildTrustManager())
    return ssl.createSSLSocketFactory()
}

def buildSslVerifier = {
    // HostNameSSLSocketVerifier has no no-arg constructor in SDK >= 6.0:
    // - (boolean examineValidity)        => checks only cert validity
    // - (boolean, boolean hostname)      => checks validity AND hostname
    // Without truststorePath the cert is not trustworthy; skipping the
    // check entirely (TrustAll) is consistent with that.
    return truststorePath
        ? new HostNameSSLSocketVerifier(false, false)
        : TrustAllSSLSocketVerifier.getInstance()
}

def openConn = {
    LDAPConnectionOptions o = new LDAPConnectionOptions()
    o.setConnectTimeoutMillis(5000)
    if (useSSL) {
        o.setSSLSocketVerifier(buildSslVerifier())
        LDAPConnection c = new LDAPConnection(buildSslFactory(), o, host, port)
        return c
    }
    LDAPConnection c = new LDAPConnection(o, host, port)
    if (useTLS) {
        javax.net.ssl.TrustManager tm = buildTrustManager()
        c.startTLS(new SSLUtil(tm))
    }
    return c
}

// ---------------------------------------------------------------------------
// 6. Replay of the operations
//    One LDAP connection is opened per conn of the file and reused for all
//    the operations of that conn, in op order. With CONCURRENCY > 1 several
//    connections are replayed in parallel (one worker thread owns a whole
//    connection), so the session state of each connection is preserved while
//    the load (number of simultaneous connections) rises. Pacing is only
//    meaningful in the sequential mode (global timeline of the file).
// ---------------------------------------------------------------------------
// Shared accumulator lock: the metrics, the global counters, the failure
// lists and the sub-sample list are all written by the worker threads and
// merged under this lock.
Object lock = new Object()
List<SRClass> subs = []
Instant prevTs = null

// Executes one LDAP operation on `c` and returns the observed result.
// `st` carries the per-connection session state ([bound: ...]) and `connErr`
// the open-connection error, if any. The returned map holds the latency,
// the outcome flags (replayed / matched / infraErr), the mismatch flags,
// the sub-sample, the operation type and the per-minute bucket key.
def execOp = { LDAPConnection c, Map op, int pass, Map st, String connErr ->
    SRClass sub = new SRClass()
    String label = op.type + " conn=" + op.conn + " op=" + op.op
    if (loops > 1 || curveMode) label = "pass" + pass + " " + label
    sub.setSampleLabel(label)
    sub.sampleStart()

    boolean ok = false
    String msg = ""
    // `opReplayed` is true when LDAP returned a reply (any code). The
    // connection side is healthy. `opMatched` is true when that reply
    // matches what the log predicted. `opInfraErr` is true when LDAP
    // did NOT reply at all (SSL failure, network failure, ...).
    boolean opReplayed = false
    boolean opMatched = false
    boolean opInfraErr = false
    // Set true by UNBIND: replayConn should stop issuing further ops on
    // this connection (the socket is dead).
    boolean closed = false
    // Mismatch flags of this operation, reported in the metrics
    boolean mismatchErr = false
    boolean mismatchCount = false
    boolean mismatchDns = false

    try {
        if (c == null) {
            msg = connErr ?: "Connection unavailable"
            opInfraErr = true
        } else if (op.type == "BIND") {
            // ------------------------------------------------------ BIND
            String dn = op.binddn
            if (!dn) {
                msg = "BIND without binddn (empty column)"
            } else {
                String pw = passMap.containsKey(dn) ? passMap[dn] : (defaultPass ? defaultPass : "")
                if (!pw) {
                    msg = "No password for " + dn + " (set PASSWORD_FILE or LDAP_DEFAULT_PASSWORD)"
                } else {
                    int expected = toInt(op.err, 0)
                    int code = -1
                    long t0 = System.currentTimeMillis()
                    try {
                        BindResult br = c.bind(dn, pw)
                        code = br.getResultCode().intValue()
                    } catch (LDAPException e) {
                        code = e.getResultCode().intValue()
                    }
                    long elapsed = System.currentTimeMillis() - t0
                    // in LDAP, a successful bind => authenticated connection;
                    // a failed bind => unauthenticated connection
                    st.bound = (code == 0)
                    // The bind either succeeded or LDAP returned an error
                    // code: in both cases the server did reply. The replay
                    // is considered successful as long as the result code
                    // was actually observable.
                    opReplayed = (code >= 0)
                    if (code == expected) {
                        opMatched = true
                        ok = true
                        msg = "BIND OK (" + elapsed + " ms)"
} else if (op.type == "UNBIND") {
            // ------------------------------------------------------ UNBIND
            // Graceful disconnect. After UNBIND the connection is dead:
            // any further op on this conn would fail, so replayConn breaks
            // out of the loop on the `closed` flag in the returned map.
            try {
                c.unbind()
                opReplayed = true
                opMatched = true
                ok = true
                closed = true
                msg = "UNBIND OK"
            } catch (LDAPException e) {
                // UNBIND errors are still considered as closing the conn
                // (the server is unlikely to accept further ops anyway).
                opReplayed = (e.getResultCode().intValue() >= 0)
                opMatched = opReplayed
                ok = opReplayed
                closed = true
                msg = "UNBIND: " + e.getResultCode()
            }
        } else if (op.type == "ABANDON") {
            // ------------------------------------------------------ ABANDON
            // Fire-and-forget: no result is expected. The filter column
            // carries the message ID of the operation to cancel.
            int abandonedId = toInt(op.filter, -1)
            if (abandonedId < 0) {
                msg = "ABANDON without a numeric message id in the filter column"
            } else {
                try {
                    c.abandon(abandonedId)
                    opReplayed = true
                    opMatched = true
                    ok = true
                    msg = "ABANDON id=" + abandonedId
                } catch (LDAPException e) {
                    opReplayed = (e.getResultCode().intValue() >= 0)
                    opMatched = opReplayed
                    ok = opReplayed
                    msg = "ABANDON id=" + abandonedId + " " + e.getResultCode()
                }
            }
        } else if (op.type == "CMP") {
            // ------------------------------------------------------ CMP
            // LDAP compare: tests if `entry` has `attribute == value`.
            // Filter format (RFC 4515): "attr:value" or "attr::base64value".
            // The connection must already be bound (CMP runs under the DN
            // that bound it, exactly like SRCH).
            String filter = op.filter
            String attr = ""
            String value = ""
            if (filter && filter.indexOf(':') > 0) {
                attr  = filter.substring(0, filter.indexOf(':')).trim()
                value = filter.substring(filter.indexOf(':') + 1)
                if (value.startsWith(":")) value = value.substring(1)   // binary: drop leading ":"
            }
            if (!attr || !op.base) {
                msg = "CMP needs base + filter=attr:value (got base='" +
                      op.base + "' filter='" + filter + "')"
            } else if (!st.bound && sysDn) {
                // Same fallback as SRCH: optional system bind if needed
                try {
                    c.bind(sysDn, sysPw)
                    st.bound = true
                } catch (LDAPException e) {
                    msg = "System bind failed: " + e.getResultCode() + " (" + sysDn + ")"
                }
            }
            if (attr && op.base && (st.bound || !sysDn)) {
                int expected = toInt(op.err, 0)
                int code = -1
                long t0 = System.currentTimeMillis()
                try {
                    CompareResult cr = c.compare(op.base, attr, value)
                    code = cr.getResultCode().intValue()
                } catch (LDAPException e) {
                    code = e.getResultCode().intValue()
                }
                long ms = System.currentTimeMillis() - t0
                opReplayed = (code >= 0)
                if (code == expected) {
                    opMatched = true
                    ok = true
                    msg = "CMP " + (code == 0 ? "TRUE" : (code == 5 ? "FALSE" : "OK")) +
                          " " + attr + "=" + value + " (" + ms + " ms)"
                } else {
                    mismatchErr = true
                    msg = "CMP resultCode=" + code + ", expected=" + expected +
                          " (" + attr + "=" + value + ")"
                }
            } else if (attr && op.base && !msg) {
                msg = "Connection not bound and no LDAP_SYSTEM_DN configured"
            }
        } else {
                        mismatchErr = true
                        msg = "BIND resultCode=" + code + ", expected=" + expected
                    }
                }
            }
        } else {
            // ------------------------------------------------------ SRCH
            boolean canProceed = true
            // Identity: reuse the connection if already authenticated by a
            // previous BIND of the same conn; otherwise optional system bind;
            // otherwise anonymous search.
            if (!st.bound && sysDn) {
                try {
                    c.bind(sysDn, sysPw)
                    st.bound = true
                } catch (LDAPException e) {
                    canProceed = false
                    msg = "System bind failed: " + e.getResultCode() + " (" + sysDn + ")"
                }
            }

            if (canProceed) {
                SearchScope ss = scopeOf(op.scope)
                DereferencePolicy dp = derefOf(op.deref)
                String[] attrsArr = op.attrs ? op.attrs.split("\\s+") : new String[0]

                String filter = op.filter ? op.filter : "(objectClass=*)"
                SearchResult sr
                try {
                    sr = c.search(op.base, ss, dp, 0, 0, false, filter, attrsArr)
                } catch (LDAPSearchException e) {
                    sr = e.getSearchResult()
                    if (sr == null) {
                        msg = "SRCH error: " + e.getResultCode() + " (" + e.getDiagnosticMessage() + ")"
                        opInfraErr = true
                    }
                }

                if (sr != null) {
                    opReplayed = true
                    int code = sr.getResultCode().intValue()
                    int expected = toInt(op.err, 0)
                    int count = sr.getEntryCount()
                    int expectedCount = toInt(op.nentries, -1)

                    List<String> actualDns = sr.getSearchEntries().collect { it.getDN() }.sort()
                    List<String> expectedDnsList = null
                    if (compareDns && op.expectedDns) {
                        expectedDnsList = op.expectedDns.split(",").collect { it.trim() }.sort()
                    }

                    StringBuilder sb = new StringBuilder()
                    sb.append("SRCH ").append(count).append(" entrie(s)")
                    if (expectedCount >= 0 && count != expectedCount) {
                        sb.append(", EXPECTED ").append(expectedCount)
                    }
                    sb.append(", base=").append(op.base)
                    sb.append(", scope=").append(op.scope).append(", deref=").append(op.deref)
                    if (op.filter) sb.append(", filter=").append(op.filter)
                    // original log timing, for information only
                    if (op.etime) sb.append(", etimeOrig=").append(op.etime)

                    boolean matchCode = (code == expected)
                    boolean matchCount = (expectedCount < 0 || count == expectedCount)
                    boolean matchDns = !(compareDns && expectedDnsList != null && actualDns != expectedDnsList)
                    opMatched = matchCode && matchCount && matchDns
                    ok = opMatched
                    if (compareDns && expectedDnsList != null && actualDns != expectedDnsList) {
                        List<String> missing = expectedDnsList - actualDns
                        List<String> extra   = actualDns - expectedDnsList
                        sb.append(", DNs differ (missing=").append(missing.size())
                          .append(", extra=").append(extra.size()).append(")")
                    }
                    mismatchErr = !matchCode
                    mismatchCount = !matchCount
                    mismatchDns = !matchDns
                    sb.append(opMatched ? " => OK" : " => FAIL")
                    msg = sb.toString()
                }
            } else {
                opInfraErr = true
            }
        }
    } catch (Throwable t) {
        ok = false
        msg = "Exception: " + t.toString()
    }

    sub.sampleEnd()
    long lat = sub.getTime()
    return [ sub: sub, label: label, lat: lat, ok: ok, msg: msg,
             opReplayed: opReplayed, opMatched: opMatched,
             opInfraErr: opInfraErr, mismatchErr: mismatchErr,
             mismatchCount: mismatchCount, mismatchDns: mismatchDns,
             type: op.type,
             closed: closed,
             minute: op.ts.length() >= 16 ? op.ts.substring(0, 16) : "unknown" ]
}

// Merges one operation result into the shared accumulators (metrics,
// global counters, failure lists and the sub-sample list).
def recordOp = { Map r ->
    synchronized (lock) {
        Map met = metrics[r.type]
        if (met == null) {
            met = newMetric()
            metrics[r.type] = met
        }
        met.total++
        met.latSum += r.lat
        met.latList << r.lat
        if (r.lat < met.latMin) met.latMin = r.lat
        if (r.lat > met.latMax) met.latMax = r.lat
        if (r.opReplayed) met.replayed++ else met.notReplayed++
        if (r.opMatched) met.matched++ else if (r.opReplayed) met.mismatched++
        if (r.opInfraErr) met.infraErr++
        if (r.mismatchErr) met.errMismatch++
        if (r.mismatchCount) met.countMismatch++
        if (r.mismatchDns) met.dnsMismatch++

        // Per-minute bucket (based on the operation timestamp of the file):
        // shows how the number of operations, the errors and the latency
        // evolve over time (behaviour vs the load).
        Map bk = met.buckets[r.minute]
        if (bk == null) {
            bk = [ ops: 0, replayed: 0, matched: 0, mismatched: 0, infraErr: 0,
                   latSum: 0L, latMax: 0L ]
            met.buckets[r.minute] = bk
        }
        bk.ops++
        bk.latSum += r.lat
        if (r.lat > bk.latMax) bk.latMax = r.lat
        if (r.opReplayed) bk.replayed++
        if (r.opMatched) bk.matched++
        else if (r.opReplayed) bk.mismatched++
        if (r.opInfraErr) bk.infraErr++

        r.sub.setSuccessful(r.opMatched)
        r.sub.setResponseMessage(r.msg)
        r.sub.setResponseData(r.opMatched ? "OK - " + r.msg : "Fail - " + r.msg, "UTF-8")
        subs << r.sub

        total++
        if (r.opReplayed) {
            passed++
            if (r.opMatched) matched++
        } else if (r.opInfraErr) {
            infraErr++
        }
        if (!r.opMatched) {
            if (r.opInfraErr) {
                infraFailures << (r.label + " : " + r.msg)
            } else {
                fidelityFailures << (r.label + " : " + r.msg)
            }
        }
    }
}

// Replays one connection of the file on a dedicated LDAP connection.
def replayConn = { String cid, int pass ->
    List<Map> connOps = byConn[cid]
    LDAPConnection cur = null
    Map st = [bound: false, closed: false]
    String connErr = null

    try {
        try {
            cur = openConn()
        } catch (Throwable t) {
            connErr = "LDAP connection failed (" + host + ":" + port + "): " + t
        }
        if (cur != null) {
            synchronized (lock) {
                activeConns++
                if (activeConns > peakConcurrent) peakConcurrent = activeConns
            }
        }
        LDAPConnection c = cur

        connOps.each { op ->
            Map r = execOp(c, op, pass, st, connErr)
            recordOp(r)
            // UNBIND closed the connection: stop issuing further ops on it.
            if (r.closed) return
            // Optional pacing between operations (sequential mode only:
            // a global per-pass timeline makes no sense when several
            // connections run in parallel).
            if (pacingMode != "none" && ops.size() > 1 && concurrency <= 1) {
                try {
                    Instant t = Instant.parse(op.ts)
                    if (prevTs != null) {
                        long d = Duration.between(prevTs, t).toMillis()
                        if (d < 0) d = 0
                        d = Math.min(d, pacingCap)
                        if (d > 0) Thread.sleep(d)
                    }
                    prevTs = t
                } catch (DateTimeParseException e) {
                    // unreadable timestamp: pacing ignored
                }
            }
        }
    } finally {
        if (cur != null) {
            try { cur.close() } catch (Throwable t) { /* ignore */ }
            cur = null
            synchronized (lock) { activeConns-- }
        }
    }
}

// ---------------------------------------------------------------------------
// 6b. Concurrency curve driver (CONCURRENCY_PROFILE / TEST_DURATION_S)
//     A "gate" limits how many worker threads may hold an open LDAP
//     connection at the same time. A scheduler thread reads the target
//     concurrency from the profile every 500 ms and updates the gate, so the
//     number of simultaneous connections follows the curve (ramp-up,
//     plateau, ramp-down, second hump ...). Workers replay connections in
//     round-robin until the duration is reached (TEST_DURATION_S or the end
//     of the profile), so the workload repeats in a loop when needed.
// ---------------------------------------------------------------------------

// Gate: admits at most `target` concurrent connections; `target` is updated
// live by the scheduler so the load follows the profile.
class ConcurrencyGate {
    Object lock = new Object()
    int target = 1
    int active = 0
    boolean stopped = false

    void setTarget(int t) {
        synchronized (lock) {
            target = Math.max(1, t)
            lock.notifyAll()
        }
    }

    // Returns true when admitted (worker may open a connection), false when
    // the driver has stopped (no new connections accepted).
    boolean acquire() {
        synchronized (lock) {
            while (!stopped && active >= target) {
                lock.wait()
            }
            if (stopped) return false
            active++
            return true
        }
    }

    void release() {
        synchronized (lock) {
            active--
            lock.notifyAll()
        }
    }

    void stop() {
        synchronized (lock) {
            stopped = true
            lock.notifyAll()
        }
    }
}

// Concurrency profile: a piecewise-linear curve (time, target concurrency).
// Time is either seconds from the start of the test, or HH:MM of a day
// (scaled by TIME_SCALE seconds per day-minute when TEST_DURATION_S is not
// set; when TEST_DURATION_S is set the whole day is compressed into it).
class ConcurrencyProfile {
    List points = []       // [time, conc] sorted by time
    double duration = 0.0

    static ConcurrencyProfile parse(String path, double timeScale, double durationSec) {
        ConcurrencyProfile p = new ConcurrencyProfile()
        File f = new File(path)
        if (!f.exists()) throw new RuntimeException("Concurrency profile not found: " + path)
        List raw = []
        boolean dayClock = false
        f.eachLine { line ->
            String l = line.trim()
            if (!l || l.startsWith("#")) return
            String[] a = l.split("[\\s,;]+")
            if (a.length < 2) return
            String timeStr = a[0]
            double t
            if (timeStr.contains(":")) {
                dayClock = true
                String[] hm = timeStr.split(":")
                t = Integer.parseInt(hm[0]) * 60 + Integer.parseInt(hm[1])   // day minutes
            } else {
                t = Double.parseDouble(timeStr)                              // seconds
            }
            double c = Double.parseDouble(a[1])
            raw << [t, c]
        }
        if (raw.isEmpty()) throw new RuntimeException("Concurrency profile is empty: " + path)
        raw.sort { a, b -> a[0] <=> b[0] }
        if (dayClock) {
            // The profile models a day (HH:MM). Compress the whole day into
            // TEST_DURATION_S when it is set; otherwise scale by TIME_SCALE
            // (seconds of test per day-minute, default 1 -> a full day = 24
            // minutes of test).
            double spanMin = raw[-1][0] - raw[0][0]
            double scale = (durationSec > 0 && spanMin > 0) ? durationSec / spanMin : timeScale
            p.points = raw.collect { [ (it[0] - raw[0][0]) * scale, it[1] ] }
            p.duration = p.points[-1][0]
        } else {
            // Seconds from test start; TEST_DURATION_S truncates it.
            p.points = raw
            p.duration = raw[-1][0]
            if (durationSec > 0 && durationSec < p.duration) p.duration = durationSec
        }
        return p
    }

    double maxConcurrency() {
        double m = 1
        points.each { if (it[1] > m) m = it[1] }
        return m
    }

    // Target concurrency at elapsed time t (linear interpolation).
    double at(double t) {
        if (points.isEmpty()) return 1
        if (t <= points[0][0]) return points[0][1]
        for (int i = 1; i < points.size(); i++) {
            if (t <= points[i][0]) {
                def a = points[i - 1]
                def b = points[i]
                double span = b[0] - a[0]
                if (span <= 0) return b[1]
                double frac = (t - a[0]) / span
                return a[1] + frac * (b[1] - a[1])
            }
        }
        return points[-1][1]
    }
}

// Build the profile once (after the replay file has been read). A profile
// alone, a duration alone, or both can be used.
ConcurrencyProfile curveProfile = null
if (profilePath) {
    try {
        curveProfile = ConcurrencyProfile.parse(profilePath, timeScale, durationSec)
        curveMode = true
    } catch (Throwable t) {
        infraFailures << "Concurrency profile error: " + t.getMessage()
        sampleResult.setSuccessful(false)
        sampleResult.setResponseMessage("Concurrency profile error: " + t.getMessage())
        return
    }
} else if (durationSec > 0) {
    // Constant concurrency for a fixed duration (the profile is a flat line).
    curveProfile = new ConcurrencyProfile()
    curveProfile.points = [[0.0, (double) concurrency]]
    curveProfile.duration = durationSec
    curveMode = true
}

// Curve driver: worker pool sized to the profile max, gated by a target that
// the scheduler updates every 500 ms from the profile. Workers replay
// connections in round-robin until the scheduler stops them.
// `curveCsv` records the (elapsed, target) pairs so the HTML report can
// overlay the intended concurrency curve on the measured one.
List<String> curveCsv = []
def runCurveDriver = { ConcurrencyProfile profile ->
    pacingMode = "none"   // the curve controls the rhythm, not the file gaps
    ConcurrencyGate gate = new ConcurrencyGate()
    gate.setTarget((int) Math.round(profile.at(0)))
    int maxConc = Math.max(1, (int) Math.round(profile.maxConcurrency()))
    java.util.concurrent.ExecutorService pool =
        java.util.concurrent.Executors.newFixedThreadPool(maxConc)
    java.util.concurrent.atomic.AtomicLong idx = new java.util.concurrent.atomic.AtomicLong(0)
    long t0 = System.currentTimeMillis()

    Thread sched = Thread.start {
        try {
            while (true) {
                double el = (System.currentTimeMillis() - t0) / 1000.0
                if (el >= profile.duration) break
                if (stopOnInfraErr && infraErr > 0) {
                    curveCsv << String.format("%.1f,STOP", el)
                    break
                }
                double target = profile.at(el)
                curveCsv << String.format("%.1f,%.1f", el, target)
                gate.setTarget((int) Math.round(target))
                Thread.sleep(500)
            }
        } catch (InterruptedException e) {
            // interrupted
        }
        gate.stop()
    }

    List<java.util.concurrent.Future> futures = []
    try {
        for (int w = 0; w < maxConc; w++) {
            futures << pool.submit({ ->
                while (true) {
                    if (!gate.acquire()) break
                    try {
                        long i = idx.getAndIncrement()
                        int pass = (int) (i / connOrder.size()) + 1
                        String cid = connOrder[(int) (i % connOrder.size())]
                        replayConn(cid, pass)
                    } finally {
                        gate.release()
                    }
                }
            })
        }
        sched.join()
        pool.shutdown()
        pool.awaitTermination(120, java.util.concurrent.TimeUnit.SECONDS)
    } finally {
        pool.shutdownNow()
    }
    futures.each { f ->
        try { f.get() } catch (java.util.concurrent.ExecutionException e) {
            synchronized (lock) {
                infraErr++
                infraFailures << ("worker exception: " + e.getCause())
            }
        }
    }
}

if (curveMode && curveProfile != null) {
    runCurveDriver(curveProfile)
} else if (concurrency <= 1) {
    // Sequential (historical behaviour): one connection at a time, global pacing.
    (1..loops).each { pass ->
        prevTs = null
        connOrder.each { cid -> replayConn(cid, pass) }
    }
} else {
    // Parallel: fixed pool of `concurrency` threads, one task per connection.
    java.util.concurrent.ExecutorService pool =
        java.util.concurrent.Executors.newFixedThreadPool(concurrency)
    List<java.util.concurrent.Future> futures = []
    try {
        (1..loops).each { pass ->
            connOrder.each { cid ->
                futures << pool.submit({ -> replayConn(cid, pass) })
            }
        }
        futures.each { f ->
            try { f.get() } catch (java.util.concurrent.ExecutionException e) {
                synchronized (lock) {
                    infraErr++
                    infraFailures << ("worker exception: " + e.getCause())
                }
            }
        }
    } finally {
        pool.shutdown()
    }
}

// Attach the collected sub-samples to the parent sample (now single-threaded).
subs.each { sampleResult.addSubResult(it) }

// ---------------------------------------------------------------------------
// 7. Metrics report in the parent sample (and optional file)
// ---------------------------------------------------------------------------
long runEndMs = System.currentTimeMillis()
long runDurMs = runEndMs - runStartMs
double throughput = runDurMs > 0 ? (total * 1000.0 / runDurMs) : 0.0

sampleResult.setSampleLabel("Replay " + replayPath + " (" + total + " ops)")
sampleResult.setSuccessful(infraErr == 0)
sampleResult.setResponseMessage(infraErr + " infrastructure errors / " + total + " operations")

StringBuilder summary = new StringBuilder()
summary.append("Replay of file: ").append(replayPath).append("\n")
if (loops > 1) summary.append("Loops: ").append(loops).append("\n")
if (curveMode) {
    summary.append("Concurrency curve: ")
    if (profilePath) summary.append(profilePath).append(" ")
    summary.append("(target ").append(String.format("%.0f", curveProfile.maxConcurrency()))
          .append(" max), duration ")
    if (durationSec > 0) {
        summary.append(String.format("%.0f s", durationSec))
    } else {
        summary.append(String.format("%.0f s", curveProfile.duration))
    }
    summary.append("\n")
}
if (replayStart || replayEnd) {
    summary.append("Time range: ")
    if (replayStart) summary.append("from ").append(replayStart)
    if (replayStart && replayEnd) summary.append(" to ")
    if (replayEnd) summary.append(replayEnd)
    summary.append("\n")
}
summary.append("Run duration: ").append(runDurMs).append(" ms, throughput: ")
      .append(String.format("%.1f", throughput)).append(" ops/s\n")
summary.append("Total: ").append(total).append(" operations, ")
      .append(infraErr).append(" infra error(s), peak concurrent connections: ")
      .append(peakConcurrent)
if (ignored > 0) {
    summary.append(", ").append(ignored).append(" line(s) ignored (filter with OR operator '|')")
}
summary.append("\n")

// Metrics by operation type
if (metrics.isEmpty()) {
    summary.append("\n(no metric collected)\n")
} else {
    // Primary table: the load-test view. Response times (AVG/p50/p95/p99/MAX)
    // and throughput (RATE/s) are what the test measures; INFRA_ERR is the
    // only real error (LDAP did not reply). Fidelity vs the log is a
    // secondary, informational check (see the FIDELITY CHECK block below).
    summary.append("\nMETRICS BY TYPE (response times, load test view):\n")
    summary.append(String.format("%-6s %8s %9s %8s %8s %8s %8s %8s %11s%n",
        "TYPE", "TOTAL", "RATE/s", "AVGms", "p50", "p95", "p99", "MAXms", "INFRA_ERR"))
    summary.append(String.format("%-6s %8s %9s %8s %8s %8s %8s %8s %11s%n",
        "-----", "-----", "------", "-----", "----", "----", "----", "-----", "---------"))
    metrics.each { type, met ->
        double avg = met.total > 0 ? (met.latSum / met.total) : 0.0
        List<Long> sorted = met.latList.sort()
        long p50 = percentile(sorted, 50.0)
        long p95 = percentile(sorted, 95.0)
        long p99 = percentile(sorted, 99.0)
        summary.append(String.format("%-6s %8d %9.1f %8.1f %8d %8d %8d %8d %11d%n",
            type, met.total,
            met.total > 0 ? (met.total * 1000.0 / runDurMs) : 0.0,
            avg, p50, p95, p99, met.latMax,
            met.infraErr))
    }

    // Secondary, informational block: how faithful the replay was vs the log.
    // Not a load-test criterion: a wrong password or a missing entry counts
    // as "LDAP replied" (see the METRICS BY TYPE semantics).
    summary.append("\nFIDELITY CHECK (informational):\n")
    summary.append(String.format("%-6s %8s %9s %9s %11s %10s %11s %10s%n",
        "TYPE", "TOTAL", "REPLAYED", "MATCHED", "MISMATCHED", "ERR_MIS", "CNT_MIS", "DNS_MIS"))
    summary.append(String.format("%-6s %8s %9s %9s %11s %10s %11s %10s%n",
        "-----", "-----", "---------", "-------", "----------", "-------", "-------", "-------"))
    metrics.each { type, met ->
        summary.append(String.format("%-6s %8d %9d %9d %11d %10d %11d %10d%n",
            type, met.total, met.replayed, met.matched, met.mismatched,
            met.errMismatch, met.countMismatch, met.dnsMismatch))
    }

    // Per-minute buckets: behaviour of the load over time.
    summary.append("\nBEHAVIOUR OVER TIME (per minute of the original log):\n")
    metrics.each { type, met ->
        if (met.buckets.isEmpty()) return
        summary.append("  ").append(type).append(":\n")
        summary.append(String.format("    %-17s %8s %9s %9s %9s %9s %9s%n",
            "MINUTE", "OPS", "REPLAYED", "MATCHED", "MISMATCHED", "INFRA_ERR", "AVGms"))
        met.buckets.sort().each { minute, bk ->
            double bavg = bk.ops > 0 ? (bk.latSum / bk.ops) : 0.0
            summary.append(String.format("    %-17s %8d %9d %9d %9d %9d %9.1f%n",
                minute, bk.ops, bk.replayed, bk.matched, bk.mismatched, bk.infraErr, bavg))
        }
    }
}

summary.append("\n")
if (infraFailures) {
    summary.append("INFRASTRUCTURE ERRORS:\n")
    infraFailures.each { f -> summary.append("  - ").append(f).append("\n") }
} else {
    summary.append("No infrastructure errors: LDAP replied on every operation.\n")
}
if (fidelityFailures) {
    summary.append("\nFIDELITY MISMATCHES (LDAP replied, but the reply differs from the log):\n")
    fidelityFailures.each { f -> summary.append("  - ").append(f).append("\n") }
} else {
    summary.append("All replays matched the original log.\n")
}
sampleResult.setResponseData(summary.toString(), "UTF-8")

// Optional: write the report to a file for post-run analysis
if (reportFile) {
    try {
        File rf = new File(reportFile)
        File rp = rf.getParentFile()
        if (rp != null && !rp.exists()) rp.mkdirs()
        rf.write(summary.toString(), "UTF-8")
    } catch (Throwable t) {
        infraFailures << "Report file write failed: " + t
        sampleResult.setResponseData(summary.toString() + "REPORT FILE WRITE FAILED: " + t + "\n", "UTF-8")
    }
}

// Optional: write the target concurrency curve (elapsed_seconds, target) so
// the HTML dashboard can overlay the intended load on the measured one. Only
// meaningful in curve mode; written next to the report file.
if (curveMode && reportFile && curveCsv) {
    try {
        File rf = new File(reportFile)
        File rp = rf.getParentFile()
        File cf = new File(rp, "concurrency_curve.csv")
        StringBuilder csv = new StringBuilder("elapsed_s,target_conn\n")
        curveCsv.each { l -> csv.append(l).append("\n") }
        cf.write(csv.toString(), "UTF-8")
    } catch (Throwable t) {
        // non-fatal: the curve stays available in the textual report
    }
}