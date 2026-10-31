# Same-image AAA TLS restoration (explicit opt-in)

`gnmi_same_image_tls` and `_gnmi_same_image_tls_flow` implement the same restoration
owner. `test_gnmi_aaa.py` imports the former as `gnmi_tls` for **all seven fresh
cases**; the twelve shared role cases use the latter through `_RoleTlsOwner`.
Fresh and shared lifetimes therefore have identical native restoration work.
The fresh fixture depends explicitly on `loganalyzer`; shared transitions and
module-final cleanup retain their existing function/module analysis windows.
Generic sanity/config/core checks and test assertions are not disabled.

## Boundary

This contract is for the AAA module's owned mutations only: GNMI server/cert
hashes, the GNMI_CLIENT_CERT table (default-cert-auth deletes every mapping),
DEVICE_METADATA/localhost/cloudtype (running and persistent configuration) and
the standard DUT/PTF certificate leaves.
Full decoded configuration and raw owned hashes are compared independently;
unrelated drift fails instead of being hidden by a broad rollback. Temporary
syslog configuration uses the explicit exact-destination ownership integration
described below; no other syslog row is owned.

The public/general `gnmi_tls`, deprecated wrappers, reboot, rotation, 2038,
benchmark, ZMQ and upgrade consumers retain the historical lifecycle. In
particular both `test_upgrade_gnoi.py` and `test_upgrade_smart_switch_gnoi.py`
are unchanged. **Their old-checkpoint/migration behavior is not fixed or
qualified by this change.** There is no runtime-error fallback between contracts.
Do not opt another consumer in without auditing its mutations and image lifetime.

Image identity is read uncached before mutation and before/after restoration:
current sonic-installer image, version-file digest, root mount, boot ID and live
gNMI container image ID. An image/reboot/rootfs change fails the new contract
before stopping or restoring the DUT. Protected recovery is retained. A PTF
certificate restore and generated-controller-directory cleanup are independent.
This does not defend against an adversary reverting all identity evidence, nor
support reboot/upgrade within the new lifecycle.

## Original service verifier

Automatic admission is only for an **observed** running plaintext endpoint with
`--noTLS`, valid port and a listener correlated to the native service PID via
`ss -ltnp`. An explicit bind must match; omitted bind is derived from that PID's
actual listener, never from an unrelated same-port process. Wildcards are mapped
to loopback only for probing. Secure launcher branches normally omit bind; the
reference launcher (sonic-buildimage 3a0f640a) does so, and reference sonic-gnmi
86c3c5b6 server.go uses `net.Listen("tcp", fmt.Sprintf(":%d", config.Port))`.
Observed listeners, not assumed defaults, are authoritative. Multiple native
processes, missing PID evidence, unsupported addresses or conflicting test
listeners fail admission. Endpoint comparison excludes changing PID numbers but
retains target, listener addresses and transport after restart.

Every automatic attempt uses existing DUT Python **grpc only**, a fresh channel,
a three-second fixed Capabilities RPC and 64KiB receive limit. A separate output
FD is retained **only** by action `capabilities`: it emits the bounded raw response
as a versioned base64 frame. Capabilities is explicitly public service metadata;
this is not a general payload-return API. All normal stdout/stderr/import errors
remain private; secure endpoints never enter the plaintext probe. Controller
`pygnmi.spec.v080.gnmi_pb2.CapabilityResponse` decodes the wire and compares
nonempty version/models/encodings independently of private configuration. No
DUT pygnmi import or installation occurs. Missing controller decoder fails
admission. RPC error details are never written to the public FD. Server-supplied
Capabilities contents are public by contract, not arbitrary secret detection.

For TLS/mTLS, authenticated plaintext, routing metadata, or another execution
location, override the **module-scoped** fixture `gnmi_original_service_verifier`
in the AAA module (replace its import) with an existing authorized probe factory.
The concrete API is a zero-argument callable returning exactly `True` on success;
exceptions/other values fail admission/readiness. It is called before mutation
and afresh after endpoint restoration (up to 60 seconds, two-second intervals).
The probe must itself impose a <=3s RPC timeout and close each channel. It must
validate a nonmutating semantic response, use the original endpoint/namespace,
existing authorized client identity, original server trust anchor/name and auth
or routing metadata. Never use newly generated test certs, `skip_verify`, or
insecure transport for a secure original service. The server's client-verifying
CA is not automatically a suitable server trust anchor.

Example wiring a caller-owned verifier (the probe body is deliberately not
invented; it must use the lab’s existing authorized client API):

```python
@pytest.fixture(scope="module")
def gnmi_original_service_verifier():
    # lab_original_probe is a caller-owned zero-argument function. Its closure
    # holds existing authorized credentials/trust/metadata, never shell argv.
    # Its implementation must enforce fresh channels + <=3s semantic RPC and
    # return True only for the expected original response. It must be reviewed
    # for its own library logging/exception confidentiality before enabling it.
    return lab_original_probe
```

This is an injection contract, not an inventory credential discovery API. No
probe is fabricated when original credentials are unavailable. The owner checks
the original listener/bind/transport independently even with a supplied probe.
Caller-probe timeout/confidentiality are contractual: arbitrary Python callables
cannot be forcibly killed safely by this fixture. Qualify the supplied probe.

## Private state and safe ordering

On each remote owner, an exclusive `/var/tmp/gnmi-restore-<random>` directory is
root-owned 0700, with umask077 and 0600 payload/log files. No original file bytes,
configuration, runtime argv or raw hashes leave that host. Fixed secret-free
Python source and path/status go through Ansible, plus only the bounded public
Capabilities frame described above. Both child descriptors
are redirected before reading state, and outer shell stdout/stderr are suppressed
for bootstrap failures. Root access is required and verified. **No fetch,
cross-owner staging, controller payload, or rootfs-survival transfer exists.**

No CLI checkpoint/rollback/replace is used in this new path. Source inspection
found GCU logs patch values to syslog even with stdout redirected. Owned hashes
are read/written using redis-py with `decode_responses=False` and supported
`SonicDBConfig.getDbSock/getDbId('CONFIG_DB')` discovery (SWSS reference
5aac3c184e9932b57923eaa2cbf071ac3c399e5b). No SonicV2Connector.get_all is used:
its literal-"None" normalization is not raw. Byte keys/fields/values are base64
encoded only inside private JSON, including extra CNs, literal None/NULL/empty
values. Missing hashes remain missing (Redis cannot store an empty hash).
Cloudtype presence and raw bytes are saved separately, never recovered from the
decoded configuration. Both raw postchecks and independent cfggen equality are
required. redis-py does not add SWSS/GCU write-value syslog logging; cfggen capture via
`get_config_json` stays inside the protected process. Full-config comparison
still detects unowned leaks. Historical general flow remains unchanged.

All original leaves are backed up and metadata-preflighted before any unlink.
Supported: absent paths, ordinary single-link files, symlink text, directory
membership, mode/uid/gid/mtime. Access time is not an invariant. ACL/xattrs,
nontrivial filesystem flags, hardlinked regular files, special files, symlink
ancestors and unsupported ioctl filesystems are rejected before detach. Linux
extent/index flags are permitted as filesystem implementation properties.
This assumes trusted root and no concurrent writer within the owned namespace;
it is not an adversarial race-resistant filesystem transaction.

Teardown closes the test client, checks image, stops/verifies the watcher,
restores owned raw config, verifies full decoded config, stops again, restores
DUT/PTF files, starts the original service, checks original listener plus semantic
readiness, and runs unchanged critical-process health checking. Failed operations
remain visible. Safe independent PTF/controller cleanup continues. No restart is
called successful restoration without readiness. Backups are discarded only
after success; failure reports both nonsecret DUT and PTF recovery IDs when retained. The testbed owner
must inspect protected state privately and decide recovery/removal; it must not
print `private.log`/JSON payloads into ordinary test logs. Admission failure also
retains private diagnostics (explicit manual recovery/removal, no automatic TTL).

## Persistent startup configuration

The immutable native-entry `/etc/sonic/config_db.json` snapshot is independent of
running CONFIG_DB and is captured before test mutation, privately on the DUT.
It is NOT added to the certificate helper's full-file ownership list. Both case
and outer restoration compare the current decoded startup configuration with
that startup baseline after removing only `GNMI/gnmi`, `GNMI/certs`, all
`GNMI_CLIENT_CERT` mappings, and `DEVICE_METADATA/localhost/cloudtype`, plus
only the explicitly registered forwarding destination in its declared states
when that opt-in context is used (see below). Extra GNMI/syslog rows, metadata
fields and all other tables must remain equal. Duplicate JSON
keys, invalid JSON, metadata drift and symlink changes fail closed **before any
owned DB restoration**. No config-save, broad rollback or running-to-startup
baseline substitution is used. A full save that propagates unrelated differences
between preexisting running/startup configurations is deliberately rejected:
those differences are not owned by this fixture.

Formatting/timestamp-only changes without an owned semantic delta are rejected
as unexplained drift. Only after that semantic-drift gate may original startup bytes be restored,
including original whitespace/key order, supported metadata and absence. The
existing metadata preflight rejects unsupported xattrs/ACLs/flags/hardlinks.
A single symlink to a regular file (or absent target) is supported: its text and
metadata remain unchanged; the target is snapshotted/restored. Chained symlinks,
symlink ancestors and other unsupported types fail admission. Regular contents
are staged with mode0600 on the target filesystem, assigned original metadata,
fsynced, rechecked for concurrent drift, then atomically replaced and the parent
directory fsynced. Original private recovery is retained on every failure. This
is not an adversarial transaction against concurrent root writers.

Shared case cleanup now stops the native service before raw role/cloudtype
restoration, stops it again after DB notifications, restores startup bytes, and
starts it with the unchanged shared TLS configuration/certificates. A bounded
60s PID-owned50052 listener check and existing critical-process check precede
case verification; subsequent test RPCs retain their authentication assertions.
This adds a per-case service stop/start, but does not regenerate certificates.
Performance must be remeasured; old timing is not evidence for this revision.
Outer cleanup restores startup after the second stop and before original-service
startup. After readiness/health, both lifetimes observe exact persistent state
for two seconds at100ms polling cadence, failing immediately on a late write,
never repairing it repeatedly. Next shared admission checks again. This is a
bounded observation window, not a proof that no later asynchronous writer can
exist; live qualification must check native-entry independently before generic
cleanup. The exact lower-level writer in the v3 failure remains uninstrumented.

## Required qualification

Offline production-action regressions execute the unchanged helper with synthetic
OS/Redis/grpc dependencies, distinct normalized/decoded and raw representations,
image refusal, PID correlation and public-output negatives. They are stronger
than owner call-order mocks but do not prove actual SSH/become/callback privacy,
filesystem ioctl behavior, swsscommon semantics, server restart or readiness.
The parent owns named full review, the staged synthetic root helper/real wrapper
transport gate, then native VS correctness/failure testing and matched A*/B.
A* must differ only in reuse lifetime; common same-image owner and per-case
checks must match. No performance claim until valid native-restored pairs pass.

## Forwarding destination ownership (AAA-only opt-in)

The forwarding cases pass `NativeTlsState.remote_syslog(destination, vrf)` to
`capture_remote_syslog(configuration=...)`. Other syslog consumers retain their
existing CLI add/delete path; public/upgrade TLS fixtures are unchanged. The
60-second capture, UDP/514 action/readiness checks, and exact remote/local audit
record comparison are unchanged. Shared-role case save/restore/reuse ordering
is unchanged; no forwarding actions run in a shared role case.

At native admission, raw `SYSLOG_SERVER` hashes are saved privately alongside
original running/persistent state. Before the first forwarding mutation, the
owner validates the same image, exact persistent baseline and unchanged raw
syslog table, then exclusively registers **one exact destination**. Registration
cannot replace an earlier declaration or adopt a post-failure baseline. It
records the raw original destination (including absence, `NULL`, literal `None`,
empty strings and extra fields) independently of the startup destination.
Neither original row nor any configuration payload is returned to the controller.

The opt-in path does not use CLI add/delete: add rejects an existing destination,
and delete would lose its original VRF/port/extra fields. Instead it atomically
replaces only the registered raw Redis hash with explicit UDP port `514` and,
when requested, VRF `mgmt`, using a watched redis-py transaction. It then invokes
the CLI's `rsyslog-config` reload sequence, with output kept in the existing
private log. This bypass is limited to the validated AAA destination/VRF; it is
not a general replacement for syslog CLI validation. Original values never pass
through CLI argv, SWSS set-entry logging, or a decoding/normalizing write API.

The configuration context encloses capture cleanup. Its `finally` restores the
original raw row even if apply/reload partially succeeds, capture fails, the
body fails, or a pytest `BaseException` escapes. It runs before the enclosing
native TLS finalizer and the function LogAnalyzer. A cleanup error remains an
error; the outer owner must not relabel later recovery as native success.
Changed-image actions refuse before Redis/service writes, while independent
PTF/controller cleanup remains the native owner's responsibility.

Persistent restoration still occurs only in the enclosing native owner, after
stopping its gNMI writer. Its guard recognizes only the registered destination's
explicit declared states: original startup row/absence, independently captured
original decoded host/default-namespace running row/absence, or the exact
temporary UDP/514 row. The host decoder is selected explicitly rather than
assuming GCU's multi-ASIC namespace wrapper is a single CONFIG_DB. The
running-original alternative covers a save after context cleanup; it is not
proof of which service actually wrote the file. Additional destination fields,
changed ports, unknown rows, unrelated tables and metadata drift still fail.
Before outer configuration/persistent writes, raw syslog must again equal the
immutable native original, including every other destination. The existing
persistent atomic restore preserves original file existence, bytes/format and
supported metadata (including mtime and supported symlinks); its concurrency
recheck and post-start quiet-window verification remain enabled.

Concurrency limits remain explicit: Redis WATCH protects the destination hash
against a transaction-time conflicting writer. Whole-table raw pre/post checks
reject unrelated drift; they are not a global lock over arbitrary external
writers. File restoration similarly retains its pre-replace snapshot check and
late-write detection, not a universal filesystem writer lock. Unsupported or
concurrent drift fails and retains protected recovery evidence; no blind retry
or baseline rebase occurs.

Offline production-action and real-pytest scheduling regressions cover Get then
Set, independent startup/running rows, sentinel/empty/absent states, unknown rows
and fields, transaction/apply/body/capture/cleanup/image failures, exact native
bytes/metadata, and finalizer-before-analyzer ordering. They use synthetic
Redis/OS/service adapters, **not** a real Redis transaction, rsyslog reload,
protected transport qualification or live endpoint/RPC restoration proof.
Those remain testbed-owner gates on the exact frozen candidate. V4's real
forwarding-Set native failure is retained, not reclassified as observer noise.
