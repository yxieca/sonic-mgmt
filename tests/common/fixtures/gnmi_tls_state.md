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
DEVICE_METADATA/localhost/cloudtype and the standard DUT/PTF certificate leaves.
Full decoded configuration and raw owned hashes are compared independently;
unrelated drift fails instead of being hidden by a broad rollback. Temporary
syslog configuration remains owned by its existing context manager.

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
