"""Opt-in SAME-IMAGE gNMI restoration; not an upgrade migration contract.

Original material stays on its owning host in a root-owned 0700 directory.
Only fixed program text, paths, status and explicitly public Capabilities cross Ansible. See gnmi_tls_state.md
for baseline verifier, metadata, transport qualification and recovery limits.
"""
import base64
from contextlib import contextmanager
import inspect
import shlex
import shutil
import tempfile
import uuid

from tests.common.grpc_config import grpc_config
from tests.common.platform.processes_utils import wait_critical_processes
from tests.common.utilities import wait_until


def _remote(root, action, paths, syslog_spec=None):
    """Secret-free program, executed as root; never return snapshot contents."""
    import array
    import base64
    import fcntl
    import hashlib
    import ipaddress
    import json
    import os
    import re
    import shutil
    import stat
    import subprocess
    import sys
    import tempfile
    from copy import deepcopy

    # Only the public Capabilities action retains a separate output descriptor.
    # All imports, diagnostics and private operations still use private.log.
    public_fd = os.dup(1) if action == 'capabilities' else None
    os.umask(0o077)
    # /var/tmp is a trusted root-owned sticky directory; reject symlink or
    # writable non-sticky ancestors before constructing the private boundary.
    parent = os.path.dirname(root)
    while True:
        ancestor = os.lstat(parent)
        if (not stat.S_ISDIR(ancestor.st_mode) or ancestor.st_uid != 0
                or (ancestor.st_mode & 0o022 and not ancestor.st_mode & stat.S_ISVTX)):
            raise RuntimeError('unsafe recovery ancestor')
        if parent == '/':
            break
        parent = os.path.dirname(parent)
    if os.geteuid() != 0:
        raise RuntimeError('root required')
    if action == 'init':
        os.mkdir(root, 0o700)  # Exclusive; never reuse an existing backup.
    st = os.lstat(root)
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or stat.S_IMODE(st.st_mode) != 0o700:
        raise RuntimeError('invalid recovery directory')
    # Redirect before importing device libraries or reading any original data.
    fd = os.open(root + '/private.log', os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
    os.dup2(fd, 1)
    os.dup2(fd, 2)
    os.close(fd)

    def save(name, value):
        fd = os.open(root + '/' + name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w') as stream:
            json.dump(value, stream)

    def load(name):
        with open(root + '/' + name) as stream:
            return json.load(stream)

    def command(argv):
        return subprocess.check_output(argv, stderr=subprocess.STDOUT, timeout=120).decode()

    def parents(path):
        parent = os.path.dirname(path)
        while parent != '/':
            if os.path.lexists(parent) and not stat.S_ISDIR(os.lstat(parent).st_mode):
                raise RuntimeError('non-directory ancestor')
            parent = os.path.dirname(parent)

    def snapshot(path):
        parents(path)
        if not os.path.lexists(path):
            return None
        st = os.lstat(path)
        # ACLs are xattrs on Linux. Reject unsupported properties BEFORE detach.
        if os.listxattr(path, follow_symlinks=False) or getattr(st, 'st_flags', 0):
            raise RuntimeError('unsupported file metadata')
        item = dict(mode=stat.S_IMODE(st.st_mode), uid=st.st_uid, gid=st.st_gid,
                    mtime=st.st_mtime_ns)
        if stat.S_ISLNK(st.st_mode):
            item.update(kind='link', target=os.readlink(path))
        elif stat.S_ISREG(st.st_mode) or stat.S_ISDIR(st.st_mode):
            if stat.S_ISREG(st.st_mode) and st.st_nlink != 1:
                raise RuntimeError('hardlinked file')
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                flags = array.array('L', [0])
                # FS_IOC_GETFLAGS; tolerate only extents/index (not user metadata).
                fcntl.ioctl(fd, 0x80086601, flags, True)
                if flags[0] & ~(0x80000 | 0x1000):
                    raise RuntimeError('unsupported filesystem flags')
                if stat.S_ISDIR(st.st_mode):
                    item.update(kind='dir', children=sorted(os.listdir(path)))
                else:
                    with os.fdopen(os.dup(fd), 'rb') as stream:
                        item.update(kind='file', data=base64.b64encode(stream.read()).decode())
            finally:
                os.close(fd)
        else:
            raise RuntimeError('unsupported file type')
        return item

    persistent_path = '/etc/sonic/config_db.json'

    def persistent_snapshot():
        leaf = snapshot(persistent_path)
        target = None
        if leaf and leaf['kind'] == 'link':
            target = os.path.normpath(os.path.join(os.path.dirname(persistent_path), leaf['target']))
            if target == persistent_path:
                raise RuntimeError('persistent symlink cycle')
            content = snapshot(target)
        else:
            content = leaf
        if content and content['kind'] != 'file':
            raise RuntimeError('unsupported persistent configuration type')
        return dict(leaf=leaf, target=target, content=content)

    def persistent_json(saved):
        # Reject ambiguous JSON rather than letting duplicate keys conceal drift.
        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise RuntimeError('duplicate persistent configuration key')
                result[key] = value
            return result
        content = saved['content']
        value = (json.loads(base64.b64decode(content['data']), object_pairs_hook=unique)
                 if content else {})
        if not isinstance(value, dict):
            raise RuntimeError('invalid persistent configuration')
        return value

    def unowned(value):
        value = deepcopy(value)
        # Own two GNMI rows, NOT arbitrary rows in that table. All principal
        # rows are owned because default-cert-auth removes all mappings.
        for table, rows in (('GNMI', ('gnmi', 'certs')), ('DEVICE_METADATA', ('localhost',))):
            if table not in value:
                continue
            if not isinstance(value[table], dict):
                raise RuntimeError('invalid persistent table')
            for row in rows:
                if table == 'GNMI':
                    value[table].pop(row, None)
                elif row in value[table]:
                    if not isinstance(value[table][row], dict):
                        raise RuntimeError('invalid persistent metadata')
                    value[table][row].pop('cloudtype', None)
                    if not value[table][row]:
                        del value[table][row]
            if not value[table]:
                # Empty scaffolding is equivalent only for an owned-only
                # table/row; unrelated rows/fields above are never removed.
                del value[table]
        value.pop('GNMI_CLIENT_CERT', None)
        # Only an explicitly registered destination, and only its declared
        # states, may differ. Never mask the SYSLOG_SERVER table or extra fields.
        if os.path.exists(root + '/syslog.json'):
            owned = load('syslog.json')
            table = value.get('SYSLOG_SERVER', {})
            if not isinstance(table, dict):
                raise RuntimeError('invalid persistent syslog table')
            row = [owned['destination'] in table, table.get(owned['destination'])]
            if row not in owned['persistent_states']:
                raise RuntimeError('unowned persistent syslog destination drift')
            table.pop(owned['destination'], None)
            if not table:
                value.pop('SYSLOG_SERVER', None)
        return value

    def persistent_check(exact=False):
        saved = load('persistent.json')
        current = persistent_snapshot()
        # The startup and running baselines are independent: a Set may save the
        # entire running DB. Only OUR fields may differ from STARTUP, however.
        if unowned(persistent_json(current)) != unowned(persistent_json(saved)):
            raise RuntimeError('unrelated persistent configuration drift')
        if saved['target'] != current['target'] or (saved['target'] and saved['leaf'] != current['leaf']):
            raise RuntimeError('persistent symlink drift')
        old, now = saved['content'], current['content']
        if old and not now:
            raise RuntimeError('persistent configuration disappeared')
        if old and any(old[k] != now[k] for k in ('kind', 'uid', 'gid', 'mode')):
            raise RuntimeError('persistent metadata drift')
        if exact and current != saved:
            raise RuntimeError('persistent configuration not restored or late write')
        return saved, current

    def shared_ready():
        processes, sockets = runtime()
        return (len(processes) == 1 and
                any(processes[0][0] in pids and address.rsplit(':', 1)[-1] == '50052'
                    for address, pids in sockets))

    def persistent_watch():
        # Observe, NEVER repair, late writes over a bounded quiet window. The
        # event wait is polling cadence, not a sleep offered as writer proof.
        import threading
        import time
        deadline = time.monotonic() + 2
        wake = threading.Event()
        while True:
            persistent_check(exact=True)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            wake.wait(min(0.1, remaining))

    def persistent_restore():
        same_image()  # In the actual action, before ANY persistent write.
        if os.path.exists(root + '/syslog.json') and syslog_raw(db()) != load('syslog-original.json'):
            raise RuntimeError('syslog context did not restore original raw state')
        saved, current = persistent_check()
        if saved == current:
            return
        # A metadata/format-only edit is not evidence of an owned Set. Do not
        # hide it by rewriting the original just because semantics compare equal.
        if persistent_json(saved) == persistent_json(current):
            raise RuntimeError('unexplained persistent bytes or timestamp drift')
        path = saved['target'] or persistent_path
        original = saved['content']
        if original is None:
            # Absence is owned only after checking every newly persisted field.
            if persistent_snapshot() != current:
                raise RuntimeError('concurrent persistent configuration write')
            os.unlink(path)
        else:
            # Never truncate the live file. Stage privately on the same fs,
            # restore supported metadata, recheck, and atomically replace it.
            fd, staged = tempfile.mkstemp(prefix='.gnmi-restore-', dir=os.path.dirname(path))
            try:
                with os.fdopen(fd, 'wb') as stream:
                    stream.write(base64.b64decode(original['data']))
                    stream.flush()
                    os.fchown(stream.fileno(), original['uid'], original['gid'])
                    os.fchmod(stream.fileno(), original['mode'])
                    os.utime(stream.fileno(), ns=(original['mtime'], original['mtime']))
                    os.fsync(stream.fileno())
                if persistent_snapshot() != current:
                    raise RuntimeError('concurrent persistent configuration write')
                os.replace(staged, path)
            finally:
                if os.path.lexists(staged):
                    os.unlink(staged)
        directory = os.open(os.path.dirname(path), os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        persistent_check(exact=True)

    def image():
        # Never use cached duthost facts. Detect OS, boot/rootfs and service image
        # replacement, even when the version label was reused.
        current = [line for line in command(['sonic-installer', 'list']).splitlines()
                   if line.startswith('Current:')]
        if len(current) != 1:
            raise RuntimeError('cannot identify current image')
        values = [current, command(['docker', 'inspect', '--format', '{{.Image}}', 'gnmi'])]
        for path in ('/etc/sonic/sonic_version.yml', '/proc/sys/kernel/random/boot_id'):
            with open(path, 'rb') as stream:
                values.append(hashlib.sha256(stream.read()).hexdigest())
        with open('/proc/mounts') as stream:
            values.append([line.strip() for line in stream if line.split()[1] == '/'])
        return values

    def runtime():
        processes = []
        for pid in os.listdir('/proc'):
            if not pid.isdigit():
                continue
            try:
                with open('/proc/' + pid + '/cmdline', 'rb') as stream:
                    argv = stream.read().decode().strip('\0').split('\0')
                if argv[0] in ('/usr/sbin/telemetry', '/usr/sbin/gnmi'):
                    processes.append((pid, argv))
            except (FileNotFoundError, ProcessLookupError, PermissionError):
                continue
        sockets = [(line.split()[3], re.findall(r'pid=(\d+)', line))
                   for line in command(['ss', '-H', '-ltnp']).splitlines()]
        return processes, sockets

    def endpoint():
        processes, sockets = runtime()
        if len(processes) != 1:
            raise RuntimeError('expected one native service')
        pid, argv = processes[0]
        options = {}
        for index, value in enumerate(argv[1:], 1):
            if value.startswith('-'):
                name, sep, data = value.lstrip('-').partition('=')
                options[name] = data if sep else (argv[index + 1] if index + 1 < len(argv)
                                                  and not argv[index + 1].startswith('-') else True)
        port = int(options.get('port', 0))
        if not 0 < port < 65536:
            raise RuntimeError('unsupported endpoint')
        # Correlate the native service PID, never an unrelated same-port socket.
        listeners = sorted(s for s, pids in sockets if pid in pids and s.rsplit(':', 1)[-1] == str(port))
        if not listeners or (port != 50052 and any(s.rsplit(':', 1)[-1] == '50052' for s, _ in sockets)):
            raise RuntimeError('missing original or conflicting test listener')
        addresses = [s.rsplit(':', 1)[0].strip('[]') for s in listeners]
        # Secure launcher branches omit bind_address. The server defaults to
        # wildcard TCP; derive its effective address from PID-owned listeners,
        # rather than assuming a default or trusting an arbitrary same-port PID.
        address = options.get('bind_address')
        if address is not None:
            address = address.strip('[]')
            if address not in addresses and not (address in ('::', '0.0.0.0') and '*' in addresses):
                raise RuntimeError('bind/listener mismatch')
        else:
            address = addresses[0]
        address = {'*': '127.0.0.1', '::': '::1', '0.0.0.0': '127.0.0.1'}.get(address, address)
        ipaddress.ip_address(address)  # Reject ambiguous DNS/device/VRF targets.
        target = '[{}]:{}'.format(address, port) if ':' in address else '{}:{}'.format(address, port)
        return dict(target=target, listeners=listeners, plaintext=options.get('noTLS') in (True, 'true'))

    def capabilities():
        import grpc
        original = load('endpoint.json')
        if not original['plaintext']:
            raise RuntimeError('secure baseline needs caller verifier')
        # Explicit public exception: ONLY bounded bytes returned by this fixed
        # nonmutating RPC may leave the host. No private file/exception output.
        with grpc.insecure_channel(original['target'], options=[('grpc.max_receive_message_length', 65536)]) as channel:
            result = channel.unary_unary('/gnmi.gNMI/Capabilities')(b'', timeout=3)
        if not isinstance(result, bytes) or not 0 < len(result) <= 65536:
            raise RuntimeError('invalid capabilities wire size')
        os.write(public_fd, b'GNMI_CAPABILITIES_V1:' + base64.b64encode(result) + b'\n')
        os.close(public_fd)

    def db():
        # SonicV2Connector.get_all normalizes literal "None". Use redis-py
        # bytes directly, with SONiC's supported socket/database discovery API.
        # No CLI argv or SWSS write/error logging receives private values.
        import redis
        from swsscommon.swsscommon import SonicDBConfig
        return redis.Redis(unix_socket_path=SonicDBConfig.getDbSock('CONFIG_DB'),
                           db=SonicDBConfig.getDbId('CONFIG_DB'), decode_responses=False,
                           socket_timeout=5, socket_connect_timeout=5)

    keys = ('GNMI|gnmi', 'GNMI|certs', 'GNMI_CLIENT_CERT|test.client.gnmi.sonic')
    metadata_key = 'DEVICE_METADATA|localhost'

    def pack(value):
        return base64.b64encode(value).decode('ascii')

    def raw(conn):
        # Default-cert-auth deletes ALL principal mappings, not just our test CN.
        owned = {key.encode() for key in keys} | set(conn.keys('GNMI_CLIENT_CERT|*'))
        hashes = {pack(key): {pack(k): pack(v) for k, v in conn.hgetall(key).items()} for key in owned}
        cloud = conn.hget(metadata_key, 'cloudtype')
        return dict(hashes=hashes, cloudtype=None if cloud is None else pack(cloud))

    def restore_hash(conn, key, fields):
        conn.delete(key)
        for field, value in fields.items():
            conn.hset(key, base64.b64decode(field), base64.b64decode(value))

    def restore_cloud(conn, saved):
        if saved['cloudtype'] is None:
            conn.hdel(metadata_key, 'cloudtype')
        else:
            conn.hset(metadata_key, 'cloudtype', base64.b64decode(saved['cloudtype']))

    def syslog_raw(conn):
        return {pack(key): {pack(k): pack(v) for k, v in conn.hgetall(key).items()}
                for key in conn.keys('SYSLOG_SERVER|*')}

    def syslog_check(conn, owned):
        current = syslog_raw(conn)
        original = load('syslog-original.json')
        key = owned['key']
        row = current.pop(key, {})
        original.pop(key, None)
        if current != original or row not in (owned['raw'], owned['temporary']):
            raise RuntimeError('unowned running syslog drift')
        return row

    def syslog_write(conn, owned, target):
        same_image()
        persistent_check()  # Including unrelated destinations, BEFORE writes.
        current = syslog_check(conn, owned)
        key = base64.b64decode(owned['key'])
        # Atomic exact-row replacement, with a compare-and-swap on that row.
        # Values stay in redis-py/private memory, never CLI argv or SWSS logs.
        with conn.pipeline() as transaction:
            transaction.watch(key)
            if transaction.hgetall(key) != {base64.b64decode(k): base64.b64decode(v)
                                            for k, v in current.items()}:
                raise RuntimeError('concurrent syslog destination write')
            same_image()
            transaction.multi()
            transaction.delete(key)
            if target:
                transaction.hset(key, mapping={base64.b64decode(k): base64.b64decode(v)
                                               for k, v in target.items()})
            transaction.execute()
        if syslog_check(conn, owned) != target:
            raise RuntimeError('syslog destination restoration mismatch')
        same_image()
        # Match the CLI's explicit reload; row notifications alone are not a
        # readiness contract. The capture helper still checks UDP/514 action.
        command(['systemctl', 'reset-failed', 'rsyslog-config', 'rsyslog'])
        command(['systemctl', 'restart', 'rsyslog-config'])

    def config():
        from generic_config_updater.generic_updater import get_config_json
        return get_config_json()

    def same_image():
        if image() != load('image.json'):
            raise RuntimeError('image changed; original restoration forbidden')

    if action == 'init':
        saved = {path: snapshot(path) for path in paths}
        # Owned parent paths may be absent, but never symlinks/non-directories.
        for path in paths:
            if any(saved[p] and saved[p]['kind'] != 'dir' for p in paths if path.startswith(p + '/')):
                raise RuntimeError('unsupported owned parent')
        save('files.json', saved)
    elif action == 'baseline':
        save('image.json', image())
        save('endpoint.json', endpoint())
        save('config.json', config())
        conn = db()
        save('raw.json', raw(conn))
        save('syslog-original.json', syslog_raw(conn))
        saved = persistent_snapshot()
        persistent_json(saved)  # Admission validates JSON before test mutation.
        save('persistent.json', saved)
    elif action == 'syslog-save':
        same_image()
        persistent_check(exact=True)
        # Public destination/VRF only. Exactly one context per fresh AAA owner;
        # exclusive save refuses a second registration or rebasing after failure.
        destination, vrf = syslog_spec
        if str(ipaddress.ip_address(destination)) != destination or vrf not in (None, 'mgmt'):
            raise RuntimeError('unsupported syslog capture destination or VRF')
        conn = db()
        original = syslog_raw(conn)
        if original != load('syslog-original.json'):
            raise RuntimeError('running syslog drift before ownership')
        key = pack(('SYSLOG_SERVER|' + destination).encode())
        temporary = {'port': '514'}
        if vrf is not None:
            temporary['vrf'] = vrf
        startup = persistent_json(load('persistent.json')).get('SYSLOG_SERVER', {})
        # Use the host/default namespace, matching db() and config_db.json.
        # GCU's config() nests namespaces on multi-ASIC devices.
        running = json.loads(command(['sonic-cfggen', '-d', '--print-data'])).get('SYSLOG_SERVER', {})
        if not isinstance(startup, dict) or not isinstance(running, dict):
            raise RuntimeError('invalid syslog table')
        save('syslog.json', dict(destination=destination, key=key, raw=original.get(key, {}),
                                 temporary={pack(k.encode()): pack(v.encode()) for k, v in temporary.items()},
                                 persistent_states=[[destination in startup, startup.get(destination)],
                                                    [destination in running, running.get(destination)],
                                                    [True, temporary]]))
    elif action in ('syslog-apply', 'syslog-restore'):
        same_image()
        owned = load('syslog.json')
        syslog_write(db(), owned, owned['temporary'] if action == 'syslog-apply' else owned['raw'])
    elif action == 'persistent-check':
        same_image()
        persistent_check()
    elif action == 'persistent-restore':
        persistent_restore()
    elif action == 'persistent-verify':
        same_image()
        persistent_watch()
    elif action == 'shared-ready':
        same_image()
        if not shared_ready():
            raise RuntimeError('shared TLS listener not ready')
    elif action == 'capabilities':
        capabilities()
    elif action == 'image':
        same_image()
    elif action == 'endpoint':
        if endpoint() != load('endpoint.json'):
            raise RuntimeError('endpoint not restored')
    elif action in ('stop', 'start'):
        same_image()
        command(['docker', 'exec', 'gnmi', 'supervisorctl', action, 'gnmi-native'])
        if action == 'stop' and runtime()[0]:
            raise RuntimeError('watcher still running')
    elif action == 'detach':
        saved = load('files.json')
        # Confirm original state still matches before unlinking ANY leaf.
        if {path: snapshot(path) for path in paths} != saved:
            raise RuntimeError('file drift before detach')
        for path, old in saved.items():
            if old and old['kind'] != 'dir':
                os.unlink(path)
    elif action == 'case-save':
        same_image()
        persistent_check(exact=True)
        save('case-config.json', config())
        mapping = raw(db())
        if not mapping['hashes'][pack(keys[2].encode())].get(pack(b'role@')):
            raise RuntimeError('missing test principal role')
        save('case-raw.json', mapping)
    elif action == 'case-verify':
        same_image()  # Shared admission, before the next test can mutate.
        persistent_check(exact=True)
        if config() != load('case-config.json') or raw(db()) != load('case-raw.json'):
            raise RuntimeError('unrelated AAA case configuration drift')
    elif action == 'case-restore':
        same_image()  # MUST precede every DB write, including finally cleanup.
        persistent_check()  # Refuse unrelated startup drift BEFORE owned DB writes.
        conn = db()
        saved = load('case-raw.json')
        try:
            restore_hash(conn, keys[2], saved['hashes'][pack(keys[2].encode())])
        finally:
            restore_cloud(conn, saved)
        if raw(conn) != saved or config() != load('case-config.json'):
            raise RuntimeError('case restoration mismatch')
    elif action == 'config':
        same_image()
        persistent_check()  # Refuse unrelated startup drift before owned restoration.
        # A failed forwarding context must not be hidden by outer recovery.
        conn = db()
        if os.path.exists(root + '/syslog.json') and syslog_raw(conn) != load('syslog-original.json'):
            raise RuntimeError('syslog context did not restore original raw state')
        # Only owned raw hashes/cloudtype; no GCU patch-value syslog logging.
        failures = []
        saved = load('raw.json')
        for key in set(raw(conn)['hashes']) - set(saved['hashes']):
            try:
                conn.delete(base64.b64decode(key))
            except Exception:
                failures.append('added principal')
        for key, fields in saved['hashes'].items():
            try:
                restore_hash(conn, base64.b64decode(key), fields)
            except Exception:
                failures.append('hash')
        restore_cloud(conn, saved)
        if failures or raw(conn) != saved or config() != load('config.json'):
            raise RuntimeError('config restoration mismatch')
    elif action == 'restore':
        saved = load('files.json')
        for path in paths:
            parents(path)
        for path in sorted(paths, key=len, reverse=True):
            old = saved[path]
            if os.path.lexists(path):
                if stat.S_ISDIR(os.lstat(path).st_mode):
                    if old is None:
                        os.rmdir(path)  # Never remove unknown additions.
                    elif old['kind'] != 'dir':
                        raise RuntimeError('leaf became a directory')
                elif old is None or old['kind'] != 'dir':
                    os.unlink(path)
                else:
                    raise RuntimeError('directory changed type')
        for path in sorted(paths, key=len):
            old = saved[path]
            if not old:
                continue
            if old['kind'] == 'dir':
                os.makedirs(path, exist_ok=True)
            elif old['kind'] == 'link':
                os.symlink(old['target'], path)
            else:
                fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                with os.fdopen(fd, 'wb') as stream:
                    stream.write(base64.b64decode(old['data']))
            os.chown(path, old['uid'], old['gid'], follow_symlinks=False)
            if old['kind'] != 'link':
                os.chmod(path, old['mode'])
        for path in sorted(paths, key=len, reverse=True):
            if saved[path]:
                os.utime(path, ns=(saved[path]['mtime'], saved[path]['mtime']), follow_symlinks=False)
        if {path: snapshot(path) for path in paths} != saved:
            raise RuntimeError('file restoration mismatch')
    elif action == 'discard':
        shutil.rmtree(root)  # Only this exclusive 0700 recovery directory.
    else:
        raise RuntimeError('unknown operation')
    sys.stdout.flush()
    sys.stderr.flush()


class RemoteState:
    def __init__(self, host, paths):
        self.host, self.paths = host, paths
        self.root = '/var/tmp/gnmi-restore-' + uuid.uuid4().hex
        self.run('init')

    def run(self, action, syslog_spec=None):
        # Program contains paths, never payloads. Bootstrap failures before the
        # protected fd exists have read no secrets. Ansible stderr is suppressed
        # as an additional boundary (not a substitute for private child output).
        source = inspect.getsource(_remote) + '\n_remote({!r}, {!r}, {!r}, {!r})'.format(
            self.root, action, self.paths, syslog_spec)
        try:
            redirect = ' 2>/dev/null' if action == 'capabilities' else ' >/dev/null 2>&1'
            result = self.host.shell('python3 -c ' + shlex.quote(source) + redirect,
                                     module_ignore_errors=True, verbose=False)
            ok = result.get('rc', 1) == 0
        except BaseException:
            ok = False
        if ok and action == 'capabilities':
            return _decode_capabilities(result.get('stdout', ''))
        if not ok:
            raise RuntimeError('gNMI restoration operation {} failed; recovery {}'.format(action, self.root)) from None


def _decode_capabilities(output):
    """Controller-only pygnmi decoder; public, bounded Capabilities wire only."""
    try:
        prefix = 'GNMI_CAPABILITIES_V1:'
        if not isinstance(output, str) or not output.startswith(prefix) or len(output) > 87406:
            raise ValueError('invalid frame')
        wire = base64.b64decode(output[len(prefix):].rstrip('\n'), validate=True)
        if not 0 < len(wire) <= 65536:
            raise ValueError('invalid wire')
        from pygnmi.spec.v080.gnmi_pb2 import CapabilityResponse
        response = CapabilityResponse.FromString(wire)
        if not response.gNMI_version or not response.supported_models or not response.supported_encodings:
            raise ValueError('incomplete capabilities')
        return [response.gNMI_version,
                sorted([m.name, m.organization, m.version] for m in response.supported_models),
                sorted(response.supported_encodings)]
    except Exception:
        raise RuntimeError('Invalid public Capabilities response or unavailable controller decoder') from None


class NativeTlsState:
    """Same-image owner. Optional verifier() must be a fresh, <=3s RPC returning bool.

    Secure/authenticated baselines MUST supply it through the fixture documented
    in gnmi_tls_state.md. It owns existing trust/name/client/auth metadata, does
    not mutate the service, and must not log secrets or attach them to errors.
    """
    def __init__(self, duthost, ptfhost, verifier=None):
        self.dut = duthost
        self.verifier = verifier
        self.prepared = False
        self.dut_files = RemoteState(duthost, [grpc_config.DUT_CERT_DIR] +
                                     list(grpc_config.get_dut_cert_paths().values()))
        self.ptf_files = None
        self.cert_dir = None
        try:
            self.ptf_files = RemoteState(ptfhost, list(grpc_config.get_ptf_cert_paths().values()))
            self.dut_files.run('baseline')
            if verifier is None:
                self.original_capabilities = self.dut_files.run('capabilities')
            elif not self._verify():
                raise RuntimeError('Original service verifier rejected baseline')
            self.cert_dir = tempfile.mkdtemp(prefix='gnoi_certs_')
        except BaseException:
            # No original files/config changed. Retain private diagnostic/recovery
            # material on admission failure; expose only its opaque directory ID.
            raise RuntimeError('gNMI baseline admission failed; ' + self.recovery_ids()) from None

    def recovery_ids(self):
        return 'DUT recovery {}; PTF recovery {}'.format(
            self.dut_files.root, self.ptf_files.root if self.ptf_files else 'not created')

    def _verify(self):
        try:
            return self.verifier() is True
        except BaseException:
            return False

    @contextmanager
    def remote_syslog(self, destination, vrf=None):
        # Registration has no DUT config writes. Once it succeeds, restoration
        # runs even when apply partially fails or pytest raises BaseException.
        self.dut_files.run('syslog-save', (destination, vrf))
        try:
            self.dut_files.run('syslog-apply')
            yield
        finally:
            self.dut_files.run('syslog-restore')
        # Persistent restoration belongs to the enclosing native owner, after
        # stopping its writer. Keep the exact-row declaration until then.

    def case_save(self):
        self.dut_files.run('case-save')

    def case_verify(self):
        self.dut_files.run('case-verify')

    def case_restore(self):
        # Stop the Set writer before repairing either DB. Preserve the shared
        # TLS files; a stopped supervisor program will not autorestart on its
        # own. Config notifications can restart it, hence the second stop.
        self.dut_files.run('persistent-check')
        self.dut_files.run('stop')
        self.dut_files.run('case-restore')
        self.dut_files.run('stop')
        self.dut_files.run('persistent-restore')
        self.dut_files.run('start')

        def ready():
            try:
                self.dut_files.run('shared-ready')
                return True
            except RuntimeError:
                return False
        if not wait_until(60, 2, 0, ready):
            raise RuntimeError('Shared TLS listener not restored within 60s')
        wait_critical_processes(self.dut)
        self.dut_files.run('case-verify')
        self.dut_files.run('persistent-verify')

    def prepare(self):
        self.dut_files.run('image')
        self.prepared = True  # stop can partially succeed; teardown must run.
        self.dut_files.run('stop')
        self.dut_files.run('detach')
        self.ptf_files.run('detach')

    def ready(self):
        try:
            self.dut_files.run('endpoint')
            if self.verifier is not None:
                return self._verify()
            return self.dut_files.run('capabilities') == self.original_capabilities
        except Exception:
            return False

    def restore(self, client=None):
        errors = []

        def attempt(label, operation):
            try:
                operation()
                return True
            except BaseException:
                errors.append(label)  # No payload-bearing exception chains.
                return False

        if client is not None:
            attempt('client close', client.close)
        same = not self.prepared or attempt('image changed/unavailable', lambda: self.dut_files.run('image'))
        if self.prepared and same:
            persistent_ok = attempt('persistent drift', lambda: self.dut_files.run('persistent-check'))
            stopped = attempt('stop', lambda: self.dut_files.run('stop'))
            config_ok = (attempt('configuration', lambda: self.dut_files.run('config'))
                         if stopped and persistent_ok else False)
            # Configuration notifications may restart the watcher. Stop again
            # even after a config failure, before changing any watched file.
            stopped = attempt('stop after config', lambda: self.dut_files.run('stop'))
            persistent_ok = (attempt('persistent configuration', lambda: self.dut_files.run('persistent-restore'))
                             if stopped and config_ok else False)
            files_ok = attempt('DUT files', lambda: self.dut_files.run('restore')) if stopped else False
            if not stopped:
                errors.append('DUT files retained: watcher not stopped')
            attempt('PTF files', lambda: self.ptf_files.run('restore'))
            if stopped and config_ok and persistent_ok and files_ok:
                if attempt('start', lambda: self.dut_files.run('start')):
                    attempt('original endpoint/semantic readiness', self.wait_ready)
                attempt('critical processes', lambda: wait_critical_processes(self.dut))
            attempt('persistent exit verification', lambda: self.dut_files.run('persistent-verify'))
            attempt('exit image', lambda: self.dut_files.run('image'))
        elif self.prepared:
            # No old config/file writes or service stop on a changed image.
            # PTF is independent and can safely restore its own original files.
            attempt('PTF files', lambda: self.ptf_files.run('restore'))
        if self.cert_dir:
            attempt('local certificates', lambda: shutil.rmtree(self.cert_dir))
        if not errors:
            attempt('PTF recovery cleanup', lambda: self.ptf_files.run('discard'))
            if not errors:
                attempt('DUT recovery cleanup', lambda: self.dut_files.run('discard'))
        if errors:
            raise RuntimeError('gNMI same-image restoration failed: {}; {}'.format(
                ', '.join(errors), self.recovery_ids())) from None

    def wait_ready(self):
        if not wait_until(60, 2, 0, self.ready):
            raise RuntimeError('Original endpoint/semantic readiness not restored within 60s')
