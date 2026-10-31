"""Offline owner/command-construction regressions, NOT real transport proof."""
import ast
import base64
import builtins
from copy import deepcopy
from contextlib import contextmanager, ExitStack
import io
import json
import os
import stat
import sys
import inspect
from pathlib import Path
import shlex
import shutil
import tempfile
from types import ModuleType, SimpleNamespace
from unittest.mock import Mock
import uuid

import pytest

SOURCE = Path(__file__).resolve().parents[2] / 'fixtures/gnmi_tls_state.py'
GRPC = SOURCE.with_name('grpc_fixtures.py')


def load():
    tree = ast.parse(SOURCE.read_text())
    tree.body = [node for node in tree.body if not isinstance(node, (ast.Import, ast.ImportFrom))]
    ns = dict(base64=base64, contextmanager=contextmanager, inspect=inspect, shlex=shlex, shutil=shutil,
              tempfile=tempfile, uuid=uuid, wait_until=lambda timeout, interval, delay, fn: fn())
    exec(compile(tree, str(SOURCE), 'exec'), ns)
    ns['grpc_config'] = SimpleNamespace(DUT_CERT_DIR='/certs',
                                        get_dut_cert_paths=lambda: {'key': '/certs/key'},
                                        get_ptf_cert_paths=lambda: {'key': '/ptf/key'})
    return ns


@pytest.fixture
def owner(tmp_path):
    ns = load()
    state = ns['NativeTlsState'].__new__(ns['NativeTlsState'])
    events = []
    state.dut = Mock()
    state.verifier = None
    state.prepared = True
    state.cert_dir = str(tmp_path / 'generated')
    Path(state.cert_dir).mkdir()
    state.dut_files = SimpleNamespace(root='/private/id', run=Mock(side_effect=lambda op: events.append('dut:' + op)))
    state.ptf_files = SimpleNamespace(root='/private/ptf-id',
                                      run=Mock(side_effect=lambda op: events.append('ptf:' + op)))
    state.wait_ready = Mock(side_effect=lambda: events.append('ready'))
    ns['wait_critical_processes'] = Mock(side_effect=lambda _: events.append('health'))
    return ns, state, events


def test_restoration_order_inside_common_owner(owner):
    _, state, events = owner
    state.restore()
    assert events == ['dut:image', 'dut:persistent-check', 'dut:stop', 'dut:config', 'dut:stop',
                      'dut:persistent-restore', 'dut:restore', 'ptf:restore', 'dut:start', 'ready', 'health',
                      'dut:persistent-verify', 'dut:image', 'ptf:discard', 'dut:discard']
    assert not Path(state.cert_dir).exists()


@pytest.mark.parametrize('operation', ['image', 'stop', 'config', 'restore', 'start', 'ready', 'health', 'close',
                                       'persistent-check', 'persistent-restore', 'persistent-verify'])
@pytest.mark.parametrize('exception', [ValueError, pytest.fail.Exception])
def test_failure_visible_independent_cleanup_recovery_retained(owner, operation, exception):
    ns, state, events = owner
    token = 'SYNTHETIC_PRIVATE_KEY_CHECKPOINT_AUTH'
    client = Mock()

    def run(op):
        events.append('dut:' + op)
        if op == operation:
            raise exception(token)
    state.dut_files.run.side_effect = run
    if operation in ('ready', 'health', 'close'):
        {'ready': state.wait_ready, 'health': ns['wait_critical_processes'],
         'close': client.close}[operation].side_effect = exception(token)
    with pytest.raises(RuntimeError, match='same-image restoration failed') as result:
        state.restore(client)
    assert token not in str(result.value)
    assert 'DUT recovery /private/id; PTF recovery /private/ptf-id' in str(result.value)
    assert result.value.__cause__ is None
    assert 'ptf:restore' in events
    assert 'dut:discard' not in events and 'ptf:discard' not in events
    assert not Path(state.cert_dir).exists()
    if operation == 'image':
        assert events == ['dut:image', 'ptf:restore']
    if operation in ('image', 'stop', 'config', 'restore'):
        assert 'dut:start' not in events


def test_ptf_failure_does_not_prevent_original_service_start(owner):
    _, state, events = owner
    state.ptf_files.run.side_effect = ValueError('private')
    with pytest.raises(RuntimeError):
        state.restore()
    assert 'dut:start' in events and 'ready' in events
    assert 'dut:discard' not in events


def test_prepare_checks_image_and_stops_before_detach(owner):
    _, state, events = owner
    state.prepare()
    assert events == ['dut:image', 'dut:stop', 'dut:detach', 'ptf:detach']


def test_endpoint_and_semantic_both_required_with_fresh_verifier(owner):
    _, state, _ = owner
    state.verifier = Mock(side_effect=[False, True])
    assert not state.ready()
    assert state.ready()
    assert state.verifier.call_count == 2
    state.dut_files.run.side_effect = RuntimeError('not listening')
    assert not state.ready()
    assert state.verifier.call_count == 2


@pytest.mark.parametrize('result', [False, 'true', None])
def test_secure_verifier_requires_explicit_true(owner, result):
    _, state, _ = owner
    state.verifier = Mock(return_value=result)
    assert not state._verify()


@pytest.mark.parametrize('secure', [False, True])
def test_supported_original_verifier_preflight_without_minted_credentials(secure):
    ns = load()
    states = []

    def remote(*args):
        value = Mock(root='/private/id')
        states.append(value)
        return value
    ns['RemoteState'] = remote
    verifier = Mock(return_value=True) if secure else None
    state = ns['NativeTlsState'](Mock(), Mock(), verifier=verifier)
    actions = [call.args[0] for call in states[0].run.call_args_list]
    assert actions == (['baseline'] if secure else ['baseline', 'capabilities'])
    assert 'detach' not in actions and 'stop' not in actions
    if secure:
        verifier.assert_called_once_with()
    shutil.rmtree(state.cert_dir)


def test_failed_original_verifier_cannot_mutate():
    ns = load()
    dut, ptf = Mock(root='/private/id'), Mock()
    ns['RemoteState'] = Mock(side_effect=[dut, ptf])
    with pytest.raises(RuntimeError, match='admission failed'):
        ns['NativeTlsState'](Mock(), Mock(), verifier=lambda: False)
    assert [call.args[0] for call in dut.run.call_args_list] == ['baseline']
    ptf.run.assert_not_called()


@pytest.mark.parametrize('action', ['init', 'baseline', 'config', 'restore', 'case-save', 'case-restore'])
def test_remote_command_contains_no_payload_and_redirects_both_streams(action):
    ns = load()
    host = Mock()
    host.shell.return_value = {'rc': 0, 'stdout': '', 'stderr': ''}
    state = ns['RemoteState'](host, ['/certs/key'])
    state.secret = 'SYNTHETIC_PRIVATE_PAYLOAD'
    state.run(action)
    cmd = host.shell.call_args.args[0]
    assert state.secret not in cmd
    assert cmd.endswith(' >/dev/null 2>&1')
    assert 'os.dup2(fd, 1)' in cmd and 'os.dup2(fd, 2)' in cmd
    assert 'O_NOFOLLOW' in cmd
    assert 'json.dumps(self' not in cmd


def test_original_data_never_returned_or_used_as_child_argv():
    source = SOURCE.read_text()
    assert 'print(' not in source
    assert "['config', 'replace'" not in source and "['config', 'rollback'" not in source
    assert 'base64.b64encode(stream.read())' in source  # stays in private files.json
    assert 'conn.hset(key, base64.b64decode(field), base64.b64decode(value))' in source
    assert "if failures or raw(conn) != saved or config() != load('config.json')" in source
    assert 'st_nlink != 1' in source and 'os.listxattr' in source and 'fcntl.ioctl' in source


def test_all_aaa_cases_explicit_opt_in_and_upgrades_remain_historical():
    root = SOURCE.parents[2]
    aaa = (root / 'gnmi/test_gnmi_aaa.py').read_text()
    assert 'gnmi_same_image_tls as gnmi_tls' in aaa
    assert '_gnmi_same_image_tls_flow' in SOURCE.with_name('gnmi_aaa.py').read_text()
    for name in ('test_upgrade_gnoi.py', 'test_upgrade_smart_switch_gnoi.py'):
        text = (root / 'upgrade_path' / name).read_text()
        assert 'gnmi_same_image' not in text
        assert 'gnmi_tls' in text
    tree = ast.parse(GRPC.read_text())
    functions = {n.name: n for n in tree.body if isinstance(n, ast.FunctionDef)}
    assert '_gnmi_tls_flow' in ast.unparse(functions['gnmi_tls'])
    assert 'loganalyzer' in [a.arg for a in functions['gnmi_same_image_tls'].args.args]


@pytest.mark.parametrize('failure', ['setup', 'restore', 'restore-pytest', None])
def test_actual_same_image_generator_finalizes(failure):
    ns = load()
    state = Mock(cert_dir='/private/local')
    fixture = SimpleNamespace(pygnmi_client=Mock())
    ns.update(NativeTlsState=Mock(return_value=state), _tls_client_fixture=Mock(return_value=fixture),
              _establish_gnoi_tls_handshake=Mock())
    tree = ast.parse(GRPC.read_text())
    tree.body = [node for node in tree.body if getattr(node, 'name', '') == '_gnmi_same_image_tls_flow']
    exec(compile(tree, str(GRPC), 'exec'), ns)
    if failure == 'setup':
        ns['_establish_gnoi_tls_handshake'].side_effect = ValueError('setup')
    elif failure:
        error = pytest.fail.Exception if failure.endswith('pytest') else ValueError
        state.restore.side_effect = error('cleanup')
    flow = ns['_gnmi_same_image_tls_flow'](Mock(), Mock())
    if failure == 'setup':
        with pytest.raises(ValueError):
            next(flow)
        state.restore.assert_called_once_with(None)
    else:
        assert next(flow) is fixture
        with pytest.raises(pytest.fail.Exception if failure == 'restore-pytest' else
                           ValueError if failure else StopIteration):
            next(flow)
        state.restore.assert_called_once_with(fixture.pygnmi_client)
        assert fixture._same_image_state is state


class RawRedis:
    """Independent bytes storage; legacy get_all adversary normalizes None."""
    def __init__(self):
        self.data = {}
        self.writes = []
        self.corrupt = False

    @staticmethod
    def b(value):
        return value.encode() if isinstance(value, str) else value

    def keys(self, pattern):
        assert pattern in ('GNMI_CLIENT_CERT|*', 'SYSLOG_SERVER|*')
        return [k for k in self.data if k.startswith(pattern[:-1].encode())]

    def hgetall(self, key):
        return deepcopy(self.data.get(self.b(key), {}))

    def get_all(self, db, key):
        return {k.decode(): '' if v == b'None' else v.decode() for k, v in self.hgetall(key).items()}

    def hget(self, key, field):
        return self.hgetall(key).get(self.b(field))

    def delete(self, key):
        self.writes.append(('delete', key))
        self.data.pop(self.b(key), None)

    def hset(self, key, field, value):
        self.writes.append(('hset', key, field, value))
        value = self.b(value)
        if self.corrupt and value == b'None':
            value = b''
        self.data.setdefault(self.b(key), {})[self.b(field)] = value

    def pipeline(self):
        conn = self

        class Transaction:
            def __init__(self):
                self.pending = []

            def __enter__(self):
                return self

            def __exit__(self, *args):
                pass

            def watch(self, key):
                self.key, self.original = key, conn.hgetall(key)

            def hgetall(self, key):
                return conn.hgetall(key)

            def multi(self):
                pass

            def delete(self, key):
                self.pending.append(lambda: conn.delete(key))

            def hset(self, key, mapping):
                self.pending.append(lambda: [conn.hset(key, f, v) for f, v in mapping.items()])

            def execute(self):
                if conn.hgetall(self.key) != self.original:
                    raise RuntimeError('synthetic watch conflict')
                for operation in self.pending:
                    operation()
        return Transaction()

    def hdel(self, key, field):
        self.writes.append(('hdel', key, field))
        self.data.get(self.b(key), {}).pop(self.b(field), None)


@pytest.fixture
def production_remote(tmp_path, monkeypatch):
    """Execute unmodified _remote actions; mock OS/device APIs, NOT action bodies.

    Not root/ioctl/transport proof. Real local private JSON files are used. FDs
    are modeled so the production output allowlist can be asserted safely.
    """
    ns = load()
    root = tmp_path / 'recovery'
    root.mkdir(mode=0o700)
    persistent = tmp_path / 'config_db.json'
    conn = RawRedis()
    env = SimpleNamespace(root=root, conn=conn, image='A', argv=[
        '/usr/sbin/telemetry', '--port', '8080', '--noTLS', '--bind_address', '127.0.0.1'],
        listeners='LISTEN 0 128 127.0.0.1:8080 0.0.0.0:* users:(("telemetry",pid=42,fd=8))',
        output=[], commands=[], wire=b'public-capabilities', grpc_calls=[], persistent=persistent)
    original_open = builtins.open
    original_lstat = os.lstat
    original_listdir = os.listdir
    original_dup = os.dup
    original_close = os.close
    original_osopen = os.open

    def opened(path, mode='r', *args, **kwargs):
        content = {'/etc/sonic/sonic_version.yml': b'version',
                   '/proc/sys/kernel/random/boot_id': b'boot',
                   '/proc/mounts': 'root / ext4 rw 0 0',
                   '/proc/42/cmdline': ('\0'.join(env.argv) + '\0').encode()}
        if str(path) in content:
            value = content[str(path)]
            return io.BytesIO(value) if 'b' in mode else io.StringIO(value)
        return original_open(path, mode, *args, **kwargs)

    def lstat(path, *args, **kwargs):
        if str(path) == str(env.root):
            return SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=0)
        if str(path) in [str(p) for p in env.root.parents]:
            return SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0)
        return original_lstat(path, *args, **kwargs)

    def command(argv, **kwargs):
        env.commands.append(argv)
        if argv == ['sonic-installer', 'list']:
            return ('Current: ' + env.image).encode()
        if argv[:2] == ['docker', 'inspect']:
            return b'container-image'
        if argv == ['ss', '-H', '-ltnp']:
            return env.listeners.encode()
        if argv[0] == 'systemctl':
            return b''
        if argv == ['sonic-cfggen', '-d', '--print-data']:
            return json.dumps(env.decoded()).encode()
        raise AssertionError('unexpected command')

    def connect(**kwargs):
        assert kwargs == dict(unix_socket_path='/synthetic/redis.sock', db=4, decode_responses=False,
                              socket_timeout=5, socket_connect_timeout=5)
        return conn

    def decoded():
        # Independent cfggen representation deliberately hides literal None and
        # NULL. Equality here CANNOT detect corrupted original raw values.
        def fields_decoded(fields):
            return {f.decode(): '' if v == b'None' else v.decode(errors='replace')
                    for f, v in fields.items() if f != b'NULL'}
        result = {k.decode(): fields_decoded(fields) for k, fields in conn.data.items()
                  if fields and not k.startswith(b'SYSLOG_SERVER|')}
        syslog = {k.decode().split('|', 1)[1]: fields_decoded(fields) for k, fields in conn.data.items()
                  if fields and k.startswith(b'SYSLOG_SERVER|')}
        if syslog:
            result['SYSLOG_SERVER'] = syslog
        return result

    swss = ModuleType('swsscommon.swsscommon')
    swss.SonicDBConfig = SimpleNamespace(getDbSock=lambda _: '/synthetic/redis.sock', getDbId=lambda _: 4)
    swss.SonicV2Connector = Mock(return_value=conn)
    monkeypatch.setitem(sys.modules, 'swsscommon', ModuleType('swsscommon'))
    monkeypatch.setitem(sys.modules, 'swsscommon.swsscommon', swss)
    monkeypatch.setitem(sys.modules, 'redis', SimpleNamespace(Redis=connect))
    monkeypatch.setitem(sys.modules, 'generic_config_updater', ModuleType('generic_config_updater'))
    monkeypatch.setitem(sys.modules, 'generic_config_updater.generic_updater',
                        SimpleNamespace(get_config_json=decoded))

    class Channel:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            env.grpc_calls.append('closed')

        def unary_unary(self, method):
            assert method == '/gnmi.gNMI/Capabilities'

            def rpc(request, timeout):
                assert request == b'' and timeout == 3
                if isinstance(env.wire, Exception):
                    raise env.wire
                return env.wire
            return rpc

    def channel(target, options):
        env.grpc_calls.append((target, options))
        return Channel()

    monkeypatch.setitem(sys.modules, 'grpc', SimpleNamespace(insecure_channel=channel))
    monkeypatch.setattr(builtins, 'open', opened)
    monkeypatch.setattr(os, 'lstat', lstat)
    monkeypatch.setattr(os, 'listdir', lambda p: ['42'] if p == '/proc' else original_listdir(p))
    monkeypatch.setattr(os, 'geteuid', lambda: 0)
    monkeypatch.setattr(os, 'umask', lambda _: None)
    monkeypatch.setattr(os, 'open',
                        lambda p, *a, **kw: 999 if str(p).endswith('/private.log') else original_osopen(p, *a, **kw))
    monkeypatch.setattr(os, 'dup', lambda fd: 998 if fd == 1 else original_dup(fd))
    monkeypatch.setattr(os, 'dup2', lambda *args: None)
    monkeypatch.setattr(os, 'close', lambda fd: None if fd in (998, 999) else original_close(fd))
    monkeypatch.setattr(os, 'write', lambda fd, value: env.output.append((fd, value)))
    monkeypatch.setattr('subprocess.check_output', command)
    # Keep production action bodies intact; relocate ONLY the fixed DUT path.
    source = inspect.getsource(ns['_remote']).replace("'/etc/sonic/config_db.json'", repr(str(persistent)))
    exec(compile(source, str(SOURCE), 'exec'), ns)
    monkeypatch.setattr('fcntl.ioctl', lambda *args: None)  # Linux metadata capability modeled on macOS.
    monkeypatch.setattr(os, 'listxattr', lambda *args, **kwargs: [], raising=False)
    monkeypatch.setattr(os, 'fchown', lambda *args: None)  # Fixture files already belong to this uid/gid.
    env.run = lambda action, spec=None: ns['_remote'](str(env.root), action, [], spec)
    env.decoded = decoded
    env.ns = ns
    return env


@pytest.mark.parametrize('action', ['case-save', 'case-verify', 'case-restore', 'config'])
def test_production_image_mismatch_zero_db_writes(production_remote, action):
    env = production_remote
    env.run('baseline')
    env.image = 'B'
    with pytest.raises(RuntimeError, match='image changed'):
        env.run(action)
    assert env.conn.writes == [] and env.output == []


@pytest.mark.parametrize('cloud', [None, b'', b'None', b'NULL', b'Private'])
@pytest.mark.parametrize('action', ['case-restore', 'config'])
def test_production_raw_restore_not_cfggen_or_sonicv2_normalization(production_remote, cloud, action):
    env = production_remote
    principal = b'GNMI_CLIENT_CERT|test.client.gnmi.sonic'
    env.conn.data = {principal: {b'role@': b'readonly', b'NULL': b'None', b'empty': b''},
                     b'GNMI|gnmi': {b'port': b'8080', b'NULL': b'None'},
                     b'GNMI_CLIENT_CERT|other': {b'role@': b'readwrite', b'NULL': b'NULL'},
                     b'DEVICE_METADATA|localhost': {b'type': b'ToR'}}
    if cloud is not None:
        env.conn.data[b'DEVICE_METADATA|localhost'][b'cloudtype'] = cloud
    expected = deepcopy(env.conn.data)
    # Demonstrate the adversary in the review, rather than a self-consistent mock.
    assert env.conn.get_all('CONFIG_DB', principal)['NULL'] == ''
    assert 'NULL' not in env.decoded()[principal.decode()]
    env.run('baseline')
    env.run('case-save')
    env.conn.data[principal] = {b'role@': b'admin'}
    env.conn.data[b'DEVICE_METADATA|localhost'][b'cloudtype'] = b'changed'
    if action == 'config':
        env.conn.data.pop(b'GNMI_CLIENT_CERT|other')
        env.conn.data[b'GNMI_CLIENT_CERT|extra'] = {b'role@': b'admin'}
    env.run(action)
    assert env.conn.data == expected  # Absent GNMI|certs remains absent.
    assert env.output == []
    assert all('None' not in repr(argv) for argv in env.commands)


@pytest.mark.parametrize('action', ['case-restore', 'config'])
def test_production_raw_postcheck_catches_loss_hidden_by_cfggen(production_remote, action):
    env = production_remote
    env.conn.data = {b'GNMI_CLIENT_CERT|test.client.gnmi.sonic': {b'role@': b'readonly', b'NULL': b'None'}}
    env.run('baseline')
    env.run('case-save')
    decoded = env.decoded()
    env.conn.corrupt = True
    with pytest.raises(RuntimeError, match='restoration mismatch'):
        env.run(action)
    assert env.decoded() == decoded
    assert env.output == []


@pytest.mark.parametrize('auth', [['--allow_no_client_auth'], ['--ca_crt', '/private/original-ca']])
@pytest.mark.parametrize('bind', ['*', '[::]', '0.0.0.0'])
def test_production_secure_default_bind_reaches_verifier(production_remote, auth, bind):
    env = production_remote
    env.argv = ['/usr/sbin/telemetry', '--port', '8080', '--server_crt', '/private/cert',
                '--server_key', '/private/key'] + auth
    env.listeners = 'LISTEN 0 128 {}:8080 *:* users:(("telemetry",pid=42,fd=8))'.format(bind)
    env.run('baseline')
    endpoint = json.loads((env.root / 'endpoint.json').read_text())
    assert not endpoint['plaintext']
    state = env.ns['NativeTlsState'].__new__(env.ns['NativeTlsState'])
    state.dut_files = SimpleNamespace(run=env.run)
    state.verifier = Mock(return_value=True)
    assert state.ready()
    state.verifier.assert_called_once_with()
    assert env.grpc_calls == []
    # Secure baseline without authorized verifier must NEVER use plaintext.
    with pytest.raises(RuntimeError, match='secure baseline'):
        env.run('capabilities')
    assert env.grpc_calls == [] and env.output == []


@pytest.mark.parametrize('listeners', [
    'LISTEN 0 128 *:8080 *:* users:(("unrelated",pid=999,fd=8))',
    'LISTEN 0 128 *:8080 *:*',
    'LISTEN 0 128 *:8080 *:* users:(("telemetry",pid=42,fd=8))\n'
    'LISTEN 0 128 *:50052 *:* users:(("other",pid=999,fd=9))'])
def test_production_default_bind_rejects_unrelated_or_conflicting_listener(production_remote, listeners):
    env = production_remote
    env.argv = ['/usr/sbin/telemetry', '--port', '8080', '--server_crt', '/private/cert']
    env.listeners = listeners
    with pytest.raises(RuntimeError, match='listener'):
        env.run('baseline')
    assert env.conn.writes == [] and env.output == []


def test_production_public_wire_only_no_dut_decoder(production_remote, monkeypatch):
    env = production_remote
    monkeypatch.setitem(sys.modules, 'pygnmi', None)
    env.run('baseline')
    (env.root / 'private-secret').write_text('PRIVATE_SENTINEL')
    env.run('capabilities')
    assert env.output == [(998, b'GNMI_CAPABILITIES_V1:' + base64.b64encode(env.wire) + b'\n')]
    assert env.grpc_calls == [('127.0.0.1:8080', [('grpc.max_receive_message_length', 65536)]), 'closed']
    assert 'PRIVATE_SENTINEL' not in repr(env.output + env.commands)


@pytest.mark.parametrize('wire', [b'', b'x' * 65537, 'PRIVATE_SENTINEL', RuntimeError('PRIVATE_SENTINEL')])
def test_production_public_channel_rejects_nonwire_oversize_and_exceptions(production_remote, wire):
    env = production_remote
    env.run('baseline')
    env.wire = wire
    with pytest.raises(RuntimeError):
        env.run('capabilities')
    assert env.output == []


@pytest.mark.parametrize('frame', ['', 'PRIVATE_SENTINEL', 'GNMI_CAPABILITIES_V1:!',
                                   'GNMI_CAPABILITIES_V1:', 'GNMI_CAPABILITIES_V1:' + 'A' * 87400])
def test_controller_parser_rejects_invalid_frames_without_payload_errors(frame):
    with pytest.raises(RuntimeError, match='Invalid public Capabilities') as error:
        load()['_decode_capabilities'](frame)
    assert 'PRIVATE_SENTINEL' not in str(error.value)


def test_controller_parser_uses_generated_schema_when_available():
    pytest.importorskip('pygnmi.spec.v080.gnmi_pb2', reason='controller pygnmi absent; no installation authorized')
    from pygnmi.spec.v080.gnmi_pb2 import CapabilityResponse
    response = CapabilityResponse(gNMI_version='0.8.0', supported_encodings=[0])
    response.supported_models.add(name='model', organization='org', version='1')
    frame = 'GNMI_CAPABILITIES_V1:' + base64.b64encode(response.SerializeToString()).decode() + '\n'
    assert load()['_decode_capabilities'](frame) == ['0.8.0', [['model', 'org', '1']], [0]]


def test_production_case_image_refusal_preserves_independent_cleanup(production_remote, tmp_path):
    env = production_remote
    env.run('baseline')
    env.image = 'B'
    state = env.ns['NativeTlsState'].__new__(env.ns['NativeTlsState'])
    state.dut_files = SimpleNamespace(root=str(env.root), run=env.run)
    state.ptf_files = Mock(root='/private/ptf-id')
    state.prepared = True
    state.cert_dir = str(tmp_path / 'controller-certs')
    Path(state.cert_dir).mkdir()
    with pytest.raises(RuntimeError, match='image changed'):
        state.case_restore()
    with pytest.raises(RuntimeError, match='same-image restoration failed'):
        state.restore()
    state.ptf_files.run.assert_called_once_with('restore')
    assert not Path(state.cert_dir).exists()
    assert env.conn.writes == [] and env.output == []


def test_controller_missing_decoder_fails_closed(monkeypatch):
    monkeypatch.setitem(sys.modules, 'pygnmi', None)
    with pytest.raises(RuntimeError, match='unavailable controller decoder'):
        load()['_decode_capabilities']('GNMI_CAPABILITIES_V1:' + base64.b64encode(b'public-wire').decode())


def seed_persistent(env, value):
    env.persistent.write_text(json.dumps(value, indent=3) + '\n\n')
    os.chmod(env.persistent, 0o640)
    os.utime(env.persistent, ns=(1234567890000000000, 1234567890000000000))


def persistent_identity(path):
    info = path.stat()
    return path.read_bytes(), info.st_mode, info.st_uid, info.st_gid, info.st_mtime_ns


@pytest.mark.parametrize('existing', [False, True])
@pytest.mark.parametrize('cloud', [None, '', 'None', 'NULL', 'Private'])
def test_production_persistent_owned_deltas_preserve_independent_baselines(production_remote, existing, cloud):
    env = production_remote
    startup = {'DEVICE_METADATA': {'localhost': {'type': 'ToR'}}, 'FEATURE': {'x': {'state': 'enabled'}}}
    if cloud is not None:
        startup['DEVICE_METADATA']['localhost']['cloudtype'] = cloud
    if existing:
        startup.update(GNMI={'gnmi': {'port': '8080', 'empty': '', 'NULL': 'None'},
                             'certs': {'server_key': '/old/key'}, 'unowned-row': {'keep': 'NULL'}},
                       GNMI_CLIENT_CERT={'other': {'role': ['readonly'], 'NULL': 'None', 'empty': ''},
                                         'test.client.gnmi.sonic': {'role': ['readwrite'], 'extra': 'NULL'}})
    seed_persistent(env, startup)
    expected = persistent_identity(env.persistent)
    # Running is intentionally NOT the startup snapshot, including owned state.
    env.conn.data = {b'GNMI|gnmi': {b'port': b'50052'},
                     b'GNMI_CLIENT_CERT|test.client.gnmi.sonic': {b'role@': b'readonly', b'NULL': b'None'}}
    env.run('baseline')
    env.run('case-save')
    running = deepcopy(env.conn.data)
    for role in ('admin', '', 'None'):
        persisted = deepcopy(startup)
        persisted.setdefault('GNMI', {})['gnmi'] = {'port': '50052', 'user_auth': 'true'}
        persisted['GNMI']['certs'] = {'server_key': '/test/key'}
        persisted['GNMI_CLIENT_CERT'] = {'test.client.gnmi.sonic': {'role': [role]}}
        persisted['DEVICE_METADATA']['localhost']['cloudtype'] = 'Public'
        env.persistent.write_text(json.dumps(persisted))
        env.conn.data[b'GNMI_CLIENT_CERT|test.client.gnmi.sonic'] = {b'role@': role.encode()}
        env.conn.data[b'DEVICE_METADATA|localhost'] = {b'cloudtype': b'Public'}
        env.run('case-restore')
        env.run('persistent-restore')
        env.run('case-verify')
        assert persistent_identity(env.persistent) == expected
        assert {k: v for k, v in env.conn.data.items() if v} == running
    env.run('config')
    env.run('persistent-restore')
    assert persistent_identity(env.persistent) == expected
    assert env.output == []


@pytest.mark.parametrize('drift', ['feature', 'gnmi-row', 'metadata-field', 'metadata-mode', 'malformed', 'duplicate'])
@pytest.mark.parametrize('action', ['config', 'case-restore', 'persistent-restore'])
def test_production_persistent_unrelated_drift_precedes_any_owned_restore(production_remote, drift, action):
    env = production_remote
    baseline = {'FEATURE': {'x': {'state': 'enabled'}}, 'DEVICE_METADATA': {'localhost': {'type': 'ToR'}}}
    seed_persistent(env, baseline)
    env.conn.data = {b'GNMI_CLIENT_CERT|test.client.gnmi.sonic': {b'role@': b'readonly'}}
    env.run('baseline')
    env.run('case-save')
    changed = deepcopy(baseline)
    changed['GNMI'] = {'gnmi': {'port': '50052'}}
    if drift == 'feature':
        changed['FEATURE']['x']['state'] = 'disabled'
    elif drift == 'gnmi-row':
        changed['GNMI']['unowned'] = {'extra': 'bad'}
    elif drift == 'metadata-field':
        changed['DEVICE_METADATA']['localhost']['type'] = 'Spine'
    env.persistent.write_text(json.dumps(changed))
    if drift == 'metadata-mode':
        os.chmod(env.persistent, 0o600)
    elif drift == 'malformed':
        env.persistent.write_text('{bad')
    elif drift == 'duplicate':
        env.persistent.write_text('{"FEATURE": {}, "FEATURE": {}}')
    before = persistent_identity(env.persistent)
    with pytest.raises((RuntimeError, ValueError)):
        env.run(action)
    assert env.conn.writes == []
    assert persistent_identity(env.persistent) == before
    assert env.output == []


@pytest.mark.parametrize('symlink', [False, True])
@pytest.mark.parametrize('absent', [False, True])
def test_production_persistent_absence_and_symlink_contract(production_remote, symlink, absent):
    env = production_remote
    path = env.persistent
    if symlink:
        target = path.with_name('startup.json')
        path.symlink_to(target.name)
        path = target
    if not absent:
        path.write_text(' { "GNMI" : {} }\n')
    env.run('baseline')
    expected = path.read_bytes() if path.exists() else None
    link_before = os.lstat(env.persistent) if symlink else None
    path.write_text('{"GNMI":{"gnmi":{"port":"50052"}}, "GNMI_CLIENT_CERT":{}}')
    env.run('persistent-restore')
    assert (path.read_bytes() if path.exists() else None) == expected
    if symlink:
        assert env.persistent.is_symlink() and os.readlink(env.persistent) == path.name
        assert os.lstat(env.persistent).st_mtime_ns == link_before.st_mtime_ns


@pytest.mark.parametrize('action', ['persistent-check', 'persistent-restore', 'persistent-verify'])
def test_production_persistent_image_guard_zero_writes(production_remote, monkeypatch, action):
    env = production_remote
    seed_persistent(env, {})
    env.run('baseline')
    env.persistent.write_text('{"GNMI":{"gnmi":{"port":"50052"}}}')
    expected = persistent_identity(env.persistent)
    env.image = 'replacement'
    replace = Mock(side_effect=AssertionError('must not write'))
    monkeypatch.setattr(os, 'replace', replace)
    with pytest.raises(RuntimeError, match='image changed'):
        env.run(action)
    assert not replace.called and env.conn.writes == []
    assert persistent_identity(env.persistent) == expected


@pytest.mark.parametrize('failure', ['write', 'read', 'atomic', 'fsync', 'racing-writer'])
def test_production_persistent_io_failure_retains_original_recovery(production_remote, monkeypatch, failure):
    env = production_remote
    seed_persistent(env, {})
    env.run('baseline')
    env.persistent.write_text('{"GNMI":{"gnmi":{"port":"50052"}}}')
    expected = persistent_identity(env.persistent)
    if failure == 'write':
        monkeypatch.setattr(tempfile, 'mkstemp', Mock(side_effect=OSError('synthetic write failure')))
    elif failure == 'read':
        opened = os.open

        def fail_read(path, *args, **kwargs):
            if str(path) == str(env.persistent):
                raise OSError('synthetic read failure')
            return opened(path, *args, **kwargs)
        monkeypatch.setattr(os, 'open', fail_read)
    elif failure == 'atomic':
        monkeypatch.setattr(os, 'replace', Mock(side_effect=OSError('synthetic atomic failure')))
    elif failure == 'fsync':
        monkeypatch.setattr(os, 'fsync', Mock(side_effect=OSError('synthetic fsync failure')))
    else:
        fsync = os.fsync

        def race(fd):
            env.persistent.write_text('{"UNRELATED":{"new":"writer"}}')
            return fsync(fd)
        monkeypatch.setattr(os, 'fsync', race)
    with pytest.raises((RuntimeError, OSError)):
        env.run('persistent-restore')
    if failure != 'racing-writer':
        assert persistent_identity(env.persistent) == expected
    else:
        assert json.loads(env.persistent.read_text()) == {'UNRELATED': {'new': 'writer'}}
    assert (env.root / 'persistent.json').exists()
    assert not list(env.persistent.parent.glob('.gnmi-restore-*'))
    assert env.output == []


def test_production_late_write_is_detected_never_repaired(production_remote, monkeypatch):
    env = production_remote
    seed_persistent(env, {})
    env.run('baseline')
    import threading

    def write_late(*args):
        env.persistent.write_text('{"GNMI":{"gnmi":{"port":"50052"}}}')
    monkeypatch.setattr(threading.Event, 'wait', write_late)
    with pytest.raises(RuntimeError, match='late write'):
        env.run('persistent-verify')
    assert json.loads(env.persistent.read_text())['GNMI']['gnmi']['port'] == '50052'
    assert (env.root / 'persistent.json').exists()


def test_shared_case_stops_writer_and_verifies_after_restart(owner):
    _, state, events = owner
    state.case_restore()
    assert events == ['dut:persistent-check', 'dut:stop', 'dut:case-restore', 'dut:stop',
                      'dut:persistent-restore', 'dut:start', 'dut:shared-ready', 'health',
                      'dut:case-verify', 'dut:persistent-verify']


@pytest.mark.parametrize('bad', ['symlink-replaced', 'hardlink', 'xattr', 'directory', 'deleted'])
def test_production_persistent_unsupported_or_replaced_state_refused(production_remote, monkeypatch, bad):
    env = production_remote
    seed_persistent(env, {})
    if bad == 'symlink-replaced':
        target = env.persistent.with_name('target.json')
        env.persistent.rename(target)
        env.persistent.symlink_to(target.name)
    env.run('baseline')
    if bad == 'symlink-replaced':
        env.persistent.unlink()
        env.persistent.write_text('{}')
    elif bad == 'hardlink':
        os.link(env.persistent, env.persistent.with_name('hardlink.json'))
    elif bad == 'xattr':
        monkeypatch.setattr(os, 'listxattr', lambda *args, **kwargs: ['user.synthetic'])
    elif bad == 'directory':
        env.persistent.unlink()
        env.persistent.mkdir()
    else:
        env.persistent.unlink()
    with pytest.raises(RuntimeError):
        env.run('persistent-restore')
    assert env.conn.writes == [] and env.output == []


@pytest.mark.parametrize('operation', ['persistent-check', 'stop', 'case-restore', 'persistent-restore',
                                       'start', 'shared-ready', 'case-verify', 'persistent-verify'])
def test_shared_case_failure_propagates_without_successful_reuse(owner, operation):
    _, state, events = owner

    def run(op):
        events.append('dut:' + op)
        if op == operation:
            raise RuntimeError('synthetic')
    state.dut_files.run.side_effect = run
    with pytest.raises(RuntimeError):
        state.case_restore()
    assert 'dut:discard' not in events
    if operation in ('persistent-check', 'stop', 'case-restore', 'persistent-restore'):
        assert 'dut:start' not in events


def test_production_shared_readiness_uses_native_pid(production_remote):
    env = production_remote
    env.run('baseline')
    env.listeners = 'LISTEN 0 128 *:50052 *:* users:(("unrelated",pid=999,fd=8))'
    with pytest.raises(RuntimeError, match='not ready'):
        env.run('shared-ready')
    env.listeners = 'LISTEN 0 128 *:50052 *:* users:(("telemetry",pid=42,fd=8))'
    env.run('shared-ready')


@pytest.mark.parametrize('format_only', [True, False])
def test_production_no_owned_semantic_delta_does_not_hide_file_drift(production_remote, format_only):
    env = production_remote
    seed_persistent(env, {'FEATURE': {}})
    env.run('baseline')
    if format_only:
        env.persistent.write_text('{"FEATURE":{}}')
    else:
        os.utime(env.persistent, ns=(1234567891000000000, 1234567891000000000))
    expected = persistent_identity(env.persistent)
    with pytest.raises(RuntimeError, match='unexplained persistent'):
        env.run('persistent-restore')
    assert persistent_identity(env.persistent) == expected


DESTINATION = '192.0.2.18'
SYSLOG_KEY = ('SYSLOG_SERVER|' + DESTINATION).encode()
OTHER_SYSLOG_KEY = b'SYSLOG_SERVER|192.0.2.19'


def startup_evidence(path):
    info = path.stat()
    return path.read_bytes(), info.st_mode, info.st_uid, info.st_gid, info.st_mtime_ns


def forwarding_owner(env):
    state = env.ns['NativeTlsState'].__new__(env.ns['NativeTlsState'])
    state.dut_files = SimpleNamespace(run=env.run)
    return state


def seed_forwarding(env, raw=None, startup=None):
    env.conn.data[OTHER_SYSLOG_KEY] = {b'port': b'6514', b'extra': b'None'}
    if raw is not None:
        env.conn.data[SYSLOG_KEY] = raw
    value = {'SYSLOG_SERVER': {'192.0.2.19': {'port': '6514', 'extra': 'unrelated'}},
             'FEATURE': {'unchanged': {'state': 'enabled'}}}
    if startup is not None:
        value['SYSLOG_SERVER'][DESTINATION] = startup
    seed_persistent(env, value)
    return value


@pytest.mark.parametrize('vrf', [None, 'mgmt'])
@pytest.mark.parametrize('raw', [
    None, {b'NULL': b'NULL'}, {b'extra': b'None'}, {b'extra': b''},
    {b'vrf': b'other', b'port': b'6514', b'source': b'192.0.2.22', b'extra': b'NULL'},
])
@pytest.mark.parametrize('startup', [
    None, {}, {'extra': ''}, {'extra': 'None'}, {'extra': 'NULL'},
    {'port': '10514', 'vrf': 'startup', 'private': 'synthetic'},
])
def test_forward_get_then_set_production_actions_restore_independent_originals(production_remote, vrf, raw, startup):
    env = production_remote
    original = seed_forwarding(env, raw, startup)
    expected_file = startup_evidence(env.persistent)
    expected_raw = deepcopy(env.conn.data)
    for operation in ('get', 'set'):
        if operation == 'set':
            env.root = env.root.with_name('second-private-owner')
            env.root.mkdir(mode=0o700)
        env.run('baseline')
        owner = forwarding_owner(env)
        with owner.remote_syslog(DESTINATION, vrf):
            temporary = {b'port': b'514'}
            if vrf:
                temporary[b'vrf'] = vrf.encode()
            assert env.conn.data[SYSLOG_KEY] == temporary
            if operation == 'set':
                saved = deepcopy(original)
                saved['SYSLOG_SERVER'][DESTINATION] = {k.decode(): v.decode() for k, v in temporary.items()}
                saved['GNMI'] = {'gnmi': {'port': '50052'}}
                env.persistent.write_text(json.dumps(saved))
        # Context restores running BEFORE outer owner restores persistent state.
        assert env.conn.data == expected_raw
        env.run('config')
        env.run('persistent-restore')
        assert startup_evidence(env.persistent) == expected_file
        assert env.conn.data == expected_raw
        assert env.output == []
        assert 'synthetic' not in repr(env.commands)


@pytest.mark.parametrize('drift', ['other-running', 'other-running-normalized', 'owned-running-extra',
                                   'other-startup', 'owned-startup-extra', 'owned-startup-port'])
@pytest.mark.parametrize('action', ['syslog-restore', 'config', 'persistent-restore'])
def test_forwarding_never_blesses_unknown_rows_or_fields(production_remote, drift, action):
    env = production_remote
    original = seed_forwarding(env)
    env.run('baseline')
    env.run('syslog-save', (DESTINATION, None))
    env.run('syslog-apply')
    env.run('syslog-restore')
    if drift.startswith('other-running'):
        env.conn.data[OTHER_SYSLOG_KEY][b'extra'] = b'' if drift.endswith('normalized') else b'changed'
    elif drift == 'owned-running-extra':
        env.conn.data[SYSLOG_KEY] = {b'port': b'514', b'unknown': b'None'}
    else:
        changed = deepcopy(original)
        changed['SYSLOG_SERVER'][DESTINATION] = {'port': '514'}
        if drift == 'other-startup':
            changed['SYSLOG_SERVER']['192.0.2.19']['extra'] = 'changed'
        elif drift == 'owned-startup-extra':
            changed['SYSLOG_SERVER'][DESTINATION]['extra'] = 'unknown'
        else:
            changed['SYSLOG_SERVER'][DESTINATION]['port'] = '6514'
        env.persistent.write_text(json.dumps(changed))
    env.conn.writes.clear()
    before = startup_evidence(env.persistent)
    # persistent-restore is file-only; its raw-state gate is required too.
    with pytest.raises(RuntimeError):
        env.run(action)
    assert env.conn.writes == [] and startup_evidence(env.persistent) == before
    assert env.output == []


@pytest.mark.parametrize('action', ['syslog-save', 'syslog-apply', 'syslog-restore'])
def test_forwarding_image_change_precedes_writes_and_commands(production_remote, action):
    env = production_remote
    seed_forwarding(env)
    env.run('baseline')
    if action != 'syslog-save':
        env.run('syslog-save', (DESTINATION, None))
    if action == 'syslog-restore':
        env.run('syslog-apply')
    env.image = 'replacement'
    env.conn.writes.clear()
    env.commands.clear()
    original = startup_evidence(env.persistent)
    with pytest.raises(RuntimeError, match='image changed'):
        env.run(action, (DESTINATION, None))
    assert not env.conn.writes and startup_evidence(env.persistent) == original
    assert not any(command[0] == 'systemctl' for command in env.commands)


@pytest.mark.parametrize('exception', [ValueError, pytest.fail.Exception])
@pytest.mark.parametrize('failure', ['apply', 'body', 'restore'])
def test_forwarding_owner_finally_preserves_failures(owner, failure, exception):
    _, state, events = owner

    def run(action, spec=None):
        events.append(action)
        if action == 'syslog-' + failure:
            raise exception('synthetic-' + failure)
    state.dut_files.run.side_effect = run
    with pytest.raises(exception, match='synthetic-' + failure):
        with state.remote_syslog(DESTINATION):
            if failure == 'body':
                raise exception('synthetic-body')
    assert events == ['syslog-save', 'syslog-apply', 'syslog-restore']


def test_forwarding_production_apply_failure_after_write_still_restores(production_remote, monkeypatch):
    env = production_remote
    seed_forwarding(env, {b'vrf': b'original', b'port': b'6514', b'NULL': b'None'})
    expected = deepcopy(env.conn.data)
    env.run('baseline')
    check_output = __import__('subprocess').check_output
    failed = []

    def fail_reload(argv, **kwargs):
        if argv == ['systemctl', 'restart', 'rsyslog-config'] and not failed:
            failed.append(True)
            raise RuntimeError('synthetic apply reload failure')
        return check_output(argv, **kwargs)
    monkeypatch.setattr('subprocess.check_output', fail_reload)
    with pytest.raises(RuntimeError, match='apply reload failure'):
        with forwarding_owner(env).remote_syslog(DESTINATION):
            pytest.fail('must not enter body')
    assert env.conn.data == expected
    assert env.output == []


def test_forwarding_registration_is_exclusive_before_mutation(production_remote):
    env = production_remote
    seed_forwarding(env)
    env.run('baseline')
    env.run('syslog-save', (DESTINATION, None))
    with pytest.raises(FileExistsError):
        env.run('syslog-save', (DESTINATION, None))
    assert env.conn.writes == []


def test_forwarding_no_registration_means_no_syslog_ownership(production_remote):
    env = production_remote
    original = seed_forwarding(env)
    env.run('baseline')
    original['SYSLOG_SERVER'][DESTINATION] = {'port': '514'}
    env.persistent.write_text(json.dumps(original))
    with pytest.raises(RuntimeError, match='unrelated persistent'):
        env.run('persistent-restore')
    assert env.conn.writes == []


def load_capture(namespace):
    path = SOURCE.parents[1] / 'helpers/syslog_helpers.py'
    tree = ast.parse(path.read_text())
    tree.body = [node for node in tree.body if getattr(node, 'name', '') == 'capture_remote_syslog']
    namespace.update(contextmanager=contextmanager, ExitStack=ExitStack, os=os, shlex=shlex, uuid=uuid,
                     SYSLOG_CAPTURE_SECONDS=60, wait_until=lambda timeout, interval, delay, fn: fn(),
                     pytest_assert=lambda condition, message: pytest.fail(message) if not condition else None)
    exec(compile(tree, str(path), 'exec'), namespace)
    return namespace['capture_remote_syslog']


@pytest.mark.parametrize('failure', ['action', 'capture-start', 'body', 'ready', 'close', 'join', 'remove', None])
@pytest.mark.parametrize('exception', [ValueError, pytest.fail.Exception])
def test_capture_finally_restores_configuration_after_any_failure(owner, failure, exception):
    _, state, events = owner
    state.dut_files.run.side_effect = lambda action, spec=None: events.append(action)
    pool, result, dut = Mock(), Mock(), Mock()
    result.ready.return_value = True
    namespace = {'add_syslog_server': Mock(), 'del_syslog_server': Mock()}
    capture = load_capture(namespace)

    def shell(command, **kwargs):
        if command.startswith('grep') and failure == 'action':
            raise exception('synthetic-action')
        if kwargs.get('module_async'):
            assert 'timeout 60 tcpdump' in command
            return pool, result
        if command.startswith('sudo test') and failure == 'capture-start':
            raise exception('synthetic-capture-start')
        if command.startswith('sudo rm') and failure == 'remove':
            raise exception('synthetic-remove')
        return {'rc': 0}
    dut.shell.side_effect = shell
    if failure in ('ready', 'close', 'join'):
        {'ready': result.ready, 'close': pool.close, 'join': pool.join}[failure].side_effect = exception('synthetic')

    def run():
        with capture(dut, DESTINATION, configuration=state.remote_syslog(DESTINATION)):
            events.append('body')
            if failure == 'body':
                raise exception('synthetic-body')
    if failure:
        with pytest.raises(exception):
            run()
    else:
        run()
    assert events[:2] == ['syslog-save', 'syslog-apply']
    assert events[-1] == 'syslog-restore'
    namespace['add_syslog_server'].assert_not_called()
    namespace['del_syslog_server'].assert_not_called()


def test_legacy_capture_keeps_default_add_delete_contract():
    namespace = {'add_syslog_server': Mock(return_value={'rc': 0}), 'del_syslog_server': Mock()}
    capture = load_capture(namespace)
    pool, result, dut = Mock(), Mock(), Mock()
    result.ready.return_value = True
    dut.shell.side_effect = lambda command, **kwargs: (pool, result) if kwargs.get('module_async') else {'rc': 0}
    with capture(dut, DESTINATION, vrf='mgmt'):
        pass
    namespace['add_syslog_server'].assert_called_once_with(dut, DESTINATION, vrf='mgmt')
    namespace['del_syslog_server'].assert_called_once_with(dut, DESTINATION, module_ignore_errors=True)


@pytest.mark.parametrize('failure', [None, 'apply', 'body', 'capture-close', 'context-restore', 'image'])
def test_real_pytest_forwarding_finally_before_native_restore_analyzer_and_generic(tmp_path, failure):
    """Real pytest fixture scheduling + production actions, not a thrown yield.

    Device filesystem/Redis/service APIs are synthetic. This does not qualify
    real Redis transactions, rsyslog, private transport or a live semantic RPC.
    """
    import subprocess
    import textwrap
    prelude = '''
import ast
import importlib.util
import json
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock
import pytest
spec = importlib.util.spec_from_file_location('adapter', ADAPTER)
adapter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(adapter)
production_remote = adapter.production_remote
failure = FAILURE
events = []

def pytest_sessionfinish(session, exitstatus):
    Path('events.json').write_text(json.dumps(events))

'''
    fixtures = textwrap.dedent('''
        @pytest.fixture
        def core_dump_and_config_check():
            events.append('generic-start')
            yield
            events.append('generic-check')

        @pytest.fixture
        def loganalyzer(core_dump_and_config_check):
            events.append('analyzer-start')
            yield
            events.append('analyzer-check')

        @pytest.fixture
        def duthosts(production_remote):
            env = production_remote
            original = adapter.seed_forwarding(env, {b'port': b'6514', b'extra': b'None'},
                                               {'port': '1514', 'extra': 'NULL'})
            expected_raw = deepcopy(env.conn.data)
            expected_file = adapter.startup_evidence(env.persistent)
            env.run('baseline')
            (env.root / 'files.json').write_text('{}')
            state = adapter.forwarding_owner(env)
            state.dut = Mock()
            state.ptf_files = SimpleNamespace(root='/synthetic-ptf', run=lambda action: events.append('ptf:' + action))
            state.dut_files.root = str(env.root)
            state.prepared = True
            state.cert_dir = None
            state.verifier = None
            state.prepare = lambda: None  # Handshake setup tested elsewhere; isolate forwarding lifetime.
            state.wait_ready = lambda: env.run('endpoint')
            env.ns['wait_critical_processes'] = lambda dut: events.append('health')
            actual = env.run
            def run(action, spec=None):
                events.append(action)
                # Model only service supervisor API; all configuration/guard/
                # persistent/file actions below execute the production program.
                if action in ('stop', 'start', 'persistent-verify'):
                    if action == 'persistent-verify':
                        assert adapter.startup_evidence(env.persistent) == expected_file
                    return
                if action == 'syslog-apply' and failure == 'apply':
                    actual(action, spec)
                    pytest.fail('injected-apply')
                if action == 'syslog-restore' and failure == 'context-restore':
                    actual(action, spec)
                    pytest.fail('injected-context-restore')
                if action == 'discard':
                    assert env.conn.data == expected_raw
                    assert adapter.startup_evidence(env.persistent) == expected_file
                    events.append('native-original-exact')
                    return  # Keep private synthetic artifacts; root lstat is modeled.
                return actual(action, spec)
            state.dut_files.run = run
            env.state = state
            env.original = original
            env.expected_raw = expected_raw
            env.expected_file = expected_file
            return [env]

        @pytest.fixture
        def ptfhost(): return Mock()
        @pytest.fixture
        def gnmi_original_service_verifier(): return None
        def _get_target_duthost(duthosts, request): return duthosts[0]
        def NativeTlsState(dut, ptf, verifier=None): return dut.state
        def _establish_gnoi_tls_handshake(*args, **kwargs): pass
        def _tls_client_fixture(dut, ptf, cert_dir):
            return SimpleNamespace(duthost=dut, pygnmi_client=Mock())
    ''')
    tree = ast.parse(GRPC.read_text())
    production = '\n\n'.join(ast.unparse(node) for node in tree.body
                             if getattr(node, 'name', '') in ('_gnmi_same_image_tls_flow', 'gnmi_same_image_tls'))
    prelude = prelude.replace('ADAPTER', repr(str(Path(__file__).resolve()))).replace('FAILURE', repr(failure))
    (tmp_path / 'conftest.py').write_text(prelude + fixtures + production)
    (tmp_path / 'pytest.ini').write_text('[pytest]\n')
    (tmp_path / 'test_forwarding.py').write_text(textwrap.dedent('''
        import json
        from copy import deepcopy
        from unittest.mock import Mock
        import pytest
        from conftest import adapter, events, failure

        @pytest.mark.parametrize('operation', ['get', 'set'])
        def test_forwarding(gnmi_same_image_tls, operation):
            env = gnmi_same_image_tls.duthost
            pool, result, dut = Mock(), Mock(), Mock()
            result.ready.return_value = True
            dut.shell.side_effect = lambda command, **kwargs: ((pool, result) if kwargs.get('module_async')
                                                               else {'rc': 0})
            if failure == 'capture-close':
                pool.close.side_effect = pytest.fail.Exception('injected-capture-close')
            capture = adapter.load_capture({})
            with capture(dut, adapter.DESTINATION,
                         configuration=env.state.remote_syslog(adapter.DESTINATION)):
                events.append('body-' + operation)
                if operation == 'set':
                    current = deepcopy(env.original)
                    current['SYSLOG_SERVER'][adapter.DESTINATION] = {'port': '514'}
                    env.persistent.write_text(json.dumps(current))
                if failure == 'body':
                    pytest.fail('injected-body')
                if failure == 'image':
                    env.image = 'replacement'
            assert env.conn.data == env.expected_raw
            events.append('context-original-exact')
    '''))
    result = subprocess.run([sys.executable, '-m', 'pytest', '-q', 'test_forwarding.py'],
                            cwd=tmp_path, text=True, capture_output=True)
    (tmp_path / 'subprocess-output.txt').write_text(result.stdout + result.stderr)
    assert result.returncode == (0 if failure is None else 1), result.stdout + result.stderr
    assert 'restoration failed: DUT recovery cleanup' not in result.stdout, result.stdout
    if failure and failure != 'image':
        assert 'injected-' + failure in result.stdout, result.stdout
    events = json.loads((tmp_path / 'events.json').read_text())
    assert events.count('analyzer-check') == events.count('generic-check') == 2
    for start in [index for index, event in enumerate(events) if event == 'generic-start']:
        finish = events.index('generic-check', start)
        case = events[start:finish + 1]
        assert case.index('syslog-restore') < case.index('image') < case.index('analyzer-check')
        assert case[-1] == 'generic-check'
        if failure != 'image':
            assert case.index('syslog-restore') < case.index('config') < case.index('persistent-restore')
            assert case.index('native-original-exact') < case.index('analyzer-check')
        else:
            assert 'config' not in case and 'persistent-restore' not in case
            assert 'ptf:restore' in case


@pytest.mark.parametrize('startup_kind', ['absent-file', 'absent-table', 'empty-table', 'null-row', 'symlink'])
def test_forwarding_preserves_startup_existence_and_row_shape(production_remote, startup_kind):
    env = production_remote
    original = {}
    path = env.persistent
    if startup_kind in ('empty-table', 'null-row'):
        original['SYSLOG_SERVER'] = {} if startup_kind == 'empty-table' else {DESTINATION: None}
    if startup_kind != 'absent-file':
        seed_persistent(env, original)
    if startup_kind == 'symlink':
        target = path.with_name('startup-target.json')
        path.rename(target)
        path.symlink_to(target.name)
        path = target
    expected = startup_evidence(path) if path.exists() else None
    leaf_mtime = os.lstat(env.persistent).st_mtime_ns if startup_kind == 'symlink' else None
    env.run('baseline')
    with forwarding_owner(env).remote_syslog(DESTINATION):
        path.write_text(json.dumps({'SYSLOG_SERVER': {DESTINATION: {'port': '514'}}}))
    env.run('config')
    env.run('persistent-restore')
    assert (startup_evidence(path) if path.exists() else None) == expected
    if startup_kind == 'symlink':
        assert env.persistent.is_symlink()
        assert os.lstat(env.persistent).st_mtime_ns == leaf_mtime
    assert env.conn.data == {} and env.output == []


@pytest.mark.parametrize('action', ['syslog-save', 'syslog-apply', 'syslog-restore'])
def test_forwarding_unregistered_new_running_destination_fails_before_writes(production_remote, action):
    env = production_remote
    seed_forwarding(env)
    env.run('baseline')
    if action != 'syslog-save':
        env.run('syslog-save', (DESTINATION, None))
    if action == 'syslog-restore':
        env.run('syslog-apply')
    env.conn.data[b'SYSLOG_SERVER|192.0.2.99'] = {b'port': b'514'}
    env.conn.writes.clear()
    with pytest.raises(RuntimeError, match='syslog drift'):
        env.run(action, (DESTINATION, None))
    assert env.conn.writes == []


def test_forwarding_actual_action_raw_verification_rejects_normalization(production_remote):
    env = production_remote
    seed_forwarding(env, {b'extra': b'None', b'NULL': b'NULL'})
    original_decoded = env.decoded()
    env.run('baseline')
    env.run('syslog-save', (DESTINATION, None))
    env.run('syslog-apply')
    env.conn.corrupt = True
    with pytest.raises(RuntimeError, match='syslog drift'):
        env.run('syslog-restore')
    assert env.decoded() == original_decoded
    assert env.output == []


@pytest.mark.parametrize('failure', ['before-execute', 'watch-conflict'])
def test_forwarding_transaction_failure_never_commits_partial_row(production_remote, monkeypatch, failure):
    env = production_remote
    seed_forwarding(env, {b'port': b'6514', b'extra': b'None'})
    env.run('baseline')
    env.run('syslog-save', (DESTINATION, None))
    pipeline = env.conn.pipeline

    def transaction():
        value = pipeline()
        execute = value.execute

        def fail():
            if failure == 'watch-conflict':
                env.conn.data[SYSLOG_KEY][b'unknown-writer'] = b'changed'
                return execute()
            raise RuntimeError('synthetic transaction failure')
        value.execute = fail
        return value
    monkeypatch.setattr(env.conn, 'pipeline', transaction)
    with pytest.raises(RuntimeError):
        env.run('syslog-apply')
    assert env.conn.writes == []
    assert env.conn.data[SYSLOG_KEY][b'port'] == b'6514'


def test_forwarding_controller_transmits_only_public_destination_not_raw_state():
    ns = load()
    host = Mock()
    host.shell.return_value = {'rc': 0, 'stdout': '', 'stderr': ''}
    remote = ns['RemoteState'](host, [])
    remote.private_row = {'key': 'SYNTHETIC_OLD_SYSLOG_SECRET'}
    remote.run('syslog-save', (DESTINATION, 'mgmt'))
    command = host.shell.call_args.args[0]
    assert DESTINATION in command and 'SYNTHETIC_OLD_SYSLOG_SECRET' not in command
    assert command.endswith(' >/dev/null 2>&1')


def test_forwarding_failed_registration_never_enters_mutation_or_cleanup(owner):
    _, state, events = owner

    def fail(action, spec=None):
        events.append(action)
        raise pytest.fail.Exception('registration refused')
    state.dut_files.run.side_effect = fail
    with pytest.raises(pytest.fail.Exception, match='registration refused'):
        with state.remote_syslog(DESTINATION):
            pytest.fail('must not enter')
    assert events == ['syslog-save']


def test_forwarding_body_and_cleanup_failures_remain_chained(owner):
    _, state, _ = owner

    def run(action, spec=None):
        if action == 'syslog-restore':
            raise RuntimeError('cleanup failed')
    state.dut_files.run.side_effect = run
    with pytest.raises(RuntimeError, match='cleanup failed') as failure:
        with state.remote_syslog(DESTINATION):
            pytest.fail('body failed')
    assert isinstance(failure.value.__context__, pytest.fail.Exception)
    assert 'body failed' in str(failure.value.__context__)


@pytest.mark.parametrize('metadata', ['mode', 'mtime-only'])
def test_forwarding_metadata_drift_is_not_blessed(production_remote, metadata):
    env = production_remote
    seed_forwarding(env)
    env.run('baseline')
    env.run('syslog-save', (DESTINATION, None))
    env.run('syslog-apply')
    env.run('syslog-restore')
    if metadata == 'mode':
        os.chmod(env.persistent, 0o600)
    else:
        os.utime(env.persistent, ns=(1234567891000000000, 1234567891000000000))
    before = startup_evidence(env.persistent)
    env.conn.writes.clear()
    with pytest.raises(RuntimeError):
        env.run('persistent-restore')
    assert env.conn.writes == [] and startup_evidence(env.persistent) == before


def test_forwarding_host_namespace_running_snapshot_not_multi_asic_wrapper(production_remote, monkeypatch):
    env = production_remote
    original = seed_forwarding(env, {b'port': b'6514', b'extra': b'None'}, {'port': '1514'})
    expected = startup_evidence(env.persistent)
    updater = sys.modules['generic_config_updater.generic_updater']
    monkeypatch.setattr(updater, 'get_config_json', lambda: {'localhost': env.decoded(), 'asic0': {}})
    env.run('baseline')
    with forwarding_owner(env).remote_syslog(DESTINATION):
        pass
    # A writer persisting the restored host running row is still exact known
    # destination ownership, not adoption of GCU's all-namespace wrapper.
    original['SYSLOG_SERVER'][DESTINATION] = env.decoded()['SYSLOG_SERVER'][DESTINATION]
    env.persistent.write_text(json.dumps(original))
    env.run('config')
    env.run('persistent-restore')
    assert startup_evidence(env.persistent) == expected
