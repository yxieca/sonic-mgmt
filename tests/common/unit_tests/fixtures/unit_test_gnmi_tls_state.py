"""Offline owner/command-construction regressions, NOT real transport proof."""
import ast
import base64
import builtins
from copy import deepcopy
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
    ns = dict(base64=base64, inspect=inspect, shlex=shlex, shutil=shutil, tempfile=tempfile, uuid=uuid,
              wait_until=lambda timeout, interval, delay, fn: fn())
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
        assert pattern == 'GNMI_CLIENT_CERT|*'
        return [k for k in self.data if k.startswith(b'GNMI_CLIENT_CERT|')]

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
        if str(path) == str(root):
            return SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=0)
        if str(path) in [str(p) for p in root.parents]:
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
        raise AssertionError('unexpected command')

    def connect(**kwargs):
        assert kwargs == dict(unix_socket_path='/synthetic/redis.sock', db=4, decode_responses=False,
                              socket_timeout=5, socket_connect_timeout=5)
        return conn

    def decoded():
        # Independent cfggen representation deliberately hides literal None and
        # NULL. Equality here CANNOT detect corrupted original raw values.
        return {k.decode(): {f.decode(): '' if v == b'None' else v.decode(errors='replace')
                             for f, v in fields.items() if f != b'NULL'}
                for k, fields in conn.data.items() if fields}

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
    env.run = lambda action: ns['_remote'](str(root), action, [])
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
