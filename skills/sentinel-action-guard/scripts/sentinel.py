#!/usr/bin/env python3
"""Bounded artifact MCP supervisor; Guardian owns decisions on private pipes."""
from __future__ import annotations

import argparse
from collections import deque
import fcntl
import select
import socket
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import selectors
import shutil
import stat
import subprocess
import sys
import termios
import time

MAX_TEXT = 16384
MAX_LINE = 131072
MAX_REQUESTS = 1024
PROTOCOL = '2025-11-25'
SKILL = Path(__file__).resolve().parents[1]
ID_RE = re.compile(r'[a-z0-9][a-z0-9-]{0,63}\Z')
FILE_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z')
DEFAULT = {'version': 1, 'slots': {
    'draft': {'file': 'draft.md', 'decision': 'allow'},
    'reviewed': {'file': 'reviewed.md', 'decision': 'ask'},
    'locked': {'file': 'locked.md', 'decision': 'deny'}}}


class Invalid(ValueError):
    pass


def unique(pairs):
    obj = {}
    for k, v in pairs:
        if k in obj:
            raise Invalid('duplicate JSON key')
        obj[k] = v
    return obj


def loads(raw):
    def bad_constant(_):
        raise Invalid('nonfinite JSON number')
    return json.loads(raw, object_pairs_hook=unique, parse_constant=bad_constant)


def exact(obj, keys):
    if not isinstance(obj, dict) or set(obj) != set(keys):
        raise Invalid('unexpected or missing fields')


def encoded(obj):
    return (json.dumps(obj, ensure_ascii=True, allow_nan=False, separators=(',', ':'))+'\n').encode()


def write_all(fd, data):
    view = memoryview(data)
    while view:
        try:
            n = os.write(fd, view)
        except BlockingIOError:
            if not select.select([], [fd], [], 10)[1]:
                raise OSError('output channel timeout')
            continue
        if n <= 0:
            raise OSError('short write')
        view = view[n:]


def regular(fd):
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        raise Invalid('not a regular file')


def bounded_read(fd, limit):
    regular(fd)
    chunks = bytearray()
    while len(chunks) <= limit:
        chunk = os.read(fd, min(65536, limit+1-len(chunks)))
        if not chunk:
            return bytes(chunks)
        chunks.extend(chunk)
    raise Invalid('file exceeds size limit')


def config_check(config):
    exact(config, ['version', 'slots'])
    if type(config['version']) is not int or config['version'] != 1:
        raise Invalid('unsupported config version')
    slots = config['slots']
    if not isinstance(slots, dict) or not 1 <= len(slots) <= 32:
        raise Invalid('expected 1 to 32 enrolled slots')
    names = set()
    for slot, item in slots.items():
        if not ID_RE.fullmatch(slot):
            raise Invalid('invalid slot identifier')
        exact(item, ['file', 'decision'])
        if not isinstance(item['file'], str) or not FILE_RE.fullmatch(item['file']):
            raise Invalid('slot requires a single safe filename')
        if item['file'] in names or item['decision'] not in ['allow', 'ask', 'deny']:
            raise Invalid('duplicate filename or invalid decision')
        names.add(item['file'])
    return config


class Store:
    """Pinned directory descriptors; actor strings never become paths."""
    def __init__(self, root):
        root = Path(root).absolute()
        if root != root.resolve(strict=True):
            raise Invalid('use a canonical store path without symlinks')
        self.root = root
        self.fds = []
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        try:
            self.rootfd = os.open(root, flags)
            self.fds.append(self.rootfd)
            self.artfd = os.open('artifacts', flags, dir_fd=self.rootfd)
            self.fds.append(self.artfd)
            self.ctrlfd = os.open('control', flags, dir_fd=self.rootfd)
            self.fds.append(self.ctrlfd)
            for fd in self.fds:
                info = os.fstat(fd)
                if info.st_uid != os.getuid() or info.st_mode & 0o077:
                    raise Invalid('store directories must be private and owned by this user')
            lockfd = os.open('operator.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW |
                             os.O_CLOEXEC, 0o600, dir_fd=self.ctrlfd)
            self.fds.append(lockfd)
            regular(lockfd)
            fcntl.flock(lockfd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            fd = os.open('config.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                         dir_fd=self.rootfd)
            try:
                self.config = config_check(loads(bounded_read(fd, 16384).decode('utf-8')))
            finally:
                os.close(fd)
            try:
                info = os.stat('audit.sqlite3', dir_fd=self.ctrlfd, follow_symlinks=False)
                if not stat.S_ISREG(info.st_mode):
                    raise Invalid('unsafe audit file')
            except FileNotFoundError:
                pass
            self.logfd = os.open('executor.jsonl', os.O_WRONLY | os.O_APPEND | os.O_CREAT |
                                 os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=self.ctrlfd)
            self.fds.append(self.logfd)
            regular(self.logfd)
            self.identities = [self.identity(x) for x in [self.rootfd, self.artfd, self.ctrlfd]]
        except BaseException:
            self.close()
            raise

    @staticmethod
    def identity(fd):
        s = os.fstat(fd)
        return s.st_dev, s.st_ino

    def validate(self):
        values = [os.stat(self.root, follow_symlinks=False),
                  os.stat('artifacts', dir_fd=self.rootfd, follow_symlinks=False),
                  os.stat('control', dir_fd=self.rootfd, follow_symlinks=False)]
        for value, ident in zip(values, self.identities):
            if not stat.S_ISDIR(value.st_mode) or (value.st_dev, value.st_ino) != ident:
                raise Invalid('enrolled directory changed')

    def receipt(self, data):
        write_all(self.logfd, encoded(data))
        os.fsync(self.logfd)

    def execute(self, request, guard):
        self.validate()
        if not guard():
            raise Invalid('operation cancelled or approval expired')
        slot = request['slot']
        filename = self.config['slots'][slot]['file']
        common = {'request_id': request['args']['request_id'], 'slot': slot,
                  'operation': request['operation']}
        self.receipt({**common, 'stage': 'attempt', 'attempted': True, 'committed': False})
        committed = False
        temp = None
        try:
            if request['operation'] == 'read':
                fd = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK |
                             os.O_CLOEXEC, dir_fd=self.artfd)
                try:
                    raw = bounded_read(fd, MAX_TEXT)
                finally:
                    os.close(fd)
                content = raw.decode('utf-8', errors='strict')
                result = {'slot': slot, 'bytes': len(raw),
                          'sha256': hashlib.sha256(raw).hexdigest()}
                request['read_content'] = content
            else:
                raw = request['content'].encode('utf-8')
                # Write privately, then atomically link without replacement. A failed
                # or cancelled commit cannot leave a partial destination artifact.
                temp = '.pending-'+secrets.token_hex(16)
                fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                             os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=self.ctrlfd)
                try:
                    write_all(fd, raw)
                    os.fsync(fd)
                finally:
                    os.close(fd)
                self.validate()
                if not guard():
                    raise Invalid('operation cancelled or approval expired')
                os.link(temp, filename, src_dir_fd=self.ctrlfd, dst_dir_fd=self.artfd,
                        follow_symlinks=False)
                committed = True
                os.fsync(self.artfd)
                result = {'slot': slot, 'bytes': len(raw),
                          'sha256': hashlib.sha256(raw).hexdigest(), 'created': True}
            self.receipt({**common, 'stage': 'result', 'attempted': False,
                          'committed': committed, **result})
            return result
        except BaseException:
            # A failure after link is an unknown delivery outcome, never "no effect".
            request['commit_observed'] = committed
            raise
        finally:
            if temp is not None:
                try:
                    os.unlink(temp, dir_fd=self.ctrlfd)
                except FileNotFoundError:
                    pass

    def close(self):
        for fd in reversed(self.fds):
            os.close(fd)
        self.fds.clear()


class Lines:
    def __init__(self):
        self.buffer = bytearray()

    def feed(self, data):
        self.buffer.extend(data)
        lines = []
        while b'\n' in self.buffer:
            at = self.buffer.index(10)
            if at > MAX_LINE:
                raise Invalid('line exceeds size limit')
            lines.append(bytes(self.buffer[:at]))
            del self.buffer[:at+1]
        if len(self.buffer) > MAX_LINE:
            raise Invalid('line exceeds size limit')
        return lines


class Outbox:
    """Bounded nonblocking output; a stopped reader cannot hold approval open."""
    def __init__(self, fd):
        self.fd = fd
        self.parts = deque()
        self.size = 0

    def put(self, data):
        if self.size+len(data) > 262144:
            raise Invalid('output backlog limit reached')
        self.parts.append([memoryview(data), time.monotonic()+2])
        self.size += len(data)

    def flush(self):
        budget = 65536
        while self.parts and budget:
            view, deadline = self.parts[0]
            if time.monotonic() >= deadline:
                raise Invalid('output reader unavailable')
            try:
                count = os.write(self.fd, view[:budget])
            except BlockingIOError:
                return
            if count <= 0:
                raise OSError('output channel closed')
            self.size -= count
            budget -= count
            if count == len(view):
                self.parts.popleft()
            else:
                self.parts[0][0] = view[count:]


class Supervisor:
    def __init__(self, options):
        self.options = options
        self.store = Store(options.root)
        self.select = selectors.DefaultSelector()
        self.actor_lines, self.engine_lines, self.tty_lines = Lines(), Lines(), Lines()
        self.active = None
        self.counter = 0
        self.seen = set()
        self.initialized = False
        self.ready = False
        self.actor_closed = False
        self.nonce = secrets.token_hex(16)
        self.child = None
        self.tty = None
        self.listener = None
        self.connection = None
        self.runfd = None
        self.socket_identity = None
        self.run_identity = None
        self.actor_in = sys.stdin.fileno() if options.command == 'serve' else None
        self.actor_out = sys.stdout.fileno() if options.command == 'serve' else None
        self.outbox = Outbox(self.actor_out) if self.actor_out is not None else None
        self.tty_outbox = None
        self.actor_pending = deque()
        self.input_busy = False

    def send(self, obj):
        self.outbox.put(encoded(obj))

    def error(self, ident, message, code=-32602):
        self.send({'jsonrpc': '2.0', 'id': ident, 'error': {'code': code, 'message': message}})

    def result(self, ident, result):
        self.send({'jsonrpc': '2.0', 'id': ident, 'result': result})

    def child_send(self, obj):
        write_all(self.child.stdin.fileno(), encoded(obj))

    def binding(self):
        a = self.active
        return {'call_id': a['call_id'], 'nonce': self.nonce,
                'request_id': a['args']['request_id'], 'sha256': a['args']['sha256']}

    def tools(self):
        slots = sorted(self.store.config['slots'])
        prop = {'slot': {'type': 'string', 'enum': slots}}
        return [
            {'name': 'read_artifact', 'description': 'Read one enrolled UTF8 artifact (16KiB limit).',
             'inputSchema': {'type': 'object', 'properties': prop,
                             'required': ['slot'], 'additionalProperties': False}},
            {'name': 'write_artifact', 'description': 'Create a new enrolled artifact. Review may require the separate human terminal; existing files are never overwritten.',
             'inputSchema': {'type': 'object', 'properties': {**prop, 'content': {
                 'type': 'string', 'maxLength': MAX_TEXT, 'description': 'At most16384UTF8bytes.'}},
                 'required': ['slot', 'content'], 'additionalProperties': False}}]

    def actor_message(self, raw):
        ident = None
        try:
            request = loads(raw.decode('utf-8'))
            if not isinstance(request, dict) or request.get('jsonrpc') != '2.0':
                raise Invalid('expected JSON-RPC object')
            if set(request)-{'jsonrpc', 'id', 'method', 'params'}:
                raise Invalid('unknown JSON-RPC fields')
            method = request.get('method')
            if not isinstance(method, str):
                raise Invalid('missing method')
            params = request.get('params', {})
            if 'id' not in request:
                if method == 'notifications/initialized' and self.initialized:
                    self.ready = True
                elif method == 'notifications/cancelled' and isinstance(params, dict):
                    a = self.active
                    if a and type(params.get('requestId')) is type(a['id']) and params.get('requestId') == a['id']:
                        a['cancelled'] = True
                        self.deny_pending()
                return  # Unknown notifications cannot run a tool.
            ident = request['id']
            if type(ident) not in [str, int] or isinstance(ident, str) and not 1 <= len(ident.encode('utf-8')) <= 256:
                raise Invalid('invalid request ID')
            key = (type(ident), ident)
            if key in self.seen:
                raise Invalid('request ID already used in this run')
            if len(self.seen) >= MAX_REQUESTS:
                raise Invalid('request limit reached; start a new run')
            self.seen.add(key)
            if method == 'initialize':
                if self.initialized or not isinstance(params, dict) or not isinstance(params.get('protocolVersion'), str):
                    raise Invalid('invalid or repeated initialization')
                self.initialized = True
                self.result(ident, {'protocolVersion': PROTOCOL, 'capabilities': {'tools': {}},
                                   'serverInfo': {'name': 'sentinel-action-guard', 'version': '0.1.0'}})
            elif method == 'ping':
                self.result(ident, {})
            elif not self.ready:
                raise Invalid('initialize and send notifications/initialized first')
            elif method == 'tools/list':
                self.result(ident, {'tools': self.tools()})
            elif method == 'tools/call':
                self.start_call(ident, params)
            else:
                self.error(ident, 'method not found', -32601)
        except (Invalid, ValueError, TypeError, UnicodeError, RecursionError):
            # Malformed input is not a source of execution or approval capability.
            safe_id = ident if type(ident) in [str, int] else None
            self.error(safe_id, 'invalid request or parameters')

    def start_call(self, ident, params):
        if not isinstance(params, dict) or set(params)-{'name', 'arguments', '_meta'} or not {'name', 'arguments'} <= set(params):
            raise Invalid('invalid tools/call parameters')
        name, args = params['name'], params['arguments']
        if name not in ['read_artifact', 'write_artifact']:
            raise Invalid('unknown tool')
        operation = 'read' if name == 'read_artifact' else 'write'
        exact(args, ['slot'] if operation == 'read' else ['slot', 'content'])
        slot = args['slot']
        if not isinstance(slot, str) or slot not in self.store.config['slots']:
            raise Invalid('unknown slot')
        content = args.get('content', '')
        if not isinstance(content, str):
            raise Invalid('expected text content')
        raw = content.encode('utf-8', errors='strict')
        if len(raw) > MAX_TEXT:
            raise Invalid('text exceeds size limit')
        if self.active:
            self.error(ident, 'another operation is still pending', -32001)
            return
        self.counter += 1
        item = self.store.config['slots'][slot]
        tool = 'artifact.read' if operation == 'read' else 'artifact.write.'+item['decision']
        meta = {'request_id': self.nonce+':'+str(self.counter), 'slot': slot,
                'path': str(self.store.root/'artifacts'/item['file']),
                'sha256': hashlib.sha256(raw).hexdigest() if operation == 'write' else '',
                'bytes': len(raw) if operation == 'write' else 0}
        self.active = {'id': ident, 'call_id': self.counter, 'args': meta, 'slot': slot,
                       'operation': operation, 'content': content, 'decision': item['decision'],
                       'cancelled': False, 'approved': False, 'waiting': False,
                       'executed': False, 'deadline': time.monotonic()+self.options.approval_timeout}
        self.child_send({'op': 'call', 'id': self.counter, 'tool': tool, 'args': meta})

    def drain_actor(self):
        byte_budget, message_budget = 65536, 32
        self.input_busy = True
        while not self.actor_closed and self.actor_in is not None and message_budget:
            if self.actor_pending:
                self.actor_message(self.actor_pending.popleft())
                message_budget -= 1
                continue
            if byte_budget <= 0:
                return
            try:
                data = os.read(self.actor_in, min(32768, byte_budget))
            except BlockingIOError:
                self.input_busy = False
                return
            if not data:
                self.actor_closed = True
                self.input_busy = False
                if self.active:
                    self.active['cancelled'] = True
                self.deny_pending()
                return
            byte_budget -= len(data)
            self.actor_pending.extend(line for line in self.actor_lines.feed(data) if line.strip())
            if len(self.actor_pending) > 256:
                raise Invalid('input backlog limit reached')

    def deny_pending(self):
        if self.active and self.active['waiting']:
            self.child_send({'op': 'approval', **self.binding(), 'decision': False})
            self.active['waiting'] = False

    def guard(self):
        self.drain_actor()
        a = self.active
        return (not self.actor_closed and not a['cancelled'] and
                not self.input_busy and not self.actor_pending and not self.actor_lines.buffer and
                (a['operation'] == 'read' or a['decision'] == 'allow' or
                 a['approved'] and time.monotonic() < a['deadline']))

    def engine_message(self, raw):
        event = loads(raw.decode('utf-8'))
        if not isinstance(event, dict) or not self.active:
            raise Invalid('unexpected mediator message')
        a = self.active
        if event.get('call_id') != a['call_id'] or type(event.get('call_id')) is not int:
            raise Invalid('mediator request mismatch')
        kind = event.get('event')
        if kind in ['approval', 'execute']:
            exact(event, ['event', 'call_id', 'nonce', 'args'])
            if event['nonce'] != self.nonce or event['args'] != a['args']:
                raise Invalid('mediator metadata mismatch')
            if kind == 'approval':
                if a['operation'] != 'write' or a['decision'] != 'ask' or a.get('challenged'):
                    raise Invalid('unexpected approval request')
                a['challenged'] = True
                a['waiting'] = True
                if a['cancelled'] or self.actor_closed:
                    self.deny_pending()
                    return
                termios.tcflush(self.tty, termios.TCIFLUSH)
                self.tty_lines = Lines()
                a['challenge'] = secrets.token_hex(16)
                a['deadline'] = time.monotonic()+self.options.approval_timeout
                prompt = '\nSentinel review (JSON-escaped exact content)\n'+json.dumps({
                    'slot': a['slot'], 'path': a['args']['path'], 'bytes': a['args']['bytes'],
                    'sha256': a['args']['sha256'], 'content': a['content']}, ensure_ascii=True)+'\n'
                prompt += 'To create these exact bytes, type approve '+a['challenge']+'\n> '
                self.tty_outbox.put(prompt.encode())
            else:
                if a['executed']:
                    raise Invalid('repeated executor invocation')
                a['executed'] = True
                try:
                    receipt = self.store.execute(a, self.guard)
                    a['receipt'] = receipt
                    reply = {'ok': True, 'result': receipt}
                except (OSError, Invalid, UnicodeError):
                    reply = {'ok': False, 'result': None}
                self.child_send({'op': 'execute', **self.binding(), **reply})
        elif kind == 'result':
            exact(event, ['event', 'call_id', 'status', 'detail'])
            if event['status'] == 'allowed':
                if not a['executed'] or 'receipt' not in a or event['detail'] != a['receipt']:
                    raise Invalid('unverified execution receipt')
                result = dict(a['receipt'])
                if a['operation'] == 'read':
                    result['content'] = a['read_content']
                if not a['cancelled'] and not self.actor_closed:
                    self.result(a['id'], {'content': [{'type': 'text', 'text': json.dumps(result, ensure_ascii=True)}], 'isError': False})
            elif event['status'] in ['blocked', 'upstream_error']:
                if not a['cancelled'] and not self.actor_closed:
                    msg = ('Delivery outcome unknown; inspect the slot before retrying.'
                           if a.get('commit_observed') else 'Operation blocked or could not be completed.')
                    self.error(a['id'], msg, -32000)
            else:
                raise Invalid('unknown mediator status')
            self.active = None
        else:
            raise Invalid('unknown mediator event')

    def terminal_message(self, line):
        a = self.active
        if a and a['waiting']:
            ok = (line.decode('utf-8', errors='replace').rstrip('\r') == 'approve '+a['challenge']
                  and not self.tty_outbox.size and not a['cancelled'] and time.monotonic() < a['deadline'])
            a['approved'] = ok
            self.child_send({'op': 'approval', **self.binding(), 'decision': ok})
            a['waiting'] = False

    def listen_actor(self):
        self.store.validate()
        self.run_name = 'run-'+self.nonce
        os.mkdir(self.run_name, 0o700, dir_fd=self.store.ctrlfd)
        info = os.stat(self.run_name, dir_fd=self.store.ctrlfd, follow_symlinks=False)
        self.run_identity = (info.st_dev, info.st_ino)
        self.runfd = os.open(self.run_name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                             os.O_CLOEXEC, dir_fd=self.store.ctrlfd)
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        # Both processes use their own held directory FD. This avoids AF_UNIX's
        # short pathname limit without placing sockets in a global shared folder.
        self.listener.bind('/proc/self/fd/'+str(self.runfd)+'/actor.sock')
        os.chmod('actor.sock', 0o600, dir_fd=self.runfd)
        info = os.stat('actor.sock', dir_fd=self.runfd, follow_symlinks=False)
        self.socket_identity = (info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode))
        self.listener.listen(1)
        self.listener.setblocking(False)
        self.select.register(self.listener.fileno(), selectors.EVENT_READ, 'listener')
        command = [sys.executable, str(Path(__file__).resolve()), 'connect',
                   '--root', str(self.store.root), '--run', self.nonce]
        print(json.dumps({'root': str(self.store.root), 'run': self.nonce,
                          'command': command}), flush=True)

    def accept_actor(self):
        connection, _ = self.listener.accept()
        try:
            # Local permissions are hygiene, not a same-UID process sandbox.
            import struct
            _, uid, _ = struct.unpack('3i', connection.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i')))
            if uid != os.getuid():
                raise Invalid('actor connection owner mismatch')
            connection.setblocking(False)
            self.connection = connection
            self.actor_in = self.actor_out = connection.fileno()
            self.outbox = Outbox(self.actor_out)
            self.select.unregister(self.listener.fileno())
            self.listener.close()
            self.listener = None
            self.select.register(self.actor_in, selectors.EVENT_READ, 'actor')
        except BaseException:
            connection.close()
            raise

    def cleanup_actor(self):
        if self.runfd is None:
            return
        try:
            info = os.stat(self.run_name, dir_fd=self.store.ctrlfd, follow_symlinks=False)
            if not stat.S_ISDIR(info.st_mode) or (info.st_dev, info.st_ino) != self.run_identity:
                print('Sentinel left replaced run directory untouched.', file=sys.stderr)
                return
            try:
                info = os.stat('actor.sock', dir_fd=self.runfd, follow_symlinks=False)
                identity = (info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode))
                if self.socket_identity is None or identity != self.socket_identity:
                    print('Sentinel left replaced actor socket path untouched.', file=sys.stderr)
                    return
                os.unlink('actor.sock', dir_fd=self.runfd)
            except FileNotFoundError:
                pass
            try:
                os.rmdir(self.run_name, dir_fd=self.store.ctrlfd)
            except OSError:
                print('Sentinel left nonempty run directory untouched.', file=sys.stderr)
        except FileNotFoundError:
            pass
        finally:
            os.close(self.runfd)
            self.runfd = None

    def run(self):
        try:
            if self.options.command == 'serve' and os.isatty(self.actor_in):
                raise Invalid('actor MCP input must be a pipe, separate from the human terminal')
            self.tty = os.open('/dev/tty', os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK | os.O_CLOEXEC)
            if not os.isatty(self.tty):
                raise Invalid('a separate controlling operator terminal is required')
            self.tty_outbox = Outbox(self.tty)
            if self.actor_in is not None:
                os.set_blocking(self.actor_in, False)
                os.set_blocking(self.actor_out, False)
            policy = SKILL/'runtime/policy.toml'
            self.child = subprocess.Popen([str(Path(self.options.engine).resolve(strict=True)),
                str(policy), str(self.store.root/'control/audit.sqlite3'), self.nonce],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=sys.stderr, close_fds=True)
            os.set_blocking(self.child.stdout.fileno(), False)
            self.select.register(self.child.stdout.fileno(), selectors.EVENT_READ, 'engine')
            self.select.register(self.tty, selectors.EVENT_READ, 'tty')
            started = False
            startup_deadline = time.monotonic()+10
            while not self.actor_closed:
                for key, _ in self.select.select(0.1):
                    if key.data == 'listener':
                        self.accept_actor()
                    elif key.data == 'actor':
                        if started:
                            self.drain_actor()
                    elif key.data == 'tty':
                        data = os.read(self.tty, 4096)
                        if not data:
                            self.deny_pending()
                            raise Invalid('operator terminal closed')
                        for line in self.tty_lines.feed(data):
                            self.terminal_message(line)
                    else:
                        data = os.read(self.child.stdout.fileno(), 65536)
                        if not data:
                            raise Invalid('mediator unavailable; no direct execution fallback')
                        for line in self.engine_lines.feed(data):
                            if not started:
                                if loads(line.decode()) != {'event': 'ready', 'protocol': 1}:
                                    raise Invalid('invalid mediator startup')
                                started = True
                                if self.options.command == 'operator':
                                    self.listen_actor()
                                else:
                                    self.select.register(self.actor_in, selectors.EVENT_READ, 'actor')
                            else:
                                self.engine_message(line)
                if not started and time.monotonic() >= startup_deadline:
                    raise Invalid('mediator startup timeout')
                if self.active and self.active['waiting'] and time.monotonic() >= self.active['deadline']:
                    self.deny_pending()
                if self.actor_pending:
                    self.drain_actor()
                if not self.actor_closed and self.outbox is not None:
                    self.outbox.flush()
                self.tty_outbox.flush()
            return 0
        finally:
            if self.child:
                if self.child.poll() is None:
                    self.child.kill()
                self.child.wait()
            if self.tty is not None:
                os.close(self.tty)
            if self.connection is not None:
                self.connection.close()
            if self.listener is not None:
                self.listener.close()
            self.cleanup_actor()
            self.select.close()
            self.store.close()


def connect_actor(root, run):
    """Transport only: one connection, no approval verb or mutating-call replay."""
    if not re.fullmatch(r'[a-f0-9]{32}', run):
        raise Invalid('invalid run identifier')
    root = Path(root).absolute()
    if root != root.resolve(strict=True):
        raise Invalid('use the canonical operator store path')
    fds = []
    sock = None
    selector = selectors.DefaultSelector()
    try:
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        for name in [root, 'control', 'run-'+run]:
            fd = os.open(name, flags, **({'dir_fd': fds[-1]} if fds else {}))
            fds.append(fd)
            info = os.fstat(fd)
            if info.st_uid != os.getuid() or info.st_mode & 0o077:
                raise Invalid('operator directories must be private and owned by this user')
        info = os.stat('actor.sock', dir_fd=fds[-1], follow_symlinks=False)
        if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise Invalid('unsafe actor socket')
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect('/proc/self/fd/'+str(fds[-1])+'/actor.sock')
        sock.setblocking(False)
        os.set_blocking(sys.stdin.fileno(), False)
        os.set_blocking(sys.stdout.fileno(), False)
        selector.register(sys.stdin.fileno(), selectors.EVENT_READ, 'actor')
        selector.register(sock.fileno(), selectors.EVENT_READ, 'operator')
        inbound, outbound = Lines(), Lines()
        to_operator, to_actor = Outbox(sock.fileno()), Outbox(sys.stdout.fileno())
        operator_closed = False
        while True:
            for key, _ in selector.select(0.05):
                data = os.read(key.fd, 65536)
                if not data:
                    if key.data == 'actor':
                        return 0
                    operator_closed = True
                    selector.unregister(sock.fileno())
                    selector.unregister(sys.stdin.fileno())
                    break
                lines = inbound if key.data == 'actor' else outbound
                target = to_operator if key.data == 'actor' else to_actor
                for line in lines.feed(data):
                    target.put(line+b'\n')
            if not operator_closed:
                to_operator.flush()
            to_actor.flush()
            if operator_closed and not to_actor.size:
                return 1 if outbound.buffer else 0
    finally:
        if sock is not None:
            sock.close()
        selector.close()
        for fd in reversed(fds):
            os.close(fd)


def init_store(root):
    supplied = Path(root).absolute()
    try:
        os.stat(supplied, follow_symlinks=False)
    except FileNotFoundError:
        pass
    else:
        raise FileExistsError('store path already exists')
    path = supplied.parent.resolve(strict=True)/supplied.name
    path.mkdir(mode=0o700)  # Exclusive enrollment; no existing directory accepted.
    (path/'artifacts').mkdir(mode=0o700)
    (path/'control').mkdir(mode=0o700)
    fd = os.open(path/'config.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        write_all(fd, encoded(DEFAULT))
    finally:
        os.close(fd)
    print(json.dumps({'initialized': str(path), 'slots': DEFAULT['slots']}))


def build_engine(destination):
    destination = Path(destination).resolve()
    destination.mkdir(mode=0o700)
    shutil.copytree(SKILL/'runtime', destination/'source')
    for directory in ['cache', 'target', 'tmp']:
        (destination/directory).mkdir(mode=0o700)
    env = dict(os.environ, CARGO_HOME=str(destination/'cache'),
               CARGO_TARGET_DIR=str(destination/'target'), TMPDIR=str(destination/'tmp'))
    subprocess.run(['cargo', 'build', '--locked', '--jobs', '2', '-p', 'sentinel-engine'],
                   cwd=destination/'source', env=env, check=True)
    print(json.dumps({'engine': str(destination/'target/debug/sentinel-engine')}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('init').add_argument('root')
    sub.add_parser('build').add_argument('destination')
    for name in ['serve', 'operator']:
        serve = sub.add_parser(name)
        serve.add_argument('--root', required=True)
        serve.add_argument('--engine', required=True)
        serve.add_argument('--approval-timeout', type=float, default=60)
    bridge = sub.add_parser('connect')
    bridge.add_argument('--root', required=True)
    bridge.add_argument('--run', required=True)
    args = parser.parse_args()
    try:
        if args.command == 'init':
            init_store(args.root)
        elif args.command == 'build':
            build_engine(args.destination)
        elif args.command == 'connect':
            return connect_actor(args.root, args.run)
        else:
            if not 0.05 <= args.approval_timeout <= 300:
                raise Invalid('approval timeout must be0.05to300seconds')
            return Supervisor(args).run()
        return 0
    except (Invalid, OSError, ValueError, subprocess.SubprocessError) as exc:
        print('Sentinel stopped: '+str(exc), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
