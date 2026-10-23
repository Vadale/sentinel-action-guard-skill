#!/usr/bin/env python3
"""Real Linux bridge/Gateway smoke test with a scripted, separate operator PTY."""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pty
import re
import select
import subprocess
import sys
import termios
import time


def line(stream, timeout=10):
    data = bytearray()
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not select.select([stream], [], [], max(0, deadline-time.monotonic()))[0]:
            break
        byte = os.read(stream.fileno(), 1)
        if not byte:
            raise RuntimeError('unexpected response EOF')
        data.extend(byte)
        if byte == b'\n':
            return json.loads(data)
        if len(data) > 131072:
            raise RuntimeError('oversized response')
    raise TimeoutError('response deadline')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--engine', required=True, type=Path)
    parser.add_argument('--work', required=True, type=Path)
    args = parser.parse_args()
    work = args.work.resolve()
    work.mkdir(mode=0o700)  # New destination only; never reuse another run.
    script = Path(__file__).resolve().parents[1]/'skills/sentinel-action-guard/scripts/sentinel.py'
    store = work/'store'
    subprocess.run([sys.executable, str(script), 'init', str(store)], check=True,
                   stdout=subprocess.PIPE)
    master, slave = pty.openpty()
    settings = termios.tcgetattr(slave)
    settings[3] &= ~termios.ECHO
    termios.tcsetattr(slave, termios.TCSANOW, settings)

    def terminal():
        os.setsid()
        fcntl.ioctl(slave, termios.TIOCSCTTY, 0)

    operator = actor = None
    results = []
    with (work/'operator.stderr').open('wb') as errors:
        try:
            operator = subprocess.Popen([sys.executable, str(script), 'operator',
                '--root', str(store), '--engine', str(args.engine.resolve()),
                '--approval-timeout', '10'], stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=errors, preexec_fn=terminal,
                pass_fds=(slave,), bufsize=0)
            os.close(slave)
            slave = None
            receipt = line(operator.stdout)
            actor = subprocess.Popen(receipt['command'], stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, stderr=errors, bufsize=0)
            ident = 0

            def send(method, params, notification=False):
                nonlocal ident
                ident += 1
                message = {'jsonrpc': '2.0', 'method': method, 'params': params}
                if not notification:
                    message['id'] = ident
                actor.stdin.write((json.dumps(message)+'\n').encode())
                return ident

            def receive(expected):
                response = line(actor.stdout)
                assert response.get('id') == expected, response
                return response

            def tool(name, values):
                return send('tools/call', {'name': name, 'arguments': values})

            def success(response):
                assert 'error' not in response, response
                assert not response['result'].get('isError'), response
                return json.loads(response['result']['content'][0]['text'])

            first = receive(send('initialize', {'protocolVersion': '2025-11-25',
                'capabilities': {}, 'clientInfo': {'name': 'public-smoke', 'version': '1'}}))
            assert first['result']['protocolVersion'] == '2025-11-25'
            send('notifications/initialized', {}, True)
            listed = receive(send('tools/list', {}))['result']['tools']
            assert {t['name'] for t in listed} == {'read_artifact', 'write_artifact'}

            draft = '# Batch note\nValidation failed; retry not authorized.\n'
            made = success(receive(tool('write_artifact', {'slot': 'draft', 'content': draft})))
            assert made['created'] is True and made['sha256'] == hashlib.sha256(draft.encode()).hexdigest()
            assert (store/'artifacts/draft.md').read_bytes() == draft.encode()
            read = success(receive(tool('read_artifact', {'slot': 'draft'})))
            assert read['content'] == draft and read['sha256'] == made['sha256']
            results.append('allow_exact_bytes_and_readback')

            journal = store/'control/executor.jsonl'
            before = journal.read_bytes()
            denied = receive(tool('write_artifact', {'slot': 'locked', 'content': 'must not appear'}))
            assert 'error' in denied and not (store/'artifacts/locked.md').exists()
            assert journal.read_bytes() == before
            results.append('deny_without_executor_or_artifact')

            reviewed = '# Reviewed note\nCause remains unknown.\n'
            pending = tool('write_artifact', {'slot': 'reviewed', 'content': reviewed})
            prompt = bytearray()
            deadline = time.monotonic()+5
            challenge = None
            while time.monotonic() < deadline:
                if select.select([master], [], [], 0.1)[0]:
                    prompt.extend(os.read(master, 65536))
                challenge = re.search(rb'type approve ([a-f0-9]{32})\r?\n> ', prompt)
                if challenge:
                    break
            assert challenge, prompt
            assert hashlib.sha256(reviewed.encode()).hexdigest().encode() in prompt
            assert not (store/'artifacts/reviewed.md').exists()
            assert not select.select([actor.stdout], [], [], 0.1)[0]
            os.write(master, b'approve '+challenge.group(1)+b'\n')
            accepted = success(receive(pending))
            assert accepted['created'] is True
            assert (store/'artifacts/reviewed.md').read_bytes() == reviewed.encode()
            results.append('separate_approval_pending_then_exact_commit')
            actor.stdin.close()
            assert actor.wait(timeout=5) == 0
            assert operator.wait(timeout=5) == 0
            report = {'status': 'PASS', 'checks': results,
                'supervisor_sha256': hashlib.sha256(script.read_bytes()).hexdigest(),
                'engine_sha256': hashlib.sha256(args.engine.read_bytes()).hexdigest(),
                'limits': ['Synthetic scripted operator; no human or named-client validation.',
                           'Only the bounded artifact tools are covered.']}
            (work/'result.json').write_text(json.dumps(report, indent=2)+'\n')
            print(json.dumps(report, indent=2))
            return 0
        finally:
            for process in [actor, operator]:
                if process and process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
            os.close(master)
            if slave is not None:
                os.close(slave)


if __name__ == '__main__':
    sys.exit(main())
