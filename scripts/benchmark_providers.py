"""Maintained real-provider and DNSx acceptance labs, confined to owned namespaces.

Ported from the accepted 2026-10-07 procedures. Public forwarding is absent;
durations are functional observations, not calibrated performance comparisons.
"""
from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import socket
import socketserver
import struct
import subprocess
import sys
import threading
import time
import traceback
import uuid

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
from scripts import benchmark as common
from scripts.benchmark import write_json as save
from scripts.benchmark_subdomain import process_identity as birth


def saved_names(path: Path) -> set[str]:
    """The passive writer terminates even an empty report with a newline."""
    return {name for name in path.read_text(encoding="utf-8").splitlines() if name}

# Amass 5.0.0 engine/plugins/support/resolvers.go, plus its wildcard resolver.
# These addresses are aliases of loopback ONLY inside the disposable namespace.
RESOLVER_ALIASES = ["1.0.0.1","1.1.1.1","138.197.140.189","149.112.112.112","149.112.121.10","149.112.122.10","156.154.70.5","156.157.71.5","162.243.19.47","176.103.130.130","176.103.130.131","185.228.168.9","185.228.169.9","2.56.220.2","205.171.2.65","205.171.3.65","208.67.220.220","208.67.222.222","209.244.0.3","209.244.0.4","209.88.198.133","216.146.35.35","216.146.36.36","216.87.84.211","23.90.4.6","37.235.1.177","38.132.106.139","64.6.64.6","64.6.65.6","74.82.42.42","76.223.122.150","76.76.10.0","76.76.19.19","76.76.2.0","77.88.8.1","77.88.8.8","78.47.64.161","8.20.247.20","8.26.56.26","8.8.4.4","8.8.8.8","80.80.80.80","80.80.81.81","81.218.119.11","84.200.69.80","84.200.70.40","89.233.43.71","9.9.9.9","91.239.100.100","94.130.180.225","94.140.14.14","94.140.15.15","95.85.95.85"]

def providers_worker(args) -> int:
    SOURCE = args.candidate
    ROOT = args.directory
    PYTHON = args.python
    DNSX = args.dnsx
    sys.path.insert(0, str(SOURCE))
    from modules.subdomain import (inspect_provider_compatibility, run_dnsx, run_amass,
        run_subfinder, run_passive_provider, stop_provider)

    compatibility = {}
    selected = {'subfinder': (args.subfinder, '2.13.0')}
    if args.profile == 'full':
        selected.update(amass=(args.amass, '5.0.0'), dnsx=(DNSX, '1.3.1'))
    for name, (executable, wanted) in selected.items():
        compatibility[name] = inspect_provider_compatibility(name, executable)
        if compatibility[name]['version'] != wanted:
            raise RuntimeError(f"Controlled lab requires {name} {wanted}; observed {compatibility[name]}")
    (args.directory / 'compatibility.json').write_text(json.dumps(compatibility, indent=2))

    ROOT.mkdir(parents=True, exist_ok=True)
    os.chdir(SOURCE)
    subprocess.run(['/usr/sbin/ip', 'link', 'set', 'lo', 'up'], check=True)
    os.environ['XDG_CONFIG_HOME'] = str(ROOT / 'config')
    Path(os.environ['XDG_CONFIG_HOME']).mkdir(exist_ok=True)
    os.environ['NO_COLOR'] = 'true'

    owned = []
    original_popen = subprocess.Popen
    class TrackedPopen(original_popen):
        def __init__(self, command, *args, **kwargs):
            super().__init__(command, *args, **kwargs)
            self.evidence = {'pid': self.pid, 'birth': birth(self.pid),
                             'command': [str(v) for v in command]}
            owned.append(self.evidence)
            save(ROOT / 'processes.json', owned)
            self.streams = {name: kwargs.get(name) for name in ('stdout', 'stderr')}
        def wait(self, *args, **kwargs):
            result = super().wait(*args, **kwargs)
            self.evidence['exit_code'] = result
            for name, stream in self.streams.items():
                if hasattr(stream, 'fileno'):
                    try:
                        raw = os.pread(stream.fileno(), 2 * 1024 * 1024, 0)
                        (ROOT / f'process-{self.pid}-{name}.log').write_bytes(raw)
                    except (OSError, ValueError):
                        pass
            return result
    subprocess.Popen = TrackedPopen

    def record_descendants(pid):
        try:
            children = Path(f'/proc/{pid}/task/{pid}/children').read_text().split()
        except OSError:
            return
        for child in map(int, children):
            token = birth(child)
            if token and not any(v['pid'] == child and v['birth'] == token for v in owned):
                try:
                    command = Path(f'/proc/{child}/cmdline').read_bytes().decode().split('\0')[:-1]
                except OSError:
                    command = []
                owned.append({'pid': child, 'birth': token, 'command': command, 'parent': pid})
            record_descendants(child)

    import http.client
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    import re
    import ssl
    from urllib.parse import urlsplit, parse_qs

    subprocess.run(['mount', '--make-rprivate', '/'], check=True)
    resolv = ROOT / 'resolv.conf'
    resolv.write_text('nameserver 127.0.0.1\noptions timeout:1 attempts:1\n')
    subprocess.run(['mount', '--bind', str(resolv), '/etc/resolv.conf'], check=True)
    aliases = RESOLVER_ALIASES
    for address in aliases:
        subprocess.run(['ip', 'addr', 'add', address + '/32', 'dev', 'lo'], check=True)
    for key in ['HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'http_proxy', 'https_proxy', 'all_proxy']:
        os.environ.pop(key, None)
    os.environ['NO_PROXY'] = '*'

    TLS_KEY = ROOT / 'lab-private-key.pem'
    TLS_CERT = ROOT / 'lab-cert.pem'
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
        '-subj', '/CN=crt.sh', '-addext', 'subjectAltName=DNS:crt.sh,DNS:bgp.tools',
        '-keyout', str(TLS_KEY), '-out', str(TLS_CERT)], check=True,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    TLS_KEY.chmod(0o600)
    os.environ['SSL_CERT_FILE'] = str(TLS_CERT)

    TARGET = 'hylianlab.test'
    SUB_NAMES = {'a.' + TARGET, 'v6.' + TARGET, 'shared.' + TARGET, 'dead.' + TARGET}
    AMASS_NAMES = {TARGET, 'amass.' + TARGET, 'shared.' + TARGET}
    AMASS_SOURCE_NAMES = AMASS_NAMES | {'dead.' + TARGET}
    CONFIRMED = (SUB_NAMES | AMASS_NAMES) - {'dead.' + TARGET}
    active_case = ''
    dns_queries, http_requests, cases = [], [], []
    response_limit = None
    address_answers = 0
    lock = threading.Lock()
    DNSX_MARKER = ROOT / 'dnsx-started'

    def namewire(name):
        return b''.join(bytes([len(s)]) + s.encode() for s in name.split('.')) + b'\0'

    def dns_response(packet):
        nonlocal address_answers
        if len(packet) < 17 or len(packet) > 2048:
            return None
        offset, labels = 12, []
        while offset < len(packet) and packet[offset]:
            size = packet[offset]
            if size > 63 or offset + size + 1 >= len(packet):
                return None
            labels.append(packet[offset + 1:offset + size + 1].decode('ascii').lower())
            offset += size + 1
        offset += 1
        if offset + 4 > len(packet):
            return None
        kind, klass = struct.unpack('!HH', packet[offset:offset + 4])
        name = '.'.join(labels)
        row = {'case': active_case, 'name': name, 'type': kind, 'time': time.monotonic(), 'action': 'pending',
               'stage': 'dnsx' if DNSX_MARKER.exists() else 'provider'}
        with lock:
            dns_queries.append(row)
        live = name in CONFIRMED
        infrastructure = name in {'bgp.tools', 'crt.sh', 'ns.fixture.invalid'}
        code = 0 if live or infrastructure else 3
        answer = b''
        if klass == 1 and kind in (1, 28) and (live or infrastructure):
            address = None
            if kind == 1 and name != 'v6.' + TARGET:
                address = socket.inet_pton(socket.AF_INET, '127.0.0.33' if infrastructure else '192.0.2.10')
            if kind == 28 and live and name == 'v6.' + TARGET:
                address = socket.inet_pton(socket.AF_INET6, '2001:db8::10')
            if address:
                with lock:
                    if live and response_limit is not None and row['stage'] == 'dnsx':
                        if address_answers >= response_limit:
                            row['action'] = 'drop'
                            return None
                        address_answers += 1
                answer = b'\xc0\x0c' + struct.pack('!HHIH', kind, 1, 60, len(address)) + address
        if kind == 2 and name == TARGET:
            value = namewire('ns.fixture.invalid')
            answer = b'\xc0\x0c' + struct.pack('!HHIH', 2, 1, 60, len(value)) + value
        row.update(action='reply', rcode=code, answer_count=bool(answer))
        return packet[:2] + struct.pack('!HHHHH', 0x8180 | code, 1, bool(answer), 0, 0) + packet[12:offset + 4] + answer

    class UDPHandler(socketserver.BaseRequestHandler):
        def handle(self):
            packet, transport = self.request
            response = dns_response(packet)
            if response:
                transport.sendto(response, self.client_address)

    class TCPHandler(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(1)
            prefix = self.request.recv(2)
            if len(prefix) != 2:
                return
            size = struct.unpack('!H', prefix)[0]
            if size > 2048:
                return
            data = bytearray()
            while len(data) < size:
                chunk = self.request.recv(size - len(data))
                if not chunk:
                    return
                data.extend(chunk)
            response = dns_response(bytes(data))
            if response:
                self.request.sendall(struct.pack('!H', len(response)) + response)

    class UDPServer(socketserver.ThreadingUDPServer):
        daemon_threads = True
    class TCPServer(socketserver.ThreadingTCPServer):
        daemon_threads = True
        allow_reuse_address = True

    class SourceHandler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'
        def do_GET(self):
            query = parse_qs(urlsplit(self.path).query)
            provider = 'amass' if 'CN' in query else 'subfinder'
            requested = (query.get('CN') or query.get('q') or [''])[0]
            is_target = requested.strip('%.') == TARGET
            names = sorted(AMASS_SOURCE_NAMES if provider == 'amass' else SUB_NAMES | {TARGET}) if is_target else []
            data = [{'id': i + 1, 'name_value': n} for i, n in enumerate(names)]
            if names:
                data += [{'id': 99, 'name_value': 'shared.' + TARGET + '\nshared.' + TARGET},
                         {'id': 100, 'name_value': 'foreign.invalid'}]
            body = json.dumps(data).encode()
            with lock:
                http_requests.append({'case': active_case, 'provider': provider, 'host': self.headers.get('Host'),
                    'path': self.path, 'names': names, 'time': time.monotonic()})
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        def log_message(self, *args):
            pass

    servers = [UDPServer(('0.0.0.0', 53), UDPHandler), TCPServer(('0.0.0.0', 53), TCPHandler),
               ThreadingHTTPServer(('0.0.0.0', 443), SourceHandler)]
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(TLS_CERT, TLS_KEY)
    servers[-1].socket = context.wrap_socket(servers[-1].socket, server_side=True)
    threads = [threading.Thread(target=s.serve_forever, kwargs={'poll_interval': .05}) for s in servers]
    for thread in threads:
        thread.start()

    provider_config = ROOT / 'subfinder-provider-config.yaml'
    provider_config.write_text('{}\n')
    subfinder_config = ROOT / 'subfinder-config.yaml'
    subfinder_config.write_text('sources:\n  - crtsh\ntimeout: 2\nmax-time: 1\n')
    SUBFINDER = ROOT / 'subfinder-real'
    SUBFINDER.write_text(f'#!{PYTHON}\nimport os,sys\nos.execv({args.subfinder!r}, [{args.subfinder!r}, "-s", "crtsh", "-duc", "-timeout", "2", "-max-time", "1", "-rl", "2", "-config", {str(subfinder_config)!r}, "-pc", {str(provider_config)!r}, *sys.argv[1:]])\n')
    SUBFINDER.chmod(0o700)
    DNSX_EXEC = ROOT / 'dnsx-real'
    DNSX_EXEC.write_text(f'#!{PYTHON}\nimport os,sys\nfrom pathlib import Path\nif "-r" in sys.argv: Path({str(DNSX_MARKER)!r}).write_text(str(os.getpid()))\nos.execv({DNSX!r}, [{DNSX!r}, *sys.argv[1:]])\n')
    DNSX_EXEC.chmod(0o700)
    amass_config = ROOT / 'amass-config.yaml'
    amass_config.write_text('options:\n  active: false\n  bruteforce:\n    enabled: false\n  alterations:\n    enabled: false\ntransformations:\n  FQDN->Known-FQDN:\n    ttl: 1440\n    confidence: 100\n  FQDN->DNS:\n    ttl: 1440\n    confidence: 100\n  FQDN->crt.sh:\n    ttl: 1440\n    confidence: 100\n')
    os.environ['AMASS_CONFIG'] = str(amass_config)
    save(ROOT / 'environment.json', {'python': sys.version, 'executable': sys.executable,
        'commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
        'status': subprocess.check_output(['git', 'status', '--short'], text=True),
        'network_namespace': os.readlink('/proc/self/ns/net'), 'mount_namespace': os.readlink('/proc/self/ns/mnt'),
        'addresses': json.loads(subprocess.check_output(['ip', '-j', 'address'], text=True)),
        'routes': json.loads(subprocess.check_output(['ip', '-j', 'route'], text=True)),
        'binary_sha256': {p: hashlib.sha256(Path(p).read_bytes()).hexdigest() for p, _ in selected.values()},
        'subfinder_exec_wrapper': SUBFINDER.read_text(), 'dns_aliases': aliases})

    def checkpoint():
        save(ROOT / 'cases.json', cases)
        save(ROOT / 'dns-queries.json', dns_queries)
        save(ROOT / 'http-requests.json', http_requests)
        save(ROOT / 'processes.json', owned)

    def case(label, function, oracle):
        nonlocal active_case, response_limit, address_answers
        active_case, response_limit, address_answers = label, None, 0
        DNSX_MARKER.unlink(missing_ok=True)
        started = time.monotonic()
        entry = {'label': label, 'oracle': oracle, 'status': 'failed'}
        try:
            observation = function()
            entry['observation'], entry['status'] = observation, 'passed'
        except Exception:
            entry['error'] = traceback.format_exc()
        entry['elapsed_seconds'] = round(time.monotonic() - started, 3)
        cases.append(entry)
        checkpoint()
        print(label, entry['status'], entry.get('error', ''), flush=True)

    def provider(provider, target=TARGET, expected=None, timeout=60):
        result = (run_subfinder(target, executable_path=str(SUBFINDER), timeout=timeout) if provider == 'subfinder' else
            run_amass(target, executable_path=args.amass, timeout=timeout, graph_parent=ROOT / active_case))
        observed = dataclasses.asdict(result)
        save(ROOT / (active_case + '.json'), observed)
        assert result.status == 'completed' and result.exit_code == 0, observed
        assert set(result.subdomains) == expected, observed
        matching = [r for r in http_requests if r['case'] == active_case and r['provider'] == provider]
        assert matching, 'no controlled source request'
        return observed

    def graphql(query, variables=None):
        connection = http.client.HTTPConnection('127.0.0.1', 4000, timeout=2)
        try:
            connection.request('POST', '/graphql', json.dumps({'query': query, 'variables': variables or {}}), {'Content-Type': 'application/json'})
            response = connection.getresponse()
            data = json.loads(response.read(1024 * 1024))
            assert response.status == 200 and not data.get('errors'), data
            return data
        finally:
            connection.close()

    def empty_engine():
        directory = ROOT / 'empty-engine'
        home = directory / 'home'
        (home / 'amass').mkdir(parents=True)
        env = dict(os.environ, XDG_CONFIG_HOME=str(home))
        with (directory / 'engine.log').open('wb') as stream:
            engine = subprocess.Popen([args.amass, 'engine', '-log-dir', str(directory)],
                stdout=stream, stderr=stream, env=env, start_new_session=True)
            try:
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline:
                    try:
                        ready = graphql('{__typename}')
                        break
                    except (OSError, ValueError, AssertionError):
                        assert engine.poll() is None, 'engine exited'
                        time.sleep(.1)
                else:
                    raise AssertionError('engine readiness deadline')
                config = {'scope': {'domains': [TARGET]}, 'transformations': {}, 'active': False}
                session = graphql('mutation($config:String!){createSessionFromJson(input:{config:$config}){sessionToken}}', {'config': json.dumps(config)})
                token = session['data']['createSessionFromJson']['sessionToken']
                stats = graphql('query($token:String!){sessionStats(sessionToken:$token){WorkItemsCompleted WorkItemsTotal}}', {'token': token})
                assert stats['data']['sessionStats'] == {'WorkItemsCompleted': 0, 'WorkItemsTotal': 0}, stats
                terminated = graphql('mutation($token:String!){terminateSession(sessionToken:$token)}', {'token': token})
                assert terminated['data']['terminateSession'] is True, terminated
                time.sleep(1)
                command = [args.amass, 'subs', '-names', '-d', TARGET, '-dir', str(home / 'amass'), '-config', str(amass_config), '-nocolor']
                names = run_passive_provider(TARGET, 'Amass empty graph', command, timeout=10)
                assert names.status == 'completed' and names.subdomains == [], names
                return {'ready': ready, 'session': session, 'stats': stats, 'terminated': terminated,
                        'empty_graph': dataclasses.asdict(names), 'database': str(home / 'amass/assetdb.db')}
            finally:
                stop_provider(engine)

    def cli(providers, fault=None):
        nonlocal response_limit, address_answers
        directory = ROOT / active_case
        directory.mkdir()
        command = [PYTHON, str(SOURCE / 'hylianscan.py'), TARGET, '--quiet', '-o', str(directory / 'report.txt'), '--json-output', 'report.json']
        if 'subfinder' in providers:
            command += ['--subfinder', '--subfinder-path', str(SUBFINDER), '--subfinder-timeout', '20']
        if 'amass' in providers:
            command += ['--amass', '--amass-path', args.amass, '--amass-timeout', '60']
        if 'dnsx' in providers:
            command += ['--dnsx', '--dnsx-path', str(DNSX_EXEC), '--dnsx-resolver', '127.0.0.1:53', '--dnsx-threads', '2',
                '--dnsx-rate-limit', '5', '--dnsx-timeout', '10' if fault else '.5', '--dnsx-retry', '1',
                '--dnsx-process-timeout', '4' if fault == 'timeout' else '30', '--dnsx-json']
        if fault:
            command += ['--ipv4']
            response_limit, address_answers = 2, 0
        save(directory / 'command.json', command)
        with (directory / 'stdout.log').open('wb') as stdout, (directory / 'stderr.log').open('wb') as stderr:
            process = subprocess.Popen(command, stdout=stdout, stderr=stderr, cwd=directory, start_new_session=True)
            sent, started = False, time.monotonic()
            try:
                while process.poll() is None and time.monotonic() - started < 85:
                    record_descendants(process.pid)
                    journals = ''.join(p.read_text() for p in directory.glob('*_observed_*.tsv'))
                    if fault == 'interrupt' and not sent and journals.count('dnsx\t') >= 2:
                        process.send_signal(signal.SIGINT)
                        sent = True
                    time.sleep(.03)
                if process.poll() is None:
                    process.send_signal(signal.SIGINT)
                code = process.wait(timeout=10)
            finally:
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
        document = json.loads((directory / 'output/report.json').read_text())
        journal = ''.join(p.read_text() for p in directory.glob('*_observed_*.tsv'))
        txt = saved_names(directory / 'report.txt')
        expected_candidates = (SUB_NAMES if 'subfinder' in providers else set()) | (AMASS_NAMES if 'amass' in providers else set())
        results = document['results']
        assert set(results['candidates']['subdomains']) == expected_candidates, results
        assert set(results['subdomains']) == txt, results
        expected_code = 1 if fault == 'timeout' else 130 if fault else 0
        assert code == expected_code, (code, expected_code)
        if 'dnsx' in providers:
            checkpoint_names = saved_names(directory / 'report_candidates.txt')
            assert checkpoint_names == expected_candidates
            status = 'timed_out' if fault == 'timeout' else 'interrupted' if fault else 'completed'
            assert results['resolution']['status'] == status, results
            assert {m['host'] for m in results['resolution']['metadata']} == txt, results
            if fault:
                answered = {q['name'] for q in dns_queries if q['case'] == active_case and q['stage'] == 'dnsx' and q['action'] == 'reply' and q.get('answer_count') and q['name'] in CONFIRMED}
                assert txt == answered and len(txt) == 2, (txt, answered)
                assert sent if fault == 'interrupt' else True
            else:
                assert txt == expected_candidates & CONFIRMED, txt
        else:
            assert txt == expected_candidates, txt
        for p in providers:
            expected = txt if p == 'dnsx' else SUB_NAMES if p == 'subfinder' else AMASS_NAMES
            observed = {line.split('\t')[1] for line in journal.splitlines() if line.startswith(p + '\t')}
            assert observed == expected, (p, observed, expected)
        for row in document['providers']:
            assert row['compatibility']['status'] == 'tested', row
            if row['name'] != 'dnsx':
                assert row['status'] == 'completed' and row['exit_code'] == 0, row
        return {'exit_code': code, 'signal_sent': sent, 'candidates': sorted(expected_candidates), 'findings': sorted(txt), 'providers': document['providers']}

    try:
        case('subfinder-real-normal', lambda: provider('subfinder', expected=SUB_NAMES), sorted(SUB_NAMES))
        case('subfinder-real-empty', lambda: provider('subfinder', 'empty.invalid', set()), [])
        case('cli-subfinder', lambda: cli(['subfinder']), sorted(SUB_NAMES))
        if args.profile == 'full':
            case('amass-empty-engine-session-graph', empty_engine, 'owned engine, zero assets, empty graph')
            case('amass-real-populated', lambda: provider('amass', expected=AMASS_NAMES), sorted(AMASS_NAMES))
            case('cli-amass', lambda: cli(['amass']), sorted(AMASS_NAMES))
            case('cli-combined-dnsx', lambda: cli(['subfinder', 'amass', 'dnsx']), sorted(CONFIRMED))
            case('cli-combined-timeout', lambda: cli(['subfinder', 'amass', 'dnsx'], 'timeout'), 'partial2; candidates6; exit1')
            case('cli-combined-interrupt', lambda: cli(['subfinder', 'amass', 'dnsx'], 'interrupt'), 'partial2; candidates6; exit130')
    finally:
        for server in servers:
            server.shutdown()
        for thread in threads:
            thread.join(1)
        for server in servers:
            server.server_close()
        TLS_KEY.unlink(missing_ok=True)
        time.sleep(.1)
        survivors = [v for v in owned if v['birth'] and birth(v['pid']) == v['birth']]
        checkpoint()
        save(ROOT / 'cleanup.json', {'survivors': survivors, 'owned_births': len(owned),
            'fixture_threads_alive': [t.is_alive() for t in threads], 'private_key_removed': not TLS_KEY.exists(),
            'routes': json.loads(subprocess.check_output(['ip', '-j', 'route'], text=True))})
        print('CLEANUP', len(survivors), 'survivors', flush=True)
    return 1 if any(c['status'] != 'passed' for c in cases) or survivors else 0



def dnsx_worker(args) -> int:
    SOURCE = args.candidate
    ROOT = args.directory
    PYTHON = args.python
    DNSX = args.dnsx
    sys.path.insert(0, str(SOURCE))
    from modules.subdomain import inspect_provider_compatibility, run_dnsx, run_amass, run_passive_provider

    compatibility = {}
    for name, (executable, wanted) in {'dnsx': (DNSX, '1.3.1')}.items():
        compatibility[name] = inspect_provider_compatibility(name, executable)
        if compatibility[name]['version'] != wanted:
            raise RuntimeError(f"Controlled lab requires {name} {wanted}; observed {compatibility[name]}")
    (args.directory / 'compatibility.json').write_text(json.dumps(compatibility, indent=2))

    ROOT.mkdir(parents=True, exist_ok=True)
    os.chdir(SOURCE)
    subprocess.run(['/usr/sbin/ip', 'link', 'set', 'lo', 'up'], check=True)
    os.environ['XDG_CONFIG_HOME'] = str(ROOT / 'config')
    Path(os.environ['XDG_CONFIG_HOME']).mkdir(exist_ok=True)
    os.environ['NO_COLOR'] = 'true'

    owned = []
    original_popen = subprocess.Popen
    class TrackedPopen(original_popen):
        def __init__(self, command, *args, **kwargs):
            super().__init__(command, *args, **kwargs)
            self.evidence = {'pid': self.pid, 'birth': birth(self.pid),
                             'command': [str(v) for v in command]}
            owned.append(self.evidence)
            save(ROOT / 'processes.json', owned)
            self.streams = {name: kwargs.get(name) for name in ('stdout', 'stderr')}
        def wait(self, *args, **kwargs):
            result = super().wait(*args, **kwargs)
            self.evidence['exit_code'] = result
            for name, stream in self.streams.items():
                if hasattr(stream, 'fileno'):
                    try:
                        raw = os.pread(stream.fileno(), 2 * 1024 * 1024, 0)
                        (ROOT / f'process-{self.pid}-{name}.log').write_bytes(raw)
                    except (OSError, ValueError):
                        pass
            return result
    subprocess.Popen = TrackedPopen

    def record_descendants(pid):
        try:
            children = Path(f'/proc/{pid}/task/{pid}/children').read_text().split()
        except OSError:
            return
        for child in map(int, children):
            token = birth(child)
            if token and not any(v['pid'] == child and v['birth'] == token for v in owned):
                try:
                    command = Path(f'/proc/{child}/cmdline').read_bytes().decode().split('\0')[:-1]
                except OSError:
                    command = []
                owned.append({'pid': child, 'birth': token, 'command': command, 'parent': pid})
            record_descendants(child)

    def namewire(name):
        return b''.join(bytes([len(part)]) + part.encode() for part in name.split('.')) + b'\0'

    def rr(owner, kind, value):
        return owner + struct.pack('!HHIH', kind, 1, 60, len(value)) + value

    class Zone(socketserver.ThreadingUDPServer):
        daemon_threads = True
        def __init__(self):
            super().__init__(('127.0.0.1', 0), DNSHandler)
            self.lock = threading.Lock()
            self.queries = []
            self.response_limit = None
            self.answers = 0
        def reset(self, limit=None):
            self.response_limit, self.answers = limit, 0

    class DNSHandler(socketserver.BaseRequestHandler):
        def handle(self):
            packet, transport = self.request
            if len(packet) < 17 or len(packet) > 2048:
                return
            offset, labels = 12, []
            while offset < len(packet) and packet[offset]:
                size = packet[offset]
                if size > 63 or offset + size + 1 >= len(packet):
                    return
                labels.append(packet[offset + 1:offset + 1 + size].decode('ascii').lower())
                offset += size + 1
            offset += 1
            if offset + 4 > len(packet):
                return
            kind, klass = struct.unpack('!HH', packet[offset:offset + 4])
            name = '.'.join(labels)
            row = {'name': name, 'type': kind, 'time': time.monotonic(), 'case': active_case, 'action': 'pending'}
            with self.server.lock:
                self.server.queries.append(row)
                if len(self.server.queries) > 5000:
                    row['action'] = 'budget_drop'
                    return
                if self.server.response_limit is not None:
                    if self.server.answers >= self.server.response_limit:
                        row['action'] = 'drop'
                        return
                    self.server.answers += 1
            first = labels[0] if labels else ''
            if first == 'drop':
                row['action'] = 'drop'
                return
            if first == 'delay':
                time.sleep(.15)
            wildcard = name.endswith('.wild.example.test')
            live = first in {'a', 'aaaa', 'dual', 'alias', 'delay', 'unique'} or first.startswith('good') or wildcard
            code = 2 if first == 'servfail' else 0 if live or first == 'nodata' else 3
            records = []
            owner = b'\xc0\x0c'
            if first == 'alias' and kind in (1, 28):
                records.append(rr(owner, 5, namewire('dual.example.test')))
                owner = namewire('dual.example.test')
            if klass == 1 and live:
                if kind == 1 and first != 'aaaa':
                    address = '192.0.2.99' if wildcard and first != 'unique' else '192.0.2.10'
                    records.append(rr(owner, 1, socket.inet_pton(socket.AF_INET, address)))
                elif kind == 28 and first != 'a':
                    records.append(rr(owner, 28, socket.inet_pton(socket.AF_INET6, '2001:db8::20' if first == 'unique' else '2001:db8::10')))
            row.update(action='reply', rcode=code, answer_count=len(records))
            header = packet[:2] + struct.pack('!HHHHH', 0x8180 | code, 1, len(records), 0, 0)
            transport.sendto(header + packet[12:offset + 4] + b''.join(records), self.client_address)

    cases = []
    active_case = ''
    zone = Zone()
    server_thread = threading.Thread(target=zone.serve_forever, kwargs={'poll_interval': .05})
    server_thread.start()
    resolver = f'127.0.0.1:{zone.server_address[1]}'
    environment = {'commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
        'git_status': subprocess.check_output(['git', 'status', '--short'], text=True),
        'python': sys.version, 'executable': sys.executable, 'kernel': platform.platform(),
        'network_namespace': os.readlink('/proc/self/ns/net'),
        'addresses': subprocess.check_output(['/usr/sbin/ip', '-j', 'address'], text=True),
        'routes': subprocess.check_output(['/usr/sbin/ip', '-j', 'route'], text=True),
        'resolver': resolver, 'binary_sha256': {p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
            for p in [DNSX]}}
    save(ROOT / 'environment.json', environment)

    def case(label, function, oracle=None):
        nonlocal active_case
        active_case = label
        started = time.monotonic()
        entry = {'label': label, 'oracle': oracle, 'status': 'failed'}
        try:
            entry['observation'] = function()
            entry['status'] = 'passed'
        except Exception:
            entry['error'] = traceback.format_exc()
        entry['elapsed_seconds'] = round(time.monotonic() - started, 3)
        cases.append(entry)
        save(ROOT / 'cases.json', cases)
        save(ROOT / 'queries.json', zone.queries)
        save(ROOT / 'processes.json', owned)
        print(label, entry['status'], entry.get('error', ''), flush=True)

    def compatible(provider, executable):
        result = inspect_provider_compatibility(provider, executable)
        assert result['status'] == 'tested', result
        return result

    def direct(names, expected, family='dual-stack', wildcard=False):
        zone.reset()
        names = [n + '.example.test' for n in names]
        result = run_dnsx(names, executable_path=DNSX, resolver=resolver,
            address_family=family, threads=2, rate_limit=20, query_timeout=.4,
            retry=1, json_output=True, auto_wildcard=wildcard, timeout=30)
        observed = dataclasses.asdict(result)
        save(ROOT / (active_case + '.json'), observed)
        assert result.status == 'completed' and result.exit_code == 0, result
        assert set(result.subdomains) == {n + '.example.test' for n in expected}, result
        assert {m['host'] for m in result.metadata} == set(result.subdomains), result
        for row in result.metadata:
            assert row['status_code'] == 'NOERROR', row
            assert row.get('a') or row.get('aaaa'), row
            assert row.get('a', []) == (['192.0.2.99'] if '.wild.' in row['host'] and not row['host'].startswith('unique.') else ['192.0.2.10']) if row.get('a') else True
            if row.get('aaaa'):
                assert row['aaaa'] == ['2001:db8::10'], row
            if family == 'ipv4':
                assert not row.get('aaaa'), row
            if family == 'ipv6':
                assert not row.get('a'), row
            if row['host'] == 'alias.example.test':
                assert row['cname'] == ['dual.example.test'], row
        return observed

    def cli(fault=None, empty=False):
        zone.reset(2 if fault else None)
        directory = ROOT / active_case
        directory.mkdir()
        candidates = ([] if empty else [f'good{i:02}.example.test' for i in range(16)] if fault else
            [n + '.example.test' for n in ['a', 'aaaa', 'dual', 'alias', 'nodata', 'dead', 'servfail', 'delay']])
        lines = list(candidates)
        if not empty and not fault:
            lines += ['A.EXAMPLE.TEST.', 'http://a.example.test', 'foreign.invalid', '*.example.test']
        manifest = directory / 'manifest.json'
        save(manifest, {'domain': 'example.test', 'version': '2.16.0', 'lines': lines})
        wrapper = directory / 'subfinder-fixture'
        wrapper.write_text(f'#!{PYTHON}\nimport sys\nfrom pathlib import Path\nsys.path.insert(0, {str(SOURCE)!r})\nfrom scripts.benchmark_subdomain_provider import main\nraise SystemExit(main("subfinder", Path({str(manifest)!r}), sys.argv[1:]))\n')
        wrapper.chmod(0o700)
        command = [PYTHON, str(SOURCE / 'hylianscan.py'), 'example.test', '--subfinder',
            '--subfinder-path', str(wrapper), '--dnsx', '--dnsx-path', DNSX,
            '--dnsx-resolver', resolver, '--dnsx-threads', '2', '--dnsx-rate-limit', '20',
            '--dnsx-timeout', '10' if fault else '.4', '--dnsx-retry', '1',
            '--dnsx-process-timeout', '4' if fault == 'timeout' else '30', '--dnsx-json',
            '--json-output', str(directory / 'report.json'), '-o', str(directory / 'report.txt'), '--quiet']
        if fault:
            command.append('--ipv4')
        save(directory / 'command.json', command)
        with (directory / 'stdout.log').open('wb') as stdout, (directory / 'stderr.log').open('wb') as stderr:
            process = subprocess.Popen(command, stdout=stdout, stderr=stderr, start_new_session=True, cwd=directory)
            started = time.monotonic()
            sent = False
            try:
                while process.poll() is None and time.monotonic() - started < 40:
                    record_descendants(process.pid)
                    journals = list(directory.glob('*_observed_*.tsv'))
                    journal = ''.join(p.read_text() for p in journals)
                    queries = [q for q in zone.queries if q['case'] == active_case]
                    if fault == 'interrupt' and not sent and journal.count('dnsx\t') >= 2 and any(q['action'] == 'drop' for q in queries):
                        process.send_signal(signal.SIGINT)
                        sent = True
                    time.sleep(.02)
                if process.poll() is None:
                    process.send_signal(signal.SIGINT)
                code = process.wait(timeout=10)
            finally:
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
        document = json.loads((directory / 'output' / 'report.json').read_text())
        results = document['results']
        txt = saved_names(directory / 'report.txt')
        checkpoint = saved_names(directory / 'report_candidates.txt')
        journal = ''.join(p.read_text() for p in directory.glob('*_observed_*.tsv'))
        expected_status = 'timed_out' if fault == 'timeout' else 'interrupted' if fault else 'skipped' if empty else 'completed'
        expected_code = 1 if fault == 'timeout' else 130 if fault else 0
        assert code == expected_code, (code, expected_code)
        assert results['resolution']['status'] == expected_status, results
        assert set(results['candidates']['subdomains']) == set(candidates) == checkpoint, results
        assert set(results['subdomains']) == txt == set(results['resolution']['subdomains']), results
        assert {m['host'] for m in results['resolution']['metadata']} == txt, results
        if fault:
            expected = {q['name'] for q in zone.queries if q['case'] == active_case and q['action'] == 'reply' and q.get('answer_count')}
            assert txt == expected and len(txt) == 2, (txt, expected)
            assert sent if fault == 'interrupt' else True
        else:
            expected = set() if empty else {n + '.example.test' for n in ['a', 'aaaa', 'dual', 'alias', 'delay']}
            assert txt == expected, (txt, expected)
        assert {line.split('\t')[1] for line in journal.splitlines() if line.startswith('subfinder\t')} == set(candidates), journal
        assert {line.split('\t')[1] for line in journal.splitlines() if line.startswith('dnsx\t')} == txt, journal
        assert not any(q['name'] in {'foreign.invalid', '*.example.test'} for q in zone.queries), 'out of scope query'
        return {'exit_code': code, 'provider_status': expected_status, 'candidates': len(candidates),
                'resolved': sorted(txt), 'signal_sent': sent, 'discovery': 'committed executable fixture', 'resolution': 'real DNSx'}

    try:
        names = ['a', 'aaaa', 'dual', 'alias', 'nodata', 'dead', 'servfail', 'drop', 'delay']
        case('dnsx-dual-stack', lambda: direct(names, ['a', 'aaaa', 'dual', 'alias', 'delay']), '5 address-bearing names')
        case('cli-completed', lambda: cli(), '8 candidates, 5 findings; TXT/JSON/journal')
        case('cli-empty', lambda: cli(empty=True), 'validated DNSx then skipped; empty reports')
        if args.profile == 'full':
            case('dnsx-ipv4', lambda: direct(names, ['a', 'dual', 'alias', 'delay'], 'ipv4'), '4 IPv4 names')
            case('dnsx-ipv6', lambda: direct(names, ['aaaa', 'dual', 'alias', 'delay'], 'ipv6'), '4 IPv6 names')
            wild = ['one.wild', 'two.wild', 'unique.wild']
            case('dnsx-wildcard-distinct-both-families', lambda: direct(wild, ['unique.wild'], 'ipv4', True), ['unique.wild'])
            case('cli-timeout', lambda: cli('timeout'), 'exit1, timed_out, partial2 persisted')
            case('cli-interrupt', lambda: cli('interrupt'), 'exit130, interrupted, partial2 persisted')
    finally:
        zone.shutdown()
        server_thread.join(1)
        zone.server_close()
        save(ROOT / 'queries.json', zone.queries)
        time.sleep(.1)
        survivors = [v for v in owned if v['birth'] and birth(v['pid']) == v['birth']]
        save(ROOT / 'processes.json', owned)
        save(ROOT / 'cleanup.json', {'server_thread_alive': server_thread.is_alive(), 'owned_births': len(owned), 'survivors': survivors,
            'network_namespace': os.readlink('/proc/self/ns/net'), 'routes': subprocess.check_output(['/usr/sbin/ip', '-j', 'route'], text=True)})
        print('CLEANUP', len(survivors), 'survivors', flush=True)
    return 1 if any(c['status'] != 'passed' for c in cases) or survivors else 0



def verify_namespace(netns: str, mountns: str) -> None:
    if (sys.platform != "linux" or os.geteuid() != 0
            or os.readlink("/proc/self/ns/net") == netns
            or os.readlink("/proc/self/ns/mnt") == mountns):
        raise RuntimeError("Worker requires fresh user/network/mount namespaces; host execution refused")
    links = json.loads(subprocess.check_output(["ip", "-j", "link"], text=True))
    if {link["ifname"] for link in links} != {"lo"}:
        raise RuntimeError("Controlled namespace must contain only loopback")
    for family in ("-4", "-6"):
        if json.loads(subprocess.check_output(["ip", family, "-j", "route"], text=True)):
            raise RuntimeError("Controlled namespace has routes; refusing execution")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--battery", choices=("providers", "dnsx"), default="providers")
    parser.add_argument("--profile", choices=("quick", "full"), default="quick")
    parser.add_argument("--candidate", type=Path, default=REPO)
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--subfinder", default="subfinder")
    parser.add_argument("--amass", default="amass")
    parser.add_argument("--dnsx", default="dnsx")
    parser.add_argument("--run-timeout", type=common.positive_float, default=240)
    parser.add_argument("--min-free-gib", type=common.positive_float, default=1)
    parser.add_argument("--resources", action="store_true")
    parser.add_argument("--_worker", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--_netns", help=argparse.SUPPRESS)
    parser.add_argument("--_mountns", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    args.candidate = args.candidate.resolve()
    if args._worker:
        verify_namespace(args._netns, args._mountns)
        args.directory = args.output_dir.resolve()
        return providers_worker(args) if args.battery == "providers" else dnsx_worker(args)
    if sys.platform != "linux" or not (args.candidate / "hylianscan.py").is_file():
        parser.error("Requires Linux and a Hylianscan source checkout")
    selected = ("dnsx",) if args.battery == "dnsx" else (
        ("subfinder", "amass", "dnsx") if args.profile == "full" else ("subfinder",))
    for name in ("python", *selected):
        resolved = shutil.which(getattr(args, name))
        if not resolved:
            parser.error(f"Missing selected executable: {getattr(args, name)}")
        setattr(args, name, str(Path(resolved).absolute()))
    args.directory = (args.output_dir or REPO / "output/benchmark").resolve() / (
        common.build_timestamp() + "_" + uuid.uuid4().hex[:8])
    args.directory.mkdir(parents=True, exist_ok=False)
    common.disk_preflight(args.directory, args)
    namespace = ["unshare", "--user", "--map-root-user", "--net", "--mount", "--fork"]
    worker = [args.python, str(Path(__file__).resolve()), "--_worker", "--battery", args.battery,
              "--profile", args.profile, "--candidate", str(args.candidate), "--python", args.python,
              "--output-dir", str(args.directory), "--subfinder", args.subfinder, "--amass", args.amass,
              "--dnsx", args.dnsx, "--_netns", os.readlink("/proc/self/ns/net"),
              "--_mountns", os.readlink("/proc/self/ns/mnt")]
    if args.resources:
        worker = common.resource_command(args, args.directory / "resources.json", worker)
    command = namespace + worker
    common.write_json(args.directory / "command.json", command)
    common.write_json(args.directory / "source.json", common.source_metadata(args.candidate))
    print(f"Controlled {args.battery} evidence: {args.directory}", flush=True)
    with (args.directory / "worker.log").open("w") as log:
        process = subprocess.Popen(command, stdout=log, stderr=log, start_new_session=True)
        try:
            code = process.wait(timeout=args.run_timeout)
        except subprocess.TimeoutExpired:
            from scripts.benchmark_subdomain import stop_worker
            stop_worker(process)
            common.write_json(args.directory / "outcome.json", {"status": "timed_out"})
            return 1
        except KeyboardInterrupt:
            common.write_json(args.directory / "outcome.json", {"status": "interrupted"})
            return 130
        finally:
            # Native providers may own separate process groups. Stop only recorded
            # births that still match; namespace removal alone does not reap them.
            from scripts.benchmark_subdomain import process_identity, stop_worker
            recorded = args.directory / "processes.json"
            entries = []
            watchdog = args.directory / "watchdog"
            try:
                watchdog.mkdir(exist_ok=True)
                if recorded.exists():
                    for row in json.loads(recorded.read_text()):
                        pid, token = row["pid"], row.get("birth")
                        try:
                            if token and process_identity(pid) == token and os.getpgid(pid) == pid:
                                entries.append({"pid": pid, "process_identity": token})
                        except ProcessLookupError:
                            pass
                (watchdog / "launches.jsonl").write_text("".join(json.dumps(row) + "\n" for row in entries))
            finally:
                try:
                    stop_worker(process, watchdog)
                finally:
                    (args.directory / "lab-private-key.pem").unlink(missing_ok=True)
    common.write_json(args.directory / "outcome.json", {"exit_code": code,
                      "status": "completed" if code == 0 else "failed",
                      "measurement_scope": "Entire lab worker including fixture services and setup"})
    return code


def run_benchmark(args: argparse.Namespace) -> int:
    if args.reference or args.regression_percent is not None:
        raise ValueError("Real-provider acceptance cases do not support calibrated performance comparisons")
    arguments = ["--battery", args.benchmark, "--profile", args.profile, "--candidate", str(args.candidate),
                 "--python", args.python, "--run-timeout", str(args.run_timeout), "--min-free-gib", str(args.min_free_gib),
                 "--subfinder", args.subfinder_path, "--amass", args.amass_path, "--dnsx", args.dnsx_path]
    if args.output_dir:
        arguments += ["--output-dir", str(args.output_dir)]
    if args.resources:
        arguments.append("--resources")
    return main(arguments)


if __name__ == "__main__":
    raise SystemExit(main())
