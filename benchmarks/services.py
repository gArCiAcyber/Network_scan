#!/usr/bin/env python3
"""Bounded, persistent services for the isolated TCP benchmark laboratory."""

from __future__ import annotations

import argparse
import errno
import json
import selectors
import signal
import socket
import ssl
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from modules.probes.http import build_http_head_request
from tests.fixtures.mock_servers import build_tls_server_context


HTTP_RESPONSE = (
    b"HTTP/1.1 200 OK\r\nServer: hylianscan-mock\r\n"
    b"Content-Length: 0\r\nConnection: close\r\n\r\n"
)


def banner(port: int) -> str:
    return f"MOCK TCP SERVICE {port}"


def read_config(path: Path) -> dict:
    config = json.loads(path.read_text(encoding="utf-8"))
    if config["address"] not in ("192.0.2.2", "127.0.0.1"):
        raise ValueError("Laboratory services require the fixed lab IP or localhost.")
    for value in config["services"]:
        if not isinstance(value["port"], int) or not 1024 <= value["port"] <= 65535:
            raise ValueError("Laboratory service ports must be unprivileged TCP ports.")
        if value["kind"] not in ("banner", "http", "https", "silent"):
            raise ValueError("Unknown laboratory service kind.")
    return config


def check_services(config: dict) -> dict:
    """Verify every listener, including a concurrent pass over dense workloads."""
    address = config["address"]
    timeout = max(2.0, config["timeout"] * 2 + config.get("delay_ms", 0) / 250)

    def check(service: dict) -> int:
        port, kind = service["port"], service["kind"]
        with socket.create_connection((address, port), timeout=timeout) as client:
            if kind == "https":
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                with context.wrap_socket(client, server_hostname="localhost") as tls:
                    tls.sendall(build_http_head_request(address))
                    if not tls.recv(4096).startswith(b"HTTP/1.1 200 OK"):
                        raise ValueError(f"HTTPS readiness failed on port {port}.")
            elif kind == "http":
                client.sendall(build_http_head_request(address))
                if not client.recv(4096).startswith(b"HTTP/1.1 200 OK"):
                    raise ValueError(f"HTTP readiness failed on port {port}.")
            elif kind == "banner":
                if client.recv(4096).decode("ascii").strip() != banner(port):
                    raise ValueError(f"Banner readiness failed on port {port}.")
            else:
                client.settimeout(0.05)
                try:
                    client.recv(1)
                except socket.timeout:
                    pass
                else:
                    raise ValueError(f"Silent service closed or replied on port {port}.")
        return port

    with ThreadPoolExecutor(max_workers=config["workers"]) as executor:
        ports = list(executor.map(check, config["services"]))
    with socket.socket() as client:
        # Windows can retry loopback refusals for about two seconds; readiness is untimed.
        client.settimeout(max(5.0, timeout))
        refusal_codes = {errno.ECONNREFUSED, getattr(errno, "WSAECONNREFUSED", errno.ECONNREFUSED)}
        if client.connect_ex((address, config["closed_check_port"])) not in refusal_codes:
            raise ValueError("Closed-port readiness check did not receive a refusal.")
    for port in config["filtered_ports"]:
        with socket.socket() as client:
            client.settimeout(0.15 + config.get("delay_ms", 0) / 250)
            try:
                client.connect((address, port))
            except socket.timeout:
                continue
            raise ValueError(f"DROP readiness check failed on port {port}.")
    return {"ready": True, "ports_checked": sorted(ports), "concurrency": config["workers"]}


def serve(config: dict, directory: Path) -> None:
    """Use one selector for hundreds of banner listeners, without thread queues."""
    running = True

    def stop(_signum: int, _frame: object) -> None:
        nonlocal running
        running = False

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    context = build_tls_server_context(directory)
    counts = {str(service["port"]): 0 for service in config["services"]}
    stats = {"accepted_by_port": counts, "peak_silent_connections": 0, "errors": []}
    silent: dict[socket.socket, float] = {}
    with selectors.DefaultSelector() as selector:
        try:
            for service in config["services"]:
                listener = socket.socket()
                try:
                    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    listener.bind((config["address"], service["port"]))
                    listener.listen(max(128, config["workers"] * 2))
                    listener.setblocking(False)
                    selector.register(listener, selectors.EVENT_READ, service)
                except BaseException:
                    listener.close()
                    raise
            (directory / "ready.json").write_text(
                json.dumps({"ready": True, "listeners": len(counts)}), encoding="utf-8"
            )
            while running and not (directory / "stop").exists():
                for key, _ in selector.select(0.1):
                    if key.data is None:
                        client = key.fileobj
                        try:
                            closed = not client.recv(4096)
                        except ConnectionError:
                            closed = True
                        if closed:
                            selector.unregister(client)
                            silent.pop(client, None)
                            client.close()
                        continue
                    client, _ = key.fileobj.accept()
                    service = key.data
                    counts[str(service["port"])] += 1
                    if service["kind"] == "silent":
                        client.setblocking(False)
                        selector.register(client, selectors.EVENT_READ, None)
                        silent[client] = time.monotonic() + config["timeout"] * 3 + 5
                        stats["peak_silent_connections"] = max(
                            stats["peak_silent_connections"], len(silent)
                        )
                        continue
                    with client:
                        client.settimeout(max(2.0, config["timeout"] * 2))
                        try:
                            if service["kind"] == "banner":
                                client.sendall((banner(service["port"]) + "\r\n").encode("ascii"))
                            elif service["kind"] == "https":
                                with context.wrap_socket(client, server_side=True) as tls:
                                    if tls.recv(8192).startswith(b"HEAD "):
                                        tls.sendall(HTTP_RESPONSE)
                            elif client.recv(8192).startswith(b"HEAD "):
                                client.sendall(HTTP_RESPONSE)
                        except (ssl.SSLError, ConnectionError, socket.timeout):
                            # Discovery closes before a banner/TLS exchange; this is expected.
                            pass
                for client, deadline in list(silent.items()):
                    if time.monotonic() >= deadline:
                        selector.unregister(client)
                        silent.pop(client)
                        client.close()
        except BaseException as error:
            stats["errors"].append(f"{type(error).__name__}: {error}")
            raise
        finally:
            for key in list(selector.get_map().values()):
                key.fileobj.close()
            (directory / "services.json").write_text(json.dumps(stats, indent=2), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("config", type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    config = read_config(args.config)
    if args.check:
        print(json.dumps(check_services(config)))
    else:
        serve(config, args.config.parent)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
