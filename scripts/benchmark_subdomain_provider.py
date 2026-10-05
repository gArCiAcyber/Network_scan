"""Strict offline executable fixtures for the passive provider contracts."""

import argparse
import json
import os
import sys
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path


def _options(arguments: list[str], values: set[str], switches: set[str]) -> dict[str, str | bool]:
    parsed: dict[str, str | bool] = {}
    index = 0
    while index < len(arguments):
        flag = arguments[index]
        if flag in parsed or flag not in values | switches:
            raise ValueError(f"unexpected or repeated option: {flag}")
        if flag in switches:
            parsed[flag] = True
            index += 1
        else:
            if index + 1 == len(arguments) or arguments[index + 1].startswith("-"):
                raise ValueError(f"missing value for {flag}")
            parsed[flag] = arguments[index + 1]
            index += 2
    return parsed


def _engine(manifest: Path, stderr) -> int:
    config_variable = "APPDATA" if os.name == "nt" else "XDG_CONFIG_HOME"
    config_home = os.environ.get(config_variable)
    if not config_home or not (Path(config_home) / "amass").is_dir():
        raise ValueError(f"isolated {config_variable}/amass directory is required")

    class ReadyHandler(BaseHTTPRequestHandler):
        def do_POST(self):
            if self.path != "/graphql":
                self.send_error(404)
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= 2048:
                    raise ValueError("invalid request length")
                query = json.loads(self.rfile.read(length))
                if query != {"query": "{__typename}"}:
                    raise ValueError("only the readiness query is supported")
            except (ValueError, TypeError):
                self.send_error(400)
                return
            body = b'{"data":{"__typename":"Query"}}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format, *args):
            pass

    # The production Amass adapter requires this fixed local readiness endpoint.
    with HTTPServer(("127.0.0.1", 4000), ReadyHandler) as server:
        ready = {"pid": os.getpid(), "config_home": config_home,
                 "endpoint": "http://127.0.0.1:4000/graphql"}
        (manifest.parent / f"engine-ready-{os.getpid()}.json").write_text(
            json.dumps(ready, sort_keys=True), encoding="utf-8")
        stderr("offline Amass engine ready\n")
        server.serve_forever(poll_interval=0.1)
    return 0


def _deliver(data: dict, stdout, stderr, ready: Path, graph: Path | None = None,
             live: bool = False, graph_results: bool = False) -> int:
    lines = data["lines"]
    if not isinstance(lines, list) or not all(isinstance(line, str) for line in lines):
        raise ValueError("manifest lines must be a list of strings")
    batch_size = data.get("batch_size", 256)
    delay = data.get("delay_seconds", 0.0)
    if not isinstance(batch_size, int) or isinstance(batch_size, bool) or batch_size <= 0:
        raise ValueError("batch_size must be a positive integer")
    if not isinstance(delay, (int, float)) or not 0 <= delay < float("inf"):
        raise ValueError("delay_seconds must be finite and nonnegative")
    diagnostic = data.get("stderr", "")
    if not isinstance(diagnostic, str):
        raise ValueError("stderr must be a string")
    status = data.get("status", "completed")
    if status not in {"completed", "failed", "timed_out", "interrupted"}:
        raise ValueError("unknown manifest status")
    newline = data.get("newline", "\n")
    final_newline = data.get("final_newline", True)
    if newline not in {"\n", "\r\n"} or not isinstance(final_newline, bool):
        raise ValueError("invalid output line framing")
    # Graph queries retrieve any retained prefix without repeating enumeration's fault.
    if graph_results:
        status = "interrupted" if status == "interrupted" else "completed"
        diagnostic = "offline Amass retained graph query\n"
    elif graph is not None and status == "interrupted":
        status = "completed"
    stream = graph.open("w", encoding="utf-8", newline="\n") if graph else None
    try:
        stderr_offset = 0
        for offset in range(0, len(lines), batch_size):
            if offset and delay:
                time.sleep(delay)
            stderr(diagnostic[stderr_offset:stderr_offset + 65536])
            stderr_offset += 65536
            batch = lines[offset:offset + batch_size]
            if stream is not None:
                stream.write("".join(json.dumps(line) + "\n" for line in batch))
                stream.flush()
                stdout(f"offline Amass graph batch: {len(batch)} records\n")
            elif live:
                rendered = newline.join(f"[laboratory] {line}" for line in batch)
                stderr(rendered + (newline if final_newline or offset + batch_size < len(lines) else ""))
            else:
                rendered = newline.join(batch)
                stdout(rendered + (newline if final_newline or offset + batch_size < len(lines) else ""))
        stderr(diagnostic[stderr_offset:])
    finally:
        if stream is not None:
            stream.close()
    ready.write_text(json.dumps({"pid": os.getpid(), "emitted_count": len(lines),
                                 "graph": str(graph) if graph else None}), encoding="utf-8")
    if status in {"timed_out", "interrupted"}:
        stderr(f"offline provider awaiting {status} cancellation\n")
        time.sleep(3600)
    if graph_results:
        return 0
    exit_code = data.get("exit_code")
    if exit_code is None:
        exit_code = 7 if status == "failed" else 0
    if not isinstance(exit_code, int) or isinstance(exit_code, bool) or not 0 <= exit_code <= 255:
        raise ValueError("exit_code must be an integer from 0 through 255")
    if data.get("abrupt", False):
        # Raw logs and the ready record are flushed before bypassing normal cleanup.
        os._exit(exit_code)
    return exit_code


def main(provider: str, manifest: Path, arguments: list[str]) -> int:
    """Run one strict provider invocation and retain its raw output and command."""
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", newline="")
    manifest = Path(manifest).resolve()
    if provider not in {"subfinder", "amass"}:
        raise ValueError("provider must be subfinder or amass")
    data = json.loads(manifest.read_text(encoding="utf-8"))
    version = data.get("version", "2.16.0" if provider == "subfinder" else "5.0.0")
    stage = ("version" if arguments == ["-version"] else
             "help" if arguments == ["-h"] or arguments in (["enum", "-h"], ["subs", "-h"]) else
             "discovery" if provider == "subfinder" else
             arguments[0] if arguments and arguments[0] in {"engine", "enum", "subs"} else "usage")
    prefix = manifest.parent / f"{provider}-{stage}-{os.getpid()}"
    stdout_path = prefix.with_suffix(".stdout.log")
    stderr_path = prefix.with_suffix(".stderr.log")
    ready_path = prefix.with_suffix(".ready.json")
    command = {"provider": provider, "pid": os.getpid(), "arguments": arguments,
               "stage": stage, "data_stage": stage in {"discovery", "enum", "subs"},
               "stdout": str(stdout_path), "stderr": str(stderr_path)}
    with (manifest.parent / "provider-commands.jsonl").open("a", encoding="utf-8") as ledger:
        ledger.write(json.dumps(command, sort_keys=True) + "\n")
    with stdout_path.open("w", encoding="utf-8", newline="\n") as stdout_log, \
            stderr_path.open("w", encoding="utf-8", newline="\n") as stderr_log:
        def emit(stream, log, text):
            if text:
                stream.write(text)
                stream.flush()
                log.write(text)
                log.flush()

        stdout = lambda text: emit(sys.stdout, stdout_log, text)
        stderr = lambda text: emit(sys.stderr, stderr_log, text)
        try:
            supported = {"2.16.0"} if provider == "subfinder" else {"4.2.0", "5.0.0"}
            if version not in supported:
                raise ValueError("unsupported fixture version")
            if arguments == ["-version"]:
                stdout(f"{provider} v{version}\n")
                return 0
            if provider == "subfinder":
                if arguments == ["-h"]:
                    stdout("Subfinder options: -d DOMAIN -silent -v\n")
                    return 0
                options = _options(arguments, {"-d"}, {"-silent", "-v"})
                if set(options) not in ({"-d", "-silent"}, {"-d", "-v"}):
                    raise ValueError("expected -d DOMAIN with exactly one of -silent/-v")
            else:
                if arguments == ["-h"]:
                    stdout("Amass commands: engine enum subs\n" if version == "5.0.0" else
                           "Amass commands: enum\n")
                    return 0
                if arguments == ["enum", "-h"]:
                    if version == "5.0.0":
                        raise ValueError("Amass 5 enum -h is unsafe; use subs -h")
                    stdout("Amass enum options: -passive -d DOMAIN -dir DIRECTORY -config FILE -nocolor\n")
                    return 0
                if arguments == ["subs", "-h"] and version == "5.0.0":
                    stdout("Amass subs options: -names -d DOMAIN -dir DIRECTORY -config FILE -nocolor\n")
                    return 0
                if arguments and arguments[0] == "engine" and version == "5.0.0":
                    _options(arguments[1:], {"-log-dir"}, set())
                    return _engine(manifest, stderr)
                if not arguments or arguments[0] not in {"enum", "subs"}:
                    raise ValueError("unexpected Amass subcommand")
                if version == "4.2.0":
                    options = _options(arguments[1:], {"-d"}, {"-passive"})
                    if arguments[0] != "enum" or set(options) != {"-d", "-passive"}:
                        raise ValueError("expected Amass 4 enum -passive -d DOMAIN")
                else:
                    switch = "-passive" if arguments[0] == "enum" else "-names"
                    options = _options(arguments[1:], {"-d", "-dir", "-config"}, {switch, "-nocolor"})
                    if set(options) != {"-d", "-dir", "-config", switch, "-nocolor"}:
                        raise ValueError("incomplete Amass 5 command")
                    if not Path(str(options["-config"])).is_file():
                        raise ValueError("Amass configuration file does not exist")
            if options["-d"] != data["domain"]:
                raise ValueError("requested domain differs from the offline manifest")
            if provider == "amass" and version == "5.0.0":
                directory = Path(str(options["-dir"]))
                directory.mkdir(parents=True, exist_ok=True)
                graph = directory / "laboratory-graph.jsonl"
                if arguments[0] == "enum":
                    return _deliver(data, stdout, stderr, ready_path, graph=graph)
                retrieved = dict(data, lines=[json.loads(line) for line in graph.read_text(
                    encoding="utf-8").splitlines()])
                return _deliver(retrieved, stdout, stderr, ready_path, graph_results=True)
            return _deliver(data, stdout, stderr, ready_path, live="-v" in options)
        except (ValueError, TypeError, KeyError, OSError) as error:
            stderr(f"offline provider usage error: {error}\n")
            return 2


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, add_help=False, allow_abbrev=False)
    parser.add_argument("--provider", choices=("subfinder", "amass"), required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parsed, remaining = parser.parse_known_args()
    if remaining and remaining[0] == "--":
        remaining = remaining[1:]
    raise SystemExit(main(parsed.provider, parsed.manifest, remaining))
