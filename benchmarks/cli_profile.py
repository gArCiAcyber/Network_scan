"""Profile an unchanged CLI in a diagnostic companion, preserving its output."""

import argparse
import builtins
import cProfile
import json
import runpy
import sys
import time
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        parser.error("A target script is required")
    script = Path(command[0]).resolve()
    sys.path.insert(0, str(script.parent))
    sys.argv = [str(script), *command[1:]]
    events = []
    origin = time.perf_counter()
    profiler = cProfile.Profile()

    def mark(stage, event, **fields):
        events.append({"stage": stage, "event": event,
                       "seconds": time.perf_counter() - origin, **fields})

    def observe(name, function):
        def call(*positional, **keywords):
            mark(name, "start")
            try:
                result = function(*positional, **keywords)
                if name == "run_port_scan":
                    mark(name, "native_result", native_seconds=result.duration)
                return result
            finally:
                mark(name, "end")
        return call

    try:
        profiler.enable()
        mark("imports", "start")
        namespace = runpy.run_path(str(script), run_name="hylianlab_profile")["main"].__globals__
        mark("imports", "end")
        for name in ("parse_arguments", "parse_ports_list", "resolve_target", "run_port_scan",
                     "build_quiet_final_panel", "build_final_panel", "build_saved_text_report",
                     "save_report", "write_tcp_json_report"):
            if name in namespace:
                namespace[name] = observe(name, namespace[name])
        namespace["print"] = observe("stdout", builtins.print)
        mark("main", "start")
        try:
            namespace["main"]()
        finally:
            mark("main", "end")
    finally:
        profiler.disable()
        mark("wrapper", "end")
        args.output.parent.mkdir(parents=True, exist_ok=True)
        profiler.dump_stats(str(args.output.with_suffix(".prof")))
        args.output.write_text(json.dumps({"events": events, "command": sys.argv,
            "policy": "Companion only; nested spans overlap; interpreter startup and final persistence excluded"}),
            encoding="utf-8")


if __name__ == "__main__":
    main()
