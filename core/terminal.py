"""Linux terminal management for hylianscan."""

import os
import select
import sys
import termios
import threading
import tty

from core.banner import build_footer
from core.colors import CLEAR_LINE


_OUTPUT_LOCK = threading.Lock()


def clear_screen() -> None:
    """Clear the Linux terminal screen."""
    os.system("clear")


def write_dynamic_line(message: str) -> None:
    """Safely overwrite the current terminal line."""
    with _OUTPUT_LOCK:
        sys.stdout.write(f"\r{CLEAR_LINE}{message}")
        sys.stdout.flush()


def clear_dynamic_line() -> None:
    """Clear the current dynamic terminal line."""
    with _OUTPUT_LOCK:
        sys.stdout.write(f"\r{CLEAR_LINE}")
        sys.stdout.flush()


def print_safe(message: str = "") -> None:
    """Print a complete line without racing dynamic output."""
    with _OUTPUT_LOCK:
        sys.stdout.write(f"\r{CLEAR_LINE}{message}\n")
        sys.stdout.flush()


def flush_input_buffer() -> None:
    """Discard pending keyboard or mouse escape sequences."""
    if sys.stdin.isatty():
        termios.tcflush(sys.stdin.fileno(), termios.TCIFLUSH)


def wait_for_enter_safely(message: str) -> None:
    """Wait for Enter without echoing arrows or mouse scroll artifacts."""
    if not sys.stdin.isatty():
        input(message)
        return

    fd = sys.stdin.fileno()
    original_state = termios.tcgetattr(fd)

    sys.stdout.write(message)
    sys.stdout.flush()

    try:
        flush_input_buffer()
        tty.setcbreak(fd)
        quiet_state = termios.tcgetattr(fd)
        quiet_state[3] = quiet_state[3] & ~termios.ECHO
        termios.tcsetattr(fd, termios.TCSADRAIN, quiet_state)

        while True:
            ready, _, _ = select.select([sys.stdin], [], [])

            if not ready:
                continue

            char = sys.stdin.read(1)

            if char in ("\n", "\r"):
                break
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, original_state)
        flush_input_buffer()
        sys.stdout.write("\n")
        sys.stdout.flush()


def build_exit_prompt() -> str:
    """Return the final footer without the pause prompt."""
    return f"\n{build_footer()}\n"