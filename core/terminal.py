"""Terminal management helpers for hylianscan."""

import os
import sys
import threading

try:
    import select
except ImportError:
    select = None

try:
    import termios
    import tty
except ImportError:
    termios = None
    tty = None

try:
    import msvcrt
except ImportError:
    msvcrt = None

from core.banner import build_footer
from core.colors import CLEAR_LINE


_OUTPUT_LOCK = threading.Lock()


def has_posix_terminal_control() -> bool:
    """Return True when POSIX terminal controls are available."""
    return (
        sys.stdin.isatty()
        and select is not None
        and termios is not None
        and tty is not None
    )


def clear_screen() -> None:
    """Clear the active terminal screen."""
    command = "cls" if os.name == "nt" else "clear"
    os.system(command)


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
    if has_posix_terminal_control():
        termios.tcflush(sys.stdin.fileno(), termios.TCIFLUSH)
        return

    if msvcrt is None:
        return

    try:
        while msvcrt.kbhit():
            msvcrt.getwch()
    except OSError:
        return


def wait_for_enter_with_input(message: str) -> None:
    """Use the safest available line input fallback."""
    flush_input_buffer()
    input(message)
    flush_input_buffer()


def wait_for_enter_safely(message: str) -> None:
    """Wait for Enter without echoing arrows or mouse scroll artifacts."""
    if not has_posix_terminal_control():
        wait_for_enter_with_input(message)
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
