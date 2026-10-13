"""Terminal management helpers for hylianscan."""

import os
import re
import shutil
import sys
import threading
import unicodedata

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

from core.colors import CLEAR_LINE, RESET


_OUTPUT_LOCK = threading.Lock()
_CLEAR_FROM_CURSOR_DOWN = "\033[J"
_SGR_OR_CHARACTER = re.compile(r"\x1b\[[0-9;]*m|[^\x00-\x1f\x7f]")


def _fit_terminal_line(line: str, columns: int) -> str:
    """Keep colors while fitting one live row, leaving the wrap column unused."""
    output = []
    used = 0
    for match in _SGR_OR_CHARACTER.finditer(line):
        token = match.group()
        if token.startswith("\x1b["):
            output.append(token)
            continue
        if unicodedata.category(token).startswith("C"):
            continue
        width = 0 if unicodedata.combining(token) else (
            2 if unicodedata.east_asian_width(token) in {"W", "F"} else 1
        )
        if used + width > max(0, columns - 1):
            break
        output.append(token)
        used += width
    return "".join(output) + RESET


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


class DynamicBlockRenderer:
    """Render a small dynamic terminal block without duplicated lines."""

    def __init__(self) -> None:
        self._line_count = 0

    def render(self, lines: list[str]) -> None:
        """Rewrite the current dynamic block with the provided lines."""
        with _OUTPUT_LOCK:
            columns, rows = shutil.get_terminal_size()
            # A block taller than the screen scrolls beyond cursor-up's reach.
            lines = lines[-max(1, rows - 1):]
            if self._line_count:
                sys.stdout.write(f"\033[{self._line_count}A")

            sys.stdout.write(f"\r{_CLEAR_FROM_CURSOR_DOWN}")

            for line in lines:
                sys.stdout.write(f"{_fit_terminal_line(line, columns)}\n")

            sys.stdout.flush()
            self._line_count = len(lines)

    def clear(self) -> None:
        """Clear the rendered dynamic block."""
        with _OUTPUT_LOCK:
            if self._line_count:
                sys.stdout.write(f"\033[{self._line_count}A")

            sys.stdout.write(f"\r{_CLEAR_FROM_CURSOR_DOWN}")
            sys.stdout.flush()
            self._line_count = 0

    def release(self) -> None:
        """Stop tracking rendered lines without clearing visible output."""
        self._line_count = 0


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
