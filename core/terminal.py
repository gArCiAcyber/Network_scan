"""Terminal management helpers for hylianscan."""

import os
import shutil
import sys
import threading
import textwrap
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

from core.colors import CLEAR_LINE


_OUTPUT_LOCK = threading.Lock()
_CLEAR_FROM_CURSOR_DOWN = "\033[J"


def escape_controls(text: str, multiline: bool = False) -> str:
    """Make untrusted terminal controls visible without changing stored evidence."""
    return "".join(
        char if (multiline and char in "\n\t") or unicodedata.category(char) not in {"Cc", "Cf"}
        else char.encode("unicode_escape").decode("ascii")
        for char in text
    )


def wrap_report(text: str) -> str:
    """Wrap plain report lines to the terminal width without dropping evidence."""
    width = max(20, shutil.get_terminal_size(fallback=(100, 24)).columns)
    return "\n".join(
        textwrap.fill(line, width=width, subsequent_indent="  ",
                      replace_whitespace=False, drop_whitespace=True)
        if line else ""
        for line in text.splitlines()
    )


def format_separator() -> str:
    """Keep the traditional 72-hyphen separator within the report width."""
    return "-" * min(72, max(20, shutil.get_terminal_size(fallback=(100, 24)).columns))


def write_encoded(text: str) -> None:
    encoding = sys.stdout.encoding or "utf-8"
    sys.stdout.write(text.encode(encoding, errors="backslashreplace").decode(encoding))


def print_report(text: str) -> None:
    """Print reports even when the terminal cannot represent collected text."""
    encoding = sys.stdout.encoding or "utf-8"
    print(text.encode(encoding, errors="backslashreplace").decode(encoding))


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
        write_encoded(f"\r{CLEAR_LINE}{message}")
        sys.stdout.flush()


def clear_dynamic_line() -> None:
    """Clear the current dynamic terminal line."""
    with _OUTPUT_LOCK:
        write_encoded(f"\r{CLEAR_LINE}")
        sys.stdout.flush()


def print_safe(message: str = "") -> None:
    """Print a complete line without racing dynamic output."""
    with _OUTPUT_LOCK:
        write_encoded(f"\r{CLEAR_LINE}{message}\n")
        sys.stdout.flush()


class DynamicBlockRenderer:
    """Render a small dynamic terminal block without duplicated lines."""

    def __init__(self) -> None:
        self._line_count = 0

    def render(self, lines: list[str]) -> None:
        """Rewrite the current dynamic block with the provided lines."""
        with _OUTPUT_LOCK:
            if self._line_count:
                write_encoded(f"\033[{self._line_count}A")

            write_encoded(f"\r{_CLEAR_FROM_CURSOR_DOWN}")

            for line in lines:
                write_encoded(f"{line}\n")

            sys.stdout.flush()
            self._line_count = len(lines)

    def clear(self) -> None:
        """Clear the rendered dynamic block."""
        with _OUTPUT_LOCK:
            if self._line_count:
                write_encoded(f"\033[{self._line_count}A")

            write_encoded(f"\r{_CLEAR_FROM_CURSOR_DOWN}")
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

    write_encoded(message)
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
        write_encoded("\n")
        sys.stdout.flush()
