"""Centralized ANSI color constants for hylianscan."""

HACKER_GREEN = "\033[92m"
ALERT_RED = "\033[31m"
INFO_BLUE = "\033[34m"
WARNING_YELLOW = "\033[33m"
MUTED_GRAY = "\033[90m"
BRIGHT_WHITE = "\033[97m"
RESET = "\033[0m"
CLEAR_LINE = "\033[K"


def paint(text: str, color: str) -> str:
    """Wrap text with an ANSI color and reset formatting."""
    return f"{color}{text}{RESET}"

