"""Centralized ANSI color constants for hylianscan."""

HACKER_GREEN = "\033[92m"
ALERT_RED = "\033[31m"
INFO_BLUE = "\033[34m"
WARNING_YELLOW = "\033[33m"
MUTED_GRAY = "\033[90m"
BRIGHT_WHITE = "\033[97m"
RESET = "\033[0m"
CLEAR_LINE = "\033[K"

# --- Bold colors for highlights (The Legend of Zelda Theme) ---
BOLD_GREEN = "\033[1;32m"   # Green Farore (highlight)
BOLD_RED = "\033[1;31m"     # Red Din (highlight)
BOLD_BLUE = "\033[1;34m"    # Blue Nayru (highlight)
BOLD_GOLD = "\033[1;33m"    # Yellow Triforce (highlight)
BOLD_MAGENTA = "\033[1;35m"  # Magenta Zelda (highlight)
BOLD_PURPLE = "\033[1;35m"   # Purple Skull Kid / Impa (highlight)
BOLD_WHITE = "\033[1;37m"   # White (highlight)

# --- The colors of the triforce (The Legend of Zelda Theme) ---
TRIFORCE_GREEN = "\033[1;32m"  # Farore / Courage
TRIFORCE_RED = "\033[1;31m"    # Din / Power
TRIFORCE_BLUE = "\033[1;34m"   # Nayru / Wisdom


def paint(text: str, color: str) -> str:
    """Wrap text with an ANSI color and reset formatting."""
    return f"{color}{text}{RESET}"
