"""Centralized ANSI color constants for hylianscan."""

HACKER_GREEN = "\033[92m"
ALERT_RED = "\033[31m"
INFO_BLUE = "\033[34m"
WARNING_YELLOW = "\033[33m"
MUTED_GRAY = "\033[90m"
BRIGHT_WHITE = "\033[97m"
RESET = "\033[0m"
CLEAR_LINE = "\033[K"

# --- The colors of the triforce (The Legend of Zelda Theme) ---
TRIFORCE_GREEN = "\033[1;32m"  # Farore / Coragem (Verde Vivo)
TRIFORCE_RED = "\033[1;31m"    # Din / Poder (Vermelho Vivo)
TRIFORCE_BLUE = "\033[1;34m"   # Nayru / Sabedoria (Azul Vivo)


def paint(text: str, color: str) -> str:
    """Wrap text with an ANSI color and reset formatting."""
    return f"{color}{text}{RESET}"