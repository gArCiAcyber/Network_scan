"""Minimalist banner rendering for hylianscan."""

from core.colors import BRIGHT_WHITE, HACKER_GREEN, MUTED_GRAY, RESET


LINK_ASCII = """⠀⠀⠀⠀⠀⠀⢀⣠⣤⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣾⣿⣿⣿⣷⣶⣶⣦⣤⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⣠⣤⣤⣷⣿⣿⣿⣯⡉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⣠⣾⣟⢿⢻⡝⣿⣿⣿⣿⣿⣆⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⢿⠬⢾⣳⠗⢲⣿⣿⣿⡏⠻⠿⢿⣶⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠸⣷⣜⢐⡶⣿⣿⣿⣿⣿⣿⣷⣶⡞⠻⢷⣄⠀⠀⠀⠀⠀⠀⠀⠀
⢠⡿⠷⣿⣾⠿⣿⣿⣿⡿⠿⢿⣿⡟⠀⠀⠁⠉⠲⢄⡀⠀⠀⠀⠀
⠘⠀⠀⠈⠀⠀⠹⣿⣿⣧⠀⢸⣿⠃⠀⠀⠀⠀⠀⠀⠉⠒⢄⡀⠀
⠀⠀⠀⠀⠀⠀⠀⠈⢻⣿⣄⢻⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠐
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢿⣿⣇⠿⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠻⣿⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⢿⣦⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠛⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀"""


def build_title() -> str:
    """Build the textual title block."""
    return (
        f"{HACKER_GREEN}hylianscan v0.4{RESET}\n"
        f"{MUTED_GRAY}high-performance tcp reconnaissance | kali linux{RESET}"
    )


def build_credits() -> str:
    """Return the project credit line."""
    return f"{BRIGHT_WHITE}Developed by:{RESET} cylink {HACKER_GREEN}|{RESET} RedByte Security"


def build_banner() -> str:
    """Build the complete minimalist banner."""
    return (
        f"{build_title()}\n\n"
        f"{HACKER_GREEN}{LINK_ASCII}{RESET}\n\n"
        f"{build_credits()}"
    )


def show_banner() -> None:
    """Print the banner to the terminal."""
    print(build_banner())
    print()

