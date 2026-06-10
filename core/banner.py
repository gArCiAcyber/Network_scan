"""Multi-colored Larry 3D Triforce banner rendering for hylianscan."""

from core.colors import HACKER_GREEN, RESET, TRIFORCE_GREEN, TRIFORCE_RED, TRIFORCE_BLUE, BOLD_GOLD, BOLD_BLUE, BOLD_WHITE, BOLD_GREEN, BOLD_RED

VERSION = "0.8"


L1 = r" __  __   __    __  __     ______   ______  __  __  ____    ____     ______  __  __   "
L2 = r"/\ \/\ \ /\ \  /\ \/\ \   /\__  _\ /\  _  \/\ \/\ \/\  _`\ /\  _`\  /\  _  \/\ \/\ \  "
L3 = r"\ \ \_\ \\ `\`\\/'/\ \ \  \/_/\ \/ \ \ \L\ \ \ `\\ \ \,\L\_\ \ \/\_\\ \ \L\ \ \ `\\ \ "
L4 = r" \ \  _  \`\ `\ /'  \ \ \  __\ \ \  \ \  __ \ \ , ` \/_\__ \\ \ \/_/_\ \  __ \ \ , ` \ "
L5 = r"  \ \ \ \ \ `\ \ \   \ \ \L\ \\_\ \__\ \ \/\ \ \ \`\ \/\ \L\ \ \ \L\ \\ \ \/\ \ \ \`\ \ "
L6 = r"   \ \_\ \_\  \ \_\   \ \____//\_____\\ \_\ \_\ \_\ \_\ `\____\ \____/ \ \_\ \_\ \_\ \_\ "
L7 = r"    \/_/\/_/   \/_/    \/___/ \/_____/ \/_/\/_/\/_/\/_/\/_____/\/___/   \/_/\/_/\/_/\/_/ "

def build_footer() -> str:
    """Return the standardized HylianScan footer centered under the banner."""
    # Centered based on the 86-character width of the Larry 3D font layout
    # Blending Triforce Gold, Nayru Blue, White, and Farore Green bold variables
    return f"                      {BOLD_GOLD}[ {BOLD_BLUE}HYLIANSCAN {BOLD_WHITE}v{VERSION} {BOLD_GREEN}- BY CYLINK {BOLD_GOLD}]{RESET}"

def build_banner() -> str:
    """Build the complete multi-colored Larry 3D banner."""
    return (
        f"{TRIFORCE_GREEN}{L1}\n"
        f"{TRIFORCE_GREEN}{L2}\n"
        f"{TRIFORCE_RED}{L3}\n"
        f"{TRIFORCE_RED}{L4}\n"
        f"{TRIFORCE_BLUE}{L5}\n"
        f"{TRIFORCE_BLUE}{L6}\n"
        f"{TRIFORCE_BLUE}{L7}{RESET}\n\n"
        f"{build_footer()}"
    )


def show_banner() -> None:
    """Print the banner to the terminal."""
    print(build_banner())
    print()