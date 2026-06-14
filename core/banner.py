"""TrueColor Slant banner rendering for hylianscan."""

from core.colors import RESET

VERSION = "0.9"
FOOTER_TEXT = f"[ HYLIANSCAN v{VERSION} - BY CYLINK ]"

SLANT_BANNER_LINES = [
    r"    __          ___                      ",
    r"   / /_  __  __/ (_)___ _____  ______________ _____",
    "  / __ \\/ / / / / / __ `/ __ \\/ ___/ ___/ __ `/ __ \\",
    r" / / / / /_/ / / / /_/ / / / (__  ) /__/ /_/ / / / /",
    r"/_/ /_/\__, /_/_/\__,_/_/ /_/____/\___/\__,_/_/ /_/",
    r"      /____/                                      ",
]

RAINBOW_STOPS = [
    (255, 48, 48),
    (255, 140, 0),
    (255, 220, 0),
    (80, 220, 80),
    (0, 210, 220),
    (80, 130, 255),
    (210, 80, 255),
]


def visible_banner_width() -> int:
    """Return the visible width of the Slant banner."""
    return max(len(line) for line in SLANT_BANNER_LINES)


def rgb_escape(red: int, green: int, blue: int) -> str:
    """Build a 24-bit ANSI foreground color escape sequence."""
    return f"\033[38;2;{red};{green};{blue}m"


def interpolate_channel(start: int, end: int, ratio: float) -> int:
    """Interpolate one RGB channel."""
    return round(start + (end - start) * ratio)


def color_at_position(position: int, width: int) -> tuple[int, int, int]:
    """Return the RGB color for a horizontal character position."""
    if width <= 1:
        return RAINBOW_STOPS[0]

    scaled_position = (position / (width - 1)) * (len(RAINBOW_STOPS) - 1)
    stop_index = min(int(scaled_position), len(RAINBOW_STOPS) - 2)
    local_ratio = scaled_position - stop_index
    start = RAINBOW_STOPS[stop_index]
    end = RAINBOW_STOPS[stop_index + 1]

    return (
        interpolate_channel(start[0], end[0], local_ratio),
        interpolate_channel(start[1], end[1], local_ratio),
        interpolate_channel(start[2], end[2], local_ratio),
    )


def apply_horizontal_gradient(line: str, width: int) -> str:
    """Apply a smooth RGB gradient to visible characters in one line."""
    rendered_parts = []

    for index, character in enumerate(line):
        if character == " ":
            rendered_parts.append(character)
            continue

        red, green, blue = color_at_position(index, width)
        rendered_parts.append(f"{rgb_escape(red, green, blue)}{character}")

    return "".join(rendered_parts) + RESET


def center_text(text: str, width: int) -> str:
    """Center plain text relative to the banner width."""
    padding = max((width - len(text)) // 2, 0)
    return f"{' ' * padding}{text}"


def build_footer(width: int | None = None) -> str:
    """Return the standardized Hylianscan footer using the banner gradient."""
    if width is None:
        width = visible_banner_width()

    return apply_horizontal_gradient(center_text(FOOTER_TEXT, width), width)


def build_banner() -> str:
    """Build the complete static Slant banner with a TrueColor gradient."""
    width = visible_banner_width()
    banner_lines = [
        apply_horizontal_gradient(line, width)
        for line in SLANT_BANNER_LINES
    ]

    return "\n".join(banner_lines) + "\n\n" + build_footer(width) + RESET


def show_banner() -> None:
    """Print the banner to the terminal."""
    print(build_banner())
    print()
