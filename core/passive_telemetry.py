"""Passive discovery activity telemetry mapping for hylianscan."""

from dataclasses import dataclass, field


TIMEOUT_KEYWORDS = ("timeout", "timed out", "deadline")
DISCOVERY_KEYWORDS = ("discovered subdomain", "found subdomain", "subdomain")
CERTIFICATE_KEYWORDS = ("cert", "certificate", "crtsh", "crt.sh", "transparency")
PASSIVE_DNS_KEYWORDS = ("dns", "passive", "resolver", "resolve")
ARCHIVE_KEYWORDS = ("archive", "wayback", "commoncrawl")
WEB_ECHO_KEYWORDS = ("url", "web", "crawl", "search", "index")
THREAT_INTEL_KEYWORDS = (
    "intel",
    "threat",
    "securitytrails",
    "shodan",
    "virustotal",
    "censys",
    "alienvault",
    "urlscan",
    "fofa",
)
AMASS_GRAPH_KEYWORDS = ("amass", "graph", "networkdb", "enum")
WARNING_KEYWORDS = ("warning", "error", "unable", "failed", "rate")
PROVIDER_STARTED_KEYWORDS = ("provider started",)
FIRST_RESULT_KEYWORDS = ("first result observed",)
PROVIDER_COMPLETED_KEYWORDS = ("provider completed",)
MERGE_STARTED_KEYWORDS = ("merge/deduplication started",)
RESULTS_SAVED_KEYWORDS = ("results saved",)


@dataclass
class PassiveActivityTelemetry:
    """Map provider output to concise terminal activity messages."""

    seen_messages: set[str] = field(default_factory=set)

    def map_provider_output(self, provider: str, output: str) -> str | None:
        """Return one deduplicated activity message for observed provider output."""
        normalized_output = output.strip().lower()

        if not normalized_output:
            return None

        message = build_activity_message(provider, normalized_output)

        if message in self.seen_messages:
            return None

        self.seen_messages.add(message)
        return message

    def map_merge_activity(self) -> str | None:
        """Return one deduplicated merge activity message."""
        return self.map_lifecycle_event("merge/deduplication started")

    def map_lifecycle_event(self, event: str, provider: str = "hylianscan") -> str | None:
        """Return one deduplicated activity message for a workflow lifecycle event."""
        normalized_event = event.strip().lower()
        normalized_provider = provider.strip().lower()
        message = build_lifecycle_activity_message(normalized_provider, normalized_event)

        if message in self.seen_messages:
            return None

        self.seen_messages.add(message)
        return message


def contains_any(value: str, keywords: tuple[str, ...]) -> bool:
    """Return True when any keyword appears in a normalized string."""
    return any(keyword in value for keyword in keywords)


def build_activity_message(provider: str, output: str) -> str:
    """Map technical provider output into a short thematic activity message."""
    normalized_provider = provider.lower()

    if contains_any(output, PROVIDER_STARTED_KEYWORDS):
        return build_lifecycle_activity_message(normalized_provider, "provider started")

    if contains_any(output, FIRST_RESULT_KEYWORDS):
        return build_lifecycle_activity_message(
            normalized_provider,
            "first result observed",
        )

    if contains_any(output, PROVIDER_COMPLETED_KEYWORDS):
        return build_lifecycle_activity_message(
            normalized_provider,
            "provider completed",
        )

    if contains_any(output, MERGE_STARTED_KEYWORDS):
        return build_lifecycle_activity_message(
            normalized_provider,
            "merge/deduplication started",
        )

    if contains_any(output, RESULTS_SAVED_KEYWORDS):
        return build_lifecycle_activity_message(normalized_provider, "results saved")

    if contains_any(output, TIMEOUT_KEYWORDS):
        return build_lifecycle_activity_message(normalized_provider, "provider timeout")

    if contains_any(output, DISCOVERY_KEYWORDS):
        return "Link is following passive DNS trails..."

    if contains_any(output, CERTIFICATE_KEYWORDS):
        return "Navi is listening for certificate clues..."

    if contains_any(output, ARCHIVE_KEYWORDS):
        return "Zelda is opening the royal archives..."

    if contains_any(output, THREAT_INTEL_KEYWORDS):
        return "Impa is reading threat-intel records..."

    if contains_any(output, WEB_ECHO_KEYWORDS):
        return "Skull Kid is searching forgotten web echoes..."

    if normalized_provider == "amass" and contains_any(output, AMASS_GRAPH_KEYWORDS):
        return "Din is awakening the Amass graph..."

    if contains_any(output, PASSIVE_DNS_KEYWORDS):
        return "Link is following passive DNS trails..."

    if contains_any(output, WARNING_KEYWORDS):
        return "Impa is reviewing provider warnings..."

    if normalized_provider == "amass":
        return "Din is awakening the Amass graph..."

    return "Link is following passive DNS trails..."


def build_lifecycle_activity_message(provider: str, event: str) -> str:
    """Map internal workflow lifecycle events into short thematic activity messages."""
    provider_label = provider.capitalize()

    if event == "provider started":
        if provider == "amass":
            return "Din is awakening the Amass passive graph..."

        if provider == "subfinder":
            return "Zelda is opening Subfinder passive records..."

        return "Zelda is opening passive discovery records..."

    if event == "first result observed":
        return f"Link spotted the first {provider_label} discovery..."

    if event == "provider completed":
        return f"Impa closed the {provider_label} records cleanly..."

    if event == "merge/deduplication started":
        return "The Triforce is merging provider discoveries..."

    if event == "results saved":
        return "The Sheikah Slate saved passive discoveries to disk..."

    if event == "provider timeout":
        return f"The Triforce preserved partial {provider_label} discoveries after timeout..."

    return "Link is following passive DNS trails..."
