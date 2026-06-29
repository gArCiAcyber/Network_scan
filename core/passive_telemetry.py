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

        if message is None:
            return None

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

        if message is None:
            return None

        if message in self.seen_messages:
            return None

        self.seen_messages.add(message)
        return message


def contains_any(value: str, keywords: tuple[str, ...]) -> bool:
    """Return True when any keyword appears in a normalized string."""
    return any(keyword in value for keyword in keywords)


def build_activity_message(provider: str, output: str) -> str | None:
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

    if contains_any(output, TIMEOUT_KEYWORDS):
        return build_lifecycle_activity_message(normalized_provider, "provider timeout")

    if contains_any(output, DISCOVERY_KEYWORDS):
        return f"Reading {provider_label(normalized_provider)} passive DNS results..."

    if contains_any(output, CERTIFICATE_KEYWORDS):
        return f"Checking {provider_label(normalized_provider)} certificate transparency data..."

    if contains_any(output, ARCHIVE_KEYWORDS):
        return f"Checking {provider_label(normalized_provider)} archived web records..."

    if contains_any(output, THREAT_INTEL_KEYWORDS):
        return f"Checking {provider_label(normalized_provider)} threat-intel sources..."

    if contains_any(output, WEB_ECHO_KEYWORDS):
        return f"Checking {provider_label(normalized_provider)} indexed web sources..."

    if normalized_provider == "amass" and contains_any(output, AMASS_GRAPH_KEYWORDS):
        return "Reading Amass passive graph data..."

    if contains_any(output, PASSIVE_DNS_KEYWORDS):
        return f"Reading {provider_label(normalized_provider)} passive DNS trails..."

    if contains_any(output, WARNING_KEYWORDS):
        return f"Reviewing {provider_label(normalized_provider)} provider warnings..."

    if normalized_provider == "amass":
        return "Reading Amass passive graph data..."

    return f"Reading {provider_label(normalized_provider)} passive source output..."


def provider_label(provider: str) -> str:
    """Return a display-safe provider label."""
    labels = {
        "subfinder": "Subfinder",
        "amass": "Amass",
        "hylianscan": "passive discovery",
    }
    return labels.get(provider, provider.capitalize())


def build_lifecycle_activity_message(provider: str, event: str) -> str | None:
    """Map internal workflow lifecycle events into concise activity messages."""
    label = provider_label(provider)

    if event == "provider started":
        return f"Running {label} passive enumeration..."

    if event == "first result observed":
        return f"{label} returned the first candidate..."

    if event == "provider completed":
        return None

    if event == "merge/deduplication started":
        return "Normalizing provider results..."

    if event == "provider timeout":
        return f"{label} timed out; preserving partial results..."

    return "Reading passive discovery provider output..."
