from __future__ import annotations

import ipaddress
import re
from collections import defaultdict

from .models import LogEvent

IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:com|net|org|io|test|example|local)\b",
    re.IGNORECASE,
)
HASH_RE = re.compile(r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b")

RFC1918_NETWORKS = tuple(
    ipaddress.ip_network(network)
    for network in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)


def is_internal_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    return any(ip in network for network in RFC1918_NETWORKS)


def extract_iocs_from_text(text: str) -> dict[str, list[str]]:
    matches: dict[str, set[str]] = defaultdict(set)
    for candidate in IPV4_RE.findall(text):
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            continue
        matches["ip_addresses"].add(candidate)

    for domain in DOMAIN_RE.findall(text):
        matches["domains"].add(domain.lower())

    for file_hash in HASH_RE.findall(text):
        matches["hashes"].add(file_hash.lower())

    return {key: sorted(values) for key, values in matches.items()}


def extract_iocs(events: list[LogEvent]) -> dict[str, list[str]]:
    combined: dict[str, set[str]] = defaultdict(set)
    for event in events:
        text = " ".join(
            [
                event.source_ip,
                event.destination_ip,
                event.destination_domain,
                event.command_line,
                event.file_hash,
                event.message,
            ]
        )
        event_iocs = extract_iocs_from_text(text)
        for key, values in event_iocs.items():
            combined[key].update(values)

    external_ips = {
        ip for ip in combined.get("ip_addresses", set()) if not is_internal_ip(ip)
    }
    if external_ips:
        combined["external_ip_addresses"].update(external_ips)

    return {key: sorted(values) for key, values in combined.items()}
