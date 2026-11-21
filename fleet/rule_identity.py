"""Compact stable rule tags, with backward-compatible legacy recognition."""

import re
import uuid

LEGACY_PREFIX = "[opnmanager:"
SHORT_PREFIX = "[om:"


def short_marker(rule_id):
    return SHORT_PREFIX + uuid.UUID(str(rule_id)).hex[:12] + "]"


def markers(rule_id):
    return (short_marker(rule_id), LEGACY_PREFIX + str(rule_id) + "]")


def matches(description, rule_id):
    return any(
        description == tag or description.startswith(tag + " ") or description.endswith(" " + tag)
        for tag in markers(rule_id)
    )


def is_managed(description):
    return description.startswith((LEGACY_PREFIX, SHORT_PREFIX)) or bool(
        re.search(r"(?:^| )\[(?:om:[0-9a-f]{12}|opnmanager:[0-9a-f-]{36})\]$", description)
    )


MARKER = re.compile(r"(?:^| )(\[om:[0-9a-f]{12}\])$")


def marker_of(description):
    """The short tag a description ends with, or None."""
    match = MARKER.search(description)
    return match[1] if match else None


def tagged(description, object_id):
    """A pushed description: the manager text followed by the object's short tag."""
    return (description.strip() + " " + short_marker(object_id)).strip()


def untagged(description):
    """A device description without its trailing short tag."""
    match = MARKER.search(description)
    return description[: match.start()].rstrip() if match else description
