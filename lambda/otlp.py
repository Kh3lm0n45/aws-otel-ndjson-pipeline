"""Pure OTLP/JSON -> ND-JSON conversion logic.

Structural conversion only: no classification, filtering, enrichment, or
message parsing. Those belong downstream in the SIEM.
"""
from __future__ import annotations

import gzip
import json
from datetime import datetime, timezone
from typing import Any, Iterator

GZIP_MAGIC = b"\x1f\x8b"

# Keys the converter writes itself. A flattened attribute with the same name
# is kept, but suffixed so it can never overwrite converter output.
RESERVED_KEYS = {
    "timestamp",
    "timeUnixNano",
    "observedTimeUnixNano",
    "body",
    "severityText",
    "severityNumber",
}


def maybe_decompress(raw: bytes) -> bytes:
    """Decide by file signature, not by extension (.json.gz may be plain JSON)."""
    if raw[:2] == GZIP_MAGIC:
        return gzip.decompress(raw)
    return raw


def parse_documents(data: bytes) -> list[dict]:
    """Parse one OTLP JSON document, or fall back to one document per line.

    Some exporters concatenate documents as ND-JSON. Try the whole payload
    first, then line-by-line. Any line that is not valid JSON raises.
    """
    text = data.decode("utf-8-sig")
    try:
        doc = json.loads(text)
        return doc if isinstance(doc, list) else [doc]
    except json.JSONDecodeError:
        docs = []
        for lineno, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                continue
            try:
                docs.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"line {lineno}: not valid JSON ({exc.msg})") from exc
        if not docs:
            raise ValueError("payload contains no JSON documents")
        return docs


def any_value(value: dict | None) -> Any:
    """Convert an OTLP AnyValue wrapper to a plain Python value."""
    if not value:
        return None
    if "stringValue" in value:
        return value["stringValue"]
    if "boolValue" in value:
        return value["boolValue"]
    if "intValue" in value:  # OTLP/JSON encodes int64 as a string
        return int(value["intValue"])
    if "doubleValue" in value:
        return value["doubleValue"]
    if "bytesValue" in value:  # base64 text, kept as-is
        return value["bytesValue"]
    if "arrayValue" in value:
        return [any_value(v) for v in value["arrayValue"].get("values", [])]
    if "kvlistValue" in value:
        return flatten_attributes(value["kvlistValue"].get("values", []))
    return None


def flatten_attributes(attrs: list[dict] | None) -> dict[str, Any]:
    """[{key, value:{stringValue:..}}] -> {key: value}."""
    return {a["key"]: any_value(a.get("value")) for a in attrs or [] if "key" in a}


def nano_to_iso(nanos: str | int | None) -> str | None:
    """Unix nanoseconds -> ISO-8601 UTC with microsecond precision.

    Integer arithmetic only: float seconds lose precision at nanosecond scale.
    """
    if nanos in (None, "", 0, "0"):
        return None
    n = int(nanos)
    seconds, rem = divmod(n, 1_000_000_000)
    dt = datetime.fromtimestamp(seconds, tz=timezone.utc).replace(microsecond=rem // 1000)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def convert_record(record: dict, resource_attrs: dict[str, Any]) -> dict[str, Any]:
    """One OTLP logRecord -> one flat event."""
    event: dict[str, Any] = {}
    ts = nano_to_iso(record.get("timeUnixNano")) or nano_to_iso(record.get("observedTimeUnixNano"))
    event["timestamp"] = ts

    # Resource attributes first, record attributes override on conflict.
    merged = {**resource_attrs, **flatten_attributes(record.get("attributes"))}
    for key, val in merged.items():
        event[f"{key}_attr" if key in RESERVED_KEYS else key] = val

    for field in ("timeUnixNano", "observedTimeUnixNano", "severityText", "severityNumber"):
        if field in record:
            event[field] = record[field]
    event["body"] = record.get("body")  # preserved untouched
    return event


def iter_events(doc: dict) -> Iterator[dict[str, Any]]:
    """Walk resourceLogs[] -> scopeLogs[] -> logRecords[]."""
    for resource_logs in doc.get("resourceLogs", []):
        resource_attrs = flatten_attributes(resource_logs.get("resource", {}).get("attributes"))
        for scope_logs in resource_logs.get("scopeLogs", []):
            for record in scope_logs.get("logRecords", []):
                yield convert_record(record, resource_attrs)


def to_ndjson(events: Iterator[dict[str, Any]]) -> tuple[bytes, int]:
    """Serialise events as exactly one JSON object per line. Returns (bytes, count).

    json.dumps escapes embedded newlines, so one event can never span lines.
    """
    lines = [json.dumps(e, separators=(",", ":"), ensure_ascii=False) for e in events]
    if not lines:
        return b"", 0
    return ("\n".join(lines) + "\n").encode("utf-8"), len(lines)


def convert_payload(raw: bytes) -> tuple[bytes, int]:
    """Raw S3 object bytes -> (ND-JSON bytes, event count)."""
    docs = parse_documents(maybe_decompress(raw))
    return to_ndjson(e for d in docs for e in iter_events(d))


def mirror_key(key: str) -> str:
    """Mirror the source key, swapping only the file suffix."""
    for suffix in (".json.gz", ".json"):
        if key.endswith(suffix):
            return key[: -len(suffix)] + ".ndjson"
    return key + ".ndjson"
