#!/usr/bin/env python3
"""Generate synthetic OTLP/JSON log files. Nothing here derives from real logs.

Usage: gen_synthetic.py OUT_DIR
Writes a plain-JSON file and a genuine gzip file, both named *.json.gz, to
reproduce the "extension lies" condition the Lambda must handle.
"""
import gzip
import json
import pathlib
import sys

BASE_NS = 1767268800000000000  # 2026-01-01T12:00:00Z


def attr(k, v):
    if isinstance(v, bool):
        return {"key": k, "value": {"boolValue": v}}
    if isinstance(v, int):
        return {"key": k, "value": {"intValue": str(v)}}  # OTLP/JSON int64 is a string
    return {"key": k, "value": {"stringValue": v}}


def record(offset_s, message, unit, source_class, **extra):
    return {
        "timeUnixNano": str(BASE_NS + offset_s * 1_000_000_000),
        "observedTimeUnixNano": str(BASE_NS + offset_s * 1_000_000_000 + 5_000_000),
        "body": {"kvlistValue": {}},
        "attributes": [
            attr("message", message),
            attr("unit", unit),
            attr("source_class", source_class),
            *[attr(k, v) for k, v in extra.items()],
        ],
    }


def build():
    return {
        "resourceLogs": [
            {
                "resource": {"attributes": [attr("site_name", "example-site")]},
                "scopeLogs": [
                    {
                        "scope": {"name": "synthetic-generator"},
                        "logRecords": [
                            record(0, "Port 13 link off", "network-syslog.service", "network-device", source_ip="10.0.0.10"),
                            record(1, "Port 13 link on", "network-syslog.service", "network-device", source_ip="10.0.0.10"),
                            record(30, "Accepted publickey for user@example.com", "sshd.service", "ssh", source_ip="10.0.0.20", session_id=4242, tty=True),
                            record(31, "session opened for user example-user", "sshd.service", "ssh", source_ip="10.0.0.20", session_id=4242),
                            record(45, "COMMAND=/usr/bin/systemctl status example", "sudo", "command", source_ip="10.0.0.20"),
                        ],
                    }
                ],
            }
        ]
    }


def main(out_dir):
    out = pathlib.Path(out_dir)
    key_dir = out / "asset-01/year=2026/month=01/day=01/hour=12"
    key_dir.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(build()).encode()
    (key_dir / "logs_000000001.json.gz").write_bytes(payload)            # plain JSON, gz name
    (key_dir / "logs_000000002.json.gz").write_bytes(gzip.compress(payload))  # real gzip
    print(f"wrote synthetic samples under {key_dir}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "samples")
