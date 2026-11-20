# Serverless OpenTelemetry log pipeline on AWS

[![tests](https://github.com/Kh3lm0n45/aws-otel-ndjson-pipeline/actions/workflows/tests.yml/badge.svg)](https://github.com/Kh3lm0n45/aws-otel-ndjson-pipeline/actions/workflows/tests.yml)

An independent demonstrator of two related patterns for getting third-party
telemetry into a SIEM safely:

1. **Authenticated delivery.** An off-AWS collector writes to S3 using
   short-lived credentials from certificates (IAM Roles Anywhere), with no
   long-lived access keys. See [`roles-anywhere/`](roles-anywhere/README.md).
2. **Structural conversion.** A Lambda converts nested OpenTelemetry (OTLP/JSON)
   into single-line ND-JSON, mirroring the S3 key hierarchy, with no
   interpretation of the data. See [`lambda/`](lambda/).

All names, IDs, IPs and log content are synthetic. The code is a clean-room
implementation of the engineering pattern.

```
Collector (outside AWS)
  | cert-based short-lived credentials (Roles Anywhere)
  v
S3 raw bucket  (immutable, authoritative)
  | s3:ObjectCreated
  v
Lambda  (structural conversion only)
  v
S3 processed bucket  (lifecycle-expired copy)
  v
SIEM ingestion
```

## What it demonstrates

| Skill | Where |
|---|---|
| Event-driven AWS design (S3 -> Lambda -> S3) | `lambda/handler.py`, `s3/raw-notification.json` |
| Resilient input handling: trusts file signature, not `.gz` extension | `otlp.maybe_decompress`, tests |
| OTLP parsing and ND-JSON conversion | `lambda/otlp.py` |
| Least-privilege IAM (Lambda role, write-only vendor role, session revocation) | `iam/` |
| Raw vs processed separation, replayability, lifecycle expiry | `docs/design-decisions.md`, `s3/` |
| Certificate-based workload auth | `roles-anywhere/` |
| Testing with synthetic data | `tests/`, `scripts/gen_synthetic.py` |
| Publication hygiene (secret and identifier scanning) | `scripts/leak_scan.sh` |

## Behaviour

- Reads bucket and key from the S3 event (URL-decoded).
- If the first two bytes are `1F 8B`, decompresses; otherwise treats the body as JSON.
- Walks `resourceLogs[] -> scopeLogs[] -> logRecords[]`; one output line per record.
- Flattens `attributes[]` into top-level fields, with OTLP typed values converted
  (`intValue` strings become integers).
- Preserves `body`, `timeUnixNano`, `observedTimeUnixNano`; adds ISO-8601 UTC `timestamp`.
- Writes to `OUTPUT_BUCKET` using the source key with `.json.gz` swapped for `.ndjson`.
  Nothing computes asset/date/hour, so new prefixes need no code change.
- Refuses to run if source and output bucket are the same (recursion guard).

Example output (one line per event):

```json
{"timestamp":"2026-01-01T12:00:00.000000Z","site_name":"example-site","message":"Port 13 link off","unit":"network-syslog.service","source_class":"network-device","source_ip":"10.0.0.10","timeUnixNano":"1767268800000000000","observedTimeUnixNano":"1767268800005000000","body":{"kvlistValue":{}}}
```

## Run it

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install pytest
python scripts/gen_synthetic.py samples
pytest -q
```

Deploy: Python 3.12+ Lambda, handler `handler.lambda_handler`, env var
`OUTPUT_BUCKET`, execution role from `iam/lambda-execution-role.json`.
`boto3` is provided by the Lambda runtime.

## Scope

Deliberately **not** done in the converter: classification, detection, filtering,
enrichment, message parsing. Those belong in the SIEM, where they can change
without redeploying ingestion plumbing.

## Not included / next steps

- Infrastructure as code (Terraform or CloudFormation) for the whole stack.
- A dead-letter queue and alarm for failed conversions.
- Large-object handling (streaming instead of reading the object into memory).
- A CI workflow running tests and the leak scan.
