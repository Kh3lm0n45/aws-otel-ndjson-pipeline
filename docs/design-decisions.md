# Design decisions

## Context

A supplier-managed platform emits OpenTelemetry logs and delivers them to S3.
The exporter is owned by the supplier and cannot be modified. The downstream
SIEM needs single-line JSON. Delivery to S3 already worked.

## Decisions

### 1. Convert in our account; do not touch the upstream exporter
We cannot change the supplier's component, and should not need to. A small
conversion layer on our side of the boundary keeps ownership clear and survives
supplier upgrades.

### 2. Structural conversion only
The Lambda reshapes data and nothing else. No classification, filtering,
enrichment or parsing. Rationale: detection logic changes often and belongs in
the SIEM; a plumbing layer that interprets data becomes a second, untested
detection engine. It also means the converter never silently drops evidence.

### 3. Trust the bytes, not the extension
Objects are named `.json.gz`, but testing showed some hold plain JSON. The
Lambda checks for the gzip magic bytes `1F 8B` and handles both. A converter
that trusted the name would fail on exactly the files that look normal.

### 4. Mirror the source key
The output key is the input key with only the suffix changed. The code never
computes asset, date or hour, so new assets and partitions need no deployment,
and partitioning remains whatever the source defines.

### 5. Two buckets
| Raw | Processed |
|---|---|
| Authoritative, untouched | Derived, disposable |
| Retained per evidence needs | Lifecycle-expired (`s3/processed-lifecycle.json`) |
| Triggers the Lambda | Never triggers it, so no recursion |

Failed conversions can be replayed from raw. The Lambda also checks
`source != output` at runtime as a second guard.

### 6. Fail loudly
Malformed input raises. Lambda retries, then the event can go to a DLQ, and the
raw object remains. The alternative, swallowing the error and skipping the file,
creates silent gaps in security telemetry.

### 7. Configuration through environment
`OUTPUT_BUCKET` is an environment variable, so identical reviewed code runs in
test and production.

### 8. Least privilege
Lambda: `GetObject` on raw, `PutObject` on processed, its own log group, and KMS
only if customer-managed keys are used. Supplier writer: `PutObject` to one
prefix and nothing else (no list, read or delete).

## Assumptions to verify against your own data

- Resource-level attributes (e.g. site name) are merged into each event, with
  record attributes winning on conflict. Confirm this matches what your SIEM
  expects.
- Attributes whose names collide with converter-written fields get an `_attr`
  suffix rather than overwriting them.
- A payload that is not one JSON document falls back to one document per line.
