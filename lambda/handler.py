"""S3 ObjectCreated -> ND-JSON converter Lambda.

Reads the raw object named in the event, converts it, and writes the result to
OUTPUT_BUCKET under the mirrored key. Failures raise so Lambda's retry / DLQ
behaviour applies and the raw object remains available for replay.
"""
from __future__ import annotations

import logging
import os
from urllib.parse import unquote_plus

import otlp

logger = logging.getLogger()
logger.setLevel(logging.INFO)

_s3 = None


def s3_client():
    global _s3
    if _s3 is None:
        import boto3  # imported lazily so unit tests need no AWS SDK

        _s3 = boto3.client("s3")
    return _s3


def process_object(bucket: str, key: str, output_bucket: str) -> str:
    if bucket == output_bucket:
        # Guard against a misconfigured trigger causing a recursive loop.
        raise ValueError("source and output bucket are identical")

    raw = s3_client().get_object(Bucket=bucket, Key=key)["Body"].read()
    body, count = otlp.convert_payload(raw)
    out_key = otlp.mirror_key(key)

    if count == 0:
        logger.warning("no log records in s3://%s/%s; nothing written", bucket, key)
        return out_key

    s3_client().put_object(
        Bucket=output_bucket,
        Key=out_key,
        Body=body,
        ContentType="application/x-ndjson",
    )
    logger.info("converted s3://%s/%s -> s3://%s/%s (%d events)", bucket, key, output_bucket, out_key, count)
    return out_key


def lambda_handler(event, context):
    output_bucket = os.environ["OUTPUT_BUCKET"]  # fail fast if unset
    written = []
    for rec in event.get("Records", []):
        bucket = rec["s3"]["bucket"]["name"]
        key = unquote_plus(rec["s3"]["object"]["key"])  # S3 event keys are URL-encoded
        written.append(process_object(bucket, key, output_bucket))
    return {"written": written}
