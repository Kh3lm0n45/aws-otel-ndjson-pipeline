import gzip
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lambda"))
sys.path.insert(0, str(ROOT / "scripts"))

import handler  # noqa: E402
import otlp  # noqa: E402
import gen_synthetic  # noqa: E402


@pytest.fixture
def payload():
    return json.dumps(gen_synthetic.build()).encode()


def lines(b):
    return b.decode().splitlines()


# ---- input detection -------------------------------------------------------

def test_plain_json_with_gz_name_is_handled(payload):
    out, n = otlp.convert_payload(payload)
    assert n == 5


def test_real_gzip_is_handled(payload):
    out, n = otlp.convert_payload(gzip.compress(payload))
    assert n == 5


def test_gzip_and_plain_give_identical_output(payload):
    assert otlp.convert_payload(payload) == otlp.convert_payload(gzip.compress(payload))


def test_utf8_bom_tolerated(payload):
    assert otlp.convert_payload(b"\xef\xbb\xbf" + payload)[1] == 5


def test_concatenated_documents_fallback(payload):
    doc = json.dumps(gen_synthetic.build())
    _, n = otlp.convert_payload((doc + "\n" + doc + "\n").encode())
    assert n == 10


def test_garbage_raises():
    with pytest.raises(ValueError):
        otlp.convert_payload(b"not json at all\n{broken")


# ---- structural conversion -------------------------------------------------

def test_one_event_per_line_and_each_line_valid_json(payload):
    out, n = otlp.convert_payload(payload)
    ls = lines(out)
    assert len(ls) == n == 5
    for line in ls:
        json.loads(line)
    assert out.endswith(b"\n")


def test_attributes_flattened_and_types_preserved(payload):
    ev = json.loads(lines(otlp.convert_payload(payload)[0])[2])
    assert ev["message"] == "Accepted publickey for user@example.com"
    assert ev["session_id"] == 4242 and isinstance(ev["session_id"], int)
    assert ev["tty"] is True
    assert ev["site_name"] == "example-site"  # resource attribute carried through


def test_body_and_raw_timestamps_preserved(payload):
    ev = json.loads(lines(otlp.convert_payload(payload)[0])[0])
    assert ev["body"] == {"kvlistValue": {}}
    assert ev["timeUnixNano"] == "1767268800000000000"
    assert ev["observedTimeUnixNano"] == "1767268800005000000"


def test_iso_timestamp_utc_microseconds(payload):
    ev = json.loads(lines(otlp.convert_payload(payload)[0])[0])
    assert ev["timestamp"] == "2026-01-01T12:00:00.000000Z"


def test_nano_precision_not_lost_to_float():
    assert otlp.nano_to_iso("1767268800123456789") == "2026-01-01T12:00:00.123456Z"


def test_falls_back_to_observed_time():
    rec = {"timeUnixNano": "0", "observedTimeUnixNano": "1767268800000000000", "body": {}}
    assert otlp.convert_record(rec, {})["timestamp"] == "2026-01-01T12:00:00.000000Z"


def test_attribute_cannot_overwrite_reserved_field():
    rec = {
        "timeUnixNano": "1767268800000000000",
        "body": {"stringValue": "real body"},
        "attributes": [{"key": "body", "value": {"stringValue": "spoofed"}}],
    }
    ev = otlp.convert_record(rec, {})
    assert ev["body"] == {"stringValue": "real body"}
    assert ev["body_attr"] == "spoofed"


def test_newline_in_message_does_not_split_line():
    rec = {
        "timeUnixNano": "1767268800000000000",
        "attributes": [{"key": "message", "value": {"stringValue": "a\nb\r\nc"}}],
    }
    out, n = otlp.to_ndjson(iter([otlp.convert_record(rec, {})]))
    assert n == 1 and len(lines(out)) == 1


def test_nested_kvlist_and_array_values():
    v = {"kvlistValue": {"values": [{"key": "a", "value": {"arrayValue": {"values": [{"intValue": "1"}, {"stringValue": "x"}]}}}]}}
    assert otlp.any_value(v) == {"a": [1, "x"]}


def test_empty_document_yields_no_events():
    assert otlp.convert_payload(b'{"resourceLogs": []}') == (b"", 0)


# ---- key mirroring ---------------------------------------------------------

@pytest.mark.parametrize(
    "src,dst",
    [
        ("asset-02/year=2026/month=11/day=20/hour=12/logs_123456789.json.gz",
         "asset-02/year=2026/month=11/day=20/hour=12/logs_123456789.ndjson"),
        ("asset-09/year=2027/month=02/day=03/hour=00/logs_x.json", "asset-09/year=2027/month=02/day=03/hour=00/logs_x.ndjson"),
        ("asset-01/odd-name", "asset-01/odd-name.ndjson"),
    ],
)
def test_mirror_key_preserves_hierarchy(src, dst):
    assert otlp.mirror_key(src) == dst


# ---- handler ---------------------------------------------------------------

class FakeS3:
    def __init__(self, objects):
        self.objects, self.puts = objects, {}

    def get_object(self, Bucket, Key):
        import io
        return {"Body": io.BytesIO(self.objects[(Bucket, Key)])}

    def put_object(self, **kw):
        self.puts[(kw["Bucket"], kw["Key"])] = kw


def s3_event(bucket, key):
    return {"Records": [{"s3": {"bucket": {"name": bucket}, "object": {"key": key}}}]}


def test_handler_end_to_end(monkeypatch, payload):
    key = "asset-02/year=2026/month=11/day=20/hour=12/logs_123.json.gz"
    fake = FakeS3({("raw-otel-logs", key): gzip.compress(payload)})
    monkeypatch.setattr(handler, "_s3", fake)
    monkeypatch.setenv("OUTPUT_BUCKET", "processed-siem-logs")
    res = handler.lambda_handler(s3_event("raw-otel-logs", key), None)
    out_key = "asset-02/year=2026/month=11/day=20/hour=12/logs_123.ndjson"
    assert res == {"written": [out_key]}
    put = fake.puts[("processed-siem-logs", out_key)]
    assert put["ContentType"] == "application/x-ndjson"
    assert len(lines(put["Body"])) == 5


def test_handler_decodes_url_encoded_keys(monkeypatch, payload):
    fake = FakeS3({("raw-otel-logs", "asset-01/a b+c.json.gz"): payload})
    monkeypatch.setattr(handler, "_s3", fake)
    monkeypatch.setenv("OUTPUT_BUCKET", "processed-siem-logs")
    handler.lambda_handler(s3_event("raw-otel-logs", "asset-01/a+b%2Bc.json.gz"), None)
    assert ("processed-siem-logs", "asset-01/a b+c.ndjson") in fake.puts


def test_handler_refuses_same_bucket(monkeypatch, payload):
    monkeypatch.setattr(handler, "_s3", FakeS3({}))
    monkeypatch.setenv("OUTPUT_BUCKET", "raw-otel-logs")
    with pytest.raises(ValueError):
        handler.lambda_handler(s3_event("raw-otel-logs", "k.json.gz"), None)


def test_handler_requires_output_bucket(monkeypatch):
    monkeypatch.delenv("OUTPUT_BUCKET", raising=False)
    with pytest.raises(KeyError):
        handler.lambda_handler(s3_event("b", "k"), None)


def test_malformed_object_raises_and_writes_nothing(monkeypatch):
    fake = FakeS3({("raw-otel-logs", "k.json.gz"): b"\x00\x01garbage"})
    monkeypatch.setattr(handler, "_s3", fake)
    monkeypatch.setenv("OUTPUT_BUCKET", "processed-siem-logs")
    with pytest.raises(Exception):
        handler.lambda_handler(s3_event("raw-otel-logs", "k.json.gz"), None)
    assert fake.puts == {}
