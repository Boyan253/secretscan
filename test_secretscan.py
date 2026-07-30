import secretscan


def test_detects_aws_key():
    hits = list(secretscan.scan_text("key = AKIAIOSFODNN7EXAMPLE"))
    assert hits and hits[0][0] == "AWS access key"

def test_detects_private_key_block():
    hits = list(secretscan.scan_text("-----BEGIN RSA PRIVATE KEY-----"))
    assert hits and "private key" in hits[0][0]


def test_detects_assigned_secret():
    hits = list(secretscan.scan_text('password = "hunter2hunter2hunter2"'))
    assert hits

def test_clean_text_has_no_hits():
    assert list(secretscan.scan_text("def add(a, b):\n    return a + b\n")) == []


def test_entropy_separates_random_from_english():
    assert secretscan.entropy("aaaaaaaa") < secretscan.entropy("f8Kq2Zx9Wp1L")

def test_redact_keeps_the_ends():
    out = secretscan.redact("ABCDEFGHIJKL")
    assert out.startswith("ABCD") and out.endswith("IJKL") and "*" in out
