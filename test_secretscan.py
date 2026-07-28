import secretscan


def test_detects_aws_key():
    hits = list(secretscan.scan_text("key = AKIAIOSFODNN7EXAMPLE"))
    assert hits and hits[0][0] == "AWS access key"

def test_detects_private_key_block():
    hits = list(secretscan.scan_text("-----BEGIN RSA PRIVATE KEY-----"))
    assert hits and "private key" in hits[0][0]
