import hashlib

from app.services.hashing import sha256_bytes, sha256_file, verify_integrity


def test_sha256_bytes_known_vector():
    assert sha256_bytes(b"abc") == hashlib.sha256(b"abc").hexdigest()


def test_verify_integrity_true(tmp_path):
    p = tmp_path / "f.txt"
    p.write_bytes(b"hello world")
    ok, actual = verify_integrity(str(p), sha256_file(str(p)))
    assert ok is True
    assert actual == sha256_file(str(p))


def test_verify_integrity_false(tmp_path):
    p = tmp_path / "f.txt"
    p.write_bytes(b"hello world")
    ok, _ = verify_integrity(str(p), "0" * 64)
    assert ok is False