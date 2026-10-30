from app.core.security import create_access_token, decode_token, hash_password, verify_password


def test_password_hash_and_verify():
    hashed = hash_password("S3cure!Pass")
    assert hashed != "S3cure!Pass"
    assert verify_password("S3cure!Pass", hashed) is True
    assert verify_password("wrong", hashed) is False


def test_password_hash_is_salted():
    assert hash_password("same") != hash_password("same")


def test_jwt_roundtrip():
    token = create_access_token("alice", "analyst", 42)
    payload = decode_token(token, expected_type="access")
    assert payload["sub"] == "alice"
    assert payload["role"] == "analyst"
    assert payload["uid"] == 42