from app.core.crypto import encrypt_bytes, decrypt_bytes, encrypt_text, decrypt_text


def test_roundtrip_bytes():
    tok = encrypt_bytes(b"secret evidence bytes")
    assert decrypt_bytes(tok) == b"secret evidence bytes"


def test_roundtrip_text():
    tok = encrypt_text("case notes")
    assert decrypt_text(tok) == "case notes"


def test_tamper_detected():
    tok = bytearray(encrypt_bytes(b"data"))
    tok[0] ^= 0xFF  # flip a byte -> ciphertext corruption
    try:
        decrypt_bytes(bytes(tok))
        asserted = False
    except Exception:
        asserted = True
    assert asserted is True