from src.symmetric.dependencies import KeyGen
from src.symmetric.settings import Options


def test_key_generation():
    options = Options()
    password = "securepassword"
    generated_key = KeyGen.default(password, options)
    txt = "Key must be a non-empty string"
    assert isinstance(generated_key, str) and len(generated_key) > 0, txt


def test_key_generation_length():
    options = Options(PBKDF2HMAC_LENGTH=32)
    password = "securepassword"
    generated_key = KeyGen.pbkdf2hmac(password, options)
    txt = "Encoded key length should be valid"
    assert len(generated_key) > options.PBKDF2HMAC_LENGTH, txt
