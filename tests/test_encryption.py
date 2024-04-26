import pytest

from src.symmetric.encryption import Key
from src.symmetric.dependencies import AES, ChaCha20


def encryption_decryption(algorithm: type):
    key = Key(algorithm=algorithm())
    password = "securepassword"
    data = "hello world"

    # Testing encryption
    symmetric_key = key.generate(password)
    encrypted_data = key.encrypt(data, symmetric_key)
    txt = "Encryption should alter data"
    assert isinstance(encrypted_data, str) and encrypted_data != data, txt

    # Testing decryption
    decrypted_data = key.decrypt(encrypted_data, symmetric_key)
    assert decrypted_data == data, "Decrypted data should match original"


def test_encryption_decryption_aes():
    encryption_decryption(AES)


def test_encryption_decryption_chacha20():
    encryption_decryption(ChaCha20)


def test_invalid_key_error_handling():
    key_instance = Key()
    invalid_key = "this_is_an_invalid_key"
    data = "test data"

    with pytest.raises(ValueError):
        key_instance.encrypt(data, invalid_key)

    with pytest.raises(ValueError):
        key_instance.decrypt(data, invalid_key)
