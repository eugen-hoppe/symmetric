from typing import Callable

from src.symmetric.interface import SymmetricEncryptionInterface, AbstractKey
from src.symmetric.settings import Options


class ConcreteEncryption(SymmetricEncryptionInterface):
    def encrypt(self, payload: str, symmetric_key: str, options: Options | None) -> str:
        return f"encrypted-{payload}-{symmetric_key}-{options.PBKDF2HMAC_SALT}"

    def decrypt(self, cipher: str, symmetric_key: str, options: Options | None) -> str:
        return f"decrypted-{cipher}-{symmetric_key}-{options.PBKDF2HMAC_SALT}"


def create_test_key_instance(algorithm, options):
    class ConcreteKey(AbstractKey):
        def __init__(self, algorithm: SymmetricEncryptionInterface, options: Options):
            self.algorithm = algorithm
            self.options = options

        def generate(self, pw: str, key_generator: Callable) -> str:
            key_gen = key_generator("a", "b")
            return f"generated-key-{pw}-{key_gen}"

    return ConcreteKey(algorithm, options)


def test_encryption():
    options = Options(PBKDF2HMAC_SALT="Salt123456789")
    algo = ConcreteEncryption()
    encrypted = algo.encrypt("data", "key123", options)
    assert encrypted == "encrypted-data-key123-Salt123456789"


def test_decryption():
    options = Options(PBKDF2HMAC_SALT="Salt123456789")
    algo = ConcreteEncryption()
    decrypted = algo.decrypt("data-encrypted", "key123", options)
    assert decrypted == "decrypted-data-encrypted-key123-Salt123456789"


def test_key_generation():
    options = Options(PBKDF2HMAC_SALT="Salt123456789")
    algo = ConcreteEncryption()
    key_instance = create_test_key_instance(algo, options)
    generated_key = key_instance.generate("password", lambda x, y: x+"-fixed-key-"+y)
    assert generated_key == "generated-key-password-a-fixed-key-b"
