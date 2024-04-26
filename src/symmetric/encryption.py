from typing import Callable

from cryptography.exceptions import InvalidKey

from .dependencies import KeyGen, AES
from .interface import AbstractKey, SymmetricEncryptionInterface
from .settings import Options, Err
from .utils import try_except


class Key(AbstractKey, SymmetricEncryptionInterface):
    def __init__(
        self,
        algorithm: SymmetricEncryptionInterface = AES(),
        options: Options = Options(),
    ) -> None:
        """Key for Symmetric Encryption"""
        self.algorithm = algorithm
        self.options = options

    @try_except((InvalidKey, ValueError, KeyError), *Err.GENERATE.value)
    def generate(self, pw: str, key_generator: Callable = KeyGen.default) -> str:
        return key_generator(pw, self.options)

    @try_except((InvalidKey, ValueError, KeyError), *Err.ENCRYPT.value)
    def encrypt(
        self, payload: str, symmetric_key: str, options: Options | None = None
    ) -> str:
        if isinstance(options, Options):
            self.options = options
        return self.algorithm.encrypt(payload, symmetric_key, options=self.options)

    @try_except((InvalidKey, ValueError, KeyError), *Err.DECRYPT.value)
    def decrypt(
        self, cipher: str, symmetric_key: str, options: Options | None = None
    ) -> str:
        if isinstance(options, Options):
            self.options = options
        return self.algorithm.decrypt(cipher, symmetric_key, self.options)
