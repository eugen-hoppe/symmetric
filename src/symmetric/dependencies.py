import base64
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from .interface import SymmetricEncryptionInterface
from .settings import Options


class KeyGen:
    @staticmethod
    def default(pw: str, options: Options) -> str:
        return KeyGen.pbkdf2hmac(pw, options)

    @staticmethod
    def pbkdf2hmac(pw: str, options: Options) -> str:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=options.PBKDF2HMAC_LENGTH,
            salt=options.PBKDF2HMAC_SALT.encode("utf-8"),
            iterations=options.PBKDF2HMAC_ITERATIONS,
            backend=default_backend(),
        )
        key_bytes = kdf.derive(pw.encode("utf-8"))
        return base64.urlsafe_b64encode(key_bytes).decode("utf-8")


class AES(SymmetricEncryptionInterface):
    def encrypt(self, payload: str, symmetric_key: str, options: Options) -> str:
        key_bytes = base64.urlsafe_b64decode(symmetric_key)
        block_size = options.AES_BLOCK_SIZE
        iv = os.urandom(block_size)
        cipher = Cipher(
            algorithms.AES(key_bytes), modes.CBC(iv), backend=default_backend()
        )
        encryptor = cipher.encryptor()
        payload_bytes = payload.encode("utf-8")
        padding_length = block_size - len(payload_bytes) % block_size
        padded_payload = payload_bytes + bytes([padding_length] * padding_length)
        encrypted = encryptor.update(padded_payload) + encryptor.finalize()
        encrypted_iv = iv + encrypted
        return base64.urlsafe_b64encode(encrypted_iv).decode("utf-8")

    def decrypt(self, cipher: str, symmetric_key: str, options: Options) -> str:
        key_bytes = base64.urlsafe_b64decode(symmetric_key)
        encrypted_iv = base64.urlsafe_b64decode(cipher)
        iv = encrypted_iv[: options.AES_BLOCK_SIZE]
        encrypted_data = encrypted_iv[options.AES_BLOCK_SIZE :]
        cipher_ = Cipher(
            algorithms.AES(key_bytes), modes.CBC(iv), backend=default_backend()
        )
        decryptor = cipher_.decryptor()
        decrypted = decryptor.update(encrypted_data) + decryptor.finalize()
        padding_length = decrypted[-1]
        unpadded_decrypted = decrypted[:-padding_length]
        return unpadded_decrypted.decode("utf-8")


class ChaCha20(SymmetricEncryptionInterface):
    def encrypt(self, payload: str, key: str, options: Options) -> str:
        key_bytes = base64.urlsafe_b64decode(key)
        nonce = os.urandom(options.CC_NONCE)
        cipher = Cipher(
            algorithms.ChaCha20(key_bytes, nonce), mode=None, backend=default_backend()
        )
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(payload.encode("utf-8")) + encryptor.finalize()
        encrypted_nonce = nonce + encrypted
        return base64.urlsafe_b64encode(encrypted_nonce).decode("utf-8")

    def decrypt(self, encrypted: str, key: str, options: Options) -> str:
        key_bytes = base64.urlsafe_b64decode(key)
        encrypted_nonce = base64.urlsafe_b64decode(encrypted)
        nonce = encrypted_nonce[: options.CC_NONCE]
        encrypted_data = encrypted_nonce[options.CC_NONCE :]
        cipher = Cipher(
            algorithms.ChaCha20(key_bytes, nonce), mode=None, backend=default_backend()
        )
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(encrypted_data) + decryptor.finalize()
        return decrypted.decode("utf-8")
