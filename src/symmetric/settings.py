import os

from dataclasses import dataclass
from enum import Enum

from dotenv import load_dotenv

from .utils import get_or_generate_salt


PRODUCTION = True

PREFIX = "SYMMETRIC_KEYS_APP_"
FROM_NONE_ERROR_HINT = "Set PRODUCTION=False or add '#debug'-tag for full traceback"


load_dotenv()


class Err(str, Enum):
    GENERATE: str = "Key generation error"
    ENCRYPT: str = "Encryption error"
    DECRYPT: str = "Decryption error"

    @property
    def value(self) -> tuple[Exception, str, str]:
        return (
            ValueError,
            self._value_ + " #prod" if PRODUCTION else " #debug",
            " [ " + FROM_NONE_ERROR_HINT if PRODUCTION else "! DEBUG=True ]",
        )


@dataclass
class Options:
    # Key Generator
    # =============
    PBKDF2HMAC_SALT: str = get_or_generate_salt(f"{PREFIX}PBKDF2HMAC_SALT")
    PBKDF2HMAC_LENGTH: int = os.getenv(f"{PREFIX}PBKDF2HMAC_LENGTH", 32)
    PBKDF2HMAC_ITERATIONS: int = os.getenv(f"{PREFIX}PBKDF2HMAC_ITERATIONS", 100_000)
    IS_PORD: str = PRODUCTION

    # Encryption Algorithms
    # =====================
    AES_BLOCK_SIZE: int = os.getenv(f"{PREFIX}_AES_BLOCK_SIZE", 16)
    CC_NONCE: int = os.getenv(f"{PREFIX}_CC_NONCE", 16)
