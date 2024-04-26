import os

from dataclasses import dataclass
from enum import Enum

from dotenv import load_dotenv

from .utils import get_or_generate_salt


PREFIX = "SYMMETRIC_KEYS_APP"
FROM_NONE_ERROR_HINT = "Set PRODUCTION=False or add '#debug'-tag for full traceback"
PRODUCTION = os.getenv(f"{PREFIX}_IS_PROD", "True") == "True"


load_dotenv()


class Err(Enum):
    GENERATE = "Key generation error"
    ENCRYPT = "Encryption error"
    DECRYPT = "Decryption error"

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
    PBKDF2HMAC_SALT: str = get_or_generate_salt(f"{PREFIX}_PBKDF2HMAC_SALT")
    PBKDF2HMAC_LENGTH: int = os.getenv(f"{PREFIX}_PBKDF2HMAC_LENGTH", 32)
    PBKDF2HMAC_ITERATIONS: int = os.getenv(f"{PREFIX}_PBKDF2HMAC_ITERATIONS", 100_000)

    # Encryption Algorithms
    # =====================
    AES_BLOCK_SIZE: int = os.getenv(f"{PREFIX}_AES_BLOCK_SIZE", 16)
    CC_NONCE: int = os.getenv(f"{PREFIX}_CC_NONCE", 16)
