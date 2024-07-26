from abc import ABC, abstractmethod
from typing import Callable

from .settings import Options


from abc import ABC, abstractmethod
from typing import Callable

from .settings import Options


class SymmetricEncryptionInterface(ABC):
    """
    An abstract base class defining the interface for symmetric encryption operations.

    This interface requires implementing classes to provide methods for encrypting
    and decrypting data using symmetric encryption algorithms, using a provided
    symmetric key and optional encryption options.
    """

    @abstractmethod
    def encrypt(self, payload: str, symmetric_key: str, options: Options | None) -> str:
        """
        Encrypts the given payload using the specified symmetric key and options.

        Args:
            payload (str): The plaintext data to be encrypted.
            symmetric_key (str): The symmetric key used for encryption.
            options (Options | None): Configuration options for encryption, such as
              block size, iterations, etc.

        Returns:
            str: The encrypted data as a string.
        """
        pass

    @abstractmethod
    def decrypt(self, cipher: str, symmetric_key: str, options: Options | None) -> str:
        """
        Decrypts the given encrypted data using the specified symmetric key and options.

        Args:
            cipher (str): The encrypted data to be decrypted.
            symmetric_key (str): The symmetric key used for decryption.
            options (Options | None): Configuration options for decryption.

        Returns:
            str: The decrypted data as a string.
        """
        pass


class AbstractKey(ABC):
    """
    A class defining the interface for handling key operations in symmetric encryption.

    Implementing classes are expected to provide methods for generating encryption keys
    and possibly other key management functionalities.
    """

    @abstractmethod
    def __init__(
        self, algorithm: SymmetricEncryptionInterface, options: Options
    ) -> None:
        """
        Initializes a new instance of an encryption key handler.

        Args:
            algorithm (SymmetricEncryptionInterface): The encryption algorithm to use.
            options (Options): Configuration options related to key generation and
              encryption parameters.
        """
        pass

    @abstractmethod
    def generate(self, pw: str, key_generator: Callable) -> str:
        """
        Generates a symmetric key based on password and key generation function.

        Args:
            pw (str): The password or secret used to generate the encryption key.
            key_generator (Callable): A function for key generation logic.

        Returns:
            str: The generated symmetric key.
        """
        pass
