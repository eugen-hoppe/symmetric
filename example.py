from src.symmetric.encryption import Key
from src.symmetric.dependencies import ChaCha20

BR = "\n"
ARROW = " - - > "
PLUS = " + "


def encryption_chacha(data: str, password: str, decrpypt: bool = False):
    key = Key(algorithm=ChaCha20())  # default AES
    if not decrpypt:
        return key.encrypt(data, key.generate(password))
    return key.decrypt(data, key.generate(password))


def main(message: str = "Hello World", password: str = "Pa$$W0rD"):
    cipher = encryption_chacha(message, password)
    decrypted_message = encryption_chacha(data=cipher, password=password, decrpypt=True)

    assert message == decrypted_message

    print(BR + f"{message:>70}", PLUS, password, ARROW, cipher)
    print(BR + f"{cipher:>70}", PLUS, password, ARROW, decrypted_message)
    print(BR)


if __name__ == "__main__":
    main()
