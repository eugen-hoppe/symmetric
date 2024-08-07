# symmetric

Symmetric is a streamlined Python library for symmetric encryption, designed to simplify secure data handling with minimal setup. Symmetric aims to reduce the complexity of cryptographic operations while maintaining robust security standards.

**Version: `1.1`**

**Python: `>=3.10`**

## Installation

### To install symmetric run:

#### Production

##### v:`latest`

```bash
pip install git+https://github.com/eugen-hoppe/symmetric.git
```

##### v:`1.1`

```bash
pip install git+https://github.com/eugen-hoppe/symmetric.git@501eab4a21b9c375b012bb708b90ef00e955c689
```

##### v:`1.0`

```bash
pip install git+https://github.com/eugen-hoppe/symmetric.git@82c87b3f79435f5bf389aca2351787e11eb03b54
```

#### Development

```bash
pip install git+https://github.com/eugen-hoppe/symmetric.git@development
```

#### Uninstall Library
```bash
pip uninstall symmetric
```

## Quick Start

Symmetric is designed to be intuitive and easy to use. Here's how you can get started with encrypting and decrypting strings:

### Setup

Ensure you have a `.env` file based on the `env-template.txt` for environment-specific configurations.

### Encrypting a String

```python
from symmetric.encryption import Key
from symmetric.dependencies import ChaCha20

# Initialize the encryption key and options
key_instance = Key(algorithm=ChaCha20())  # default AES

# Generate a symmetric key from a password
symmetric_key = key_instance.generate('your_password')

# Encrypt data
encrypted_data = key_instance.encrypt('Hello World', symmetric_key)
print('Encrypted:', encrypted_data)
```

### Decrypting a String

```python
# Decrypt data
decrypted_data = key_instance.decrypt(encrypted_data, symmetric_key)
print('Decrypted:', decrypted_data)
```

This example assumes that you have set up your environment variables correctly according to the `env-template.txt`.

## Testing

To run the tests and ensure that everything is working as expected:

```bash
pytest -vv
```

## Contributing

Contributions are welcome! Please fork the repository and submit pull requests with your enhancements.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
