"""Offline check of the actual mounted credential, using the broker read path."""
import json
import os
from pathlib import Path

from .publisher_credentials import protected_read


def main():
    result = {'key_loadable': False, 'type': None, 'bits': None}
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        path = Path(os.environ['CREDENTIALS_DIRECTORY']) / 'app-key'
        key = serialization.load_pem_private_key(protected_read(path, secret=True), password=None)
        if isinstance(key, rsa.RSAPrivateKey) and key.key_size >= 2048:
            result = {'key_loadable': True, 'type': 'rsa', 'bits': key.key_size}
    except Exception:
        pass  # Never print the key, path, parser output or exception.
    print(json.dumps(result, sort_keys=True))
    return 0 if result['key_loadable'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
