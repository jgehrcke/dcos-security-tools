import sys
import time

import requests
import jwt

import cryptography.hazmat.backends
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


cryptography_default_backend = cryptography.hazmat.backends.default_backend()


def main():
    privkeyfilepath = sys.argv[2]
    uid = sys.argv[1]
    login_endpoint = sys.argv[3]

    with open(privkeyfilepath, 'rb') as f:
        privkey = validate_privatekey_pem(f.read().decode('utf-8'))

    service_login_token = jwt.encode(
        {'uid': uid, 'exp': time.time() + 30},
        privkey,
        algorithm='RS256'
    ).decode('ascii')

    r = requests.post(
        login_endpoint,
        json={'uid': uid, 'token': service_login_token}
    )

    print(r.text)


def validate_privatekey_pem(key_pem):
    """Implement private key validation.

    Args:
        key_pem (str): RSA PKCS#8 PEM private key (traditional OpenSSL format
    """
    assert isinstance(key_pem, str)

    private_key_cryptography = serialization.load_pem_private_key(
        data=key_pem.encode('ascii'),
        password=None,
        backend=cryptography_default_backend
    )

    if not isinstance(private_key_cryptography, rsa.RSAPrivateKey):
        sys.exit('Unexpected private key type')

    return private_key_cryptography


if __name__ == "__main__":
    main()
