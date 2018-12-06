import argparse

import cryptography.hazmat.backends
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


cryptography_default_backend = cryptography.hazmat.backends.default_backend()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('privkeyfile', help='Path to private key file')
    parser.add_argument('pubkeyfile', help='Path to public key file')
    args = parser.parse_args()

    privkey_pem, pubkey_pem = generate_RSA_keypair()
    print(privkey_pem + '\n\n' + pubkey_pem)

    with open(args.privkeyfile, 'wb') as f:
        f.write(privkey_pem.encode('ascii'))

    with open(args.pubkeyfile, 'wb') as f:
        f.write(pubkey_pem.encode('ascii'))


def generate_RSA_keypair():
    """
    Generate an RSA keypair with a key size of 2048 bits and an
    exponent of 65537. Serialize the public key in the the
    X.509 SubjectPublicKeyInfo/OpenSSL PEM public key format
    (RFC 5280). Serialize the private key in the PKCS#8 (RFC 3447)
    format.

    Returns:
        (private key, public key) 2-tuple, both unicode
        objects holding the serialized keys.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=cryptography_default_backend)

    privkey_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption())

    public_key = private_key.public_key()
    pubkey_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)

    return privkey_pem.decode('ascii'), pubkey_pem.decode('ascii')


if __name__ == "__main__":
    main()
