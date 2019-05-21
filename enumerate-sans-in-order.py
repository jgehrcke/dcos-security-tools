#!/usr/bin/env python
import logging
import socket
import ssl
import sys


from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtensionOID, NameOID
from cryptography.x509.extensions import ExtensionNotFound


host = sys.argv[1]
port = int(sys.argv[2])

logging.basicConfig(format='%(asctime)s: %(message)s', level=logging.INFO)


s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tlssock = ssl.wrap_socket(s)

logging.info('Perform TLS handshake against %s:%s', host, port)
tlssock.connect((host, port))

cert_der = tlssock.getpeercert(binary_form=True)
logging.info('Server certificate received. Size: %s bytes', len(cert_der))

logging.info('Deserialize certificate')
cert = x509.load_der_x509_certificate(cert_der, default_backend())

try:
    sans = cert.extensions.get_extension_for_oid(
        ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
except ExtensionNotFound as e:
    logging.info('No SANs found: %s', e)
    logging.info('Subject Common Name: %s',
        cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME))
    sys.exit(0)

logging.info('Subject Alternative Name entries, in order:')
for san in sans.value:
    print(san)
