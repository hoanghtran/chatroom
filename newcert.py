import datetime
import ipaddress
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

CERT_FILE = "server.crt"
KEY_FILE = "server.key"

def generate_private_key():
    """Generate an RSA private key and save it to a file."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    with open(KEY_FILE, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))

    print("[✔] Private key generated and saved.")
    return private_key

def generate_ssl_certificate():
    """Generate an SSL certificate and save it to a file."""
    print("[*] Generating a new SSL certificate...")

    private_key = generate_private_key()

    # Generate Certificate with SAN
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "VN"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Hanoi"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Hanoi City"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "KMA"),
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ])

    cert = x509.CertificateBuilder()\
        .subject_name(subject)\
        .issuer_name(issuer)\
        .public_key(private_key.public_key())\
        .serial_number(x509.random_serial_number())\
        .not_valid_before(datetime.datetime.now(datetime.UTC))\
        .not_valid_after(datetime.datetime.now(datetime.UTC) + datetime.timedelta(days=365))\
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            ]),
            critical=False,
        )\
        .sign(private_key, hashes.SHA256())

    with open(CERT_FILE, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print(f"[✅] SSL Certificate and Key created successfully: {CERT_FILE}, {KEY_FILE}")

if __name__ == "__main__":
    generate_ssl_certificate()
