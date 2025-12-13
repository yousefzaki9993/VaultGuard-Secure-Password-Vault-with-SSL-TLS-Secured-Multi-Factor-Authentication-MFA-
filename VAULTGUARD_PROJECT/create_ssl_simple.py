import os
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timedelta

# ============================================
# 📌 1. مسار السكربت نفسه
# ============================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))  # ← هنا الفرق
CERTS_DIR = os.path.join(BASE_DIR, "ssl_certs")
os.makedirs(CERTS_DIR, exist_ok=True)

print("📌 SSL Certificates will be generated in:", CERTS_DIR)

# ============================================
# 📌 2. إنشاء المفتاح الخاص Private Key
# ============================================
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

private_key_path = os.path.join(CERTS_DIR, "private_key.pem")
with open(private_key_path, "wb") as key_file:
    key_file.write(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
    )

# ============================================
# 📌 3. إعداد بيانات الشهادة
# ============================================
subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "EG"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Cairo"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, "Nasr City"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "VaultGuard"),
    x509.NameAttribute(NameOID.COMMON_NAME, "localhost")
])

# ============================================
# 📌 4. إنشاء الشهادة Certificate
# ============================================
certificate = (
    x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(issuer)  # self-signed
    .public_key(private_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.utcnow())
    .not_valid_after(datetime.utcnow() + timedelta(days=365))  # سنة
    .add_extension(
        x509.SubjectAlternativeName([x509.DNSName("localhost")]),
        critical=False
    )
    .sign(private_key, hashes.SHA256(), default_backend())
)

certificate_path = os.path.join(CERTS_DIR, "certificate.pem")
with open(certificate_path, "wb") as cert_file:
    cert_file.write(certificate.public_bytes(serialization.Encoding.PEM))

# ============================================
# 📌 5. رسالة نجاح
# ============================================
print("\n✅ SSL Certificates generated successfully!")
print("🔑 Private Key:", private_key_path)
print("📜 Certificate:", certificate_path)
print("\n⚠️  ملاحظة: هذه شهادات للتجربة فقط، وليست مناسبة لبيئات الإنتاج.")
