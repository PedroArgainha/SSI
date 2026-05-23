"""
Operações com certificados X.509.

Cada utilizador tem um certificado emitido pela CA local (ver pki/ca.py).
O certificado liga o nome de utilizador (no Common Name) à chave pública
RSA da identidade.

Validação implementada:
    - assinatura do certificado verifica com a chave pública da CA
    - certificado dentro do período de validade
    - emissor é a nossa CA
    - extensões básicas presentes (BasicConstraints, KeyUsage)
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


# Período de validade dos certificados de utilizador (1 ano).
USER_CERT_VALIDITY_DAYS = 365

# Período de validade da CA (10 anos).
CA_CERT_VALIDITY_DAYS = 365 * 10


@dataclass(frozen=True)
class Identity:
    """
    Identidade extraída de um certificado validado.
    """
    username: str
    public_key: rsa.RSAPublicKey
    cert: x509.Certificate


# ----------------------------- Serialização -----------------------------

def cert_to_pem(cert: x509.Certificate) -> bytes:
    """Serializa um certificado para PEM (texto)."""
    return cert.public_bytes(serialization.Encoding.PEM)


def cert_to_der(cert: x509.Certificate) -> bytes:
    """Serializa um certificado para DER (binário, mais compacto)."""
    return cert.public_bytes(serialization.Encoding.DER)


def cert_from_pem(data: bytes) -> x509.Certificate:
    """Carrega certificado a partir de PEM."""
    return x509.load_pem_x509_certificate(data)


def cert_from_der(data: bytes) -> x509.Certificate:
    """Carrega certificado a partir de DER."""
    return x509.load_der_x509_certificate(data)


def private_key_to_pem(key: rsa.RSAPrivateKey, password: bytes | None = None) -> bytes:
    """
    Serializa chave privada para PEM (PKCS#8).

    Se 'password' for fornecida, a chave é cifrada com
    BestAvailableEncryption. Isto é usado para proteger as chaves
    privadas de identidade dos utilizadores em repouso.

    Se 'password' for None, a chave fica sem cifra criptográfica e deve
    ser protegida apenas por permissões do sistema. Mantemos este modo
    para chaves internas da CA/servidor e compatibilidade com ficheiros
    legados, não para novas chaves de utilizador.
    """
    if password is None:
        algorithm = serialization.NoEncryption()
    else:
        algorithm = serialization.BestAvailableEncryption(password)

    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=algorithm,
    )


def private_key_from_pem(data: bytes, password: bytes | None = None) -> rsa.RSAPrivateKey:
    """Carrega chave privada a partir de PEM."""
    key = serialization.load_pem_private_key(data, password=password)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise ValueError("A chave carregada não é RSA.")
    return key


# ----------------------------- CSR (Certificate Signing Request) -----------------------------
#
# Um CSR é um pedido auto-assinado de emissão de certificado:
#   - contém a chave pública do utilizador
#   - contém o nome desejado (CN = username)
#   - é assinado com a chave privada do utilizador (proof-of-possession)
#
# A CA recebe o CSR, valida (assinatura própria + nome aceitável), e emite
# o certificado. A chave privada NUNCA sai da máquina do utilizador.

def build_csr(private_key: rsa.RSAPrivateKey, username: str) -> x509.CertificateSigningRequest:
    """
    Constrói um CSR para um utilizador. Auto-assinado pela própria
    chave privada do utilizador (que prova posse da chave pública).
    """
    if not username or not username.replace("_", "").replace("-", "").isalnum():
        raise ValueError("Username inválido.")

    subject = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ssi-chat"),
        x509.NameAttribute(NameOID.COMMON_NAME, username),
    ])

    return (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .sign(private_key, _hash_for_signing())
    )


def csr_to_pem(csr: x509.CertificateSigningRequest) -> bytes:
    """Serializa um CSR para PEM."""
    return csr.public_bytes(serialization.Encoding.PEM)


def csr_from_pem(data: bytes) -> x509.CertificateSigningRequest:
    """Carrega um CSR a partir de PEM."""
    return x509.load_pem_x509_csr(data)


def validate_csr(csr: x509.CertificateSigningRequest,
                 expected_username: str | None = None) -> str:
    """
    Valida um CSR antes de a CA emitir o certificado.

    Verificações:
        1. A assinatura do CSR é válida (proof-of-possession da chave privada).
        2. A chave pública é RSA com tamanho razoável.
        3. O Common Name é um username válido.
        4. (Opcional) O Common Name bate certo com o esperado.

    Devolve o username (CN) extraído do CSR.
    """
    if not csr.is_signature_valid:
        raise CertificateValidationError("Assinatura do CSR inválida.")

    pub = csr.public_key()
    if not isinstance(pub, rsa.RSAPublicKey):
        raise CertificateValidationError("CSR não tem chave RSA.")
    if pub.key_size < 2048:
        raise CertificateValidationError(f"Chave RSA demasiado pequena: {pub.key_size} bits.")

    cn_attrs = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if not cn_attrs:
        raise CertificateValidationError("CSR sem Common Name.")
    username = cn_attrs[0].value

    if not username or not username.replace("_", "").replace("-", "").isalnum():
        raise CertificateValidationError(f"Username inválido no CSR: {username!r}")

    if expected_username is not None and username != expected_username:
        raise CertificateValidationError(
            f"CSR para {username!r}, esperado {expected_username!r}."
        )

    return username


# ----------------------------- Construção de certificados -----------------------------

def build_ca_certificate(ca_private_key: rsa.RSAPrivateKey,
                         common_name: str = "ssi-chat Local CA") -> x509.Certificate:
    """
    Constrói um certificado self-signed para a CA local.

    A CA é a root of trust: o servidor distribui o seu certificado
    aos clientes, e os clientes usam-no para validar todos os outros
    certificados de utilizador.
    """
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PT"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ssi-chat"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    now = datetime.datetime.now(datetime.timezone.utc)

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))    # tolerância
        .not_valid_after(now + datetime.timedelta(days=CA_CERT_VALIDITY_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    )

    return builder.sign(ca_private_key, _hash_for_signing())


def build_user_certificate(ca_private_key: rsa.RSAPrivateKey,
                           ca_cert: x509.Certificate,
                           username: str,
                           user_public_key: rsa.RSAPublicKey) -> x509.Certificate:
    """
    Emite um certificado para um utilizador. O nome do utilizador vai
    no Common Name do Subject.
    """
    if not username or not username.replace("_", "").replace("-", "").isalnum():
        raise ValueError("Username inválido.")

    subject = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ssi-chat"),
        x509.NameAttribute(NameOID.COMMON_NAME, username),
    ])

    now = datetime.datetime.now(datetime.timezone.utc)

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(user_public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=USER_CERT_VALIDITY_DAYS))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,    # para assinar challenges e handshake
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,       # DH é com chaves efémeras separadas
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    )

    return builder.sign(ca_private_key, _hash_for_signing())


def _hash_for_signing():
    """Algoritmo de hash usado para assinar certificados."""
    from cryptography.hazmat.primitives import hashes
    return hashes.SHA256()


# ----------------------------- Validação -----------------------------

class CertificateValidationError(Exception):
    """O certificado falhou validação."""


def validate_user_certificate(user_cert: x509.Certificate,
                              ca_cert: x509.Certificate,
                              expected_username: str | None = None) -> Identity:
    """
    Valida um certificado de utilizador contra a CA.

    Verifica:
        1. Assinatura — a CA realmente assinou este certificado.
        2. Período de validade — não expirou e já é válido.
        3. Issuer — emitido pela CA correta.
        4. Common Name — corresponde ao username esperado (se fornecido).

    Devolve uma Identity com os dados validados.
    """
    # 1. Verificar assinatura
    try:
        ca_public_key = ca_cert.public_key()
        if not isinstance(ca_public_key, rsa.RSAPublicKey):
            raise CertificateValidationError("CA não usa RSA.")

        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives import hashes

        ca_public_key.verify(
            user_cert.signature,
            user_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),  # certificados X.509 usam PKCS#1 v1.5 para a assinatura
            hashes.SHA256(),
        )
    except Exception as exc:
        raise CertificateValidationError(f"Assinatura inválida: {exc}") from exc

    # 2. Período de validade
    now = datetime.datetime.now(datetime.timezone.utc)
    if now < user_cert.not_valid_before_utc:
        raise CertificateValidationError("Certificado ainda não é válido.")
    if now > user_cert.not_valid_after_utc:
        raise CertificateValidationError("Certificado expirado.")

    # 3. Issuer
    if user_cert.issuer != ca_cert.subject:
        raise CertificateValidationError(
            f"Issuer não é a CA esperada: {user_cert.issuer.rfc4514_string()}"
        )

    # 4. Extrair username do CN
    cn_attrs = user_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if not cn_attrs:
        raise CertificateValidationError("Certificado sem Common Name.")
    username = cn_attrs[0].value

    if expected_username is not None and username != expected_username:
        raise CertificateValidationError(
            f"Username não bate certo: esperado {expected_username!r}, "
            f"certificado tem {username!r}."
        )

    public_key = user_cert.public_key()
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise CertificateValidationError("Certificado não tem chave RSA.")

    return Identity(username=username, public_key=public_key, cert=user_cert)
