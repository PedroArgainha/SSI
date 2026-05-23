"""
Emite o certificado TLS do servidor.

O canal cliente↔servidor é protegido por TLS (com `ssl` da stdlib).
O servidor precisa de um par de chaves e de um certificado emitido
pela mesma CA local que emite os certificados de utilizador.

Os clientes vão validar o certificado do servidor contra ca_cert.pem
(que receberam no enrollment), o que evita MitM no canal cliente↔servidor.

Uso:
    python -m scripts.issue_server_cert [--hostname 127.0.0.1] [--data-dir data]
"""

from __future__ import annotations

import argparse
import datetime
import ipaddress
import os
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID

from common import certs, crypto_utils
from pki.ca import CAError, LocalCA


def _write_secret(path: Path, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(str(path), flags, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


def main() -> int:
    parser = argparse.ArgumentParser(description="Emite certificado TLS para o servidor.")
    parser.add_argument("--hostname", default="127.0.0.1",
                        help="Hostname/IP no qual o servidor vai correr.")
    parser.add_argument("--data-dir", default="data")
    parser.add_argument("--force", action="store_true")
    args = parser.parse_args()

    data_dir = Path(args.data_dir)
    ca = LocalCA(data_dir / "ca")
    try:
        ca.load()
    except CAError as exc:
        print(f"[ERRO] {exc}", file=sys.stderr)
        return 1

    server_dir = data_dir / "server"
    server_dir.mkdir(parents=True, exist_ok=True)

    key_path = server_dir / "tls_key.pem"
    cert_path = server_dir / "tls_cert.pem"

    if cert_path.exists() and not args.force:
        print(f"[ERRO] Já existe um certificado em {cert_path}. Usa --force.",
              file=sys.stderr)
        return 1

    # Gerar chave do servidor.
    print("[INFO] A gerar chave RSA-3072 para o servidor...")
    server_key = crypto_utils.generate_rsa_keypair()

    # Construir certificado com SubjectAltName apropriado.
    subject = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ssi-chat"),
        x509.NameAttribute(NameOID.COMMON_NAME, f"ssi-chat server ({args.hostname})"),
    ])

    # SANs: aceitar tanto hostname como IP. A maior parte dos clientes
    # TLS modernos validam contra SANs e ignoram CN, então isto importa.
    sans: list[x509.GeneralName] = []
    try:
        sans.append(x509.IPAddress(ipaddress.ip_address(args.hostname)))
    except ValueError:
        # Não era IP, é DNS name.
        sans.append(x509.DNSName(args.hostname))

    # Sempre incluir localhost por conveniência durante testes.
    sans.append(x509.DNSName("localhost"))
    sans.append(x509.IPAddress(ipaddress.ip_address("127.0.0.1")))

    now = datetime.datetime.now(datetime.timezone.utc)

    # Aceder à chave privada da CA por baixo do encapsulamento (acesso
    # privado a propósito; este script é "interno" à infraestrutura).
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca.cert.subject)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName(sans), critical=False)
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
    )

    # A LocalCA não expõe a chave privada — adicionamos um helper ad hoc.
    ca_priv = ca._private_key  # acesso ao "interno" intencional aqui
    if ca_priv is None:
        print("[ERRO] CA sem chave privada carregada.", file=sys.stderr)
        return 1
    server_cert = builder.sign(ca_priv, hashes.SHA256())

    _write_secret(key_path, certs.private_key_to_pem(server_key))
    cert_path.write_bytes(certs.cert_to_pem(server_cert))
    os.chmod(cert_path, 0o644)

    print(f"[OK] Certificado TLS do servidor emitido.")
    print(f"     - chave: {key_path} (600)")
    print(f"     - cert:  {cert_path}")
    print(f"     - hostname/IP no SAN: {args.hostname}, localhost, 127.0.0.1")
    return 0


if __name__ == "__main__":
    sys.exit(main())
