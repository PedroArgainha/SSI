"""
Assinatura de CSR pela CA local.

Este script é executado pelo administrador da CA. Recebe um CSR
gerado pelo utilizador (com a chave privada que NUNCA esteve aqui),
valida-o, e emite um certificado.

Uso:
    python -m scripts.ca_sign_csr --csr /caminho/id_csr.pem --username alice

Output:
    Por defeito, escreve o certificado emitido em <data>/users/<username>/id_cert.pem
    e copia o cert da CA para <data>/users/<username>/ca_cert.pem.

    Se --output for fornecido, escreve só o cert nesse caminho (útil
    quando a CA está noutra máquina e queremos copiar manualmente).

Validações feitas pela CA:
    - assinatura interna do CSR (o cliente prova ter a chave privada)
    - chave RSA com tamanho aceitável
    - Common Name é um username válido
    - Common Name == username esperado pela administração
    - utilizador ainda não tem certificado emitido (a menos que --force)
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from common import certs
from pki.ca import CAError, LocalCA


def main() -> int:
    parser = argparse.ArgumentParser(description="Assina um CSR e emite certificado.")
    parser.add_argument("--csr", required=True, help="Caminho para o CSR em PEM.")
    parser.add_argument("--username", required=True,
                        help="Username esperado (tem de bater certo com o CN do CSR).")
    parser.add_argument("--data-dir", default="data", help="Diretoria base.")
    parser.add_argument("--output",
                        help="Onde escrever o certificado emitido. "
                             "Por omissão: data/users/<username>/id_cert.pem.")
    parser.add_argument("--force", action="store_true",
                        help="Sobrescrever se o certificado já existir.")
    args = parser.parse_args()

    csr_path = Path(args.csr)
    if not csr_path.exists():
        print(f"[ERRO] CSR não encontrado: {csr_path}", file=sys.stderr)
        return 1

    data_dir = Path(args.data_dir)
    ca = LocalCA(data_dir / "ca")
    try:
        ca.load()
    except CAError as exc:
        print(f"[ERRO] {exc}", file=sys.stderr)
        return 1

    # Carregar e validar o CSR.
    try:
        csr = certs.csr_from_pem(csr_path.read_bytes())
    except Exception as exc:
        print(f"[ERRO] CSR inválido: {exc}", file=sys.stderr)
        return 1

    print(f"[INFO] A validar CSR para {args.username!r}...")
    try:
        cert = ca.sign_csr(csr, expected_username=args.username)
    except (CAError, certs.CertificateValidationError) as exc:
        print(f"[ERRO] CSR rejeitado: {exc}", file=sys.stderr)
        return 1

    # Decidir destino.
    if args.output:
        cert_path = Path(args.output)
        cert_path.parent.mkdir(parents=True, exist_ok=True)
    else:
        user_dir = data_dir / "users" / args.username
        user_dir.mkdir(parents=True, exist_ok=True)
        cert_path = user_dir / "id_cert.pem"

    if cert_path.exists() and not args.force:
        print(f"[ERRO] Já existe um certificado em {cert_path}. Usa --force.", file=sys.stderr)
        return 1

    cert_path.write_bytes(certs.cert_to_pem(cert))
    os.chmod(cert_path, 0o644)
    print(f"[OK] Certificado emitido em {cert_path}")

    # Por conveniência, copiar o cert da CA para o user_dir se o destino
    # for o predefinido (assim o cliente fica com a sua root of trust local).
    if not args.output:
        ca_cert_dest = cert_path.parent / "ca_cert.pem"
        ca_cert_dest.write_bytes(ca.cert_pem)
        os.chmod(ca_cert_dest, 0o644)
        print(f"[OK] Cert da CA copiado para {ca_cert_dest}")

    # Aviso útil ao admin: lembrar o servidor que aprenda este utilizador
    # no próximo restart.
    print()
    print("Nota: o servidor carrega utilizadores enrollados no arranque.")
    print("      Se o servidor estiver a correr, reinicia-o para o reconhecer.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
