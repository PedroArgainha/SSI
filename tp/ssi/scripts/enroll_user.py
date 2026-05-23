"""
Enrollment de novo utilizador (modo combinado, para desenvolvimento).

Faz, na mesma máquina, o que normalmente seriam dois passos separados:

    1. (lado do cliente)  python -m scripts.client_keygen --username X --out-dir ...
    2. (lado da CA)       python -m scripts.ca_sign_csr --csr ... --username X

Para um deployment a sério, usa os dois scripts separadamente, executando
o keygen na máquina do utilizador e o sign_csr na máquina da CA — assim
a chave privada do utilizador NUNCA está acessível à CA.

Aqui combinamos para reduzir atrito durante testes locais. A diferença
arquitetural está claramente identificada e o protocolo cripto é o mesmo:
o CSR é construído com a chave privada e a CA só assina depois de validar
o CSR. (A chave privada continua a sair de novo da memória do processo
sem nunca tocar no `LocalCA`.)

Uso:
    python -m scripts.enroll_user --username alice [--data-dir data]

A chave privada do utilizador é cifrada com password antes de ser
escrita em disco. Em modo interativo, a password é pedida por getpass;
para testes/automação pode ser fornecida pela variável de ambiente
SSI_ID_KEY_PASSWORD, ou outra indicada por --password-env.
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from pathlib import Path

from common import certs, crypto_utils
from pki.ca import CAError, LocalCA


DEFAULT_PASSWORD_ENV = "SSI_ID_KEY_PASSWORD"


def _write_secret(path: Path, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(str(path), flags, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)



def _get_key_password(env_name: str) -> bytes:
    """Obtém password para cifrar a chave privada do utilizador."""
    env_value = os.environ.get(env_name)
    if env_value is not None:
        if not env_value:
            raise ValueError(f"Variável {env_name} está vazia.")
        return env_value.encode("utf-8")

    pw1 = getpass.getpass("Password para cifrar a chave privada: ")
    if not pw1:
        raise ValueError("Password vazia não é permitida.")
    pw2 = getpass.getpass("Confirmar password: ")
    if pw1 != pw2:
        raise ValueError("As passwords não coincidem.")
    return pw1.encode("utf-8")

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Enrolla um utilizador (combinação keygen + CSR sign para testes)."
    )
    parser.add_argument("--username", required=True, help="Nome do utilizador.")
    parser.add_argument("--data-dir", default="data", help="Diretoria base.")
    parser.add_argument("--force", action="store_true",
                        help="Sobrescrever se já existir.")
    parser.add_argument("--password-env", default=DEFAULT_PASSWORD_ENV,
                        help="Variável de ambiente com a password da chave privada "
                             f"(default: {DEFAULT_PASSWORD_ENV}).")
    args = parser.parse_args()

    username = args.username
    if not username.replace("_", "").replace("-", "").isalnum():
        print("[ERRO] Username só pode conter letras, dígitos, '-' e '_'.", file=sys.stderr)
        return 2

    data_dir = Path(args.data_dir)
    ca = LocalCA(data_dir / "ca")
    try:
        ca.load()
    except CAError as exc:
        print(f"[ERRO] {exc}", file=sys.stderr)
        print("       Corre primeiro: python -m scripts.init_ca", file=sys.stderr)
        return 1

    user_dir = data_dir / "users" / username
    if user_dir.exists() and any(user_dir.iterdir()) and not args.force:
        print(f"[ERRO] Utilizador {username!r} já existe em {user_dir}. "
              f"Usa --force para sobrescrever.", file=sys.stderr)
        return 1
    user_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(user_dir, 0o700)

    try:
        key_password = _get_key_password(args.password_env)
    except ValueError as exc:
        print(f"[ERRO] {exc}", file=sys.stderr)
        return 1

    # === Passo 1: lado do CLIENTE ===
    print(f"[CLIENTE] A gerar chave RSA-3072 para {username!r}...")
    user_key = crypto_utils.generate_rsa_keypair()

    print("[CLIENTE] A construir CSR (com proof-of-possession)...")
    csr = certs.build_csr(user_key, username)

    # Escrever a chave imediatamente (modo 600 + cifra com password).
    key_path = user_dir / "id_key.pem"
    _write_secret(key_path, certs.private_key_to_pem(user_key, password=key_password))

    # === Passo 2: lado da CA ===
    print("[CA] A validar CSR e emitir certificado...")
    try:
        user_cert = ca.sign_csr(csr, expected_username=username)
    except certs.CertificateValidationError as exc:
        print(f"[ERRO] CSR rejeitado: {exc}", file=sys.stderr)
        return 1

    cert_path = user_dir / "id_cert.pem"
    cert_path.write_bytes(certs.cert_to_pem(user_cert))
    os.chmod(cert_path, 0o644)

    # Copiar root of trust para o utilizador.
    ca_cert_path = user_dir / "ca_cert.pem"
    ca_cert_path.write_bytes(ca.cert_pem)
    os.chmod(ca_cert_path, 0o644)

    print(f"[OK] Utilizador {username!r} enrollado em {user_dir}/")
    print(f"     - chave privada:   {key_path} (modo 600, cifrada com password)")
    print(f"     - certificado:     {cert_path}")
    print(f"     - cert da CA:      {ca_cert_path}")
    print()
    print("Nota: este script combina os dois passos do enrollment para")
    print("conveniência. Em produção, usar:")
    print("  1. python -m scripts.client_keygen   (na máquina do utilizador)")
    print("  2. python -m scripts.ca_sign_csr     (na máquina da CA)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
