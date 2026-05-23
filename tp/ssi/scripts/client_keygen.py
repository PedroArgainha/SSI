"""
Geração local de identidade do utilizador: chave privada cifrada + CSR.

Este script é executado pelo PRÓPRIO UTILIZADOR, na sua máquina.
A chave privada NUNCA sai do disco do utilizador — só o CSR é enviado
à CA para certificação.

Uso:
    python -m scripts.client_keygen --username alice --out-dir data/users/alice

Cria:
    <out-dir>/id_key.pem   chave privada RSA-3072 cifrada com password (modo 600)
    <out-dir>/id_csr.pem   CSR para enviar à CA

Depois de a CA assinar o CSR, o utilizador recebe de volta:
    <out-dir>/id_cert.pem  certificado emitido pela CA
    <out-dir>/ca_cert.pem  certificado da CA (root of trust)

Notas:
    - Esta separação é o que evita que a infraestrutura/CA tenha alguma
      vez acesso à chave privada do utilizador.
    - A chave privada fica cifrada em PEM PKCS#8 com password do
      utilizador, além de ser escrita com permissões 0600.
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from pathlib import Path

from common import certs, crypto_utils

DEFAULT_PASSWORD_ENV = "SSI_ID_KEY_PASSWORD"


def _write_secret(path: Path, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(str(path), flags, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


def _get_key_password(env_name: str) -> bytes:
    """
    Obtém a password usada para cifrar a chave privada do utilizador.

    Para uso interativo, pede e confirma via getpass. Para testes ou
    automação, permite ler de uma variável de ambiente indicada por
    --password-env, sem guardar passwords no código nem em argumentos.
    """
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
        description="Gera chave privada cifrada e CSR para um utilizador."
    )
    parser.add_argument("--username", required=True, help="Nome do utilizador (vai no CN).")
    parser.add_argument("--out-dir", required=True,
                        help="Diretoria onde escrever id_key.pem e id_csr.pem.")
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

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(out_dir, 0o700)

    key_path = out_dir / "id_key.pem"
    csr_path = out_dir / "id_csr.pem"

    if (key_path.exists() or csr_path.exists()) and not args.force:
        print(f"[ERRO] Já existe chave/CSR em {out_dir}. Usa --force.", file=sys.stderr)
        return 1

    try:
        key_password = _get_key_password(args.password_env)
    except ValueError as exc:
        print(f"[ERRO] {exc}", file=sys.stderr)
        return 1

    print(f"[INFO] A gerar chave RSA-3072 para {username!r} (local)...")
    priv = crypto_utils.generate_rsa_keypair()

    print("[INFO] A construir CSR...")
    csr = certs.build_csr(priv, username)

    _write_secret(key_path, certs.private_key_to_pem(priv, password=key_password))
    csr_path.write_bytes(certs.csr_to_pem(csr))
    os.chmod(csr_path, 0o644)

    print(f"[OK] Chave cifrada e CSR gerados em {out_dir}/")
    print(f"     - {key_path} (modo 600, cifrada com password — NÃO partilhar)")
    print(f"     - {csr_path} (enviar à CA para assinatura)")
    print()
    print("Próximo passo: pedir à CA para assinar com")
    print(f"  python -m scripts.ca_sign_csr --csr {csr_path} --username {username}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
