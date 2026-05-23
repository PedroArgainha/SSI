"""
Inicializa a CA local.

Uso:
    python -m scripts.init_ca [--data-dir data]

Cria, em <data-dir>/ca/, a chave privada e o certificado autoassinado
da CA. Falha se já existirem (proteção contra apagar PKI por engano).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from pki.ca import CAError, LocalCA


def main() -> int:
    parser = argparse.ArgumentParser(description="Inicializa CA local do ssi-chat.")
    parser.add_argument("--data-dir", default="data", help="Diretoria base de estado.")
    args = parser.parse_args()

    ca_dir = Path(args.data_dir) / "ca"
    ca = LocalCA(ca_dir)

    try:
        ca.initialize()
    except CAError as exc:
        print(f"[ERRO] {exc}", file=sys.stderr)
        return 1

    print(f"[OK] CA criada em {ca_dir}")
    print(f"     - chave privada: {ca.key_path} (modo 600)")
    print(f"     - certificado:   {ca.cert_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
