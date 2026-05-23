"""
Autoridade de Certificação (CA) local.

A CA vive ao lado do servidor mas é conceptualmente separada:
    - tem a sua própria chave privada (NUNCA partilhada)
    - emite certificados que ligam usernames a chaves públicas RSA
    - o seu certificado público (autoassinado) é distribuído a clientes
      como root of trust

Em produção, a CA estaria isolada (HSM, máquina offline). Aqui usamos
ficheiros locais com permissões restritas — alinhado com o princípio
de least privilege que a Semana 3 cobre.
"""

from __future__ import annotations

import os
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa

from common import certs, crypto_utils


class CAError(Exception):
    """Erro nas operações da CA."""


class LocalCA:
    """
    Encapsula a chave privada e o certificado da CA, e expõe operações
    para emitir certificados de utilizador.

    Carregar a CA não exige password (na primeira versão); a proteção
    do ficheiro é feita por chmod 600 + ownership.
    """

    def __init__(self, ca_dir: Path):
        self.ca_dir = ca_dir
        self.key_path = ca_dir / "ca_key.pem"
        self.cert_path = ca_dir / "ca_cert.pem"

        self._private_key: rsa.RSAPrivateKey | None = None
        self._cert: x509.Certificate | None = None

    # ---------- Inicialização ----------

    def exists(self) -> bool:
        return self.key_path.exists() and self.cert_path.exists()

    def initialize(self, common_name: str = "ssi-chat Local CA") -> None:
        """
        Cria uma CA nova: gera chave privada, gera certificado autoassinado,
        escreve em disco com permissões restritas.

        Falha se já existir, para evitar destruição acidental do estado
        de PKI (que invalidaria todos os certificados emitidos).
        """
        if self.exists():
            raise CAError(f"CA já existe em {self.ca_dir}. Apagar manualmente para reinicializar.")

        self.ca_dir.mkdir(parents=True, exist_ok=True)

        ca_key = crypto_utils.generate_rsa_keypair()
        ca_cert = certs.build_ca_certificate(ca_key, common_name=common_name)

        # Escrever chave privada com permissões restritas (least privilege).
        key_bytes = certs.private_key_to_pem(ca_key)
        _write_secret(self.key_path, key_bytes)

        # Certificado pode ser legível por todos.
        cert_bytes = certs.cert_to_pem(ca_cert)
        self.cert_path.write_bytes(cert_bytes)
        os.chmod(self.cert_path, 0o644)

        self._private_key = ca_key
        self._cert = ca_cert

    def load(self) -> None:
        """Carrega a CA a partir do disco."""
        if not self.exists():
            raise CAError(f"CA não inicializada em {self.ca_dir}.")

        self._private_key = certs.private_key_from_pem(self.key_path.read_bytes())
        self._cert = certs.cert_from_pem(self.cert_path.read_bytes())

    # ---------- Acessores públicos ----------

    @property
    def cert(self) -> x509.Certificate:
        if self._cert is None:
            raise CAError("CA não carregada.")
        return self._cert

    @property
    def cert_pem(self) -> bytes:
        return certs.cert_to_pem(self.cert)

    # ---------- Emissão ----------

    def issue_user_certificate(self, username: str,
                               user_public_key: rsa.RSAPublicKey) -> x509.Certificate:
        """
        Emite um certificado para um utilizador.

        Em produção haveria proof-of-possession (o utilizador prova ter
        a chave privada, normalmente via CSR assinado). Para o trabalho
        académico ligamos isto ao fluxo de enrollment: o cliente gera a
        chave localmente e envia a chave pública à CA, que emite o cert.
        """
        if self._private_key is None or self._cert is None:
            raise CAError("CA não carregada.")
        return certs.build_user_certificate(
            ca_private_key=self._private_key,
            ca_cert=self._cert,
            username=username,
            user_public_key=user_public_key,
        )

    def sign_csr(self, csr, expected_username: str | None = None):
        """
        Assina um CSR e devolve o certificado emitido.

        Esta é a forma "correta" de emitir certificados:
            1. O cliente gerou a chave privada localmente (privada nunca sai dele).
            2. O cliente construiu um CSR assinado (proof-of-possession).
            3. A CA valida o CSR e emite um certificado sobre a chave pública.

        Validações no CSR:
            - assinatura interna do CSR (proof-of-possession)
            - chave RSA suficientemente grande
            - CN é um username aceitável

        Se 'expected_username' for fornecido, verifica que o CN bate certo —
        defesa contra um CSR enviado com username diferente do que se acordou
        no canal administrativo.
        """
        if self._private_key is None or self._cert is None:
            raise CAError("CA não carregada.")
        username = certs.validate_csr(csr, expected_username=expected_username)
        return certs.build_user_certificate(
            ca_private_key=self._private_key,
            ca_cert=self._cert,
            username=username,
            user_public_key=csr.public_key(),
        )


# ----------------------------- I/O auxiliar -----------------------------

def _write_secret(path: Path, data: bytes) -> None:
    """
    Escreve um ficheiro como segredo (modo 0600).

    Cria o ficheiro com os bits de permissão certos *desde o início* via
    os.open + O_CREAT + mode, em vez de escrever e depois chmod, para
    evitar a janela durante a qual o ficheiro existiria com permissões
    laxas (race condition trivial mas evitável).
    """
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(str(path), flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
    except Exception:
        os.close(fd)
        raise
