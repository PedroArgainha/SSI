"""
Persistência local de sessões E2E.

Cada sessão (chaves direcionais + contadores + conversation_id) é
serializada e cifrada com uma chave derivada da password do utilizador.

Esquema:
    - KDF:   Scrypt (n=2^15, r=8, p=1) sobre password + salt aleatório (16 B).
    - Cifra: AES-256-GCM com nonce aleatório (12 B). Tag de 16 B incluída.
    - Layout do ficheiro (binário):
          MAGIC(4) || VERSION(1) || SALT(16) || NONCE(12) || CIPHERTEXT(...)
    - Plaintext serializado: JSON UTF-8.

Trade-off de segurança (consciente):
    - Persistir as chaves de sessão SACRIFICA forward secrecy entre
      sessões do mesmo cliente (se a password e o ficheiro forem
      comprometidos, mensagens passadas tornam-se decifráveis).
    - Mantém-se FS *entre conversas distintas* (cada peer tem a sua
      chave) e contra um servidor comprometido (servidor nunca vê a
      chave de sessão).
    - É opcional: se o utilizador não der password, o cliente corre
      em modo sem persistência (FS estrita, mas perde sessão a cada
      restart).

Decisão pedagógica:
    - Em vez de simplesmente "matar" a FS, expomos o trade-off ao
      utilizador via flag. Isto é mais honesto e didático para defesa
      oral do que esconder uma decisão de design.
"""

from __future__ import annotations

import json
import logging
import os
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

logger = logging.getLogger("client.session_store")

_MAGIC = b"SSI1"
_VERSION = 1
_SALT_SIZE = 16
_NONCE_SIZE = 12
_KEY_SIZE = 32

# Parâmetros Scrypt — recomendados pela RFC 7914 para uso interativo.
# n=2^15 dá ~50ms numa máquina moderna; aumentar se quisermos endurecer
# contra ataques offline, custando arranque mais lento.
_SCRYPT_N = 2 ** 15
_SCRYPT_R = 8
_SCRYPT_P = 1


class SessionStoreError(Exception):
    """Erro a ler ou escrever sessão persistida."""


def _derive_key_from_password(password: bytes, salt: bytes) -> bytes:
    """Deriva chave AES-256 da password do utilizador, usando Scrypt."""
    return Scrypt(
        salt=salt,
        length=_KEY_SIZE,
        n=_SCRYPT_N,
        r=_SCRYPT_R,
        p=_SCRYPT_P,
    ).derive(password)


@dataclass
class PersistedSession:
    """
    Snapshot serializável de uma sessão E2E.

    Equivalente ao E2ESession mas sem o lock e com bytes em vez de
    objetos vivos.
    """
    peer_username: str
    conversation_id: str
    send_key: bytes
    recv_key: bytes
    send_seq: int
    recv_seq: int

    def to_json(self) -> dict[str, Any]:
        from common.protocol import b64e
        return {
            "peer_username": self.peer_username,
            "conversation_id": self.conversation_id,
            "send_key_b64": b64e(self.send_key),
            "recv_key_b64": b64e(self.recv_key),
            "send_seq": self.send_seq,
            "recv_seq": self.recv_seq,
        }

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> "PersistedSession":
        from common.protocol import b64d
        return cls(
            peer_username=data["peer_username"],
            conversation_id=data["conversation_id"],
            send_key=b64d(data["send_key_b64"]),
            recv_key=b64d(data["recv_key_b64"]),
            send_seq=int(data["send_seq"]),
            recv_seq=int(data["recv_seq"]),
        )


class SessionStore:
    """
    Persistência de sessões E2E para um utilizador.

    Cada peer fica num ficheiro separado: <dir>/<peer>.bin
    """

    def __init__(self, base_dir: Path, password: bytes):
        self.base_dir = base_dir
        self.password = password
        self.base_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.base_dir, 0o700)
        except OSError:
            pass

    def _path_for(self, peer: str) -> Path:
        if "/" in peer or ".." in peer or peer.startswith("."):
            raise ValueError(f"Peer inválido: {peer!r}")
        return self.base_dir / f"{peer}.bin"

    # ---------- Save ----------

    def save(self, sess: PersistedSession) -> None:
        """Cifra e escreve atomicamente uma sessão."""
        plaintext = json.dumps(sess.to_json(), separators=(",", ":")).encode("utf-8")

        salt = os.urandom(_SALT_SIZE)
        key = _derive_key_from_password(self.password, salt)
        nonce = os.urandom(_NONCE_SIZE)
        ct = AESGCM(key).encrypt(nonce, plaintext, _MAGIC)  # AAD = MAGIC

        blob = _MAGIC + struct.pack("!B", _VERSION) + salt + nonce + ct
        path = self._path_for(sess.peer_username)

        # Escrita atómica com tmpfile com nome único.
        # Nomes únicos por chamada evitam race condition entre saves
        # concorrentes para o mesmo peer (que aconteceria se usássemos
        # nome fixo tipo path.tmp).
        import tempfile
        fd, tmp_path = tempfile.mkstemp(
            prefix=f".{sess.peer_username}.",
            suffix=".bin.tmp",
            dir=str(self.base_dir),
        )
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(blob)
                f.flush()
                os.fsync(f.fileno())
            os.chmod(tmp_path, 0o600)
            os.replace(tmp_path, path)
        except Exception:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

    # ---------- Load ----------

    def load(self, peer: str) -> PersistedSession | None:
        """Lê e decifra a sessão para um peer. None se não existe."""
        path = self._path_for(peer)
        if not path.exists():
            return None
        return self._load_blob(path.read_bytes())

    def load_all(self) -> dict[str, PersistedSession]:
        """Carrega todas as sessões persistidas. Falhas individuais são logadas."""
        out: dict[str, PersistedSession] = {}
        for entry in self.base_dir.glob("*.bin"):
            peer = entry.stem
            try:
                sess = self._load_blob(entry.read_bytes())
                if sess is not None and sess.peer_username == peer:
                    out[peer] = sess
                elif sess is not None:
                    logger.warning("Ficheiro %s contém peer %r — incoerente, a ignorar.",
                                   entry, sess.peer_username)
            except SessionStoreError as exc:
                logger.warning("Sessão %s ilegível: %s", entry, exc)
        return out

    def _load_blob(self, blob: bytes) -> PersistedSession | None:
        if len(blob) < 4 + 1 + _SALT_SIZE + _NONCE_SIZE + 16:
            raise SessionStoreError("Blob demasiado pequeno.")
        if blob[:4] != _MAGIC:
            raise SessionStoreError("Magic bytes errados.")
        version = blob[4]
        if version != _VERSION:
            raise SessionStoreError(f"Versão desconhecida: {version}")

        offset = 5
        salt = blob[offset:offset + _SALT_SIZE]; offset += _SALT_SIZE
        nonce = blob[offset:offset + _NONCE_SIZE]; offset += _NONCE_SIZE
        ct = blob[offset:]

        key = _derive_key_from_password(self.password, salt)
        try:
            plaintext = AESGCM(key).decrypt(nonce, ct, _MAGIC)
        except InvalidTag:
            raise SessionStoreError("Password errada ou ficheiro corrompido.")

        try:
            data = json.loads(plaintext.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise SessionStoreError(f"Plaintext inválido: {exc}") from exc

        return PersistedSession.from_json(data)

    # ---------- Delete ----------

    def delete(self, peer: str) -> None:
        path = self._path_for(peer)
        try:
            path.unlink()
        except FileNotFoundError:
            pass
