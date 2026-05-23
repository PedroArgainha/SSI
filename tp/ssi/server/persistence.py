"""
Persistência das mailboxes do servidor em disco.

Cada destinatário tem um ficheiro JSON em data/server/mailboxes/<user>.json
contendo a lista de envelopes pendentes. O conteúdo é JÁ CIFRADO E2E,
portanto o servidor está apenas a guardar bytes opacos — em particular,
mesmo um atacante com acesso ao disco do servidor não vê plaintext.

Decisões de design:
    - 1 ficheiro por destinatário, em vez de 1 ficheiro global. Reduz
      contenção e simplifica a entrega (um utilizador limpa só o seu).
    - Escrita atómica via os.replace() sobre tmp file no mesmo
      diretório, para que uma falha a meio nunca deixe o ficheiro
      em estado inconsistente.
    - Permissões 600 nos ficheiros de mailbox, 700 no diretório. O
      conteúdo já é cifrado, mas defendemos em profundidade contra
      acesso casual.

Concorrência:
    - O ServerState mantém o lock global; este módulo é chamado já
      dentro desse lock, portanto não precisa de o seu.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
from pathlib import Path
from typing import Any

logger = logging.getLogger("server.persistence")


class MailboxStore:
    """
    Armazena envelopes por destinatário.

    API: load_all(), append(recipient, sender, envelope), pop_all(recipient).
    """

    def __init__(self, base_dir: Path):
        self.base_dir = base_dir
        self.base_dir.mkdir(parents=True, exist_ok=True)
        # Diretório com permissões restritas — defesa em profundidade.
        try:
            os.chmod(self.base_dir, 0o700)
        except OSError:
            # noqa — em alguns sistemas pode falhar por owner; toleramos.
            pass

    # ---------- Helpers de path ----------

    def _path_for(self, recipient: str) -> Path:
        # Sanitização: o username já foi validado quando o cert foi emitido,
        # mas defendemos contra path traversal absurdo aqui também.
        if "/" in recipient or ".." in recipient or recipient.startswith("."):
            raise ValueError(f"Recipient inválido: {recipient!r}")
        return self.base_dir / f"{recipient}.json"

    # ---------- Leitura ----------

    def load_all(self) -> dict[str, list[dict[str, Any]]]:
        """
        Lê do disco todas as mailboxes e devolve dicionário
        {recipient: [items]}, onde cada item é {"sender": ..., "envelope": ...}.

        Ficheiros corrompidos são logados e ignorados (não rebentam o
        arranque do servidor).
        """
        out: dict[str, list[dict[str, Any]]] = {}
        for entry in self.base_dir.glob("*.json"):
            recipient = entry.stem
            try:
                data = json.loads(entry.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError) as exc:
                logger.warning("Mailbox %s ilegível, a ignorar: %s", entry, exc)
                continue
            if not isinstance(data, list):
                logger.warning("Mailbox %s não é uma lista, a ignorar.", entry)
                continue
            out[recipient] = [item for item in data if isinstance(item, dict)]
        return out

    # ---------- Escrita ----------

    def write_all_for(self, recipient: str, items: list[dict[str, Any]]) -> None:
        """
        Escreve atomicamente a lista completa de items para um destinatário.
        Se a lista ficar vazia, apaga o ficheiro.
        """
        path = self._path_for(recipient)
        if not items:
            try:
                path.unlink()
            except FileNotFoundError:
                pass
            return

        # Escrita atómica: tmpfile no mesmo diretório, depois os.replace.
        # Isto garante que se houver crash a meio, ou fica o ficheiro
        # antigo intacto, ou fica o novo intacto — nunca a meio.
        fd, tmp_path = tempfile.mkstemp(
            prefix=f".{recipient}.", suffix=".json.tmp", dir=str(self.base_dir)
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(items, f, ensure_ascii=False, separators=(",", ":"))
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
