from __future__ import annotations

import base64
import json
import socket
import struct
from typing import Any

# Tamanho máximo de uma mensagem.
# Serve para evitar frames absurdamente grandes ou maliciosos.
MAX_FRAME_SIZE = 1024 * 1024  # 1 MiB


class ProtocolError(Exception):
    """Erro de framing ou parsing do protocolo."""


def b64e(data: bytes) -> str:
    """
    Codifica bytes para base64 textual.
    Na Etapa 1 usamos isto para meter payloads binários ou texto
    dentro de JSON sem problemas.
    """
    return base64.b64encode(data).decode("ascii")


def b64d(text: str) -> bytes:
    """
    Faz o inverso: base64 textual -> bytes.
    Mais tarde isto vai ser útil para ciphertexts, nonces, etc.
    """
    try:
        return base64.b64decode(text.encode("ascii"), validate=True)
    except Exception as exc:
        raise ProtocolError("Campo base64 inválido.") from exc


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    """
    Lê exatamente 'size' bytes do socket.
    Como o TCP pode devolver menos bytes do que pedimos,
    temos de repetir até completar.
    """
    chunks = bytearray()
    while len(chunks) < size:
        chunk = sock.recv(size - len(chunks))
        if not chunk:
            raise EOFError("Ligação terminada.")
        chunks.extend(chunk)
    return bytes(chunks)


def send_message(sock: socket.socket, message: dict[str, Any]) -> None:
    """
    Envia uma mensagem no nosso protocolo:
    [4 bytes com tamanho][payload JSON UTF-8]

    O prefixo de 4 bytes resolve o problema de framing em TCP.
    """
    if not isinstance(message, dict):
        raise ProtocolError("A mensagem tem de ser um dicionário.")
    if "type" not in message or not isinstance(message["type"], str):
        raise ProtocolError("A mensagem tem de incluir um campo 'type' textual.")

    # Serializa a mensagem para JSON compacto.
    raw = json.dumps(message, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    if len(raw) > MAX_FRAME_SIZE:
        raise ProtocolError("Mensagem demasiado grande.")

    # !I = inteiro sem sinal de 4 bytes em network byte order
    header = struct.pack("!I", len(raw))
    sock.sendall(header + raw)


def recv_message(sock: socket.socket) -> dict[str, Any]:
    """
    Recebe uma mensagem completa do socket:
    1) lê os 4 bytes do tamanho
    2) lê o payload com esse tamanho
    3) faz parse do JSON    
    4) valida estrutura mínima
    """
    header = _recv_exact(sock, 4)
    (size,) = struct.unpack("!I", header)

    if size <= 0 or size > MAX_FRAME_SIZE:
        raise ProtocolError("Tamanho de frame inválido.")

    payload = _recv_exact(sock, size)

    try:
        message = json.loads(payload.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise ProtocolError("JSON inválido.") from exc

    if not isinstance(message, dict):
        raise ProtocolError("A mensagem recebida não é um objeto JSON.")
    if "type" not in message or not isinstance(message["type"], str):
        raise ProtocolError("A mensagem recebida não contém um 'type' válido.")

    return message