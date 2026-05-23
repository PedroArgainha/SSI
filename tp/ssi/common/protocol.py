"""
Protocolo de framing sobre TCP.

Cada mensagem é serializada como:
    [4 bytes big-endian com o tamanho do payload] [payload JSON UTF-8]

Esta camada não trata de criptografia — está abaixo (TLS no canal
cliente↔servidor) ou acima (cifras E2E para mensagens entre clientes).
Aqui apenas garantimos:
    1. Framing fiável sobre TCP (que é stream-oriented).
    2. Parsing estrito de JSON com validação de campos mínimos.
    3. Limites de tamanho para evitar frames absurdos / DoS.
"""

from __future__ import annotations

import base64
import json
import socket
import ssl
import struct
from typing import Any, Union

# Tamanho máximo de uma mensagem (1 MiB).
# Razoável para mensagens de chat + certificados + handshakes.
MAX_FRAME_SIZE = 1024 * 1024

SocketLike = Union[socket.socket, ssl.SSLSocket]


class ProtocolError(Exception):
    """Erro de framing, parsing ou validação do protocolo."""


# ----------------------------- Base64 helpers -----------------------------
# Usamos base64 para empacotar bytes (ciphertexts, nonces, certificados em
# DER, assinaturas) dentro de campos JSON, que é texto.

def b64e(data: bytes) -> str:
    """Codifica bytes para base64 textual (ASCII)."""
    return base64.b64encode(data).decode("ascii")


def b64d(text: str) -> bytes:
    """Descodifica base64 textual para bytes, com validação estrita."""
    try:
        return base64.b64decode(text.encode("ascii"), validate=True)
    except Exception as exc:
        raise ProtocolError("Campo base64 inválido.") from exc


# ----------------------------- I/O sobre socket -----------------------------

def _recv_exact(sock: SocketLike, size: int) -> bytes:
    """
    Lê exatamente 'size' bytes do socket.

    Em TCP, recv() pode devolver menos bytes do que o pedido — temos de
    repetir até completar. Levanta EOFError se a outra ponta fechou a
    ligação a meio de um frame.
    """
    chunks = bytearray()
    while len(chunks) < size:
        chunk = sock.recv(size - len(chunks))
        if not chunk:
            raise EOFError("Ligação terminada antes de completar frame.")
        chunks.extend(chunk)
    return bytes(chunks)


def send_message(sock: SocketLike, message: dict[str, Any]) -> None:
    """
    Serializa e envia uma mensagem do nosso protocolo.

    Estrutura:
        [4 bytes big-endian: tamanho do payload] [payload JSON UTF-8]
    """
    if not isinstance(message, dict):
        raise ProtocolError("A mensagem tem de ser um dicionário.")
    if "type" not in message or not isinstance(message["type"], str):
        raise ProtocolError("A mensagem tem de incluir um campo 'type' textual.")

    raw = json.dumps(message, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    if len(raw) > MAX_FRAME_SIZE:
        raise ProtocolError(f"Mensagem demasiado grande ({len(raw)} bytes).")

    # !I = unsigned int de 4 bytes em network byte order (big-endian)
    header = struct.pack("!I", len(raw))
    sock.sendall(header + raw)


def recv_message(sock: SocketLike) -> dict[str, Any]:
    """
    Recebe uma mensagem completa do socket e devolve o dicionário JSON.

    Faz validação estrutural mínima:
        - tem de ser um objeto JSON (não array, não escalar)
        - tem de conter um campo 'type' textual
    """
    header = _recv_exact(sock, 4)
    (size,) = struct.unpack("!I", header)

    if size <= 0 or size > MAX_FRAME_SIZE:
        raise ProtocolError(f"Tamanho de frame inválido: {size}.")

    payload = _recv_exact(sock, size)

    try:
        message = json.loads(payload.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise ProtocolError("JSON inválido.") from exc
    except UnicodeDecodeError as exc:
        raise ProtocolError("Payload não é UTF-8 válido.") from exc

    if not isinstance(message, dict):
        raise ProtocolError("A mensagem recebida não é um objeto JSON.")
    if "type" not in message or not isinstance(message["type"], str):
        raise ProtocolError("A mensagem recebida não contém 'type' válido.")

    return message
