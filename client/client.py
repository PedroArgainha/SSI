from __future__ import annotations

import shlex
import socket
from typing import Any

from common.protocol import b64e, recv_message, send_message

HOST = "127.0.0.1"
PORT = 9000


def print_help() -> None:
    """Mostra os comandos disponíveis."""
    print(
        """
Comandos disponíveis:
  /register <username>
  /login <username>
  /users
  /send <destinatario> <mensagem>
  /fetch
  /logout
  /ping
  /quit
  /help
""".strip()
    )


def handle_response(response: dict[str, Any]) -> None:
    """
    Trata respostas do servidor e mostra-as ao utilizador.

    O cliente interpreta tipos de resposta como:
    - OK
    - ERROR
    - USERS
    - MESSAGES
    """
    msg_type = response["type"]

    if msg_type == "OK":
        print(f"[OK] {response.get('message', '')}")

    elif msg_type == "ERROR":
        print(f"[ERRO] {response.get('message', 'Erro desconhecido.')}")

    elif msg_type == "USERS":
        users = response.get("users", [])
        online = set(response.get("online", []))

        print("[UTILIZADORES]")
        for user in users:
            suffix = " (online)" if user in online else ""
            print(f"  - {user}{suffix}")

    elif msg_type == "MESSAGES":
        items = response.get("items", [])
        if not items:
            print("[INFO] Sem mensagens pendentes.")
            return

        print(f"[INFO] {len(items)} mensagem(ns) recebida(s):")
        for item in items:
            sender = item.get("from", "?")
            content_type = item.get("content_type", "unknown")
            payload_b64 = item.get("payload_b64", "")

            try:
                text = __import__("base64").b64decode(payload_b64).decode("utf-8", errors="replace")
            except Exception:
                text = "<payload inválido>"

            print(f"  [{content_type}] {sender}: {text}")

    else:
        print(f"[INFO] Resposta não tratada: {response}")


def main() -> None:
    """
    Arranque do cliente:
    - liga ao servidor
    - mostra help
    - entra num loop de comandos
    """
    print(f"[INFO] A ligar a {HOST}:{PORT}...")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((HOST, PORT))
        print("[INFO] Ligação estabelecida.")
        print_help()

        while True:
            try:
                line = input("ssi-chat> ").strip()
            except EOFError:
                print()
                break

            if not line:
                continue

            # shlex permite escrever mensagens com aspas
            try:
                parts = shlex.split(line)
            except ValueError as exc:
                print(f"[ERRO] Linha inválida: {exc}")
                continue

            cmd = parts[0]

            if cmd == "/help":
                print_help()
                continue

            if cmd == "/quit":
                print("[INFO] A terminar cliente.")
                break

            if cmd == "/register":
                if len(parts) != 2:
                    print("Uso: /register <username>")
                    continue

                send_message(sock, {"type": "REGISTER", "username": parts[1]})
                handle_response(recv_message(sock))

            elif cmd == "/login":
                if len(parts) != 2:
                    print("Uso: /login <username>")
                    continue

                send_message(sock, {"type": "LOGIN", "username": parts[1]})
                handle_response(recv_message(sock))

            elif cmd == "/users":
                send_message(sock, {"type": "LIST_USERS"})
                handle_response(recv_message(sock))

            elif cmd == "/send":
                if len(parts) < 3:
                    print("Uso: /send <destinatario> <mensagem>")
                    continue

                to_user = parts[1]
                plaintext = " ".join(parts[2:]).encode("utf-8")

                # Nesta etapa o payload ainda é texto simples em base64.
                # Mais tarde este campo vai passar a transportar ciphertext.
                payload_b64 = b64e(plaintext)

                send_message(
                    sock,
                    {
                        "type": "SEND",
                        "to": to_user,
                        "payload_b64": payload_b64,
                        "content_type": "raw-text",
                    },
                )
                handle_response(recv_message(sock))

            elif cmd == "/fetch":
                send_message(sock, {"type": "FETCH"})
                handle_response(recv_message(sock))

            elif cmd == "/logout":
                send_message(sock, {"type": "LOGOUT"})
                handle_response(recv_message(sock))

            elif cmd == "/ping":
                send_message(sock, {"type": "PING"})
                handle_response(recv_message(sock))

            else:
                print("[ERRO] Comando desconhecido. Usa /help.")


if __name__ == "__main__":
    main()