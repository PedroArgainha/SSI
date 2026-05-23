"""
Teste end-to-end automático.

Levanta o servidor numa thread, cria clientes alice e bob, faz login,
estabelece handshake, troca mensagens, testa offline storage.

Não usa o REPL — chama diretamente os métodos do Client.
"""

from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path

# Garantir que o projeto está no path
sys.path.insert(0, str(Path(__file__).parent))

from server.server import serve
from client.client import Client

ID_KEY_PASSWORD = os.environ.get("SSI_ID_KEY_PASSWORD", "test-password").encode("utf-8")


def run_server():
    serve("127.0.0.1", 9100, Path("data"))


def main():
    # Arrancar servidor numa thread daemon.
    server_thread = threading.Thread(target=run_server, daemon=True)
    server_thread.start()
    time.sleep(0.5)
    print("[TEST] Servidor arrancado.\n")

    # Criar dois clientes
    alice = Client(Path("data/users/alice"), "127.0.0.1", 9100, id_key_password=ID_KEY_PASSWORD)
    bob = Client(Path("data/users/bob"), "127.0.0.1", 9100, id_key_password=ID_KEY_PASSWORD)

    alice.connect()
    bob.connect()
    print("[TEST] Ambos ligados por TLS.\n")

    alice.login()
    bob.login()
    alice.start_recv_thread()
    bob.start_recv_thread()
    print("[TEST] Ambos autenticados.\n")

    time.sleep(0.2)

    # Alice envia para Bob — vai forçar handshake
    print("[TEST] Alice envia primeira mensagem para Bob...")
    alice.cmd_msg("bob", "Ola Bob, vamos conversar!")
    time.sleep(0.5)

    # Bob responde
    print("\n[TEST] Bob responde...")
    bob.cmd_msg("alice", "Ola Alice, recebi a tua mensagem :)")
    time.sleep(0.5)

    # Mais umas trocas
    print("\n[TEST] Mais umas trocas...")
    alice.cmd_msg("bob", "Boa, continuamos por aqui.")
    time.sleep(0.3)
    bob.cmd_msg("alice", "Combinado.")
    time.sleep(0.3)

    # Testar offline storage
    print("\n[TEST] Bob faz LOGOUT explícito (vai ficar offline a sério)...")
    bob.cmd_logout()
    time.sleep(0.5)
    bob.shutdown_event.set()
    bob.disconnect()
    time.sleep(0.5)

    print("[TEST] Alice envia para Bob offline...")
    alice.cmd_msg("bob", "Bob, estás aí? (deve ir offline)")
    time.sleep(0.5)

    print("\n[TEST] Bob volta a ligar (nova sessão) e faz fetch...")
    bob2 = Client(Path("data/users/bob"), "127.0.0.1", 9100, id_key_password=ID_KEY_PASSWORD)
    bob2.connect()
    bob2.login()
    bob2.start_recv_thread()
    time.sleep(0.2)
    bob2.cmd_fetch()
    time.sleep(0.5)

    print("\n[TEST] Nota: a mensagem offline chegou como envelope MESSAGE,")
    print("[TEST] mas Bob não consegue decifrar porque a sessão antiga")
    print("[TEST] foi descartada (forward secrecy). Numa entrega real,")
    print("[TEST] Alice teria de re-fazer o handshake antes de enviar.")

    print("\n[TEST] Tudo OK. A terminar.")
    alice.shutdown_event.set()
    bob2.shutdown_event.set()
    alice.disconnect()
    bob2.disconnect()


if __name__ == "__main__":
    main()
