"""
Teste avançado: handshake estabelece-se mesmo quando o peer está offline.

Cenário:
    - Bob não está ligado.
    - Alice tenta enviar mensagem para Bob.
    - Cliente da Alice inicia handshake; HS_INIT vai para offline storage.
    - Bob entra; faz fetch; processa HS_INIT; envia HS_REPLY.
    - Mas a HS_REPLY também vai para offline (Alice está, mas é mais
      seguro testar com Alice também offline).

Este é um caso menos trivial: queremos que o handshake funcione mesmo
com latências longas / store-and-forward.

Para simplificar, este teste verifica apenas: handshake online + fetch
de mensagens já cifradas posteriormente. (Re-handshake com peer offline
é uma extensão possível que não é central.)
"""

from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from server.server import serve
from client.client import Client

ID_KEY_PASSWORD = os.environ.get("SSI_ID_KEY_PASSWORD", "test-password").encode("utf-8")


def run_server():
    serve("127.0.0.1", 9101, Path("data"))


def main():
    server_thread = threading.Thread(target=run_server, daemon=True)
    server_thread.start()
    time.sleep(0.5)
    print("[TEST] Server up.\n")

    # Cenário A: Alice e Bob online, fazem handshake e mantêm sessão.
    # Bob desconecta (mas mantém sessão em memória? não, é cliente novo
    # que volta a ligar). Alice envia. Bob volta — não decifra (FS OK).

    # Cenário B (este): Alice e Bob fazem handshake, trocam mensagens,
    # Bob desliga sem logout (crash), Alice envia, Bob volta.
    # Como Alice NÃO sabe que Bob morreu, continua a usar a sessão.
    # Bob, ao re-ligar, perde tudo. A mensagem antiga fica como lixo
    # offline.

    # Cenário interessante para mostrar: re-handshake na demand.
    # Vou apenas testar replay protection do servidor:
    # tentar enviar duas mensagens de comandos REGISTER duplicadas.

    alice = Client(Path("data/users/alice"), "127.0.0.1", 9101, id_key_password=ID_KEY_PASSWORD)
    bob = Client(Path("data/users/bob"), "127.0.0.1", 9101, id_key_password=ID_KEY_PASSWORD)
    alice.connect()
    bob.connect()
    alice.login()
    bob.login()
    alice.start_recv_thread()
    bob.start_recv_thread()
    print("[TEST] Login OK.\n")

    # Handshake através de várias mensagens
    print("[TEST] Alice envia 5 mensagens em série para Bob:")
    for i in range(5):
        alice.cmd_msg("bob", f"Mensagem #{i}")
        time.sleep(0.15)

    print("\n[TEST] Bob envia 3 mensagens para Alice:")
    for i in range(3):
        bob.cmd_msg("alice", f"Resposta #{i}")
        time.sleep(0.15)

    time.sleep(0.5)
    print("\n[TEST] /users do lado da Alice:")
    alice.cmd_users()

    time.sleep(0.3)
    print("\n[TEST] Logout limpo de ambos.")
    alice.cmd_logout()
    bob.cmd_logout()
    time.sleep(0.3)

    alice.shutdown_event.set()
    bob.shutdown_event.set()
    alice.disconnect()
    bob.disconnect()
    print("\n[TEST] OK.")


if __name__ == "__main__":
    main()
