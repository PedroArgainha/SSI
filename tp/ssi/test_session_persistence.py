"""
Teste da persistência local de sessões E2E cifradas.

Cenário que SEM persistência falhava (ver test_e2e.py "FS impede decifrar
após reinício"):

    1. Alice e Bob ligam-se. Alice tem session_store ativo.
    2. Fazem handshake e trocam mensagens. Sessão cifrada gravada em disco.
    3. Bob faz LOGOUT e simula crash (cliente totalmente fechado).
    4. Alice envia mais uma mensagem. Vai para mailbox offline do servidor.
    5. Bob volta, com session_store ativo (mesma password). Carrega sessão
       persistida. Faz FETCH e DECIFRA com sucesso.

Também testa que password errada falha a carregar sessões.
"""

from __future__ import annotations

import shutil
import socket
import ssl
import os
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from common import certs
from server.persistence import MailboxStore
from server.server import (
    ClientSession,
    OfflineMessage,
    ServerState,
    load_enrolled_users,
    make_tls_context,
)
from client.client import Client

ID_KEY_PASSWORD = os.environ.get("SSI_ID_KEY_PASSWORD", "test-password").encode("utf-8")


PORT = 9212


def run_server(stop_evt: threading.Event, ready_evt: threading.Event) -> None:
    data_dir = Path("data")
    ca_cert_path = data_dir / "ca" / "ca_cert.pem"
    ca_cert = certs.cert_from_pem(ca_cert_path.read_bytes())
    mailbox_store = MailboxStore(data_dir / "server" / "mailboxes")
    state = ServerState(ca_cert=ca_cert, mailbox_store=mailbox_store)
    state.users = load_enrolled_users(data_dir, ca_cert)
    persisted = mailbox_store.load_all()
    for r, items in persisted.items():
        if r in state.users:
            state.mailboxes[r] = [
                OfflineMessage(sender=str(it.get("sender", "?")),
                               recipient=r, payload=it.get("envelope") or {})
                for it in items
            ]

    tls_ctx = make_tls_context(
        data_dir / "server" / "tls_cert.pem",
        data_dir / "server" / "tls_key.pem",
        ca_cert_path,
    )
    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    raw.bind(("127.0.0.1", PORT))
    raw.listen(16)
    raw.settimeout(0.2)
    ready_evt.set()
    try:
        while not stop_evt.is_set():
            try:
                cs, addr = raw.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                ts = tls_ctx.wrap_socket(cs, server_side=True)
            except ssl.SSLError:
                cs.close()
                continue
            session = ClientSession(ts, addr, state)
            threading.Thread(target=session.run, daemon=True).start()
    finally:
        raw.close()


def main() -> None:
    # Limpar tudo que possa ter ficado de testes anteriores.
    for d in (Path("data/server/mailboxes"),
              Path("data/users/alice/sessions"),
              Path("data/users/bob/sessions")):
        if d.exists():
            shutil.rmtree(d)

    print("=== FASE 1: arrancar servidor ===")
    stop = threading.Event()
    ready = threading.Event()
    t = threading.Thread(target=run_server, args=(stop, ready), daemon=True)
    t.start()
    ready.wait(timeout=2.0)

    pw_alice = b"alice-password"
    pw_bob = b"bob-password"

    print("\n=== FASE 2: ambos ligam com session_store ativo ===")
    alice = Client(Path("data/users/alice"), "127.0.0.1", PORT,
                   session_password=pw_alice,
                   id_key_password=ID_KEY_PASSWORD)
    bob = Client(Path("data/users/bob"), "127.0.0.1", PORT,
                 session_password=pw_bob,
                 id_key_password=ID_KEY_PASSWORD)
    alice.connect(); bob.connect()
    alice.login(); bob.login()
    alice._load_persisted_sessions(); bob._load_persisted_sessions()
    alice.start_recv_thread(); bob.start_recv_thread()

    print("\n=== FASE 3: handshake + mensagens ===")
    alice.cmd_msg("bob", "primeira, com sessão persistida")
    time.sleep(0.4)
    bob.cmd_msg("alice", "ack: primeira recebida")
    time.sleep(0.3)

    print("\n=== Verificar que sessões estão em disco ===")
    alice_sess = Path("data/users/alice/sessions/bob.bin")
    bob_sess = Path("data/users/bob/sessions/alice.bin")
    print(f"  alice/sessions/bob.bin: {alice_sess.exists()} "
          f"({alice_sess.stat().st_size if alice_sess.exists() else 0} bytes)")
    print(f"  bob/sessions/alice.bin: {bob_sess.exists()} "
          f"({bob_sess.stat().st_size if bob_sess.exists() else 0} bytes)")
    # Confirmar que é opaco
    if alice_sess.exists():
        sample = alice_sess.read_bytes()[:20]
        print(f"  preview opaco: {sample!r}")

    print("\n=== FASE 4: Bob sai (logout limpo) e fecha cliente ===")
    bob.cmd_logout()
    time.sleep(0.3)
    bob.shutdown_event.set()
    bob.disconnect()
    time.sleep(0.3)

    print("\n=== FASE 5: Alice envia mais uma — vai para mailbox ===")
    alice.cmd_msg("bob", "esta vai esperar pelo Bob no servidor")
    time.sleep(0.4)

    print("\n=== FASE 6: Bob volta com cliente NOVO + mesma password ===")
    bob_new = Client(Path("data/users/bob"), "127.0.0.1", PORT,
                     session_password=pw_bob,
                     id_key_password=ID_KEY_PASSWORD)
    bob_new.connect()
    bob_new.login()
    bob_new._load_persisted_sessions()
    bob_new.start_recv_thread()
    time.sleep(0.2)

    print("\n=== FASE 7: Bob faz FETCH — deve DECIFRAR a mensagem ===")
    bob_new.cmd_fetch()
    time.sleep(0.5)

    print("\n=== FASE 8: testar password errada ===")
    try:
        bob_evil = Client(Path("data/users/bob"), "127.0.0.1", PORT,
                          session_password=b"WRONG-PASSWORD",
                          id_key_password=ID_KEY_PASSWORD)
        # A inicialização não falha; é o load_all que falha.
        result = bob_evil.session_store.load_all()
        print(f"  load com pw errada devolveu: {result} (esperado: vazio, com warnings)")
    except Exception as exc:
        print(f"  exceção (esperado): {exc}")

    alice.shutdown_event.set(); alice.disconnect()
    bob_new.shutdown_event.set(); bob_new.disconnect()
    stop.set()
    t.join(timeout=3.0)
    print("\n=== Concluído ===")


if __name__ == "__main__":
    main()
