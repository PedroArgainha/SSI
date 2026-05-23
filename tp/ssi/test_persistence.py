"""
Teste de persistência: o servidor pode reiniciar sem perder mensagens
offline pendentes.
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


PORT = 9211


def run_server(stop_evt: threading.Event, ready_evt: threading.Event,
               port: int = PORT) -> None:
    """Levanta um servidor na porta dada. Pára quando stop_evt for set."""
    data_dir = Path("data")
    ca_cert_path = data_dir / "ca" / "ca_cert.pem"
    server_cert = data_dir / "server" / "tls_cert.pem"
    server_key = data_dir / "server" / "tls_key.pem"

    ca_cert = certs.cert_from_pem(ca_cert_path.read_bytes())
    mailbox_store = MailboxStore(data_dir / "server" / "mailboxes")
    state = ServerState(ca_cert=ca_cert, mailbox_store=mailbox_store)
    state.users = load_enrolled_users(data_dir, ca_cert)
    persisted = mailbox_store.load_all()
    for r, items in persisted.items():
        if r in state.users:
            state.mailboxes[r] = [
                OfflineMessage(
                    sender=str(it.get("sender", "?")),
                    recipient=r,
                    payload=it.get("envelope") or {},
                )
                for it in items
            ]
    print(f"[SRV] Restauradas mailboxes: "
          f"{ {k: len(v) for k, v in state.mailboxes.items()} }")

    tls_ctx = make_tls_context(server_cert, server_key, ca_cert_path)
    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    raw.bind(("127.0.0.1", port))
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
    mailbox_dir = Path("data/server/mailboxes")
    if mailbox_dir.exists():
        shutil.rmtree(mailbox_dir)

    print("\n=== FASE 1: arrancar servidor ===")
    stop1 = threading.Event()
    ready1 = threading.Event()
    t1 = threading.Thread(target=run_server, args=(stop1, ready1), daemon=True)
    t1.start()
    ready1.wait(timeout=2.0)

    print("\n=== FASE 2: Alice online, Bob offline. Alice envia. ===")
    alice = Client(Path("data/users/alice"), "127.0.0.1", PORT, id_key_password=ID_KEY_PASSWORD)
    alice.connect()
    alice.login()
    alice.start_recv_thread()
    alice.cmd_msg("bob", "este envelope tem de sobreviver ao restart do servidor")
    time.sleep(0.4)

    bob_mailbox = mailbox_dir / "bob.json"
    print(f"\n  bob.json existe? {bob_mailbox.exists()}")
    if bob_mailbox.exists():
        size = bob_mailbox.stat().st_size
        mode = oct(bob_mailbox.stat().st_mode & 0o777)
        print(f"  tamanho: {size} bytes, permissões: {mode}")
        sample = bob_mailbox.read_text()[:150]
        print(f"  preview (opaco/cifrado): {sample!r}")

    alice.shutdown_event.set()
    alice.disconnect()

    print("\n=== FASE 3: parar servidor ===")
    stop1.set()
    t1.join(timeout=3.0)
    print(f"  thread parou: {not t1.is_alive()}")

    print("\n=== FASE 4: arrancar servidor de novo ===")
    stop2 = threading.Event()
    ready2 = threading.Event()
    t2 = threading.Thread(target=run_server, args=(stop2, ready2), daemon=True)
    t2.start()
    ready2.wait(timeout=2.0)

    print("\n=== FASE 5: Bob liga e faz FETCH ===")
    bob = Client(Path("data/users/bob"), "127.0.0.1", PORT, id_key_password=ID_KEY_PASSWORD)
    bob.connect()
    bob.login()
    bob.start_recv_thread()
    bob.cmd_fetch()
    time.sleep(0.4)

    print(f"\n  bob.json após fetch existe? {bob_mailbox.exists()}")

    bob.shutdown_event.set()
    bob.disconnect()
    stop2.set()
    t2.join(timeout=3.0)

    print("\n=== Concluído ===")


if __name__ == "__main__":
    main()
