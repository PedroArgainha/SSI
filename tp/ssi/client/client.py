"""
Cliente CLI do ssi-chat.

Estrutura:
    - Liga-se ao servidor por TLS (verifica cert do servidor contra a
      CA local).
    - Faz LOGIN_INIT/LOGIN_RESPONSE (challenge-response com a sua chave RSA).
    - Tem uma thread de receção que processa mensagens chegadas a
      qualquer momento (RELAY de outros peers, respostas).
    - O main loop lê comandos da consola.

Comandos:
    /login                     -- autentica-se com a chave de id_key.pem
    /users                     -- lista utilizadores e quem está online
    /chat <user>               -- inicia (ou retoma) chat E2E com peer
    /msg <user> <texto>        -- envia mensagem cifrada (faz handshake se necessário)
    /fetch                     -- vai buscar mensagens offline pendentes
    /logout                    -- termina sessão
    /quit                      -- sai
    /help                      -- ajuda

Notas de design:
    - Toda a comunicação cliente↔servidor é em TLS (canal protegido).
    - O conteúdo das mensagens entre clientes é E2E: o servidor recebe
      apenas envelopes opacos.
    - Sessões E2E são guardadas em memória, indexadas pelo peer.
    - Se receber uma mensagem de alguém com quem ainda não falamos mas
      eles iniciaram, o nosso lado atua como responder.
"""

from __future__ import annotations

import argparse
import getpass
import logging
import os
import shlex
import socket
import ssl
import sys
import threading
import time
from pathlib import Path
from queue import Queue, Empty
from typing import Any

from cryptography.hazmat.primitives.asymmetric import rsa

from common import certs, crypto_utils
from common.protocol import (
    ProtocolError,
    b64d,
    b64e,
    recv_message,
    send_message,
)
from client.session import (
    E2ESession,
    HandshakeError,
    HandshakeInitiator,
    HandshakeResponder,
)
from client.session_store import (
    PersistedSession,
    SessionStore,
    SessionStoreError,
)

logger = logging.getLogger("client")


# ============================================================
#  Estado do cliente
# ============================================================

class Client:
    def __init__(self, user_dir: Path, host: str, port: int,
                 session_password: bytes | None = None,
                 id_key_password: bytes | None = None):
        self.user_dir = user_dir
        self.host = host
        self.port = port

        # Carregar identidade do disco.
        self.username = user_dir.name
        try:
            self.id_key: rsa.RSAPrivateKey = certs.private_key_from_pem(
                (user_dir / "id_key.pem").read_bytes(),
                password=id_key_password,
            )
        except (TypeError, ValueError) as exc:
            raise ValueError(
                "Não foi possível abrir id_key.pem. "
                "A chave privada pode estar cifrada e exigir password, "
                "ou a password fornecida está errada."
            ) from exc
        self.id_cert = certs.cert_from_pem(
            (user_dir / "id_cert.pem").read_bytes()
        )
        self.id_cert_der = certs.cert_to_der(self.id_cert)
        self.ca_cert = certs.cert_from_pem(
            (user_dir / "ca_cert.pem").read_bytes()
        )

        # Sanity: verificar que o cert de id é válido contra a CA.
        certs.validate_user_certificate(self.id_cert, self.ca_cert,
                                        expected_username=self.username)

        # Persistência opcional de sessões. Se houver password, ativa-se;
        # senão, sessões só vivem em memória (mantém FS estrita).
        self.session_store: SessionStore | None = None
        if session_password is not None:
            self.session_store = SessionStore(
                base_dir=user_dir / "sessions",
                password=session_password,
            )

        # Estado de runtime.
        self.sock: ssl.SSLSocket | None = None
        self.sessions: dict[str, E2ESession] = {}     # peer_username -> sessão
        self.pending_initiators: dict[str, HandshakeInitiator] = {}
        self._pending_responders: dict[str, HandshakeResponder] = {}
        self._pending_outbox: dict[str, list[str]] = {}    # peer -> mensagens à espera de handshake
        self.sessions_lock = threading.Lock()

        # Cache de certificados de peers obtidos via GET_CERT ao servidor.
        # Serve para fazer cross-check com os certs embebidos no
        # handshake e detetar inconsistências: o cert que o servidor tem
        # registado para o peer tem de ser exatamente igual ao que vem
        # no HS_INIT/HS_REPLY. Defesa em profundidade contra um peer
        # comprometido que apresente um cert válido (assinado pela CA)
        # mas associado a outra chave.
        self._peer_cert_cache: dict[str, bytes] = {}  # username -> cert_der
        self._peer_cert_lock = threading.Lock()

        # Comunicação entre thread de receção e main thread.
        self.responses: Queue[dict[str, Any]] = Queue()
        self.recv_thread: threading.Thread | None = None
        self.shutdown_event = threading.Event()

        # Lock que serializa escritas no socket TLS. SSLSocket.sendall
        # não é thread-safe e tanto a thread de receção (que envia
        # HS_REPLY/HS_FINISH em resposta a handshakes recebidos) como a
        # main thread (comandos do utilizador) escrevem aqui.
        self._send_lock = threading.Lock()

    # ============================================================
    #  Conexão TLS
    # ============================================================

    def connect(self) -> None:
        """Estabelece ligação TLS ao servidor, validando o cert contra a CA."""
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        # Confiança: só certificados emitidos pela nossa CA local.
        ctx.load_verify_locations(cafile=str(self.user_dir / "ca_cert.pem"))
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.check_hostname = True

        raw = socket.create_connection((self.host, self.port))
        # check_hostname valida contra os SANs do cert do servidor.
        self.sock = ctx.wrap_socket(raw, server_hostname=self.host)
        logger.info("Ligação TLS estabelecida a %s:%d", self.host, self.port)

    def disconnect(self) -> None:
        if self.sock is not None:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None

    # ============================================================
    #  Autenticação (challenge-response)
    # ============================================================

    def login(self) -> None:
        assert self.sock is not None

        self._send({"type": "LOGIN_INIT", "username": self.username})
        challenge = recv_message(self.sock)

        if challenge["type"] != "CHALLENGE":
            raise RuntimeError(f"Esperava CHALLENGE, recebi: {challenge}")

        nonce = b64d(challenge["nonce_b64"])
        to_sign = b"ssi-chat-login|" + self.username.encode() + b"|" + nonce
        signature = crypto_utils.sign_rsa(self.id_key, to_sign)

        self._send({
            "type": "LOGIN_RESPONSE",
            "signature_b64": b64e(signature),
        })

        result = recv_message(self.sock)
        if result["type"] != "OK":
            raise RuntimeError(f"Login falhou: {result.get('message')}")
        print(f"[OK] Login feito como {self.username}.")

    # ============================================================
    #  Thread de receção
    # ============================================================

    def start_recv_thread(self) -> None:
        self.recv_thread = threading.Thread(
            target=self._recv_loop, name="recv", daemon=True
        )
        self.recv_thread.start()

    def _recv_loop(self) -> None:
        assert self.sock is not None
        while not self.shutdown_event.is_set():
            try:
                msg = recv_message(self.sock)
            except (EOFError, ConnectionError, OSError):
                break
            except ProtocolError as exc:
                print(f"\n[ERRO] Frame inválido do servidor: {exc}")
                break

            self._dispatch_incoming(msg)

        self.shutdown_event.set()

    def _dispatch_incoming(self, msg: dict[str, Any]) -> None:
        """
        Decide o que fazer com uma mensagem que chegou.

        Mensagens que são respostas a comandos (OK, ERROR, USERS,
        MESSAGES, CERT, PONG) vão para a fila para o main thread tratar.

        Mensagens DELIVERY são tratadas aqui mesmo (handshake ou chat).
        """
        msg_type = msg.get("type")
        if msg_type == "DELIVERY":
            self._handle_delivery(msg)
        else:
            self.responses.put(msg)

    def _handle_delivery(self, msg: dict[str, Any]) -> None:
        sender = msg.get("from")
        envelope = msg.get("envelope") or {}
        kind = envelope.get("kind")

        if not isinstance(sender, str):
            return

        if kind == "HANDSHAKE":
            self._handle_handshake_envelope(sender, envelope)
        elif kind == "MESSAGE":
            self._handle_chat_envelope(sender, envelope)
        else:
            print(f"\n[?] Envelope desconhecido de {sender}: kind={kind}")

    # --------- Handshake ---------

    def _handle_handshake_envelope(self, sender: str, env: dict) -> None:
        sub = env.get("subkind")

        # Cross-check local: o servidor entrega o remetente autenticado no
        # campo externo DELIVERY.from. O envelope de handshake também inclui
        # from/to. Estes valores têm de bater certo; caso contrário poderia
        # haver identity misbinding ou uma mensagem RELAY mal encaminhada.
        if env.get("from") != sender or env.get("to") != self.username:
            print(
                f"\n[ERRO HANDSHAKE com {sender}] "
                "from/to inconsistentes no envelope "
                f"(outer_from={sender!r}, inner_from={env.get('from')!r}, "
                f"inner_to={env.get('to')!r}, eu={self.username!r})."
            )
            return

        try:
            if sub == "HS_INIT":
                self._handle_hs_init(sender, env)
            elif sub == "HS_REPLY":
                self._handle_hs_reply(sender, env)
            elif sub == "HS_FINISH":
                self._handle_hs_finish(sender, env)
            else:
                print(f"\n[?] Subkind de handshake desconhecido: {sub}")
        except HandshakeError as exc:
            print(f"\n[ERRO HANDSHAKE com {sender}] {exc}")

    def _handle_hs_init(self, sender: str, env: dict) -> None:
        responder = HandshakeResponder(self.username, self.id_key, self.ca_cert)
        reply = responder.process_init_and_reply(env, self.id_cert_der)
        # Guardar o responder como "pending" para finalizar quando chegar HS_FINISH.
        with self.sessions_lock:
            self._pending_responders[sender] = responder
        self._send_relay(sender, reply)
        print(f"\n[INFO] {sender} iniciou um chat. À espera de finalizar handshake...")

    def _handle_hs_reply(self, sender: str, env: dict) -> None:
        with self.sessions_lock:
            initiator = self.pending_initiators.pop(sender, None)
        if initiator is None:
            print(f"\n[ERRO] HS_REPLY de {sender} sem handshake pendente.")
            return
        finish = initiator.process_reply_and_finish(env, self.id_cert_der)
        # Ativar sessão.
        with self.sessions_lock:
            self.sessions[sender] = initiator.session  # type: ignore[assignment]
        self._persist_session(sender)
        self._send_relay(sender, finish)
        print(f"\n[OK] Sessão E2E estabelecida com {sender}.")
        self._flush_pending_outbox(sender)

    def _handle_hs_finish(self, sender: str, env: dict) -> None:
        with self.sessions_lock:
            responder = self._pending_responders.pop(sender, None)
        if responder is None:
            print(f"\n[ERRO] HS_FINISH de {sender} sem responder pendente.")
            return
        responder.process_finish(env)
        with self.sessions_lock:
            self.sessions[sender] = responder.session  # type: ignore[assignment]
        self._persist_session(sender)
        print(f"\n[OK] Sessão E2E estabelecida com {sender}.")

    # --------- Mensagens de chat ---------

    def _handle_chat_envelope(self, sender: str, env: dict) -> None:
        with self.sessions_lock:
            session = self.sessions.get(sender)
        if session is None:
            print(f"\n[ERRO] Mensagem de {sender} mas sem sessão estabelecida. "
                  f"(Talvez precises de /chat {sender} para iniciar handshake.)")
            return
        try:
            plaintext = session.decrypt(env, expected_sender=sender,
                                        my_username=self.username)
        except Exception as exc:
            print(f"\n[ERRO DECIFRA com {sender}] {exc}")
            return
        # Atualizar contador no disco — recv_seq mudou.
        self._persist_session(sender)
        text = plaintext.decode("utf-8", errors="replace")
        print(f"\n[{sender}] {text}\nssi-chat> ", end="", flush=True)

    # ============================================================
    #  Outbox (mensagens em espera por handshake terminar)
    # ============================================================

    def _flush_pending_outbox(self, peer: str) -> None:
        pending = self._pending_outbox.pop(peer, [])
        if not pending:
            return
        print(f"[INFO] A enviar {len(pending)} mensagem(ns) pendente(s) para {peer}.")
        for text in pending:
            self._send_chat_message(peer, text)

    # ============================================================
    #  Persistência local de sessões (opcional)
    # ============================================================

    def _persist_session(self, peer: str) -> None:
        """
        Se a persistência estiver ativa, escreve o snapshot da sessão
        atual para o disco (cifrado com a password do utilizador).

        Chamado depois de cada operação que muda o estado da sessão
        (criação, encrypt, decrypt). Falhas são logadas mas não
        interrompem o fluxo — perder uma escrita é menos mau do que
        falhar a operação de chat.
        """
        if self.session_store is None:
            return
        with self.sessions_lock:
            sess = self.sessions.get(peer)
            if sess is None:
                return
            with sess.lock:
                snapshot = PersistedSession(
                    peer_username=sess.peer_username,
                    conversation_id=sess.conversation_id,
                    send_key=sess.keys.send_key,
                    recv_key=sess.keys.recv_key,
                    send_seq=sess.send_seq,
                    recv_seq=sess.recv_seq,
                )
        try:
            self.session_store.save(snapshot)
        except Exception as exc:
            logger.warning("Falha a persistir sessão de %s: %s", peer, exc)

    def _load_persisted_sessions(self) -> None:
        """
        Restaura sessões cifradas em disco (se houver) para o dicionário
        em memória. Chamado uma vez depois do login.
        """
        if self.session_store is None:
            return
        try:
            persisted = self.session_store.load_all()
        except Exception as exc:
            print(f"[ERRO] Falha a carregar sessões persistidas: {exc}")
            return
        if not persisted:
            return

        for peer, ps in persisted.items():
            session = E2ESession(
                peer_username=ps.peer_username,
                conversation_id=ps.conversation_id,
                keys=crypto_utils.SessionKeys(
                    send_key=ps.send_key,
                    recv_key=ps.recv_key,
                ),
                send_seq=ps.send_seq,
                recv_seq=ps.recv_seq,
            )
            with self.sessions_lock:
                self.sessions[peer] = session
        print(f"[INFO] Restauradas {len(persisted)} sessão(ões) cifrada(s) do disco.")

    # ============================================================
    #  Comandos
    # ============================================================

    def cmd_users(self) -> None:
        self._send({"type": "LIST_USERS"})
        resp = self._await_response(expected_types=("USERS",))
        if resp["type"] != "USERS":
            print(f"[ERRO] {resp.get('message', resp)}")
            return
        users = resp.get("users", [])
        online = set(resp.get("online", []))
        print("[UTILIZADORES]")
        for u in users:
            tag = " (online)" if u in online else ""
            print(f"  - {u}{tag}")

    def cmd_chat(self, peer: str) -> None:
        """Inicia handshake com um peer (se não houver sessão ativa)."""
        if peer == self.username:
            print("[ERRO] Não podes iniciar chat contigo mesmo.")
            return
        with self.sessions_lock:
            if peer in self.sessions:
                print(f"[INFO] Já há sessão ativa com {peer}.")
                return
            if peer in self.pending_initiators:
                print(f"[INFO] Já há handshake em curso com {peer}.")
                return

        # Antes de iniciar o handshake, vamos buscar o cert do peer ao
        # servidor. Vai ser usado mais tarde no process_reply_and_finish
        # para fazer cross-check com o cert que vem dentro do HS_REPLY.
        try:
            peer_cert_der = self._fetch_peer_cert(peer)
        except Exception as exc:
            print(f"[ERRO] Falhou GET_CERT para {peer!r}: {exc}")
            return

        # Vamos iniciar.
        initiator = HandshakeInitiator(
            self.username, self.id_key, peer, self.ca_cert,
            expected_peer_cert_der=peer_cert_der,
        )
        init_msg = initiator.build_init(self.id_cert_der)
        with self.sessions_lock:
            self.pending_initiators[peer] = initiator
        self._send_relay(peer, init_msg)
        print(f"[INFO] Handshake iniciado com {peer}.")

    def cmd_msg(self, peer: str, text: str) -> None:
        """Envia mensagem cifrada para peer. Faz handshake automaticamente se necessário."""
        if peer == self.username:
            print("[ERRO] Não podes enviar mensagens a ti próprio.")
            return

        with self.sessions_lock:
            session = self.sessions.get(peer)

        if session is None:
            # Iniciar handshake e meter a mensagem em outbox para enviar quando ficar pronto.
            print(f"[INFO] Sem sessão com {peer}; a iniciar handshake primeiro...")
            self._pending_outbox.setdefault(peer, []).append(text)
            self.cmd_chat(peer)
            return

        self._send_chat_message(peer, text)

    def _send_chat_message(self, peer: str, text: str) -> None:
        with self.sessions_lock:
            session = self.sessions.get(peer)
        if session is None:
            print(f"[ERRO] Sessão com {peer} desapareceu.")
            return
        envelope = session.encrypt(text.encode("utf-8"), my_username=self.username)
        # send_seq foi incrementado dentro do encrypt — atualizar disco.
        self._persist_session(peer)
        self._send_relay(peer, envelope)
        # Esperar OK do servidor (entregue ou guardado offline).
        resp = self._await_response()
        if resp["type"] == "OK":
            print(f"[OK] -> {peer}: {resp.get('message','')}")
        else:
            print(f"[ERRO] {resp}")

    def cmd_fetch(self) -> None:
        self._send({"type": "FETCH"})
        resp = self._await_response(expected_types=("MESSAGES",))
        if resp["type"] != "MESSAGES":
            print(f"[ERRO] {resp}")
            return
        items = resp.get("items", [])
        if not items:
            print("[INFO] Sem mensagens pendentes.")
            return
        print(f"[INFO] {len(items)} envelope(s) pendente(s):")
        for it in items:
            sender = it.get("from", "?")
            envelope = it.get("envelope") or {}
            kind = envelope.get("kind")
            if kind == "HANDSHAKE":
                self._handle_handshake_envelope(sender, envelope)
            elif kind == "MESSAGE":
                self._handle_chat_envelope(sender, envelope)
            else:
                print(f"  [?] envelope desconhecido de {sender}")

    def cmd_logout(self) -> None:
        self._send({"type": "LOGOUT"})
        resp = self._await_response()
        print(f"[INFO] {resp.get('message', '')}")

    def cmd_ping(self) -> None:
        self._send({"type": "PING"})
        resp = self._await_response()
        print(f"[INFO] {resp}")

    # ============================================================
    #  Helpers
    # ============================================================

    def _send(self, message: dict[str, Any]) -> None:
        """
        Envia uma mensagem para o servidor de forma thread-safe.

        SSLSocket.sendall não é thread-safe e há dois produtores
        possíveis (thread de receção a responder a handshakes, e main
        thread a executar comandos do utilizador). O lock garante que
        cada frame chega ao servidor inteiro e sem interleaving.
        """
        with self._send_lock:
            send_message(self.sock, message)

    def _send_relay(self, to: str, envelope: dict) -> None:
        self._send({"type": "RELAY", "to": to, "envelope": envelope})

    def _fetch_peer_cert(self, peer: str) -> bytes:
        """
        Pede ao servidor o cert registado para 'peer', valida-o contra
        a CA, guarda em cache e devolve o DER.

        Usar isto na main thread; usa _send + _await_response e pode
        levantar exceções se o servidor não devolver CERT ou se o cert
        não validar contra a CA.
        """
        with self._peer_cert_lock:
            cached = self._peer_cert_cache.get(peer)
            if cached is not None:
                return cached

        self._send({"type": "GET_CERT", "username": peer})
        resp = self._await_response(expected_types=("CERT",))
        if resp.get("type") != "CERT":
            raise RuntimeError(
                f"Não foi possível obter cert de {peer!r}: {resp.get('message', resp)}"
            )
        cert_der = b64d(resp["cert_b64"])
        # Validar contra a CA — defesa contra um servidor a entregar
        # certs de outra CA ou mal formados.
        cert_obj = certs.cert_from_der(cert_der)
        certs.validate_user_certificate(cert_obj, self.ca_cert,
                                        expected_username=peer)

        with self._peer_cert_lock:
            self._peer_cert_cache[peer] = cert_der
        return cert_der

    def _await_response(self, expected_types: tuple[str, ...] = (),
                        timeout: float = 10.0) -> dict[str, Any]:
        """
        Espera por uma resposta. Se 'expected_types' for fornecido,
        ignora respostas de outros tipos (mas devolve OK/ERROR sempre).

        Isto é necessário porque a fila de respostas pode misturar
        OKs de comandos diferentes que estão em voo em paralelo.
        """
        deadline = time.monotonic() + timeout
        ignored: list[dict[str, Any]] = []
        try:
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return {"type": "ERROR", "message": "Timeout."}
                resp = self.responses.get(timeout=remaining)
                t = resp.get("type")
                # Erros e OKs genéricos passam sempre.
                if t in ("ERROR",) or not expected_types:
                    return resp
                if t in expected_types:
                    return resp
                # Não é o que queríamos — guardar para mais tarde.
                ignored.append(resp)
        finally:
            # Repor as respostas que não eram para nós.
            for r in ignored:
                self.responses.put(r)

    # ============================================================
    #  REPL
    # ============================================================

    def run_repl(self) -> None:
        print_help()
        while True:
            try:
                line = input("ssi-chat> ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                break
            if not line:
                continue
            try:
                parts = shlex.split(line)
            except ValueError as exc:
                print(f"[ERRO] {exc}")
                continue

            cmd = parts[0]
            args = parts[1:]

            if cmd in ("/quit", "/exit"):
                break
            elif cmd == "/help":
                print_help()
            elif cmd == "/users":
                self.cmd_users()
            elif cmd == "/chat":
                if len(args) != 1:
                    print("Uso: /chat <user>")
                    continue
                self.cmd_chat(args[0])
            elif cmd == "/msg":
                if len(args) < 2:
                    print("Uso: /msg <user> <texto>")
                    continue
                peer = args[0]
                text = " ".join(args[1:])
                self.cmd_msg(peer, text)
            elif cmd == "/fetch":
                self.cmd_fetch()
            elif cmd == "/logout":
                self.cmd_logout()
                break
            elif cmd == "/ping":
                self.cmd_ping()
            else:
                print(f"[ERRO] Comando desconhecido: {cmd}. Usa /help.")


def print_help() -> None:
    print("""
Comandos disponíveis:
  /users                 Lista utilizadores enrolled e quem está online.
  /chat <user>           Inicia handshake E2E com um peer (preparatório).
  /msg <user> <texto>    Envia mensagem cifrada (faz handshake se necessário).
  /fetch                 Vai buscar mensagens offline pendentes.
  /ping                  Testa a ligação ao servidor.
  /logout                Termina sessão e sai.
  /quit                  Sai sem logout explícito.
  /help                  Mostra esta ajuda.
""".strip())


# ============================================================
#  Entrada
# ============================================================

def main() -> int:
    parser = argparse.ArgumentParser(description="ssi-chat client")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--user-dir", required=True,
                        help="Diretoria com id_key.pem, id_cert.pem, ca_cert.pem.")
    parser.add_argument("--persist-sessions", action="store_true",
                        help="Persistir sessões E2E em disco, cifradas com password "
                             "(prompt interativo). Recupera conversas a seguir a um "
                             "restart do cliente, sacrificando forward secrecy entre "
                             "sessões do mesmo cliente.")
    parser.add_argument("--id-key-password-env", default="SSI_ID_KEY_PASSWORD",
                        help="Variável de ambiente com a password da chave privada "
                             "do utilizador. Se não estiver definida, a password é "
                             "pedida interativamente.")
    parser.add_argument("--legacy-unencrypted-id-key", action="store_true",
                        help="Modo de compatibilidade para chaves antigas sem password. "
                             "Não recomendado para entrega final.")
    parser.add_argument("--log-level", default="WARNING",
                        choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    user_dir = Path(args.user_dir)
    if not user_dir.exists():
        print(f"[ERRO] {user_dir} não existe.", file=sys.stderr)
        return 1

    id_key_password: bytes | None = None
    if not args.legacy_unencrypted_id_key:
        env_pw = os.environ.get(args.id_key_password_env)
        if env_pw is not None:
            if not env_pw:
                print(f"[ERRO] Variável {args.id_key_password_env} está vazia.",
                      file=sys.stderr)
                return 1
            id_key_password = env_pw.encode("utf-8")
        else:
            pw = getpass.getpass(f"Password da chave privada de {user_dir.name}: ")
            if not pw:
                print("[ERRO] Password vazia.", file=sys.stderr)
                return 1
            id_key_password = pw.encode("utf-8")

    session_password: bytes | None = None
    if args.persist_sessions:
        pw = getpass.getpass(f"Password para sessões persistidas de {user_dir.name}: ")
        if not pw:
            print("[ERRO] Password vazia.", file=sys.stderr)
            return 1
        session_password = pw.encode("utf-8")
        print("[INFO] Persistência local de sessões ATIVADA.")
        print("       Aviso: trade-off — perde-se FS entre sessões do mesmo cliente.")

    # Cada instância tem o seu estado.
    try:
        client = Client(user_dir, args.host, args.port,
                        session_password=session_password,
                        id_key_password=id_key_password)
    except ValueError as exc:
        print(f"[ERRO] {exc}", file=sys.stderr)
        return 1

    try:
        client.connect()
    except (ssl.SSLError, ConnectionError, OSError) as exc:
        print(f"[ERRO] Não consegui ligar: {exc}", file=sys.stderr)
        return 1

    try:
        client.login()
    except Exception as exc:
        print(f"[ERRO] Login falhou: {exc}", file=sys.stderr)
        client.disconnect()
        return 1

    # Restaurar sessões persistidas (se houver password).
    client._load_persisted_sessions()

    client.start_recv_thread()
    try:
        client.run_repl()
    finally:
        client.shutdown_event.set()
        client.disconnect()

    return 0


if __name__ == "__main__":
    sys.exit(main())