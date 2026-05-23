"""
Servidor central do ssi-chat.

Responsabilidades:
    - Aceitar ligações TLS de clientes (canal cliente↔servidor protegido).
    - Autenticar cada utilizador por challenge-response assinado com a sua
      chave privada (que corresponde ao seu certificado emitido pela CA).
    - Manter a lista de utilizadores online.
    - Encaminhar pedidos de certificados públicos (para o handshake E2E).
    - Encaminhar mensagens E2E entre clientes (online ou offline).
    - Armazenar mensagens offline como ciphertexts opacos. O servidor
      NUNCA tem material que lhe permita decifrar.

Modelo de ameaça implementado:
    - Servidor honesto-mas-curioso: pode ler tudo o que recebe, mas E2E
      garante que o conteúdo está cifrado de ponta a ponta.
    - Atacante ativo na rede: bloqueado pelo TLS no canal cliente↔servidor
      e pelo handshake STS autenticado entre clientes.
    - Replay e adulteração no encaminhamento: o servidor pode tentar mas
      o AAD do AES-GCM de cada mensagem inclui seq_no, ids dos peers e
      conversation_id, pelo que qualquer manipulação faz a decifragem
      falhar no destinatário.
"""

from __future__ import annotations

import argparse
import logging
import socket
import ssl
import sys
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography import x509

from common import certs, crypto_utils
from common.protocol import (
    ProtocolError,
    b64d,
    b64e,
    recv_message,
    send_message,
)
from server.persistence import MailboxStore

logger = logging.getLogger("server")


# ============================================================
#  Estado do servidor
# ============================================================

@dataclass
class EnrolledUser:
    """Utilizador que existe no sistema (tem certificado emitido)."""
    username: str
    cert: x509.Certificate
    cert_der: bytes


@dataclass
class OfflineMessage:
    """Mensagem cifrada à espera de ser entregue."""
    sender: str
    recipient: str
    payload: dict[str, Any]   # conteúdo opaco para o servidor


@dataclass
class ServerState:
    """Estado partilhado entre threads. Acesso protegido por lock."""
    ca_cert: x509.Certificate
    mailbox_store: MailboxStore
    users: dict[str, EnrolledUser] = field(default_factory=dict)
    online: dict[str, "ClientSession"] = field(default_factory=dict)
    mailboxes: dict[str, list[OfflineMessage]] = field(default_factory=dict)
    lock: threading.Lock = field(default_factory=threading.Lock)

    def persist_mailbox(self, recipient: str) -> None:
        """
        Reescreve no disco a mailbox deste destinatário a partir do
        estado em memória. Chamado já com self.lock seguro.
        """
        items = [
            {"sender": m.sender, "envelope": m.payload}
            for m in self.mailboxes.get(recipient, [])
        ]
        try:
            self.mailbox_store.write_all_for(recipient, items)
        except Exception as exc:
            logger.exception("Falha a persistir mailbox de %s: %s", recipient, exc)


# ============================================================
#  Sessão por cliente
# ============================================================

class ClientSession:
    """
    Lida com uma ligação TLS de um cliente, do início ao fim.

    Estados internos:
        - antes do login: aceita REGISTER (no-op aqui, o utilizador já
          foi enrollado offline) e LOGIN_INIT/LOGIN_RESPONSE.
        - depois do login: aceita os comandos normais.
    """

    def __init__(self, sock: ssl.SSLSocket, addr: tuple[str, int], state: ServerState):
        self.sock = sock
        self.addr = addr
        self.state = state
        self.username: str | None = None    # None enquanto não autenticado
        self.pending_challenge: bytes | None = None
        self._candidate_username: str | None = None
        self._send_lock = threading.Lock()  # send_message não é thread-safe

    # --------- I/O sincronizado ---------

    def send(self, msg: dict[str, Any]) -> None:
        """Envia uma mensagem ao cliente. Thread-safe."""
        with self._send_lock:
            send_message(self.sock, msg)

    def send_ok(self, message: str = "", **extra: Any) -> None:
        self.send({"type": "OK", "message": message, **extra})

    def send_error(self, message: str) -> None:
        self.send({"type": "ERROR", "message": message})

    # --------- Loop principal ---------

    def run(self) -> None:
        peer = f"{self.addr[0]}:{self.addr[1]}"
        logger.info("Cliente ligado: %s", peer)

        try:
            while True:
                try:
                    msg = recv_message(self.sock)
                except (EOFError, ConnectionError):
                    break
                except ProtocolError as exc:
                    logger.warning("Protocolo inválido de %s: %s", peer, exc)
                    self.send_error(f"Protocolo inválido: {exc}")
                    break

                try:
                    self._handle(msg)
                except ProtocolError as exc:
                    self.send_error(f"Mensagem inválida: {exc}")
                except Exception as exc:    # nunca deixar uma exceção matar o servidor
                    logger.exception("Erro a tratar mensagem de %s: %s", peer, exc)
                    self.send_error("Erro interno.")

        finally:
            self._cleanup()
            try:
                self.sock.close()
            except Exception:
                pass
            logger.info("Cliente desligado: %s (%s)", peer, self.username or "?")

    # --------- Despacho ---------

    def _handle(self, msg: dict[str, Any]) -> None:
        msg_type = msg["type"]

        # Antes do login só certas mensagens são permitidas.
        if self.username is None:
            if msg_type == "PING":
                self.send({"type": "PONG"})
                return
            if msg_type == "LOGIN_INIT":
                self._handle_login_init(msg)
                return
            if msg_type == "LOGIN_RESPONSE":
                self._handle_login_response(msg)
                return
            self.send_error("Tem de fazer login primeiro.")
            return

        # Já autenticado.
        if msg_type == "PING":
            self.send({"type": "PONG"})
        elif msg_type == "LIST_USERS":
            self._handle_list_users()
        elif msg_type == "GET_CERT":
            self._handle_get_cert(msg)
        elif msg_type == "RELAY":
            self._handle_relay(msg)
        elif msg_type == "FETCH":
            self._handle_fetch()
        elif msg_type == "LOGOUT":
            self._handle_logout()
        else:
            self.send_error(f"Tipo de mensagem desconhecido: {msg_type}")

    # ============================================================
    #  Autenticação (challenge-response assinado)
    # ============================================================
    #
    # 1. Cliente envia LOGIN_INIT { username }
    # 2. Servidor verifica que o utilizador existe, gera um nonce de 32
    #    bytes, guarda-o, e responde com CHALLENGE { nonce_b64 }.
    # 3. Cliente assina com a sua chave privada o tuple
    #       b"ssi-chat-login|" + username + "|" + nonce
    #    e envia LOGIN_RESPONSE { signature_b64 }.
    # 4. Servidor verifica a assinatura usando a chave pública do
    #    certificado do utilizador. Se OK, marca como online.

    _LOGIN_PREFIX = b"ssi-chat-login|"

    def _handle_login_init(self, msg: dict[str, Any]) -> None:
        username = msg.get("username")
        if not isinstance(username, str) or not username:
            self.send_error("Campo 'username' inválido.")
            return

        with self.state.lock:
            user = self.state.users.get(username)

        if user is None:
            self.send_error(f"Utilizador {username!r} não existe. (Tem de ser enrollado primeiro.)")
            return

        # Gerar nonce e guardar.
        nonce = crypto_utils.random_bytes(32)
        self.pending_challenge = nonce
        # Guardamos o username candidato para o LOGIN_RESPONSE.
        self._candidate_username = username

        self.send({"type": "CHALLENGE", "nonce_b64": b64e(nonce)})

    def _handle_login_response(self, msg: dict[str, Any]) -> None:
        if self.pending_challenge is None:
            self.send_error("Não há challenge pendente.")
            return

        sig_b64 = msg.get("signature_b64")
        if not isinstance(sig_b64, str):
            self.send_error("Falta 'signature_b64'.")
            return

        signature = b64d(sig_b64)
        username = self._candidate_username
        if username is None:
            self.send_error("Não há utilizador candidato para este challenge.")
            return

        with self.state.lock:
            user = self.state.users.get(username)
        if user is None:
            self.send_error("Utilizador desapareceu.")
            return

        # Construir o que o cliente devia ter assinado.
        to_verify = self._LOGIN_PREFIX + username.encode() + b"|" + self.pending_challenge

        public_key = user.cert.public_key()
        if not crypto_utils.verify_rsa(public_key, signature, to_verify):
            logger.warning("LOGIN falhado para %s: assinatura inválida.", username)
            # Limpa estado para evitar ataques de tentativa repetida com o mesmo nonce.
            self.pending_challenge = None
            self._candidate_username = None
            self.send_error("Assinatura inválida.")
            return

        # Sucesso. Marcar como online (substituindo qualquer sessão anterior do mesmo user).
        with self.state.lock:
            previous = self.state.online.get(username)
            self.state.online[username] = self
        if previous is not None and previous is not self:
            try:
                previous.send_error("Foste desligado: outra sessão fez login.")
                previous.sock.close()
            except Exception:
                pass

        self.username = username
        self.pending_challenge = None
        self._candidate_username = None
        logger.info("LOGIN OK: %s (%s:%d)", username, *self.addr)
        self.send_ok(f"Login bem-sucedido como {username}.")

    # ============================================================
    #  Comandos pós-login
    # ============================================================

    def _handle_list_users(self) -> None:
        with self.state.lock:
            users = sorted(self.state.users.keys())
            online = sorted(self.state.online.keys())
        self.send({"type": "USERS", "users": users, "online": online})

    def _handle_get_cert(self, msg: dict[str, Any]) -> None:
        target = msg.get("username")
        if not isinstance(target, str):
            self.send_error("Campo 'username' inválido.")
            return

        with self.state.lock:
            user = self.state.users.get(target)
        if user is None:
            self.send_error(f"Utilizador {target!r} não existe.")
            return

        self.send({
            "type": "CERT",
            "username": target,
            "cert_b64": b64e(user.cert_der),
        })

    def _handle_relay(self, msg: dict[str, Any]) -> None:
        """
        Encaminha uma mensagem para outro utilizador.

        O conteúdo de 'envelope' é opaco para o servidor. Tipicamente
        contém:
            - kind: "HANDSHAKE" ou "MESSAGE"
            - subkind, dh_pub_b64, signature_b64, cert_b64 (handshake)
            - conversation_id, seq_no, nonce_b64, ciphertext_b64,
              aad_b64 (mensagens cifradas)

        O servidor só lê o destinatário e empacota tudo o resto como está.
        """
        to = msg.get("to")
        envelope = msg.get("envelope")
        if not isinstance(to, str) or not isinstance(envelope, dict):
            self.send_error("Pedido RELAY inválido.")
            return

        with self.state.lock:
            if to not in self.state.users:
                self.send_error(f"Destinatário {to!r} não existe.")
                return
            sender_user = self.state.users.get(self.username or "")
            target_session = self.state.online.get(to)

        if sender_user is None:
            self.send_error("Sessão autenticada sem utilizador registado.")
            return

        relay_error = self._validate_relay_envelope(to, envelope, sender_user)
        if relay_error is not None:
            self.send_error(relay_error)
            return

        outbound = {
            "type": "DELIVERY",
            "from": self.username,
            "envelope": envelope,
        }

        if target_session is not None:
            try:
                target_session.send(outbound)
                self.send_ok("Entregue.")
                return
            except Exception as exc:
                logger.warning("Falha a entregar online para %s: %s — vai para offline.", to, exc)
                # Sessão morta mas ainda no mapa: limpar.
                with self.state.lock:
                    if self.state.online.get(to) is target_session:
                        del self.state.online[to]
                # cai para offline storage

        # Offline ou falhou — guardar.
        with self.state.lock:
            self.state.mailboxes.setdefault(to, []).append(
                OfflineMessage(sender=self.username or "?", recipient=to, payload=envelope)
            )
            # Persistir a mailbox em disco — sobrevive a reinicio do servidor.
            self.state.persist_mailbox(to)
        self.send_ok("Guardado para entrega offline.")

    def _validate_relay_envelope(self, to: str, envelope: dict[str, Any],
                                 sender_user: EnrolledUser) -> str | None:
        """
        Validação mínima do envelope antes de o servidor o encaminhar.

        O conteúdo das mensagens MESSAGE continua opaco. Para HANDSHAKE,
        porém, os campos from/to/cert são metadados de identidade: devem
        bater certo com o utilizador autenticado que está a fazer RELAY e
        com o destinatário escolhido. Isto evita identity misbinding e
        impede que um cliente apresente um certificado diferente do que
        está registado no servidor para o seu username.
        """
        kind = envelope.get("kind")
        if kind != "HANDSHAKE":
            return None

        subkind = envelope.get("subkind")
        if subkind not in {"HS_INIT", "HS_REPLY", "HS_FINISH"}:
            return f"Handshake inválido: subkind desconhecido {subkind!r}."

        if envelope.get("from") != self.username:
            return (
                "Handshake inválido: campo 'from' do envelope não corresponde "
                "ao utilizador autenticado."
            )
        if envelope.get("to") != to:
            return (
                "Handshake inválido: campo 'to' do envelope não corresponde "
                "ao destinatário do RELAY."
            )

        cert_b64 = envelope.get("cert_b64")
        if not isinstance(cert_b64, str):
            return "Handshake inválido: falta cert_b64 textual."
        try:
            cert_der = b64d(cert_b64)
        except ProtocolError:
            return "Handshake inválido: cert_b64 não é base64 válido."

        if cert_der != sender_user.cert_der:
            return (
                "Handshake inválido: certificado anunciado não corresponde "
                "ao certificado registado para o utilizador autenticado."
            )

        return None

    def _handle_fetch(self) -> None:
        """Devolve mensagens offline pendentes para este utilizador."""
        assert self.username is not None
        with self.state.lock:
            messages = self.state.mailboxes.pop(self.username, [])
            # Persistir vazio = apagar do disco (utilizador já as tem).
            self.state.persist_mailbox(self.username)

        items = [
            {"from": m.sender, "envelope": m.payload}
            for m in messages
        ]
        self.send({"type": "MESSAGES", "items": items})

    def _handle_logout(self) -> None:
        with self.state.lock:
            if self.username and self.state.online.get(self.username) is self:
                del self.state.online[self.username]
        self.username = None
        self.send_ok("Sessão terminada.")

    # ============================================================
    #  Limpeza
    # ============================================================

    def _cleanup(self) -> None:
        with self.state.lock:
            if self.username and self.state.online.get(self.username) is self:
                del self.state.online[self.username]


# ============================================================
#  Inicialização
# ============================================================

def load_enrolled_users(data_dir: Path, ca_cert: x509.Certificate) -> dict[str, EnrolledUser]:
    """
    Carrega da pasta data/users/ todos os utilizadores enrollados.

    Para cada subpasta, carrega o certificado, valida-o contra a CA,
    e regista-o.
    """
    users: dict[str, EnrolledUser] = {}
    users_dir = data_dir / "users"
    if not users_dir.exists():
        logger.warning("Sem utilizadores enrollados em %s.", users_dir)
        return users

    for entry in sorted(users_dir.iterdir()):
        if not entry.is_dir():
            continue
        cert_path = entry / "id_cert.pem"
        if not cert_path.exists():
            continue

        cert = certs.cert_from_pem(cert_path.read_bytes())
        try:
            identity = certs.validate_user_certificate(cert, ca_cert, expected_username=entry.name)
        except certs.CertificateValidationError as exc:
            logger.warning("Certificado inválido para %s: %s", entry.name, exc)
            continue

        users[identity.username] = EnrolledUser(
            username=identity.username,
            cert=cert,
            cert_der=certs.cert_to_der(cert),
        )

    return users


def make_tls_context(server_cert_path: Path, server_key_path: Path,
                     ca_cert_path: Path) -> ssl.SSLContext:
    """
    Constrói o SSLContext para o servidor.

    Não pedimos certificado ao cliente em TLS (mTLS) porque a autenticação
    do utilizador é feita por challenge-response na camada de aplicação
    — assim ainda mostramos no projeto a parte de challenge-response da
    matéria. (Em produção poderíamos usar mTLS para tudo.)
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile=str(server_cert_path), keyfile=str(server_key_path))
    # Cargar CA é opcional para o servidor (não pedimos cert do cliente).
    return ctx


def serve(host: str, port: int, data_dir: Path) -> None:
    ca_cert_path = data_dir / "ca" / "ca_cert.pem"
    server_cert = data_dir / "server" / "tls_cert.pem"
    server_key = data_dir / "server" / "tls_key.pem"

    if not ca_cert_path.exists():
        print("[ERRO] CA não inicializada. Corre 'python -m scripts.init_ca' primeiro.",
              file=sys.stderr)
        sys.exit(1)
    if not server_cert.exists():
        print("[ERRO] Certificado TLS do servidor não emitido. "
              "Corre 'python -m scripts.issue_server_cert'.",
              file=sys.stderr)
        sys.exit(1)

    ca_cert = certs.cert_from_pem(ca_cert_path.read_bytes())
    mailbox_store = MailboxStore(data_dir / "server" / "mailboxes")
    state = ServerState(ca_cert=ca_cert, mailbox_store=mailbox_store)
    state.users = load_enrolled_users(data_dir, ca_cert)
    logger.info("Carregados %d utilizadores enrollados.", len(state.users))

    # Carregar mailboxes pendentes do disco. Sobrevive a reinício.
    persisted = mailbox_store.load_all()
    restored_count = 0
    for recipient, items in persisted.items():
        if recipient not in state.users:
            logger.warning("Mailbox encontrada para utilizador desconhecido %r — a ignorar.",
                           recipient)
            continue
        state.mailboxes[recipient] = [
            OfflineMessage(
                sender=str(it.get("sender", "?")),
                recipient=recipient,
                payload=it.get("envelope") or {},
            )
            for it in items
        ]
        restored_count += len(state.mailboxes[recipient])
    if restored_count:
        logger.info("Restauradas %d mensagem(ns) offline do disco.", restored_count)

    tls_ctx = make_tls_context(server_cert, server_key, ca_cert_path)

    raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    raw_sock.bind((host, port))
    raw_sock.listen(16)

    logger.info("ssi-chat server à escuta em %s:%d (TLS)", host, port)

    try:
        while True:
            try:
                client_sock, addr = raw_sock.accept()
            except OSError:
                break

            try:
                tls_sock = tls_ctx.wrap_socket(client_sock, server_side=True)
            except ssl.SSLError as exc:
                logger.warning("Handshake TLS falhou de %s: %s", addr, exc)
                client_sock.close()
                continue

            session = ClientSession(tls_sock, addr, state)
            t = threading.Thread(target=session.run, name=f"client-{addr[1]}", daemon=True)
            t.start()
    except KeyboardInterrupt:
        logger.info("A terminar (Ctrl-C)...")
    finally:
        raw_sock.close()


# ============================================================
#  Entrada
# ============================================================

def main() -> int:
    parser = argparse.ArgumentParser(description="ssi-chat server")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--data-dir", default="data")
    parser.add_argument("--log-level", default="INFO",
                        choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    serve(args.host, args.port, Path(args.data_dir))
    return 0


if __name__ == "__main__":
    sys.exit(main())
