"""
Sessões End-to-End entre clientes.

Implementa o handshake Station-To-Station (STS) autenticado por
certificados e as mensagens de chat cifradas com AES-GCM.

Handshake STS (3 mensagens), inspirado no guião sts_aes_gcm.py
da Semana 8:

    Iniciador A                                  Respondedor B
    -----------                                  -------------
    gera (xA, gA = g^xA)
    HS_INIT { from=A, to=B, gA, cert_A }   --->
                                                 valida cert_A
                                                 gera (yB, gB = g^yB)
                                                 sigB = Sign_B(gB || gA || A || B)
                                          <---   HS_REPLY { gB, sigB, cert_B }
    valida cert_B
    verifica sigB com pub_B
    sigA = Sign_A(gA || gB || A || B)
    HS_FINISH { sigA }                     --->
                                                 verifica sigA com pub_A

Notas de design:
    - Os certificados vão DENTRO do handshake (não obtidos só do servidor).
      O lado iniciador faz adicionalmente um GET_CERT ao servidor antes
      do handshake e compara o cert que recebe no HS_REPLY com o que o
      servidor reportou. Isto é defesa em profundidade: detecta um peer
      comprometido que apresente um cert válido pela CA mas distinto do
      registado. No lado respondedor, o servidor também valida que o
      certificado anunciado no handshake corresponde ao utilizador
      autenticado que está a fazer RELAY.
    - O conteúdo assinado inclui ambos os g^x (transcript binding) e os
      identificadores de ambos os utilizadores (defesa contra unknown
      key share / identity misbinding).
    - Após a 3ª mensagem ambas as partes derivam a chave com HKDF e
      mantêm contadores monotónicos por direção.

Mensagens de chat:
    Após handshake, os campos de cada DELIVERY contêm:
        - kind: "MESSAGE"
        - conversation_id: identificador único negociado no handshake
          (na prática usamos o nonce concatenado dos dois pontos públicos)
        - seq_no: contador monotónico (uint64)
        - nonce_b64: nonce GCM (12 bytes derivados do seq_no)
        - aad_b64: associated data (autenticada mas não cifrada)
        - ciphertext_b64: AES-256-GCM(plaintext)

    AAD inclui: sender, recipient, conversation_id, seq_no.
    Manipular qualquer um destes campos no servidor faz a decifragem
    falhar com InvalidTag.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass, field

from cryptography import x509
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import dh, rsa

from common import certs, crypto_utils
from common.protocol import b64d, b64e


class HandshakeError(Exception):
    """Algo correu mal no handshake STS."""


class SessionError(Exception):
    """Erro no uso de uma sessão estabelecida."""


_TRANSCRIPT_PREFIX = b"ssi-chat-sts|"


def _build_signed_transcript(initiator: str, responder: str,
                             g_initiator: bytes, g_responder: bytes) -> bytes:
    """
    Constrói o "transcript" canónico que cada parte assina.

    Inclui:
        - prefixo de domínio (evita confusão com outras assinaturas do sistema)
        - identificadores de ambos os utilizadores
        - ambos os valores públicos DH

    A ordem é fixa: sempre (initiator, responder) e sempre (g_initiator,
    g_responder). Quem assina apenas alterna o seu papel ao escolher os
    bytes que assina, não a ordem dos campos.
    """
    h = hashlib.sha256()
    h.update(_TRANSCRIPT_PREFIX)
    h.update(initiator.encode())
    h.update(b"|")
    h.update(responder.encode())
    h.update(b"|")
    h.update(g_initiator)
    h.update(b"|")
    h.update(g_responder)
    return h.digest()


def _derive_conversation_id(g_initiator: bytes, g_responder: bytes) -> str:
    """
    Identificador único da conversa, derivado dos pontos DH públicos.
    Vai como AAD nas mensagens — qualquer tentativa de cross-conversation
    é detetada.
    """
    h = hashlib.sha256()
    h.update(g_initiator)
    h.update(g_responder)
    return h.hexdigest()[:32]


# ============================================================
#  Sessão E2E estabelecida
# ============================================================

@dataclass
class E2ESession:
    """
    Sessão segura entre o utilizador local e um peer.

    Mantém chaves direcionais e contadores monotónicos. Acesso
    sincronizado por lock interno porque o cliente pode receber
    mensagens em paralelo com envios (thread de receção + main).
    """
    peer_username: str
    conversation_id: str
    keys: crypto_utils.SessionKeys
    send_seq: int = 0
    recv_seq: int = 0       # próximo seq esperado a receber
    seen_seqs: set[int] = field(default_factory=set)  # janela de replay
    lock: threading.Lock = field(default_factory=threading.Lock)

    REPLAY_WINDOW = 1024     # quantos seqs recentes aceitamos fora de ordem

    # ---------- Cifragem / decifragem ----------

    def encrypt(self, plaintext: bytes, my_username: str) -> dict[str, str]:
        """
        Cifra plaintext para o peer e devolve o envelope JSON-friendly.
        """
        with self.lock:
            seq = self.send_seq
            self.send_seq += 1

        aad = self._build_aad(sender=my_username, recipient=self.peer_username, seq_no=seq)
        nonce, ct = crypto_utils.aead_encrypt(
            key=self.keys.send_key,
            plaintext=plaintext,
            aad=aad,
            seq_no=seq,
        )
        return {
            "kind": "MESSAGE",
            "conversation_id": self.conversation_id,
            "seq_no": seq,
            "nonce_b64": b64e(nonce),
            "aad_b64": b64e(aad),
            "ciphertext_b64": b64e(ct),
        }

    def decrypt(self, envelope: dict, expected_sender: str, my_username: str) -> bytes:
        """
        Decifra um envelope vindo do peer.

        Levanta SessionError se algo estiver mal: AAD não bate, replay
        detetado, conversa errada, etc.
        """
        try:
            conv_id = envelope["conversation_id"]
            seq = int(envelope["seq_no"])
            nonce = b64d(envelope["nonce_b64"])
            aad = b64d(envelope["aad_b64"])
            ct = b64d(envelope["ciphertext_b64"])
        except (KeyError, TypeError, ValueError) as exc:
            raise SessionError(f"Envelope mal formado: {exc}") from exc

        if conv_id != self.conversation_id:
            raise SessionError("conversation_id não bate certo.")

        # Reconstruir o AAD esperado e comparar — extra defesa, embora o
        # GCM já valide.
        expected_aad = self._build_aad(
            sender=expected_sender, recipient=my_username, seq_no=seq,
        )
        if aad != expected_aad:
            raise SessionError("AAD adulterado.")

        # Replay protection + decifragem + atualização de estado, tudo
        # sob o mesmo lock. Manter check e update separados era uma
        # TOCTOU latente: duas threads podiam ambas observar "seq não
        # visto", ambas decifrar a mesma mensagem replayed, e só uma
        # registar no fim. Hoje só há uma thread de receção, mas o
        # padrão deve ser seguro por construção, não por acidente.
        with self.lock:
            if seq in self.seen_seqs:
                raise SessionError(f"Replay detetado (seq={seq}).")
            if seq + self.REPLAY_WINDOW < self.recv_seq:
                raise SessionError(f"Mensagem demasiado antiga (seq={seq}).")

            try:
                plaintext = crypto_utils.aead_decrypt(
                    self.keys.recv_key, nonce, ct, aad,
                )
            except InvalidTag as exc:
                # Não registamos seq: ciphertext inválido não conta como
                # "visto" para efeitos de replay (preserva a janela útil).
                raise SessionError(
                    "Tag GCM inválida — mensagem adulterada ou chave errada."
                ) from exc

            # Só atualizamos estado depois de decifrar com sucesso.
            self.seen_seqs.add(seq)
            if seq >= self.recv_seq:
                self.recv_seq = seq + 1
            # Manter o set limitado.
            if len(self.seen_seqs) > self.REPLAY_WINDOW * 2:
                cutoff = self.recv_seq - self.REPLAY_WINDOW
                self.seen_seqs = {s for s in self.seen_seqs if s >= cutoff}

        return plaintext

    def _build_aad(self, sender: str, recipient: str, seq_no: int) -> bytes:
        """
        Constrói AAD canónico. Tudo o que importa autenticar mas não
        cifrar vai aqui.
        """
        return (
            b"ssi-chat-msg|"
            + sender.encode() + b"|"
            + recipient.encode() + b"|"
            + self.conversation_id.encode() + b"|"
            + str(seq_no).encode()
        )


# ============================================================
#  Iniciador do handshake
# ============================================================

class HandshakeInitiator:
    """
    Estado do iniciador (A) durante o handshake STS.

    Uso típico:
        h = HandshakeInitiator(my_username, my_id_key, peer_username, ca_cert)
        msg1 = h.build_init(my_cert_der)        # enviar HS_INIT
        # ... receber HS_REPLY ...
        msg3 = h.process_reply_and_finish(reply, my_cert_der)
        session = h.session                      # já está pronta
    """

    def __init__(self, my_username: str, my_id_key: rsa.RSAPrivateKey,
                 peer_username: str, ca_cert: x509.Certificate,
                 expected_peer_cert_der: bytes | None = None):
        self.my_username = my_username
        self.my_id_key = my_id_key
        self.peer_username = peer_username
        self.ca_cert = ca_cert
        # Cert do peer obtido previamente do servidor (GET_CERT). Quando
        # presente, é usado para fazer cross-check com o cert que chega
        # dentro do HS_REPLY: defesa em profundidade contra um peer que
        # apresentasse um cert válido pela CA mas distinto do registado.
        self.expected_peer_cert_der = expected_peer_cert_der

        self._dh_priv: dh.DHPrivateKey | None = None
        self._g_a_bytes: bytes | None = None
        self.session: E2ESession | None = None

    def build_init(self, my_cert_der: bytes) -> dict:
        """Primeira mensagem do handshake (A -> B)."""
        self._dh_priv = crypto_utils.generate_dh_ephemeral()
        self._g_a_bytes = crypto_utils.serialize_dh_public(self._dh_priv.public_key())

        return {
            "kind": "HANDSHAKE",
            "subkind": "HS_INIT",
            "from": self.my_username,
            "to": self.peer_username,
            "dh_pub_b64": b64e(self._g_a_bytes),
            "cert_b64": b64e(my_cert_der),
        }

    def process_reply_and_finish(self, reply: dict, my_cert_der: bytes) -> dict:
        """
        Processa HS_REPLY do B e devolve HS_FINISH para enviar a B.
        Após esta chamada, self.session está pronta.
        """
        if self._dh_priv is None or self._g_a_bytes is None:
            raise HandshakeError("Handshake não iniciado.")
        if reply.get("subkind") != "HS_REPLY":
            raise HandshakeError("Esperava HS_REPLY.")

        if reply.get("from") != self.peer_username or reply.get("to") != self.my_username:
            raise HandshakeError(
                "HS_REPLY com identidade/destinatário inconsistentes "
                f"(from={reply.get('from')!r}, to={reply.get('to')!r})."
            )

        try:
            g_b_bytes = b64d(reply["dh_pub_b64"])
            sig_b = b64d(reply["signature_b64"])
            cert_b_der = b64d(reply["cert_b64"])
        except KeyError as exc:
            raise HandshakeError(f"Campo em falta no HS_REPLY: {exc}") from exc

        # Cross-check com o cert que o servidor reportou via GET_CERT.
        # O cert dentro do handshake tem de ser exatamente igual ao
        # registado no servidor. Esta verificação só é defesa em
        # profundidade — a confiança principal vem da CA — mas apanha
        # o cenário em que duas chaves diferentes tenham sido emitidas
        # para o mesmo username, ou em que um peer comprometido
        # apresente um cert antigo/diferente.
        if self.expected_peer_cert_der is not None:
            if cert_b_der != self.expected_peer_cert_der:
                raise HandshakeError(
                    f"Cert de {self.peer_username!r} no handshake difere "
                    "do registado no servidor (possível identity binding "
                    "comprometido)."
                )

        # Validar certificado de B contra a CA e contra o nome esperado.
        cert_b = certs.cert_from_der(cert_b_der)
        try:
            identity_b = certs.validate_user_certificate(
                cert_b, self.ca_cert, expected_username=self.peer_username,
            )
        except certs.CertificateValidationError as exc:
            raise HandshakeError(f"Certificado de {self.peer_username!r} inválido: {exc}") from exc

        # Verificar assinatura de B.
        transcript = _build_signed_transcript(
            initiator=self.my_username,
            responder=self.peer_username,
            g_initiator=self._g_a_bytes,
            g_responder=g_b_bytes,
        )
        if not crypto_utils.verify_rsa(identity_b.public_key, sig_b, transcript):
            raise HandshakeError("Assinatura do peer inválida.")

        # Calcular segredo DH e derivar chaves.
        g_b = crypto_utils.deserialize_dh_public(g_b_bytes)
        shared = self._dh_priv.exchange(g_b)
        keys = crypto_utils.derive_session_keys(
            shared_secret=shared,
            initiator_name=self.my_username,
            responder_name=self.peer_username,
            am_i_initiator=True,
        )

        conv_id = _derive_conversation_id(self._g_a_bytes, g_b_bytes)

        # Construir HS_FINISH — assinatura nossa para B verificar.
        sig_a = crypto_utils.sign_rsa(self.my_id_key, transcript)

        finish_msg = {
            "kind": "HANDSHAKE",
            "subkind": "HS_FINISH",
            "from": self.my_username,
            "to": self.peer_username,
            "signature_b64": b64e(sig_a),
            "cert_b64": b64e(my_cert_der),
        }

        self.session = E2ESession(
            peer_username=self.peer_username,
            conversation_id=conv_id,
            keys=keys,
        )

        # Apagar material efémero — forward secrecy.
        self._dh_priv = None

        return finish_msg


# ============================================================
#  Respondedor do handshake
# ============================================================

class HandshakeResponder:
    """
    Estado do respondedor (B) durante o handshake STS.

    Uso típico:
        r = HandshakeResponder(my_username, my_id_key, ca_cert)
        reply = r.process_init_and_reply(init_msg, my_cert_der)
        # ... enviar reply ...
        # ... receber HS_FINISH ...
        r.process_finish(finish_msg)
        session = r.session
    """

    def __init__(self, my_username: str, my_id_key: rsa.RSAPrivateKey,
                 ca_cert: x509.Certificate):
        self.my_username = my_username
        self.my_id_key = my_id_key
        self.ca_cert = ca_cert

        self._initiator_username: str | None = None
        self._g_a_bytes: bytes | None = None
        self._g_b_bytes: bytes | None = None
        self._initiator_pub_key: rsa.RSAPublicKey | None = None
        self._initiator_cert_der: bytes | None = None
        self._pending_session: E2ESession | None = None
        self.session: E2ESession | None = None

    def process_init_and_reply(self, init: dict, my_cert_der: bytes) -> dict:
        if init.get("subkind") != "HS_INIT":
            raise HandshakeError("Esperava HS_INIT.")

        try:
            initiator_username = init["from"]
            target = init["to"]
            g_a_bytes = b64d(init["dh_pub_b64"])
            cert_a_der = b64d(init["cert_b64"])
        except KeyError as exc:
            raise HandshakeError(f"Campo em falta no HS_INIT: {exc}") from exc

        if not isinstance(initiator_username, str) or not initiator_username:
            raise HandshakeError("HS_INIT com campo 'from' inválido.")
        if target != self.my_username:
            raise HandshakeError(f"HS_INIT dirigido a {target!r}, mas eu sou {self.my_username!r}.")

        # Validar certificado de A.
        cert_a = certs.cert_from_der(cert_a_der)
        try:
            identity_a = certs.validate_user_certificate(
                cert_a, self.ca_cert, expected_username=initiator_username,
            )
        except certs.CertificateValidationError as exc:
            raise HandshakeError(f"Certificado de {initiator_username!r} inválido: {exc}") from exc

        # Gerar par DH efémero do responder.
        dh_priv = crypto_utils.generate_dh_ephemeral()
        g_b_bytes = crypto_utils.serialize_dh_public(dh_priv.public_key())

        # Construir transcript e assinar.
        transcript = _build_signed_transcript(
            initiator=initiator_username,
            responder=self.my_username,
            g_initiator=g_a_bytes,
            g_responder=g_b_bytes,
        )
        sig_b = crypto_utils.sign_rsa(self.my_id_key, transcript)

        # Já podemos derivar a chave (vamos validar a sig do iniciador no FINISH).
        g_a = crypto_utils.deserialize_dh_public(g_a_bytes)
        shared = dh_priv.exchange(g_a)
        keys = crypto_utils.derive_session_keys(
            shared_secret=shared,
            initiator_name=initiator_username,
            responder_name=self.my_username,
            am_i_initiator=False,
        )

        conv_id = _derive_conversation_id(g_a_bytes, g_b_bytes)
        self._pending_session = E2ESession(
            peer_username=initiator_username,
            conversation_id=conv_id,
            keys=keys,
        )

        # Guardar estado para validar HS_FINISH.
        self._initiator_username = initiator_username
        self._g_a_bytes = g_a_bytes
        self._g_b_bytes = g_b_bytes
        self._initiator_pub_key = identity_a.public_key
        self._initiator_cert_der = cert_a_der

        # Forward secrecy: apaga já o priv DH, já não é preciso.
        del dh_priv

        return {
            "kind": "HANDSHAKE",
            "subkind": "HS_REPLY",
            "from": self.my_username,
            "to": initiator_username,
            "dh_pub_b64": b64e(g_b_bytes),
            "signature_b64": b64e(sig_b),
            "cert_b64": b64e(my_cert_der),
        }

    def process_finish(self, finish: dict) -> None:
        if finish.get("subkind") != "HS_FINISH":
            raise HandshakeError("Esperava HS_FINISH.")
        if (self._initiator_username is None or self._g_a_bytes is None
                or self._g_b_bytes is None or self._initiator_pub_key is None
                or self._initiator_cert_der is None or self._pending_session is None):
            raise HandshakeError("Estado de handshake incompleto.")

        if finish.get("from") != self._initiator_username or finish.get("to") != self.my_username:
            raise HandshakeError(
                "HS_FINISH com identidade/destinatário inconsistentes "
                f"(from={finish.get('from')!r}, to={finish.get('to')!r})."
            )

        try:
            sig_a = b64d(finish["signature_b64"])
            cert_a_der = b64d(finish["cert_b64"])
        except KeyError as exc:
            raise HandshakeError(f"Campo em falta no HS_FINISH: {exc}") from exc

        if cert_a_der != self._initiator_cert_der:
            raise HandshakeError(
                f"Certificado de {self._initiator_username!r} mudou entre HS_INIT e HS_FINISH."
            )

        transcript = _build_signed_transcript(
            initiator=self._initiator_username,
            responder=self.my_username,
            g_initiator=self._g_a_bytes,
            g_responder=self._g_b_bytes,
        )
        if not crypto_utils.verify_rsa(self._initiator_pub_key, sig_a, transcript):
            raise HandshakeError("Assinatura do iniciador inválida no HS_FINISH.")

        self.session = self._pending_session
        self._pending_session = None