"""
Testes de segurança — ataques que devem ser DETETADOS pelo protocolo.

Não testa robustez contra todo o tipo de ataque imaginável; testa que
as defesas que implementámos funcionam como esperado.

Ataques cobertos:
    1. Login com chave errada — assinatura inválida, servidor rejeita.
    2. Certificado emitido por CA diferente — validação de cert falha.
    3. Adulteração do ciphertext — decifragem AES-GCM falha (InvalidTag).
    4. Adulteração do AAD (sender, seq_no) — falha imediata.
    5. Replay de mensagem — sessão deteta seq repetido.
    6. Trocar HS_REPLY (ataque MitM) — cliente rejeita assinatura.
"""

from __future__ import annotations

import copy
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from common import certs, crypto_utils
from common.protocol import b64d, b64e
from client.session import (
    HandshakeError,
    HandshakeInitiator,
    HandshakeResponder,
    SessionError,
)
from pki.ca import LocalCA

ID_KEY_PASSWORD = os.environ.get("SSI_ID_KEY_PASSWORD", "test-password").encode("utf-8")


def test_handshake_baseline():
    """Sanity: handshake limpo funciona."""
    ca = certs.cert_from_pem(Path("data/ca/ca_cert.pem").read_bytes())
    a_key = certs.private_key_from_pem(Path("data/users/alice/id_key.pem").read_bytes(), password=ID_KEY_PASSWORD)
    a_cert = certs.cert_from_pem(Path("data/users/alice/id_cert.pem").read_bytes())
    b_key = certs.private_key_from_pem(Path("data/users/bob/id_key.pem").read_bytes(), password=ID_KEY_PASSWORD)
    b_cert = certs.cert_from_pem(Path("data/users/bob/id_cert.pem").read_bytes())

    a_init = HandshakeInitiator("alice", a_key, "bob", ca)
    b_resp = HandshakeResponder("bob", b_key, ca)

    m1 = a_init.build_init(certs.cert_to_der(a_cert))
    m2 = b_resp.process_init_and_reply(m1, certs.cert_to_der(b_cert))
    m3 = a_init.process_reply_and_finish(m2, certs.cert_to_der(a_cert))
    b_resp.process_finish(m3)

    print("[1] OK  Baseline handshake.")
    return a_init, b_resp


def test_cert_from_other_ca():
    """Certificado emitido por uma CA diferente não passa validação."""
    import tempfile
    import shutil

    # Criar CA "atacante" num diretório temporário
    tmpdir = Path(tempfile.mkdtemp())
    try:
        evil_ca = LocalCA(tmpdir / "evil-ca")
        evil_ca.initialize(common_name="Evil CA")

        # CA atacante emite cert para "bob" — username correto, mas
        # assinatura é da CA errada.
        evil_bob_key = crypto_utils.generate_rsa_keypair()
        evil_bob_cert = evil_ca.issue_user_certificate("bob", evil_bob_key.public_key())

        # Tentar validar contra a CA correta
        good_ca = certs.cert_from_pem(Path("data/ca/ca_cert.pem").read_bytes())
        try:
            certs.validate_user_certificate(evil_bob_cert, good_ca, expected_username="bob")
            print("[2] FAIL  Certificado de CA falsa foi aceite!")
        except certs.CertificateValidationError as exc:
            print(f"[2] OK  Cert de CA falsa rejeitado: {exc}")
    finally:
        shutil.rmtree(tmpdir)


def test_ciphertext_tampering():
    """Manipular ciphertext faz decifrar falhar com InvalidTag."""
    a_init, b_resp = test_handshake_baseline()

    env = a_init.session.encrypt(b"mensagem original", my_username="alice")
    # Flip um bit no ciphertext.
    ct_bytes = bytearray(b64d(env["ciphertext_b64"]))
    ct_bytes[0] ^= 0x01
    env_evil = dict(env, ciphertext_b64=b64e(bytes(ct_bytes)))

    try:
        b_resp.session.decrypt(env_evil, expected_sender="alice", my_username="bob")
        print("[3] FAIL  Ciphertext adulterado foi decifrado!")
    except SessionError as exc:
        print(f"[3] OK  Ciphertext adulterado detetado: {exc}")


def test_aad_tampering():
    """Manipular AAD (alterando seq_no) faz tudo falhar."""
    a_init, b_resp = test_handshake_baseline()

    env = a_init.session.encrypt(b"hello", my_username="alice")
    env_evil = copy.deepcopy(env)
    env_evil["seq_no"] = 999

    try:
        b_resp.session.decrypt(env_evil, expected_sender="alice", my_username="bob")
        print("[4] FAIL  AAD adulterado foi aceite!")
    except SessionError as exc:
        print(f"[4] OK  AAD adulterado detetado: {exc}")


def test_replay():
    """Reenviar a mesma mensagem é rejeitado."""
    a_init, b_resp = test_handshake_baseline()

    env = a_init.session.encrypt(b"x", my_username="alice")
    pt = b_resp.session.decrypt(env, expected_sender="alice", my_username="bob")
    assert pt == b"x"
    try:
        b_resp.session.decrypt(env, expected_sender="alice", my_username="bob")
        print("[5] FAIL  Replay foi aceite!")
    except SessionError as exc:
        print(f"[5] OK  Replay detetado: {exc}")


def test_hs_reply_signature_swap():
    """
    Cenário MitM: atacante intercepta HS_REPLY do Bob e devolve um
    HS_REPLY criado por ele (com a sua chave + cert da CA atacante).
    A Alice deve rejeitar.
    """
    import tempfile
    import shutil

    ca = certs.cert_from_pem(Path("data/ca/ca_cert.pem").read_bytes())
    a_key = certs.private_key_from_pem(Path("data/users/alice/id_key.pem").read_bytes(), password=ID_KEY_PASSWORD)
    a_cert = certs.cert_from_pem(Path("data/users/alice/id_cert.pem").read_bytes())

    # Setup atacante
    tmpdir = Path(tempfile.mkdtemp())
    try:
        evil_ca = LocalCA(tmpdir / "evil-ca")
        evil_ca.initialize()
        evil_bob_key = crypto_utils.generate_rsa_keypair()
        evil_bob_cert = evil_ca.issue_user_certificate("bob", evil_bob_key.public_key())

        a_init = HandshakeInitiator("alice", a_key, "bob", ca)
        m1 = a_init.build_init(certs.cert_to_der(a_cert))

        # Atacante constrói um HS_REPLY com a sua chave malicíola
        from client.session import _build_signed_transcript
        evil_dh = crypto_utils.generate_dh_ephemeral()
        g_b_evil = crypto_utils.serialize_dh_public(evil_dh.public_key())
        transcript = _build_signed_transcript(
            initiator="alice", responder="bob",
            g_initiator=b64d(m1["dh_pub_b64"]),
            g_responder=g_b_evil,
        )
        evil_sig = crypto_utils.sign_rsa(evil_bob_key, transcript)
        evil_reply = {
            "kind": "HANDSHAKE",
            "subkind": "HS_REPLY",
            "from": "bob",
            "to": "alice",
            "dh_pub_b64": b64e(g_b_evil),
            "signature_b64": b64e(evil_sig),
            "cert_b64": b64e(certs.cert_to_der(evil_bob_cert)),
        }

        try:
            a_init.process_reply_and_finish(evil_reply, certs.cert_to_der(a_cert))
            print("[6] FAIL  MitM com cert de CA falsa foi aceite!")
        except HandshakeError as exc:
            print(f"[6] OK  MitM detetado: {exc}")
    finally:
        shutil.rmtree(tmpdir)


def test_hs_reply_same_ca_different_cert_cross_check():
    """
    Mesmo que a CA tenha emitido outro certificado válido para o mesmo CN
    'bob', o /chat deve comparar o certificado do HS_REPLY com o certificado
    que GET_CERT devolveu antes do handshake.
    """
    ca = certs.cert_from_pem(Path("data/ca/ca_cert.pem").read_bytes())
    ca_key = certs.private_key_from_pem(Path("data/ca/ca_key.pem").read_bytes())
    a_key = certs.private_key_from_pem(Path("data/users/alice/id_key.pem").read_bytes(), password=ID_KEY_PASSWORD)
    a_cert = certs.cert_from_pem(Path("data/users/alice/id_cert.pem").read_bytes())
    registered_bob_cert_der = Path("data/users/bob/id_cert.pem").read_bytes()
    registered_bob_cert_der = certs.cert_to_der(certs.cert_from_pem(registered_bob_cert_der))

    # Certificado alternativo para o mesmo username, assinado pela CA correta,
    # mas com outra chave. Isto simula um identity-binding perigoso.
    alt_bob_key = crypto_utils.generate_rsa_keypair()
    alt_bob_cert = certs.build_user_certificate(
        ca_private_key=ca_key,
        ca_cert=ca,
        username="bob",
        user_public_key=alt_bob_key.public_key(),
    )

    a_init = HandshakeInitiator(
        "alice", a_key, "bob", ca,
        expected_peer_cert_der=registered_bob_cert_der,
    )
    m1 = a_init.build_init(certs.cert_to_der(a_cert))

    from client.session import _build_signed_transcript
    alt_dh = crypto_utils.generate_dh_ephemeral()
    g_b_alt = crypto_utils.serialize_dh_public(alt_dh.public_key())
    transcript = _build_signed_transcript(
        initiator="alice", responder="bob",
        g_initiator=b64d(m1["dh_pub_b64"]),
        g_responder=g_b_alt,
    )
    alt_sig = crypto_utils.sign_rsa(alt_bob_key, transcript)
    alt_reply = {
        "kind": "HANDSHAKE",
        "subkind": "HS_REPLY",
        "from": "bob",
        "to": "alice",
        "dh_pub_b64": b64e(g_b_alt),
        "signature_b64": b64e(alt_sig),
        "cert_b64": b64e(certs.cert_to_der(alt_bob_cert)),
    }

    try:
        a_init.process_reply_and_finish(alt_reply, certs.cert_to_der(a_cert))
        print("[7] FAIL  Cert alternativo da mesma CA foi aceite!")
    except HandshakeError as exc:
        print(f"[7] OK  Cross-check GET_CERT vs HS_REPLY detetou troca: {exc}")


def test_server_relay_handshake_cross_check():
    """Servidor rejeita handshakes cujo from/to/cert não batem certo."""
    import tempfile
    import shutil

    from server.persistence import MailboxStore
    from server.server import ClientSession, ServerState, load_enrolled_users

    ca = certs.cert_from_pem(Path("data/ca/ca_cert.pem").read_bytes())
    a_key = certs.private_key_from_pem(Path("data/users/alice/id_key.pem").read_bytes(), password=ID_KEY_PASSWORD)
    a_cert = certs.cert_from_pem(Path("data/users/alice/id_cert.pem").read_bytes())

    tmpdir = Path(tempfile.mkdtemp())
    try:
        state = ServerState(ca_cert=ca, mailbox_store=MailboxStore(tmpdir / "mailboxes"))
        state.users = load_enrolled_users(Path("data"), ca)

        # Não usamos socket neste teste; chamamos diretamente o validador.
        sess = ClientSession(sock=None, addr=("127.0.0.1", 0), state=state)  # type: ignore[arg-type]
        sess.username = "alice"

        init = HandshakeInitiator("alice", a_key, "bob", ca).build_init(certs.cert_to_der(a_cert))
        ok = sess._validate_relay_envelope("bob", init, state.users["alice"])
        assert ok is None

        bad_from = dict(init, **{"from": "mallory"})
        bad_to = dict(init, **{"to": "mallory"})

        alt_alice_key = crypto_utils.generate_rsa_keypair()
        ca_key = certs.private_key_from_pem(Path("data/ca/ca_key.pem").read_bytes())
        alt_alice_cert = certs.build_user_certificate(
            ca_private_key=ca_key,
            ca_cert=ca,
            username="alice",
            user_public_key=alt_alice_key.public_key(),
        )
        bad_cert = dict(init, cert_b64=b64e(certs.cert_to_der(alt_alice_cert)))

        assert sess._validate_relay_envelope("bob", bad_from, state.users["alice"]) is not None
        assert sess._validate_relay_envelope("bob", bad_to, state.users["alice"]) is not None
        assert sess._validate_relay_envelope("bob", bad_cert, state.users["alice"]) is not None
        print("[8] OK  Servidor rejeita RELAY de handshake com from/to/cert inconsistentes.")
    finally:
        shutil.rmtree(tmpdir)


def test_id_key_encrypted_and_password_protected():
    """A chave privada local deve estar cifrada e protegida por password."""
    key_path = Path("data/users/alice/id_key.pem")
    data = key_path.read_bytes()
    mode = key_path.stat().st_mode & 0o777
    assert b"BEGIN ENCRYPTED PRIVATE KEY" in data
    assert mode == 0o600

    try:
        certs.private_key_from_pem(data, password=b"wrong-password")
        print("[9] FAIL  id_key.pem abriu com password errada!")
    except (TypeError, ValueError):
        print("[9] OK  id_key.pem cifrado, modo 600 e password errada rejeitada.")

    # Sanity: password correta continua a abrir a chave.
    certs.private_key_from_pem(data, password=ID_KEY_PASSWORD)


def main():
    print("=== Testes de segurança ===\n")
    test_handshake_baseline()
    test_cert_from_other_ca()
    test_ciphertext_tampering()
    test_aad_tampering()
    test_replay()
    test_hs_reply_signature_swap()
    test_hs_reply_same_ca_different_cert_cross_check()
    test_server_relay_handshake_cross_check()
    test_id_key_encrypted_and_password_protected()
    print("\n=== Concluído ===")


if __name__ == "__main__":
    main()
