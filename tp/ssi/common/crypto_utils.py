"""
Primitivas criptográficas usadas no projeto.

Escolhas (alinhadas com a matéria da UC e os guiões da Semana 7 e 8):

    - Cifra autenticada de mensagens: AES-256-GCM (AEAD).
        * Nonce de 96 bits, único por chave.
        * AAD usada para autenticar metadados (remetente, destinatário,
          conversation_id, seq_no).

    - Acordo de chaves: Diffie-Hellman clássico sobre grupo MODP de 2048
      bits (RFC 3526, grupo 14). Chaves efémeras por sessão para garantir
      forward secrecy.

    - Derivação de chaves: HKDF-SHA-256 sobre o segredo DH.
        * Derivamos duas chaves direcionais (A→B e B→A) a partir do
          mesmo segredo, usando 'info' diferentes.

    - Identidades de longo prazo: RSA-3072 para assinaturas (RSA-PSS com
      SHA-256). Usado tanto para certificados como para autenticar o
      handshake STS e o login challenge-response.

Notas pedagógicas:
    - Não usamos a chave bruta do DH; passamos sempre por HKDF, como o
      guião sts_aes_gcm.py recomenda.
    - O nonce do AES-GCM é construído determinísticamente a partir do
      seq_no (12 bytes: 4 reservados + 8 do contador). Isto garante
      unicidade sem depender de aleatoriedade — o que é mais robusto
      contra reuso de nonce, que é catastrófico em GCM.
"""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dh, padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# ----------------------------- Constantes -----------------------------

# RFC 3526 — Group 14 (MODP 2048 bits). Padronizado, suficientemente
# seguro para fins académicos. Gerar parâmetros novos demoraria muito
# tempo e não acrescenta valor.
DH_GENERATOR = 2
DH_KEY_SIZE = 2048

# AES-256-GCM
AES_KEY_SIZE = 32           # 256 bits
GCM_NONCE_SIZE = 12         # 96 bits, recomendado para GCM
GCM_TAG_SIZE = 16           # 128 bits

# RSA para identidades de longo prazo
RSA_KEY_SIZE = 3072
RSA_PUBLIC_EXPONENT = 65537


# ============================================================
#  Parâmetros DH partilhados
# ============================================================

# Carregamos uma única vez. Em produção carregaríamos de ficheiro;
# para o trabalho geramos no arranque (lento ~ alguns segundos)
# OU usamos o grupo padronizado RFC 3526.
#
# Como queremos arranque rápido, usamos o grupo RFC 3526 hard-coded.
# A biblioteca cryptography não expõe diretamente o grupo 14, mas
# permite construí-lo a partir dos parâmetros (p, g).

# p do grupo 14 da RFC 3526 (2048 bits), em hexadecimal.
_RFC3526_GROUP14_P_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF"
)


def get_dh_parameters() -> dh.DHParameters:
    """
    Devolve os parâmetros DH do grupo 14 da RFC 3526.

    Estes parâmetros são públicos e fixos — não são segredo. O segredo
    nasce dos expoentes privados que cada parte gera com generate_private_key().
    """
    p = int(_RFC3526_GROUP14_P_HEX, 16)
    pn = dh.DHParameterNumbers(p=p, g=DH_GENERATOR)
    return pn.parameters()


# ============================================================
#  Geração de chaves
# ============================================================

def generate_rsa_keypair() -> rsa.RSAPrivateKey:
    """Gera par RSA-3072 para identidade de longo prazo."""
    return rsa.generate_private_key(
        public_exponent=RSA_PUBLIC_EXPONENT,
        key_size=RSA_KEY_SIZE,
    )


def generate_dh_ephemeral() -> dh.DHPrivateKey:
    """
    Gera um par DH efémero. O privado descarta-se depois da sessão para
    garantir forward secrecy.
    """
    return get_dh_parameters().generate_private_key()


# ============================================================
#  Serialização DH
# ============================================================

def serialize_dh_public(public_key: dh.DHPublicKey) -> bytes:
    """Serializa chave pública DH para formato SubjectPublicKeyInfo (DER)."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def deserialize_dh_public(data: bytes) -> dh.DHPublicKey:
    """Desserializa chave pública DH a partir de DER."""
    key = serialization.load_der_public_key(data)
    if not isinstance(key, dh.DHPublicKey):
        raise ValueError("A chave fornecida não é DH.")
    return key


# ============================================================
#  Assinaturas RSA-PSS
# ============================================================
#
# PSS é o esquema de padding moderno para RSA. PKCS#1 v1.5 também
# funcionaria mas PSS é hoje recomendado.

_PSS_PADDING = padding.PSS(
    mgf=padding.MGF1(hashes.SHA256()),
    salt_length=padding.PSS.MAX_LENGTH,
)


def sign_rsa(private_key: rsa.RSAPrivateKey, message: bytes) -> bytes:
    """Assina uma mensagem com RSA-PSS-SHA256."""
    return private_key.sign(message, _PSS_PADDING, hashes.SHA256())


def verify_rsa(public_key: rsa.RSAPublicKey, signature: bytes, message: bytes) -> bool:
    """Verifica uma assinatura RSA-PSS-SHA256. Devolve True/False."""
    try:
        public_key.verify(signature, message, _PSS_PADDING, hashes.SHA256())
        return True
    except Exception:
        return False


# ============================================================
#  HKDF — derivação de chaves de sessão
# ============================================================

def hkdf_derive(shared_secret: bytes, info: bytes, length: int = AES_KEY_SIZE,
                salt: bytes | None = None) -> bytes:
    """
    Deriva 'length' bytes de chave a partir do segredo partilhado DH.

    'info' é um rótulo que separa diferentes derivações da mesma fonte.
    Usamos isto para ter chaves direcionais distintas (A→B vs B→A).
    """
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,                # None == zeros, conforme RFC 5869
        info=info,
    ).derive(shared_secret)


@dataclass(frozen=True)
class SessionKeys:
    """
    Chaves derivadas de uma sessão E2E entre dois utilizadores.

    Cada direção tem a sua chave para evitar que um nonce com seq_no
    igual nos dois sentidos colida (regra: nonce nunca repete sob a
    mesma chave em GCM).
    """
    send_key: bytes      # chave para mensagens que ESTE peer envia
    recv_key: bytes      # chave para mensagens que ESTE peer recebe


def derive_session_keys(shared_secret: bytes, initiator_name: str,
                        responder_name: str, am_i_initiator: bool) -> SessionKeys:
    """
    A partir do segredo DH, deriva as duas chaves direcionais.

    Os nomes do iniciador e do respondedor são incluídos no 'info' do
    HKDF para amarrar as chaves a esta conversa específica (defesa
    contra unknown-key-share).
    """
    info_i_to_r = f"ssi-chat v1 | {initiator_name} -> {responder_name}".encode()
    info_r_to_i = f"ssi-chat v1 | {responder_name} -> {initiator_name}".encode()

    key_i_to_r = hkdf_derive(shared_secret, info_i_to_r)
    key_r_to_i = hkdf_derive(shared_secret, info_r_to_i)

    if am_i_initiator:
        return SessionKeys(send_key=key_i_to_r, recv_key=key_r_to_i)
    else:
        return SessionKeys(send_key=key_r_to_i, recv_key=key_i_to_r)


# ============================================================
#  AES-GCM com construção determinística de nonce
# ============================================================

def make_gcm_nonce(seq_no: int) -> bytes:
    """
    Constrói um nonce determinístico de 12 bytes a partir de seq_no.

    Layout: 4 bytes a zero (reservados) + 8 bytes big-endian de seq_no.

    Como cada direção tem a sua chave e cada direção tem o seu contador
    monotónico, o par (chave, nonce) nunca repete — que é a única coisa
    que GCM exige a quem chama.
    """
    if seq_no < 0 or seq_no >= 2**64:
        raise ValueError("seq_no fora de gama de 64 bits.")
    return b"\x00\x00\x00\x00" + struct.pack("!Q", seq_no)


def aead_encrypt(key: bytes, plaintext: bytes, aad: bytes, seq_no: int) -> tuple[bytes, bytes]:
    """
    Cifra plaintext com AES-GCM autenticando AAD.

    Devolve (nonce, ciphertext_com_tag).
    """
    if len(key) != AES_KEY_SIZE:
        raise ValueError("Chave AES com tamanho errado.")
    nonce = make_gcm_nonce(seq_no)
    ct = AESGCM(key).encrypt(nonce, plaintext, aad)
    return nonce, ct


def aead_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    """
    Decifra e verifica autenticidade. Levanta InvalidTag se o AAD ou o
    ciphertext tiverem sido manipulados.
    """
    if len(key) != AES_KEY_SIZE:
        raise ValueError("Chave AES com tamanho errado.")
    if len(nonce) != GCM_NONCE_SIZE:
        raise ValueError("Nonce com tamanho errado.")
    return AESGCM(key).decrypt(nonce, ciphertext, aad)


# ============================================================
#  Random helpers
# ============================================================

def random_bytes(n: int) -> bytes:
    """Bytes aleatórios criptograficamente seguros."""
    return os.urandom(n)
