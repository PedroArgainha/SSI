# ssi-chat

Sistema de chat com **End-to-End Encryption (E2EE)** desenvolvido para a UC
de **Segurança de Sistemas Informáticos** (SSI). Implementa autenticação
de utilizadores por challenge-response assinado, handshake STS entre
clientes, mensagens cifradas com AES-GCM, mensagens offline e PKI local.

## Arquitetura

```
┌───────────────────────────────────────────────────────────┐
│  CA local                                                 │
│  - chave privada da CA                                    │
│  - emite certificados X.509 para utilizadores e servidor  │
└───────────────────────────────────────────────────────────┘
                              │
                              │ raiz de confiança
                              ▼
┌───────────────────────────────────────────────────────────┐
│  Servidor (honesto-mas-curioso)                           │
│  - aceita ligações TLS de clientes                        │
│  - challenge-response assinado para login                 │
│  - encaminha envelopes opacos entre clientes              │
│  - guarda mensagens offline como ciphertext               │
└───────────────────────────────────────────────────────────┘
              ▲                        ▲
              │ TLS                    │ TLS
              │                        │
       ┌──────┴───────┐         ┌──────┴───────┐
       │ Cliente A    │ STS-DH  │ Cliente B    │
       │ (E2E AES-GCM)│◄════════►│ (E2E AES-GCM)│
       └──────────────┘ via srv  └──────────────┘
```

Mais detalhes técnicos no [relatório](RELATORIO.md).

## Estrutura do código

```
common/         Protocolo, primitivas cripto, certificados (partilhado)
pki/            CA local
server/         Servidor central (server.py + persistence.py)
client/         Cliente CLI (client.py + session.py + session_store.py)
scripts/        init_ca, client_keygen, ca_sign_csr, enroll_user, issue_server_cert
data/           Estado em runtime (gerado)
```

## Setup inicial

Requisitos: Python 3.10+ com `cryptography` instalada.

```bash
pip install cryptography
```

### 1) Inicializar a CA local

```bash
python -m scripts.init_ca
```

Cria `data/ca/ca_key.pem` (modo 600) e `data/ca/ca_cert.pem`.

### 2) Emitir certificado TLS para o servidor

```bash
python -m scripts.issue_server_cert --hostname 127.0.0.1
```

### 3) Enrollar utilizadores

Há dois fluxos.

**Fluxo "produção" (recomendado, com CSR):** o utilizador gera a sua
chave privada localmente e só envia um CSR à CA. A chave privada NUNCA
está acessível à infraestrutura da CA e fica cifrada em disco com uma
password local do utilizador, além do modo `600`.

```bash
# Lado do utilizador (na sua máquina):
python -m scripts.client_keygen --username alice --out-dir alice-keys

# Lado da CA (envia-se o id_csr.pem à CA):
python -m scripts.ca_sign_csr --csr alice-keys/id_csr.pem --username alice
```

Por omissão, `client_keygen` pede e confirma a password interativamente.
Para testes/automação, pode-se usar variável de ambiente:

```bash
SSI_ID_KEY_PASSWORD='password-de-teste' \
  python -m scripts.client_keygen --username alice --out-dir alice-keys
```

**Fluxo combinado (para testes locais):** keygen + sign na mesma máquina.

```bash
python -m scripts.enroll_user --username alice
python -m scripts.enroll_user --username bob
```

Também aqui a password é pedida interativamente. Para testes locais:

```bash
SSI_ID_KEY_PASSWORD='password-de-teste' python -m scripts.enroll_user --username alice
SSI_ID_KEY_PASSWORD='password-de-teste' python -m scripts.enroll_user --username bob
```

Cada utilizador fica com `data/users/<nome>/` contendo:
- `id_key.pem` — chave RSA privada cifrada com password local (modo 600)
- `id_cert.pem` — certificado emitido pela CA
- `ca_cert.pem` — cópia do cert da CA, root of trust

## Correr o sistema

### Servidor

```bash
python -m server.server --host 127.0.0.1 --port 9000
```

### Cliente (em terminais separados)

```bash
python -m client.client --user-dir data/users/alice
python -m client.client --user-dir data/users/bob
```

O cliente pede a password local da chave privada `id_key.pem` no arranque.
Essa password nunca é enviada ao servidor; serve apenas para decifrar a
chave privada guardada localmente. Para automação, pode ser fornecida
por variável de ambiente:

```bash
SSI_ID_KEY_PASSWORD='password-de-teste' \
  python -m client.client --user-dir data/users/alice
```

Adicionar `--persist-sessions` para guardar as sessões em disco
(cifradas com password, prompt interativo). Permite recuperar conversas
após restart do cliente, ao custo de FS entre sessões do mesmo cliente.

```bash
python -m client.client --user-dir data/users/alice --persist-sessions
```

### Comandos do cliente

```
/users               Lista utilizadores e quem está online
/chat <user>         Inicia handshake E2E (preparatório)
/msg <user> <texto>  Envia mensagem cifrada (faz handshake se preciso)
/fetch               Vai buscar mensagens offline pendentes
/logout              Termina sessão e sai
/quit                Sai
/help                Ajuda
```

## Testes

```bash
# Usar a mesma password usada no enrollment de teste.
export SSI_ID_KEY_PASSWORD='password-de-teste'

python test_security.py             # ataques que devem ser detetados
python test_e2e.py                   # cenário típico ponta-a-ponta
python test_e2e_v2.py                # várias mensagens em sequência
python test_persistence.py           # mailbox sobrevive restart do servidor
python test_session_persistence.py   # sessão local cifrada (re-decifra após restart cliente)
```

## Garantias de segurança

- **Confidencialidade**: AES-256-GCM cifra todas as mensagens. O servidor
  só vê envelopes opacos.
- **Integridade e autenticidade**: GCM autentica plaintext + AAD; AAD
  inclui sender, recipient, conversation_id e seq_no.
- **Autenticidade de utilizadores**: certificados X.509 emitidos pela CA
  local (com proof-of-possession via CSR); cada handshake e login é
  assinado com a chave de identidade.
- **Proteção das chaves privadas em repouso**: `id_key.pem` é guardado
  em PEM cifrado com password local e permissões `600`; a diretoria do
  utilizador usa permissões restritivas.
- **Forward secrecy**: chaves DH efémeras por sessão (descartadas após
  cada sessão, exceto se `--persist-sessions` for usado, ver abaixo).
- **Replay protection**: contador monotónico de seq_no; janela de replay
  de 1024 mensagens.
- **MitM**: bloqueado pelo TLS no canal cliente↔servidor e pelo
  handshake STS autenticado entre clientes.
- **Persistência**: mailbox offline em disco com permissões restritas;
  conteúdo cifrado E2E (servidor não vê plaintext). As sessões
  persistidas, quando ativadas, são também cifradas com password.

## Limitações conhecidas

- **Metadados** (quem fala com quem, quando) ficam visíveis ao servidor
  — inerente à arquitetura cliente-servidor. Documentado no relatório.
- **Sem revogação** de certificados (sem CRL/OCSP). Pode ser adicionado
  como extensão; para o âmbito do trabalho, a expiração de 1 ano serve.
- **Persistência local de sessão sacrifica FS entre sessões do mesmo
  cliente**: se a password e o ficheiro de sessão forem comprometidos,
  mensagens passadas tornam-se decifráveis. Trade-off explícito,
  controlado por flag — sem `--persist-sessions`, FS estrita mas sessão
  perde-se ao reiniciar.
