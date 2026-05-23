# Relatório — ssi-chat

## 1. Introdução

O presente projeto implementa um sistema de conversação cliente-servidor com segurança ponta-a-ponta (*End-to-End Encryption*, E2EE). O servidor atua como intermediário de coordenação, autenticação, encaminhamento e armazenamento de mensagens offline, mas não tem acesso ao conteúdo em claro das mensagens trocadas entre clientes.

A solução foi desenvolvida em Python e utiliza a biblioteca `cryptography` para as primitivas criptográficas. O desenho segue o modelo de ameaça proposto para o projeto: servidor honesto-mas-curioso, atacante ativo na rede, necessidade de confidencialidade, integridade e autenticidade das comunicações, e valorização de PKI, mensagens offline e forward secrecy.

## 2. Arquitetura da solução

A arquitetura é composta por quatro blocos principais:

1. **CA local / PKI** — entidade responsável por emitir certificados X.509 para utilizadores e para o servidor.
2. **Servidor** — processo central que aceita ligações TLS, autentica clientes, mantém a lista de utilizadores online, encaminha envelopes E2E e persiste mensagens offline cifradas.
3. **Cliente** — aplicação CLI usada por cada utilizador para autenticação, listagem de utilizadores, início de conversas, envio de mensagens e recolha de mensagens offline.
4. **Camada comum** — código partilhado para framing, serialização, certificados, assinaturas, Diffie-Hellman, HKDF e AES-GCM.

A estrutura principal do repositório é:

```text
common/   protocolo, certificados e primitivas criptográficas
pki/      autoridade de certificação local
server/   servidor e persistência de mailboxes
client/   cliente CLI, sessão E2E e persistência local opcional
scripts/  geração de CA, certificados e enrollment de utilizadores
```

## 3. Fluxos funcionais

### 3.1 Inicialização da PKI

A CA local é criada com:

```bash
python -m scripts.init_ca
```

O servidor recebe um certificado TLS com:

```bash
python -m scripts.issue_server_cert --hostname 127.0.0.1
```

Os utilizadores são criados através de um fluxo com CSR ou através do fluxo combinado de testes:

```bash
python -m scripts.enroll_user --username alice
python -m scripts.enroll_user --username bob
```

No fluxo com CSR, o cliente gera a sua chave privada localmente e apenas envia o pedido de certificação à CA. Isto evita que a chave privada do utilizador seja conhecida pela infraestrutura da CA. A chave privada `id_key.pem` é guardada em PEM cifrado com uma password local do utilizador e com permissões `600`. A password nunca é enviada ao servidor nem à CA; é usada apenas para abrir a chave privada local no arranque do cliente.

### 3.2 Autenticação cliente-servidor

A ligação cliente-servidor é estabelecida por TLS, com validação do certificado do servidor contra a CA local. Depois disso, o cliente autentica-se na camada aplicacional por *challenge-response*:

1. O cliente envia `LOGIN_INIT` com o seu username.
2. O servidor gera um nonce aleatório e envia `CHALLENGE`.
3. O cliente assina `ssi-chat-login|username|nonce` com a sua chave privada RSA.
4. O servidor valida a assinatura usando a chave pública do certificado X.509 registado para esse utilizador.

Este mecanismo evita enviar passwords de autenticação ao servidor e impede replay do login, porque cada autenticação usa um nonce novo. A password local da chave privada tem apenas função de proteção em repouso: decifra `id_key.pem` no cliente e não participa no protocolo de autenticação de rede.

### 3.3 Handshake E2E entre clientes

O estabelecimento de sessão E2E usa um handshake do tipo Station-to-Station (STS):

1. O iniciador gera uma chave Diffie-Hellman efémera e envia `HS_INIT` com o seu valor público DH e certificado.
2. O respondedor valida o certificado, gera a sua chave DH efémera, assina o transcript do handshake e envia `HS_REPLY`.
3. O iniciador valida o certificado e a assinatura, deriva as chaves de sessão e envia `HS_FINISH` com a sua assinatura.
4. O respondedor valida a assinatura final e ativa a sessão.

O transcript assinado inclui os identificadores dos dois utilizadores e os dois valores públicos DH. Isto liga a chave negociada às identidades esperadas e reduz ataques de *unknown key-share* ou troca de identidade.

### 3.4 Cross-check de certificados no `/chat`

Antes de iniciar um `/chat`, o cliente iniciador pede ao servidor o certificado registado para o peer através de `GET_CERT`. Quando recebe o `HS_REPLY`, compara o certificado embebido no handshake com o certificado devolvido pelo servidor. Se forem diferentes, o handshake é rejeitado.

Esta validação protege contra o caso em que apareça um certificado alternativo para o mesmo username, mesmo que assinado pela mesma CA. Além disso, o servidor valida envelopes de handshake antes de os encaminhar, confirmando que:

- o campo interno `from` corresponde ao utilizador autenticado que fez `RELAY`;
- o campo interno `to` corresponde ao destinatário real do `RELAY`;
- o certificado anunciado no handshake é exatamente o certificado registado para o utilizador autenticado.

O cliente também valida localmente a consistência entre o remetente externo entregue pelo servidor e os campos `from`/`to` internos do envelope de handshake.

### 3.5 Envio de mensagens

Depois do handshake, cada mensagem é cifrada com AES-256-GCM. O servidor recebe apenas um envelope com:

- `conversation_id`;
- `seq_no`;
- `nonce_b64`;
- `aad_b64`;
- `ciphertext_b64`.

O AAD autentica os metadados essenciais: remetente, destinatário, identificador da conversa e número de sequência. Assim, alterações no envelope provocam falha de autenticação GCM no destinatário.

### 3.6 Mensagens offline

Se o destinatário não estiver online, o servidor guarda o envelope cifrado na mailbox do utilizador. Esta mailbox é persistida em disco com permissões restritas. Como o conteúdo é E2E, o servidor só armazena ciphertext e metadados mínimos de encaminhamento.

Quando o utilizador volta a ligar, pode executar:

```text
/fetch
```

O servidor entrega os envelopes pendentes e remove a mailbox persistida.

### 3.7 Persistência local opcional de sessões

Por omissão, as sessões E2E vivem apenas em memória. Isto preserva melhor a forward secrecy, porque ao reiniciar o cliente as chaves de sessão desaparecem.

Opcionalmente, o cliente pode arrancar com:

```bash
python -m client.client --user-dir data/users/alice --persist-sessions
```

Nesse modo, as sessões são cifradas localmente com uma password e guardadas em disco. Isto permite decifrar mensagens offline depois de reiniciar o cliente, mas sacrifica forward secrecy entre sessões se o ficheiro cifrado e a password forem comprometidos.

## 4. Modelo de segurança

### 4.1 Assunções

A solução assume:

- a CA local é uma raiz de confiança;
- as chaves privadas dos utilizadores não são comprometidas;
- o servidor é honesto para efeitos funcionais e de gestão de identidades, mas curioso quanto ao conteúdo;
- a rede pode ser observada, modificada ou atacada por man-in-the-middle;
- os algoritmos criptográficos usados pela biblioteca `cryptography` são implementados corretamente.

### 4.2 Garantias

A solução oferece:

- **Confidencialidade E2E** — mensagens cifradas com AES-GCM com chaves conhecidas apenas pelos clientes.
- **Integridade das mensagens** — GCM rejeita alterações no ciphertext ou no AAD.
- **Autenticidade cliente-servidor** — TLS valida o servidor e challenge-response valida o cliente.
- **Autenticidade cliente-cliente** — STS com certificados e assinaturas RSA-PSS autentica os participantes do handshake.
- **Proteção contra replay** — cada sessão mantém `seq_no` e conjunto de sequências já vistas.
- **Forward secrecy** — as chaves DH são efémeras e descartadas após derivação das chaves de sessão.
- **Proteção contra identity misbinding** — assinaturas incluem os dois utilizadores e os dois valores DH; o `/chat` faz cross-check do certificado esperado.
- **Proteção dos ficheiros sensíveis locais** — as chaves privadas dos utilizadores são cifradas com password local e escritas com permissões `600`; as diretorias de utilizador usam permissões restritivas.
- **Persistência segura de mailboxes offline** — o servidor guarda apenas envelopes cifrados E2E.

### 4.3 Limitações

A solução tem limitações importantes:

- O servidor continua a ver metadados: quem comunica com quem e quando.
- Não há revogação de certificados por CRL/OCSP.
- Não há rotação automática periódica de sessões E2E enquanto a conversa está ativa.
- A persistência local de sessões, quando ativada, reduz a forward secrecy prática, embora o ficheiro de sessão esteja cifrado com password.
- Não há mensagens de grupo.
- Não há modo descentralizado ou PGP-like.
- A proteção contra DoS é limitada a validação estrutural e limite de tamanho de frames.

## 5. Primitivas criptográficas utilizadas

### 5.1 TLS cliente-servidor

Usado para proteger o canal entre cliente e servidor. O cliente valida o certificado do servidor contra a CA local.

### 5.2 RSA-3072 e RSA-PSS-SHA256

Usado para:

- certificados X.509;
- challenge-response de login;
- assinaturas do handshake STS.

A assinatura usa RSA-PSS com SHA-256, evitando construções RSA determinísticas antigas.

### 5.3 Diffie-Hellman efémero

Usado no handshake E2E para estabelecer um segredo partilhado por sessão. As chaves privadas DH são efémeras e descartadas após derivação.

### 5.4 HKDF-SHA256

O segredo DH bruto não é usado diretamente como chave AES. A solução aplica HKDF-SHA256 para derivar duas chaves direcionais independentes:

- uma para mensagens iniciador → respondedor;
- outra para mensagens respondedor → iniciador.

Isto evita reutilização de nonce sob a mesma chave quando ambos os lados começam com `seq_no = 0`.

### 5.5 AES-256-GCM

Usado como cifra autenticada. Fornece confidencialidade, integridade e autenticação dos dados cifrados e do AAD.

O nonce GCM é derivado deterministicamente do `seq_no`, com 12 bytes: 4 bytes reservados a zero e 8 bytes big-endian para o contador. Como cada direção tem a sua própria chave e o contador é monotónico, o par `(chave, nonce)` não se repete dentro de uma sessão.

## 6. Validações e testes

Foram implementados e validados os seguintes testes:

```bash
python test_security.py
python test_e2e.py
python test_e2e_v2.py
python test_persistence.py
python test_session_persistence.py
```

Os testes cobrem:

- handshake E2E normal;
- rejeição de certificado emitido por CA falsa;
- rejeição de ciphertext adulterado;
- rejeição de AAD adulterado;
- rejeição de replay;
- rejeição de HS_REPLY malicioso;
- rejeição de HS_REPLY com certificado alternativo da mesma CA mas diferente do registado no servidor;
- rejeição, pelo servidor, de handshakes com `from`, `to` ou `cert_b64` inconsistentes;
- troca ponta-a-ponta de várias mensagens;
- persistência de mailboxes offline;
- persistência local cifrada de sessões.

## 7. Funcionalidades implementadas

Funcionalidades-base:

- autenticação de utilizadores;
- listagem de utilizadores;
- início de sessão E2E com `/chat`;
- envio automático de handshake via `/msg`;
- envio e receção de mensagens cifradas;
- recolha de mensagens offline com `/fetch`;
- logout explícito.

Valorizações implementadas:

- PKI local com CA self-signed;
- certificados X.509 para utilizadores e servidor;
- mensagens offline persistidas;
- forward secrecy por DH efémero;
- persistência local cifrada de sessões como modo opcional;
- testes de segurança automatizados.

## 8. Melhorias futuras

Algumas melhorias possíveis seriam:

- implementar revogação de certificados;
- adicionar rotação automática de chaves E2E durante conversas longas;
- suportar mensagens de grupo;
- criar uma camada de ocultação parcial de metadados;
- substituir DH clássico por ECDH com curva moderna;
- adicionar testes de carga e resistência a DoS;
- melhorar UX para recuperação de sessões e resolução de conflitos entre múltiplas sessões do mesmo utilizador.
