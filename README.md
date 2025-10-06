# 🛡️ Gerenciamento de Acesso - Linux Embarcado

Projeto desenvolvido para **Raspberry Pi 4** que implementa um sistema de gerenciamento de acesso com:

- Controle de **portas via GPIO** (abrir/fechar)
- **Cadastro e autenticação de usuários** (roles USER/ADMIN, senhas com SHA-512)
- Registro e consulta de **eventos de acesso**
- **Interface interativa** em terminal ou via **UART** (menu de texto)
- Envio de dados para **servidor HTTP** (JSON)
- Comunicação com servidor usando **Modbus RTU encapsulado em HTTP**
- Suporte a **execução no boot** via systemd

---


## ⚡ Funcionalidades

### Menu principal


=== GERENCIAMENTO DE ACESSO ===

1. Cadastrar usuario

2. Listar usuarios (ADMIN)

3. Testar login (auth)

4. Abrir Porta 1

5. Abrir Porta 2

6. Listar eventos (ADMIN)

7. Sair


### Cadastro de usuário


Nome (a-zA-Z0-9_-.): Victor
Role (admin|user): admin
Senha:
Confirme:
Usuario 'Victor' criado (ADMIN).


### Login e abertura de porta


Usuario: Victor
Senha:

Porta 1 ABERTA por Victor
<<< Porta 1 FECHADA


### Listagem de eventos


2025-10-06T01:10:22-03:00 Victor door=1 action=OPEN

2025-10-06T01:10:27-03:00 Victor door=1 action=CLOSE


---

## 🛠️ Requisitos

- Raspberry Pi OS / Debian / Ubuntu
- Compilador GCC
- Bibliotecas:
  ```bash
  sudo apt-get install build-essential libcurl4-openssl-dev libcrypt-dev jq -y

🔧 Compilação
git clone https://github.com/<seu_usuario>/gerenciamento_de_acesso-linux_embarcado.git
cd gerenciamento_de_acesso-linux_embarcado
gcc -O2 -Wall -o acesso main.c -lcrypt -lcurl

▶️ Uso
Modo terminal
sudo ./acesso

Modo UART
sudo ./acesso --uart


UART padrão: /dev/serial0 a 115200 8N1

🔌 Hardware

Portas (GPIO de saída)

P1 = GPIO17

P2 = GPIO27

Botões (GPIO de entrada, pull-up)

B1 = GPIO22

B2 = GPIO23

📌 Importante: GPIOs do Raspberry são 3,3 V (não toleram 5 V).
Use resistores pull-up externo se não usar o pull-up interno.

🌐 Servidor HTTP

Servidor Python simples para logar requisições:

python3 server.py

Exemplo de evento recebido
POST /api/events {
  "timestamp":"2025-10-06T01:10:22-03:00",
  "user":"Victor",
  "door":1,
  "action":"OPEN"
}

Consultando via curl
curl -s http://127.0.0.1:8080/api/events | jq .


Saída:

[
  {
    "ts": "2025-10-06T01:10:22-03:00",
    "user": "Victor",
    "door": 1,
    "action": "OPEN"
  },
  {
    "ts": "2025-10-06T01:10:27-03:00",
    "user": "Victor",
    "door": 1,
    "action": "CLOSE"
  }
]

🚀 Execução no boot (systemd)
Serviço do app

Arquivo: /etc/systemd/system/acesso.service

[Unit]
Description=Sistema de gerenciamento de acesso (GPIO+UART+HTTP)
After=network.target

[Service]
Type=simple
ExecStart=/home/victor/gerenciamento_de_acesso-linux_embarcado/acesso --uart
Environment=ACESSO_SERVER=http://127.0.0.1:8080
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target

Serviço do servidor

Arquivo: /etc/systemd/system/acesso-server.service

[Unit]
Description=Servidor HTTP de testes (acesso)
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 -u /home/victor/server.py
WorkingDirectory=/home/pi
User=victor
Group=victor
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target

👤 Autor

Victor Alves

Projeto desenvolvido como desafio de Gerenciamento de Acesso em Linux Embarcadi da PD Soluções
