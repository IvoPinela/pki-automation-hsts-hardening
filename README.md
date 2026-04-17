# Relatório Técnico: Implementação de Infraestrutura PKI e Configuração de Servidor Web Seguro

## 1. Enquadramento Académico e Objetivos do Projeto
Este projeto tem como objetivo principal a implementação e configuração de um laboratório prático de Cibersegurança que simula, em ambiente controlado, uma infraestrutura de rede corporativa segura. A necessidade de recorrer a uma **Infraestrutura de Chaves Públicas (PKI)** local surge da impossibilidade de obter certificados fidedignos de Autoridades de Certificação (CA) públicas para domínios de uso interno (como `.local`). 

Ao desenvolver esta solução do zero, o projeto demonstra proficiência em vários domínios da segurança informática:
* **Criptografia Aplicada:** Compreensão prática sobre a geração de chaves RSA, cifragem de ficheiros (AES via PKCS#8) e funções de dispersão (SHA-256).
* **Gestão de Identidades e Confiança:** Estabelecimento de uma "Chain of Trust" (Cadeia de Confiança) rigorosa, com delegação de autoridade através de extensões X.509 (`BasicConstraints`, `KeyUsage`).
* **Segurança de Redes e Resolução de Nomes:** Implementação de um servidor DNS local para interceção e redirecionamento de tráfego de domínio para a interface de *loopback* (`127.0.0.1`), permitindo simular acessos reais a um domínio FQDN (Fully Qualified Domain Name).
* **Hardening de Servidores Web:** Configuração de um Nginx com políticas de segurança estritas, rejeitando protocolos obsoletos e forçando a adoção de HTTPS via **HSTS**.

---

## 2. Arquitetura de Segurança: Os Três Pilares

### I. Hierarquia de Confiança Isolada
O projeto implementa o standard da indústria: uma PKI de duas camadas.
* **Offline Root CA:** O elemento de maior confiança. Utiliza chaves RSA de 4096 bits com validade de 10 anos. Em cenários reais, esta entidade ficaria desligada da rede num cofre físico.
* **Online Issuing (Intermediate) CA:** Assinada pela Root CA, possui `path_length:0`, garantindo que não pode gerar outras CAs. Serve exclusivamente para emitir certificados finais a servidores e utilizadores.

### II. Confidencialidade em Repouso (Chaves Encriptadas)
Em vez de armazenar chaves privadas em texto simples — o que constitui um grave risco de segurança em caso de exfiltração de dados — o projeto exige que a chave do servidor Nginx (`server.key`) seja guardada de forma encriptada no disco. A desencriptação só ocorre na memória volátil (RAM) durante o arranque do serviço Web.

### III. Mitigação de Ataques Man-in-the-Middle (HSTS)
O HTTP Strict Transport Security (HSTS) é o mecanismo de segurança que ordena ao navegador web que comunique com o servidor *exclusivamente* através de ligações HTTPS. Isto invalida ataques de *SSL Stripping*, onde um atacante força a vítima a fazer *downgrade* para HTTP não encriptado.

---

## 3. Estrutura de Diretórios
A organização lógica do laboratório previne a contaminação cruzada de ficheiros entre a entidade emissora e a entidade recetora:

```text
PROJETO_PKI/
├── scripts/
│   ├── common.py               # Lógica partilhada, X.509 extensions e caminhos
│   ├── ca_manager.py           # Gestão da Root CA e Intermediate CA
│   ├── server_manager.py       # Emissão de certificados operacionais (CSR/CRT)
│   ├── dns_server.py           # Resolver DNS local (porta 53)
│   └── verify_pki.py           # Auditoria criptográfica da cadeia X.509
├── offline_root/               # Cofre da Root CA
│   ├── certs/root.crt          # Âncora de confiança a instalar no S.O.
│   └── private/root.key        # Chave mestre (RSA-4096)
├── online_intermediate/        # Cofre da Intermediate CA
│   ├── certs/intermediate.crt  # Certificado Intermédio
│   ├── private/interm.key      # Chave intermédia (RSA-4096)
│   └── csr/server.csr          # Pedido do servidor à espera de assinatura
├── web_server/                 # Domínio aplicacional
│   ├── certs/fullchain.crt     # Certificado Servidor + Certificado Intermédio
│   ├── private/server.key      # Chave Privada Encriptada (RSA-2048)
│   └── config/dns_records.json # Registos DNS (app.cyber.local -> 127.0.0.1)
└── nginx/                      # Servidor Web Front-End
    ├── conf/
    │   ├── nginx.conf          # Configuração de segurança
    │   └── ssl/
    │       ├── global.pass     # Ficheiro com a pass de desencriptação (1234)
    │       ├── fullchain.crt   # Cópia do certificado em produção
    │       └── server.key      # Cópia da chave em produção

```

## 4. Análise Técnica dos Componentes

### O Papel Fundamental do DNS no Laboratório
Para que o browser (Chrome/Edge) valide o certificado SSL, o nome de domínio introduzido na barra de endereços (ex: `app.cyber.local`) tem de coincidir com o *Subject Alternative Name* (SAN) presente no certificado. Como este domínio não existe na internet real, é necessário manipular a resolução de nomes ao nível do Sistema Operativo.

* **A Aplicação Servidor (`dns_server.py`):** Utiliza a biblioteca `dnslib` para abrir um *socket* UDP na porta 53 do endereço `127.0.0.1`. Atua como um *DNS Proxy* Híbrido: se a consulta for para `app.cyber.local`, interceta e responde com `127.0.0.1` (com base no ficheiro `dns_records.json`); se for para qualquer outro site (ex: `google.com`), encaminha o pedido para um *upstream* público (como o `8.8.8.8`), garantindo que a máquina não perde o acesso geral à internet.
* **A Configuração do Cliente (Windows OS):** Apenas executar o script Python não é suficiente. O sistema operativo Windows envia, por defeito, as consultas DNS para o *router* do fornecedor de internet (MEO, NOS, etc.). É obrigatoriamente necessário alterar as definições da placa de rede (ex: interface "Wi-Fi") para forçar o Windows a perguntar primeiramente ao nosso servidor Python (`127.0.0.1`) onde fica o domínio `app.cyber.local`.
* **`verify_pki.py`:** Executa uma verificação criptográfica manual rigorosa (independente do browser), validando assinaturas PKCS#1 v1.5, restrições de CA, extensões de utilização (`ExtendedKeyUsageOID.SERVER_AUTH`) e a correspondência do Hostname.

---

## 5. Configuração Completa do Nginx (`nginx.conf`)

A configuração abaixo materializa as políticas de segurança. O bloco `http` contém a diretiva essencial `ssl_password_file` que resolve o desafio técnico de ler a chave `server.key` encriptada com a password `1234`.

```nginx
# Define o número de processos de trabalho (1 é suficiente para testes locais)
worker_processes  1;

# Configuração do loop de eventos
events {
    worker_connections  1024;
}

http {
    # Tipos MIME suportados
    include       mime.types;
    default_type  application/octet-stream;
    
    # Otimização de transferência de rede
    sendfile        on;
    keepalive_timeout  65;

    # [COMPONENTE CRÍTICO]: Permite ao Nginx arrancar autonomamente com chaves privadas encriptadas
    # O ficheiro global.pass deve conter apenas a palavra-passe "1234"
    ssl_password_file  ssl/global.pass;

    server {
        # Configuração restrita à porta 443 (HTTPS). O servidor rejeita HTTP (80).
        listen       443 ssl;
        server_name  app.cyber.local localhost;

        # Caminho para os artefactos criptográficos gerados pelo script Python
        ssl_certificate      ssl/fullchain.crt;
        ssl_certificate_key  ssl/server.key;

        # Hardening de TLS: Desativar TLSv1.0 e TLSv1.1 (vulneráveis)
        ssl_protocols        TLSv1.2 TLSv1.3;
        
        # Hardening de Cifras: Exigir algoritmos fortes e rejeitar hashes/cifras obsoletas (MD5, NULL)
        ssl_ciphers          HIGH:!aNULL:!MD5;
        ssl_prefer_server_ciphers  on;

        # [COMPONENTE CRÍTICO]: HTTP Strict Transport Security (HSTS)
        # max-age=31536000 força o HTTPS por 1 ano civil completo
        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;

        # Raiz documental do Nginx
        location / {
            root   html;
            index  index.html index.htm;
        }
    }
}
```

---

## 6. Procedimento de Replicação do Laboratório

Para que o sistema demonstre o cadeado verde e suporte todo o ecossistema delineado, siga os passos abaixo:

**Pré-requisito: Download do Nginx**
Caso ainda não possua o Nginx instalado, descarregue a versão para Windows a partir do site oficial:
🔗 **Link para Download:** [https://nginx.org/en/download.html](https://nginx.org/en/download.html)
*(Extraia os ficheiros para uma diretoria local, como o seu Ambiente de Trabalho).*

1. **Instalação da Root CA no Windows:** Para que os navegadores confiem na cadeia, execute um duplo-clique no ficheiro `offline_root/certs/root.crt` gerado e importe-o para os **Certificados de Raiz Fidedignos do Computador Local**.
2. **Geração PKI:**
   ```powershell
   python ca_manager.py
   python server_manager.py --domain app.cyber.local --server-password 1234
   ```
3. **Mapeamento Nginx:** Crie a pasta `ssl` no diretório de configuração do Nginx, transfira o `fullchain.crt`, o `server.key`, e crie o `global.pass` contendo o texto `1234`.
4. **Resolução DNS (Script e Sistema Operativo):** Em terminais com privilégios administrativos (Executar como Administrador):
   * Inicie o servidor DNS Python que fará a interceção:
     ```powershell
     python dns_server.py
     ```
   * Altere a configuração da placa de rede do Windows para apontar para o laboratório local:
     ```powershell
     Set-DnsClientServerAddress -InterfaceAlias "Wi-Fi" -ServerAddresses ("127.0.0.1")
     ```
     *(Nota: Se usar cabo de rede, altere "Wi-Fi" para "Ethernet").*
5. **Ativação Nginx:** Noutro terminal, arranque o servidor HTTPs:
   ```powershell
   .\nginx.exe -t  # Para validar a sintaxe
   start nginx     # Para execução em background
   ```
6. **Teste Final:** Aceda a `https://app.cyber.local`. Inspecione o certificado no browser para validar a cadeia de confiança e as respostas de rede (F12 > Network) para confirmar a injeção do cabeçalho de segurança HSTS.

---

## 7. Reversão do Ambiente (Limpeza do Laboratório)

Após a conclusão das simulações e testes do projeto, é estritamente necessário reverter as alterações efetuadas ao nível do Sistema Operativo para garantir que o computador volta a resolver nomes de domínio da Internet de forma nativa e segura, sem depender do script Python em *loopback*.

Para repor o DNS automático (via DHCP) no Windows, abra o PowerShell como Administrador e execute:

```powershell
# Comando para repor as configurações da placa Wi-Fi
Set-DnsClientServerAddress -InterfaceAlias "Wi-Fi" -ResetServerAddresses
```
*(Nota: Substitua "Wi-Fi" por "Ethernet" se o laboratório tiver sido configurado com uma ligação por cabo).*

Para garantir o encerramento completo do servidor Nginx e libertar as portas do sistema, execute:
```powershell
taskkill /f /im nginx.exe
```
