import os
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# --- CONFIGURAÇÕES DE CAMINHOS ---
INT_DIR = "online_intermediate"
SERVER_DIR = "web_server"

def load_cert(path):
    """Carrega um certificado PEM do disco."""
    with open(path, "rb") as f:
        return x509.load_pem_x509_certificate(f.read())

def load_key(path):
    """Carrega uma chave privada PEM do disco."""
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def save_pem(data, path):
    """Auxiliar para gravar ficheiros PEM."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)

def create_server_certificate(domain="app.cyber.local"):
    print(f"Iniciar a emissão para o domínio: {domain}")

    # 1. Carregar a Autoridade Intermédia (Certificado e Chave)
    try:
        int_cert = load_cert(f"{INT_DIR}/certs/intermediate.crt")
        int_key = load_key(f"{INT_DIR}/private/intermediate.key")
    except FileNotFoundError:
        print("❌ Erro: Certificados da Intermediate CA não encontrados. Corre o ca_manager.py primeiro.")
        return

    # 2. Gerar Chave Privada do Servidor Web (2048 bits para performance/compatibilidade)
    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # 3. Preparar a Identidade e Extensões (SAN)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PT"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Laboratorio Ciberseguranca"),
        x509.NameAttribute(NameOID.COMMON_NAME, domain),
    ])

    # Extensão SAN: Crucial para evitar erros no Chrome/Firefox
    san = x509.SubjectAlternativeName([
        x509.DNSName(domain),
        x509.DNSName(f"www.{domain}"),
        x509.DNSName("localhost")
    ])

    # 4. GERAR O CSR (Certificate Signing Request)
    # Isto preenche a tua pasta 'csr' e simula o pedido formal à CA
    csr = x509.CertificateSigningRequestBuilder().subject_name(
        subject
    ).add_extension(
        san, critical=False,
    ).sign(server_key, hashes.SHA256())

    # 5. ASSINAR O CERTIFICADO (A CA Intermédia processa o CSR)
    server_cert = x509.CertificateBuilder().subject_name(
        csr.subject
    ).issuer_name(
        int_cert.subject
    ).public_key(
        csr.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.now(timezone.utc)
    ).not_valid_after(
        datetime.now(timezone.utc) + timedelta(days=365) # Válido por 1 ano
    ).add_extension(
        san, critical=False
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True
    ).add_extension(
        # Define que esta chave serve para autenticação de servidor e cifragem
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=True,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        ), critical=True
    ).sign(int_key, hashes.SHA256())

    # 6. GUARDAR OS FICHEIROS NO DISCO
    
    # Guardar Chave Privada
    key_pem = server_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    save_pem(key_pem, f"{SERVER_DIR}/private/server.key")

    # Guardar o CSR (Para o teu portfólio/relatório)
    save_pem(csr.public_bytes(serialization.Encoding.PEM), f"{INT_DIR}/csr/server.csr")

    # Guardar o Certificado Individual
    cert_pem = server_cert.public_bytes(serialization.Encoding.PEM)
    save_pem(cert_pem, f"{SERVER_DIR}/certs/server.crt")

    # 7. CRIAR A FULL CHAIN (Cadeia Completa)
    # Importante: O Nginx precisa do certificado do servidor + o da intermédia
    int_pem = int_cert.public_bytes(serialization.Encoding.PEM)
    save_pem(cert_pem + int_pem, f"{SERVER_DIR}/certs/fullchain.crt")

    print("-" * 40)
    print("✅ Sucesso: Certificados do servidor gerados!")
    print(f"📂 CSR guardado em: {INT_DIR}/csr/server.csr")
    print(f"📂 Full Chain guardada em: {SERVER_DIR}/certs/fullchain.crt")
    print("-" * 40)

if __name__ == "__main__":
    create_server_certificate()