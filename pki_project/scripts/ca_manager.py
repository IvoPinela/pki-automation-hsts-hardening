import os
from datetime import datetime, timedelta, timezone
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# --- CONFIGURAÇÕES DE CAMINHOS ---
ROOT_DIR = "offline_root"
INT_DIR = "online_intermediate"

def generate_private_key(key_size=4096):
    """Gera uma chave RSA forte."""
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size
    )

def save_pem(data, path):
    """Guarda dados em formato PEM no disco."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)

def create_root_ca():
    """Cria a Root CA (Âncora de Confiança)."""
    print("Generating Root CA...")
    
    # 1. Chave Privada
    key = generate_private_key()
    
    # 2. Identidade (Subject e Issuer são iguais na Root)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PT"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Lisboa"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Cybersecurity Master Project"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Offline Root CA"),
    ])

    # 3. Construção do Certificado
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.now(timezone.utc)
    ).not_valid_after(
        datetime.now(timezone.utc) + timedelta(days=3650)  # 10 Anos
    ).add_extension(
        # CRÍTICO: Define que este certificado é uma CA
        x509.BasicConstraints(ca=True, path_length=None), critical=True,
    ).add_extension(
        # Define o uso da chave (Assinar certificados e CRLs)
        x509.KeyUsage(
            digital_signature=False,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False,
        ), critical=True,
    ).sign(key, hashes.SHA256())

    # 4. Serialização e Escrita
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption() # Em prod, usaria password
    )
    
    save_pem(key_pem, f"{ROOT_DIR}/private/root.key")
    save_pem(cert.public_bytes(serialization.Encoding.PEM), f"{ROOT_DIR}/certs/root.crt")
    
    return key, cert

def create_intermediate_ca(root_key, root_cert):
    """Cria a Intermediate CA assinada pela Root."""
    print("Generating Intermediate CA...")
    
    # 1. Chave da Intermediate
    int_key = generate_private_key()
    
    # 2. Identidade
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PT"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Cybersecurity Master Project"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Online Issuing CA"),
    ])

    # 3. Construção do Certificado Assinado pela Root
    int_cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        root_cert.subject # O emissor é a Root
    ).public_key(
        int_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.now(timezone.utc)
    ).not_valid_after(
        datetime.now(timezone.utc) + timedelta(days=1825) # 5 Anos
    ).add_extension(
        # CRÍTICO: path_length=0 significa que esta CA pode assinar sites, 
        # mas não pode criar outras CAs abaixo dela. Excelente para o mestrado.
        x509.BasicConstraints(ca=True, path_length=0), critical=True,
    ).add_extension(
        x509.KeyUsage(
            digital_signature=False,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False,
        ), critical=True,
    ).sign(root_key, hashes.SHA256())

    # 4. Guardar Ficheiros
    key_pem = int_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    save_pem(key_pem, f"{INT_DIR}/private/intermediate.key")
    save_pem(int_cert.public_bytes(serialization.Encoding.PEM), f"{INT_DIR}/certs/intermediate.crt")
    
    return int_key, int_cert

if __name__ == "__main__":
    try:
        # Gerar a Hierarquia
        r_key, r_cert = create_root_ca()
        i_key, i_cert = create_intermediate_ca(r_key, r_cert)
        
        print("-" * 30)
        print("✅ PKI Base criada com sucesso!")
        print(f"📍 Root em: {ROOT_DIR}")
        print(f"📍 Intermediate em: {INT_DIR}")
        print("-" * 30)
        
    except Exception as e:
        print(f"❌ Erro durante a geração: {e}")