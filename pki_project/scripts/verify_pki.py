from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding

def verify_chain():
    try:
        # 1. Carregar os certificados do disco
        with open("offline_root/certs/root.crt", "rb") as f:
            root = x509.load_pem_x509_certificate(f.read())
        with open("online_intermediate/certs/intermediate.crt", "rb") as f:
            intermediate = x509.load_pem_x509_certificate(f.read())
        with open("web_server/certs/server.crt", "rb") as f:
            server = x509.load_pem_x509_certificate(f.read())

        print("🔍 A iniciar validação técnica da cadeia...")

        # 2. VERIFICAÇÃO 1: A Root assinou a Intermediate?
        # Usamos a chave pública da ROOT para verificar a assinatura da INTERMEDIATE
        root.public_key().verify(
            intermediate.signature,
            intermediate.tbs_certificate_bytes,
            padding.PKCS1v15(),
            intermediate.signature_hash_algorithm,
        )
        print("✅ [1/2] Root CA -> Intermediate CA: Assinatura Válida.")

        # 3. VERIFICAÇÃO 2: A Intermediate assinou o Server?
        # Usamos a chave pública da INTERMEDIATE para verificar a assinatura do SERVER
        intermediate.public_key().verify(
            server.signature,
            server.tbs_certificate_bytes,
            padding.PKCS1v15(),
            server.signature_hash_algorithm,
        )
        print("✅ [2/2] Intermediate CA -> Server Cert: Assinatura Válida.")

        print("\n🏆 CONCLUSÃO: A cadeia de confiança está íntegra e funcional!")

    except Exception as e:
        print(f"\n❌ ERRO NA VALIDAÇÃO: {e}")
        print("Dica: Certifica-te que correstes o ca_manager.py e o server_manager.py recentemente.")

if __name__ == "__main__":
    verify_chain()