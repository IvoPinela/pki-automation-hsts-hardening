from __future__ import annotations

import argparse
from datetime import timedelta
from ipaddress import ip_address

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from common import (
    INTERMEDIATE_CERT_PATH,
    INTERMEDIATE_KEY_PATH,
    SERVER_CERT_PATH,
    SERVER_CSR_PATH,
    SERVER_FULLCHAIN_PATH,
    SERVER_KEY_PATH,
    PKIError,
    build_aia,
    build_crl_distribution_points,
    default_ca_issuer_urls,
    default_crl_urls,
    ensure_runtime_directories,
    load_certificate,
    load_private_key,
    now_utc,
    resolve_password,
    sanitize_dns_names,
    serialize_certificate,
    serialize_private_key,
    write_bytes,
)


def build_subject(country: str, organization: str, common_name: str) -> x509.Name:
    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])


def build_san(domain: str, dns_names: list[str], ip_sans: list[str]) -> x509.SubjectAlternativeName:
    values = [x509.DNSName(name) for name in sanitize_dns_names([domain, *dns_names])]
    for value in ip_sans:
        values.append(x509.IPAddress(ip_address(value)))
    return x509.SubjectAlternativeName(values)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Gera CSR e certificado de servidor assinados pela CA intermédia.')
    parser.add_argument('--domain', default='app.cyber.local')
    parser.add_argument('--country', default='PT')
    parser.add_argument('--organization', default='Laboratorio Ciberseguranca')
    parser.add_argument('--valid-days', type=int, default=365)
    parser.add_argument('--key-size', type=int, default=2048)
    parser.add_argument('--base-domain', default='cyber.local')
    parser.add_argument('--dns-san', action='append', default=[])
    parser.add_argument('--ip-san', action='append', default=[])
    parser.add_argument('--intermediate-password')
    parser.add_argument('--intermediate-password-env')
    parser.add_argument('--intermediate-allow-unencrypted', action='store_true')
    parser.add_argument('--server-password')
    parser.add_argument('--server-password-env')
    parser.add_argument('--server-allow-unencrypted', action='store_true')
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    ensure_runtime_directories()
    try:
        intermediate_password = resolve_password(password=args.intermediate_password, password_env=args.intermediate_password_env, prompt_label='a chave da Intermediate CA', allow_unencrypted=args.intermediate_allow_unencrypted)
        server_password = resolve_password(password=args.server_password, password_env=args.server_password_env, prompt_label='a chave do servidor', allow_unencrypted=args.server_allow_unencrypted)
        intermediate_cert = load_certificate(INTERMEDIATE_CERT_PATH)
        intermediate_key = load_private_key(INTERMEDIATE_KEY_PATH, intermediate_password)
        server_key = rsa.generate_private_key(public_exponent=65537, key_size=args.key_size)
        subject = build_subject(args.country, args.organization, args.domain)
        san = build_san(args.domain, args.dns_san, args.ip_san)

        csr = x509.CertificateSigningRequestBuilder().subject_name(subject).add_extension(san, critical=False).sign(server_key, hashes.SHA256())

        _, intermediate_crl_urls = default_crl_urls(args.base_domain)
        _, intermediate_aia_urls = default_ca_issuer_urls(args.base_domain)
        not_before = now_utc()
        not_after = not_before + timedelta(days=args.valid_days)

        server_cert = (
            x509.CertificateBuilder()
            .subject_name(csr.subject)
            .issuer_name(intermediate_cert.subject)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .add_extension(san, critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(server_key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(intermediate_key.public_key()), critical=False)
            .add_extension(build_crl_distribution_points(intermediate_crl_urls), critical=False)
            .add_extension(build_aia(intermediate_aia_urls), critical=False)
            .sign(intermediate_key, hashes.SHA256())
        )

        write_bytes(SERVER_KEY_PATH, serialize_private_key(server_key, server_password), private=True)
        write_bytes(SERVER_CSR_PATH, csr.public_bytes(serialization.Encoding.PEM))
        write_bytes(SERVER_CERT_PATH, serialize_certificate(server_cert))
        write_bytes(SERVER_FULLCHAIN_PATH, serialize_certificate(server_cert) + serialize_certificate(intermediate_cert))

        print('-' * 60)
        print('✅ Certificado de servidor emitido com sucesso')
        print(f'Server key: {SERVER_KEY_PATH}')
        print(f'Server CSR: {SERVER_CSR_PATH}')
        print(f'Server cert: {SERVER_CERT_PATH}')
        print(f'Server fullchain: {SERVER_FULLCHAIN_PATH}')
        print(f'Subject: {server_cert.subject.rfc4514_string()}')
        print('-' * 60)
        return 0
    except PKIError as exc:
        print(f'❌ Erro de configuração: {exc}')
        return 1
    except FileNotFoundError as exc:
        print(f'❌ Ficheiro em falta: {exc}')
        return 1
    except ValueError as exc:
        print(f'❌ Valor inválido: {exc}')
        return 1
    except Exception as exc:
        print(f'❌ Erro inesperado: {exc}')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
