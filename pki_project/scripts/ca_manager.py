from __future__ import annotations

import argparse
from datetime import timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from common import (
    INTERMEDIATE_CERT_PATH,
    INTERMEDIATE_KEY_PATH,
    ROOT_CERT_PATH,
    ROOT_KEY_PATH,
    PKIError,
    build_aia,
    build_crl_distribution_points,
    default_ca_issuer_urls,
    default_crl_urls,
    ensure_runtime_directories,
    now_utc,
    resolve_password,
    serialize_certificate,
    serialize_private_key,
    write_bytes,
)


def generate_private_key(key_size: int) -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=key_size)


def build_name(country: str, state: str, organization: str, common_name: str) -> x509.Name:
    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])


def create_root_ca(args: argparse.Namespace, password: bytes | None):
    root_key = generate_private_key(args.root_key_size)
    subject = build_name(args.country, args.state, args.organization, args.root_common_name)
    not_before = now_utc()
    not_after = not_before + timedelta(days=args.root_valid_days)
    root_crl_urls, _ = default_crl_urls(args.base_domain)
    _, root_aia_urls = default_ca_issuer_urls(args.base_domain)

    root_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=False,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False,
        ), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(root_key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()), critical=False)
        .add_extension(build_crl_distribution_points(root_crl_urls), critical=False)
        .add_extension(build_aia(root_aia_urls), critical=False)
        .sign(root_key, hashes.SHA256())
    )

    write_bytes(ROOT_KEY_PATH, serialize_private_key(root_key, password), private=True)
    write_bytes(ROOT_CERT_PATH, serialize_certificate(root_cert))
    return root_key, root_cert


def create_intermediate_ca(args: argparse.Namespace, root_key, root_cert, password: bytes | None):
    intermediate_key = generate_private_key(args.intermediate_key_size)
    subject = build_name(args.country, args.state, args.organization, args.intermediate_common_name)
    not_before = now_utc()
    not_after = not_before + timedelta(days=args.intermediate_valid_days)
    _, intermediate_crl_urls = default_crl_urls(args.base_domain)
    _, intermediate_aia_urls = default_ca_issuer_urls(args.base_domain)

    intermediate_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(root_cert.subject)
        .public_key(intermediate_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=False,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=True,
            encipher_only=False,
            decipher_only=False,
        ), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(intermediate_key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()), critical=False)
        .add_extension(build_crl_distribution_points(intermediate_crl_urls), critical=False)
        .add_extension(build_aia(intermediate_aia_urls), critical=False)
        .sign(root_key, hashes.SHA256())
    )

    write_bytes(INTERMEDIATE_KEY_PATH, serialize_private_key(intermediate_key, password), private=True)
    write_bytes(INTERMEDIATE_CERT_PATH, serialize_certificate(intermediate_cert))
    return intermediate_key, intermediate_cert


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Gera uma Root CA e uma Intermediate CA para laboratório.')
    parser.add_argument('--country', default='PT')
    parser.add_argument('--state', default='Lisboa')
    parser.add_argument('--organization', default='Cybersecurity Master Project')
    parser.add_argument('--root-common-name', default='Offline Root CA')
    parser.add_argument('--intermediate-common-name', default='Online Issuing CA')
    parser.add_argument('--root-key-size', type=int, default=4096)
    parser.add_argument('--intermediate-key-size', type=int, default=4096)
    parser.add_argument('--root-valid-days', type=int, default=3650)
    parser.add_argument('--intermediate-valid-days', type=int, default=1825)
    parser.add_argument('--base-domain', default='cyber.local')
    parser.add_argument('--root-password')
    parser.add_argument('--root-password-env')
    parser.add_argument('--root-allow-unencrypted', action='store_true')
    parser.add_argument('--intermediate-password')
    parser.add_argument('--intermediate-password-env')
    parser.add_argument('--intermediate-allow-unencrypted', action='store_true')
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    ensure_runtime_directories()
    try:
        root_password = resolve_password(password=args.root_password, password_env=args.root_password_env, prompt_label='a Root CA', allow_unencrypted=args.root_allow_unencrypted)
        intermediate_password = resolve_password(password=args.intermediate_password, password_env=args.intermediate_password_env, prompt_label='a Intermediate CA', allow_unencrypted=args.intermediate_allow_unencrypted)
        root_key, root_cert = create_root_ca(args, root_password)
        _, intermediate_cert = create_intermediate_ca(args, root_key, root_cert, intermediate_password)
        print('-' * 60)
        print('✅ Hierarquia PKI criada com sucesso')
        print(f'Root key: {ROOT_KEY_PATH}')
        print(f'Root cert: {ROOT_CERT_PATH}')
        print(f'Intermediate key: {INTERMEDIATE_KEY_PATH}')
        print(f'Intermediate cert: {INTERMEDIATE_CERT_PATH}')
        print(f'Root subject: {root_cert.subject.rfc4514_string()}')
        print(f'Intermediate subject: {intermediate_cert.subject.rfc4514_string()}')
        print('-' * 60)
        return 0
    except PKIError as exc:
        print(f'❌ Erro de configuração: {exc}')
        return 1
    except Exception as exc:
        print(f'❌ Erro inesperado: {exc}')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
