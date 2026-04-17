from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509.oid import ExtendedKeyUsageOID

from common import (
    INTERMEDIATE_CERT_PATH,
    ROOT_CERT_PATH,
    SERVER_CERT_PATH,
    PKIError,
    cert_not_valid_after_utc,
    cert_not_valid_before_utc,
    load_certificate,
)


class VerificationFailure(PKIError):
    pass


def get_extension(cert: x509.Certificate, extension_type):
    return cert.extensions.get_extension_for_class(extension_type).value


def verify_signature(issuer: x509.Certificate, subject: x509.Certificate) -> None:
    issuer.public_key().verify(subject.signature, subject.tbs_certificate_bytes, padding.PKCS1v15(), subject.signature_hash_algorithm)


def check_validity(cert: x509.Certificate, *, label: str, moment: datetime) -> None:
    if moment < cert_not_valid_before_utc(cert):
        raise VerificationFailure(f'{label}: ainda não é válido.')
    if moment > cert_not_valid_after_utc(cert):
        raise VerificationFailure(f'{label}: já expirou.')


def check_root(root: x509.Certificate, *, moment: datetime) -> None:
    if root.issuer != root.subject:
        raise VerificationFailure('Root CA: issuer e subject deveriam coincidir.')
    verify_signature(root, root)
    check_validity(root, label='Root CA', moment=moment)
    basic_constraints = get_extension(root, x509.BasicConstraints)
    if not basic_constraints.ca:
        raise VerificationFailure('Root CA: o certificado não está marcado como CA.')


def check_intermediate(root: x509.Certificate, intermediate: x509.Certificate, *, moment: datetime) -> None:
    if intermediate.issuer != root.subject:
        raise VerificationFailure('Intermediate CA: issuer não corresponde à Root CA.')
    verify_signature(root, intermediate)
    check_validity(intermediate, label='Intermediate CA', moment=moment)
    basic_constraints = get_extension(intermediate, x509.BasicConstraints)
    if not basic_constraints.ca:
        raise VerificationFailure('Intermediate CA: o certificado não está marcado como CA.')
    if basic_constraints.path_length != 0:
        raise VerificationFailure('Intermediate CA: path_length esperado era 0.')
    key_usage = get_extension(intermediate, x509.KeyUsage)
    if not key_usage.key_cert_sign:
        raise VerificationFailure('Intermediate CA: falta keyCertSign no KeyUsage.')


def hostname_matches(cert: x509.Certificate, hostname: str) -> None:
    sans = get_extension(cert, x509.SubjectAlternativeName)
    dns_names = [value.lower() for value in sans.get_values_for_type(x509.DNSName)]
    ip_addresses = [str(ip) for ip in sans.get_values_for_type(x509.IPAddress)]
    hostname = hostname.strip().lower()

    if hostname in dns_names or hostname in ip_addresses:
        return

    wildcard_matches = [name for name in dns_names if name.startswith('*.')]
    for wildcard in wildcard_matches:
        suffix = wildcard[1:]
        if hostname.endswith(suffix) and hostname.count('.') >= wildcard.count('.'):
            return

    raise VerificationFailure(f'Hostname {hostname!r} não corresponde aos SANs do certificado.')


def check_server(intermediate: x509.Certificate, server: x509.Certificate, *, hostname: str, moment: datetime) -> None:
    if server.issuer != intermediate.subject:
        raise VerificationFailure('Server cert: issuer não corresponde à Intermediate CA.')
    verify_signature(intermediate, server)
    check_validity(server, label='Server cert', moment=moment)
    hostname_matches(server, hostname)
    basic_constraints = get_extension(server, x509.BasicConstraints)
    if basic_constraints.ca:
        raise VerificationFailure('Server cert: não deve estar marcado como CA.')
    key_usage = get_extension(server, x509.KeyUsage)
    if not key_usage.digital_signature:
        raise VerificationFailure('Server cert: falta digitalSignature no KeyUsage.')
    if not (key_usage.key_encipherment or key_usage.key_agreement):
        raise VerificationFailure('Server cert: falta capacidade de encipherment/agreement no KeyUsage.')
    eku = get_extension(server, x509.ExtendedKeyUsage)
    if ExtendedKeyUsageOID.SERVER_AUTH not in eku:
        raise VerificationFailure('Server cert: falta serverAuth no ExtendedKeyUsage.')


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Valida a cadeia Root -> Intermediate -> Server.')
    parser.add_argument('--hostname', default='app.cyber.local')
    parser.add_argument('--root-cert', default=str(ROOT_CERT_PATH))
    parser.add_argument('--intermediate-cert', default=str(INTERMEDIATE_CERT_PATH))
    parser.add_argument('--server-cert', default=str(SERVER_CERT_PATH))
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        root = load_certificate(Path(args.root_cert))
        intermediate = load_certificate(Path(args.intermediate_cert))
        server = load_certificate(Path(args.server_cert))
        moment = datetime.now(timezone.utc)
        print('A iniciar validação técnica da cadeia...\n')
        check_root(root, moment=moment)
        print('✅ [1/5] Root CA autoassinada e válida.')
        check_intermediate(root, intermediate, moment=moment)
        print('✅ [2/5] Intermediate CA assinada pela Root e com constraints corretas.')
        check_server(intermediate, server, hostname=args.hostname, moment=moment)
        print('✅ [3/5] Certificado do servidor assinado pela Intermediate.')
        print('✅ [4/5] Hostname e período de validade corretos.')
        print('✅ [5/5] KeyUsage / EKU do servidor corretos.')
        print('\nConclusão: a cadeia de confiança está íntegra e consistente para o hostname indicado.')
        return 0
    except VerificationFailure as exc:
        print(f'❌ Falha de verificação: {exc}')
        return 1
    except PKIError as exc:
        print(f'❌ Erro de configuração: {exc}')
        return 1
    except Exception as exc:
        print(f'❌ Erro inesperado: {exc}')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
