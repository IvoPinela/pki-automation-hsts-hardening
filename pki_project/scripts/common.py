from __future__ import annotations

import getpass
import os
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Sequence

from cryptography import x509
from cryptography.hazmat.primitives import serialization

PROJECT_ROOT = Path(__file__).resolve().parents[1]
OFFLINE_ROOT_DIR = PROJECT_ROOT / "offline_root"
ONLINE_INTERMEDIATE_DIR = PROJECT_ROOT / "online_intermediate"
WEB_SERVER_DIR = PROJECT_ROOT / "web_server"

ROOT_CERT_PATH = OFFLINE_ROOT_DIR / "certs" / "root.crt"
ROOT_KEY_PATH = OFFLINE_ROOT_DIR / "private" / "root.key"
INTERMEDIATE_CERT_PATH = ONLINE_INTERMEDIATE_DIR / "certs" / "intermediate.crt"
INTERMEDIATE_KEY_PATH = ONLINE_INTERMEDIATE_DIR / "private" / "intermediate.key"
SERVER_CERT_PATH = WEB_SERVER_DIR / "certs" / "server.crt"
SERVER_KEY_PATH = WEB_SERVER_DIR / "private" / "server.key"
SERVER_FULLCHAIN_PATH = WEB_SERVER_DIR / "certs" / "fullchain.crt"
SERVER_CSR_PATH = ONLINE_INTERMEDIATE_DIR / "csr" / "server.csr"


class PKIError(RuntimeError):
    """Base error for project-specific PKI failures."""


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def cert_not_valid_before_utc(cert: x509.Certificate) -> datetime:
    if hasattr(cert, 'not_valid_before_utc'):
        return cert.not_valid_before_utc
    return cert.not_valid_before.replace(tzinfo=timezone.utc)


def cert_not_valid_after_utc(cert: x509.Certificate) -> datetime:
    if hasattr(cert, 'not_valid_after_utc'):
        return cert.not_valid_after_utc
    return cert.not_valid_after.replace(tzinfo=timezone.utc)


def ensure_runtime_directories() -> None:
    directories = [
        OFFLINE_ROOT_DIR / "certs",
        OFFLINE_ROOT_DIR / "private",
        OFFLINE_ROOT_DIR / "crl",
        ONLINE_INTERMEDIATE_DIR / "certs",
        ONLINE_INTERMEDIATE_DIR / "private",
        ONLINE_INTERMEDIATE_DIR / "csr",
        ONLINE_INTERMEDIATE_DIR / "crl",
        WEB_SERVER_DIR / "certs",
        WEB_SERVER_DIR / "private",
        WEB_SERVER_DIR / "config",
        WEB_SERVER_DIR / "public",
    ]
    for directory in directories:
        directory.mkdir(parents=True, exist_ok=True)


def _restrict_permissions(path: Path) -> None:
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except PermissionError:
        pass


def write_bytes(path: Path, payload: bytes, private: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    if private:
        _restrict_permissions(path)


def load_certificate(path: Path) -> x509.Certificate:
    if not path.exists():
        raise PKIError(f"Certificado não encontrado: {path}")
    return x509.load_pem_x509_certificate(path.read_bytes())


def load_private_key(path: Path, password: bytes | None):
    if not path.exists():
        raise PKIError(f"Chave privada não encontrada: {path}")
    return serialization.load_pem_private_key(path.read_bytes(), password=password)


def resolve_password(*, password: str | None, password_env: str | None, prompt_label: str, allow_unencrypted: bool) -> bytes | None:
    if password:
        return password.encode("utf-8")
    if password_env:
        env_value = os.getenv(password_env)
        if env_value:
            return env_value.encode("utf-8")
    if allow_unencrypted:
        return None
    if not os.isatty(0):
        hint = f" ou define a variável de ambiente '{password_env}'" if password_env else ""
        raise PKIError(f"É necessária uma password para {prompt_label}{hint}. Usa --allow-unencrypted apenas em laboratório.")
    first = getpass.getpass(f"Password para {prompt_label}: ")
    if not first:
        raise PKIError(f"A password para {prompt_label} não pode ser vazia.")
    second = getpass.getpass(f"Confirma a password para {prompt_label}: ")
    if first != second:
        raise PKIError(f"As passwords para {prompt_label} não coincidem.")
    return first.encode("utf-8")


def key_encryption(password: bytes | None) -> serialization.KeySerializationEncryption:
    if password:
        return serialization.BestAvailableEncryption(password)
    return serialization.NoEncryption()


def serialize_private_key(private_key, password: bytes | None) -> bytes:
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=key_encryption(password),
    )


def serialize_certificate(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def build_crl_distribution_points(urls: Sequence[str]) -> x509.CRLDistributionPoints:
    distribution_points = [
        x509.DistributionPoint(
            full_name=[x509.UniformResourceIdentifier(url) for url in urls],
            relative_name=None,
            reasons=None,
            crl_issuer=None,
        )
    ]
    return x509.CRLDistributionPoints(distribution_points)


def build_aia(issuer_urls: Sequence[str]) -> x509.AuthorityInformationAccess:
    descriptions = [
        x509.AccessDescription(
            x509.AuthorityInformationAccessOID.CA_ISSUERS,
            x509.UniformResourceIdentifier(url),
        )
        for url in issuer_urls
    ]
    return x509.AuthorityInformationAccess(descriptions)


def default_crl_urls(base_domain: str) -> tuple[list[str], list[str]]:
    base_domain = base_domain.strip().lower()
    return [f"http://pki.{base_domain}/crl/root.crl"], [f"http://pki.{base_domain}/crl/intermediate.crl"]


def default_ca_issuer_urls(base_domain: str) -> tuple[list[str], list[str]]:
    base_domain = base_domain.strip().lower()
    return [f"http://pki.{base_domain}/ca/root.crt"], [f"http://pki.{base_domain}/ca/intermediate.crt"]


def sanitize_dns_names(names: Iterable[str]) -> list[str]:
    cleaned: list[str] = []
    for name in names:
        value = name.strip().lower().rstrip('.')
        if value and value not in cleaned:
            cleaned.append(value)
    if not cleaned:
        raise PKIError('É necessário pelo menos um nome DNS válido.')
    return cleaned
