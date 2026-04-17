from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path

from dnslib import A, QTYPE, RCODE, RR
from dnslib.server import BaseResolver, DNSServer

LOGGER = logging.getLogger('dns_lab')


class HybridResolver(BaseResolver):
    def __init__(self, zone_records: dict[str, str], ttl: int, upstream: str):
        self.zone_records = {name.rstrip('.').lower(): ip for name, ip in zone_records.items()}
        self.ttl = ttl
        self.upstream = upstream

    def resolve(self, request, handler):
        qname = str(request.q.qname).rstrip('.').lower()
        qtype = QTYPE[request.q.qtype]
        if qtype == 'A' and qname in self.zone_records:
            LOGGER.info('Local DNS hit: %s -> %s', qname, self.zone_records[qname])
            reply = request.reply()
            reply.add_answer(RR(request.q.qname, QTYPE.A, rdata=A(self.zone_records[qname]), ttl=self.ttl))
            return reply
        try:
            LOGGER.info('Forwarding query: %s (%s) -> %s', qname, qtype, self.upstream)
            proxy_payload = request.send(self.upstream, 53, timeout=2.0)
            return request.from_bytes(proxy_payload)
        except Exception as exc:
            LOGGER.error('Erro ao consultar upstream DNS %s: %s', self.upstream, exc)
            reply = request.reply()
            reply.header.rcode = RCODE.SERVFAIL
            return reply


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Servidor DNS híbrido para laboratório PKI.')
    parser.add_argument('--zone-file', default=str(Path(__file__).resolve().parents[1] / 'web_server' / 'config' / 'dns_records.json'))
    parser.add_argument('--listen-address', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=53)
    parser.add_argument('--upstream', default='8.8.8.8')
    parser.add_argument('--log-level', default='INFO', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'])
    return parser.parse_args()


def load_zone_file(path: Path) -> tuple[dict[str, str], int]:
    payload = json.loads(path.read_text(encoding='utf-8'))
    records = payload.get('records', {})
    ttl = int(payload.get('ttl', 60))
    if not isinstance(records, dict) or not records:
        raise ValueError("O ficheiro de zona deve conter um objeto 'records' não vazio.")
    return records, ttl


def main() -> int:
    args = parse_args()
    logging.basicConfig(level=getattr(logging, args.log_level), format='[%(levelname)s] %(message)s')
    zone_file = Path(args.zone_file)
    if not zone_file.exists():
        print(f'❌ Ficheiro de zona não encontrado: {zone_file}')
        return 1
    try:
        records, ttl = load_zone_file(zone_file)
        resolver = HybridResolver(records, ttl=ttl, upstream=args.upstream)
        server = DNSServer(resolver, port=args.port, address=args.listen_address, logger=None)
        print(f'✅ DNS híbrido ativo em {args.listen_address}:{args.port} | registos locais={len(records)} | upstream={args.upstream}')
        server.start()
        return 0
    except KeyboardInterrupt:
        print('\nDNS terminado pelo utilizador.')
        return 0
    except Exception as exc:
        print(f'❌ Erro ao iniciar o DNS: {exc}')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
