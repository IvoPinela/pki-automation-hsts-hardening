from dnslib import RR, A, QTYPE
from dnslib.server import DNSServer, DNSLogger, BaseResolver
import socket

DOMAIN = "app.cyber.local"
IP_ALVO = "127.0.0.1"
DNS_REAL = "8.8.8.8"

class CyberResolver(BaseResolver):
    def resolve(self, request, handler):
        qname = str(request.q.qname).rstrip('.')
        
        # 1. Se for o nosso domínio de teste, respondemos nós
        if qname == DOMAIN:
            print(f"🎯 Redirecionando {DOMAIN} -> {IP_ALVO}")
            reply = request.reply()
            reply.add_answer(RR(request.q.qname, QTYPE.A, rdata=A(IP_ALVO), ttl=60))
            return reply
        
        # 2. Se for outro site, perguntamos ao DNS real (Forwarding)
        print(f"🌐 Consultando internet para: {qname}")
        try:
            proxy_payload = request.send(DNS_REAL, 53, timeout=2.0)
            return request.from_bytes(proxy_payload)
        except Exception:
            return request.reply() # Falha silenciosa

def run_dns():
    resolver = CyberResolver()
    server = DNSServer(resolver, port=53, address='127.0.0.1', logger=None)
    print(f"🚀 Servidor DNS Híbrido Ativo (Internet + Local)!")
    server.start()

if __name__ == "__main__":
    run_dns()