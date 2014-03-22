import logging
import socket
import gevent

import gevent.monkey
from gevent.server import DatagramServer
import dpkt.ip
import dpkt.dns
import dpkt.tcp
import random
import base64
import itertools
import uuid

LOGGER = logging.getLogger(__name__)

print(len(base64.b64encode(uuid.uuid4().get_bytes())))
raw_socket = None
SUFFIX = '.p1.f-q.co'
# [63chars].[63chars].[63chars].[index][uuid].evil.com
MAX_PAYLOAD_LENGTH = 253 - len(SUFFIX) - 4 - 16 - 1 # 4 dot, 16 uuid, 1 index
pending_queries = {}
finished_packet_ids = set()

class HandlerDatagramServer(gevent.server.DatagramServer):
    def __init__(self, address, handler):
        super(HandlerDatagramServer, self).__init__(address)
        self.handler = handler

    def handle(self, request, address):
        self.handler(self.sendto, request, address)


def handle_udp(sendto, raw_request, address):
    request = dpkt.dns.DNS(raw_request)
    query = request.qd[0].name[:-len(SUFFIX)]
    fragment, index, packet_id = query[:-18], query[-17:-16], query[-16:]
    if packet_id not in finished_packet_ids:
        packet_id = uuid.UUID(bytes=packet_id)
        index = ord(index)
        fragment = fragment.replace('.', '').replace('|d', '.').replace('||', '|')
        pending_queries.setdefault(packet_id, {})[index] = fragment
        payload = rebuild_payload(index, packet_id)
        if payload:
            print(payload[1:])
    response = dpkt.dns.DNS(raw_request)
    response.ar = []
    response.set_qr(True)
    response.set_rcode(dpkt.dns.DNS_RCODE_NXDOMAIN)
    sendto(str(response), address)


def rebuild_payload(index, packet_id):
    first_fragment = pending_queries[packet_id].get(0)
    if not first_fragment:
        print('[%s] received %s, missing first fragment' % (packet_id, index))
        return None
    count = ord(first_fragment[0])
    fragments = []
    for i in range(count):
        fragment = pending_queries[packet_id].get(i)
        if not fragment:
            print('[%s] received %s, still missing %s/%s' % (packet_id, index, i + 1, count))
            return None
        fragments.append(fragment)
    print('[%s] done' % packet_id)
    del pending_queries[packet_id]
    finished_packet_ids.add(packet_id.get_bytes())
    for i, fragment in enumerate(fragments):
        print(i, base64.b64encode(fragment))
    return ''.join(fragments)


def start_udp_server():
    LISTEN_IP = ''
    LISTEN_PORT = 53
    server = HandlerDatagramServer((LISTEN_IP, LISTEN_PORT), handle_udp)
    LOGGER.info('serving UDP on port %s:%s...' % (LISTEN_IP, LISTEN_PORT))
    server.serve_forever()


def main():
    global raw_socket
    gevent.monkey.patch_all()
    raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    raw_socket.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)
    gevent.joinall([
        gevent.spawn(start_udp_server)
    ])

def encode_payload(packet_id, payload, i=0):
    queries = []
    suffix = ''.join(['.', chr(i), packet_id, SUFFIX])
    if len(payload) <= 63:
        print(i, base64.b64encode(payload))
        queries.append(''.join([payload, suffix]))
    elif len(payload) <= 126:
        print(i, base64.b64encode(payload))
        queries.append(''.join([payload[:63], '.', payload[63:], suffix]))
    elif len(payload) <= 189:
        print(i, base64.b64encode(payload))
        queries.append(''.join([payload[:63], '.', payload[63:126], '.', payload[126:], suffix]))
    elif len(payload) <= MAX_PAYLOAD_LENGTH:
        print(i, base64.b64encode(payload))
        queries.append(''.join([payload[:63], '.', payload[63:126], '.', payload[126:189], '.', payload[189:], suffix]))
    else:
        queries.extend(encode_payload(packet_id, payload[:MAX_PAYLOAD_LENGTH], i))
        queries.extend(encode_payload(packet_id, payload[MAX_PAYLOAD_LENGTH:], i+1))
    return queries


if '__main__' == __name__:
    payload = dpkt.ip.IP()
    payload.data = dpkt.tcp.TCP()
    payload.data.data = ''.join(itertools.repeat('hello.', 100))
    payload = str(payload)
    payload = base64.b32encode(payload)
    count = float(len(payload) + 1) / MAX_PAYLOAD_LENGTH
    if count > int(count):
        count = int(count) + 1
    else:
        count = int(count)
    payload = ''.join([chr(count), payload])
    packet_id = uuid.uuid4()
    udp_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
    print(packet_id)
    for query in encode_payload(packet_id.get_bytes(), payload):
        dns_packet = dpkt.dns.DNS(id=random.randint(1, 65535))
        dns_packet.qd = [dpkt.dns.DNS.Q(name=query)]
        udp_socket.sendto(str(dns_packet), ('8.8.8.8', 53))