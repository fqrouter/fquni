import subprocess
import signal
import atexit
import httplib
import socket
import Queue
import thread
import base64
import logging
import dpkt.ip


LOGGER = logging.getLogger(__name__)
ip_packet_queue = Queue.Queue()

ip_blacklist = set()
tx_counters = {}


def setup_iptables():
    subprocess.check_call(
        'iptables -t mangle -A OUTPUT -p tcp -j NFQUEUE', shell=True)
    subprocess.check_call(
        'iptables -t mangle -A OUTPUT -p udp -j NFQUEUE', shell=True)
    subprocess.check_call(
        'iptables -t mangle -A OUTPUT -p icmp -j NFQUEUE', shell=True)
    subprocess.check_call(
        'iptables -t filter -A INPUT -p icmp --icmp-type 11 -j DROP', shell=True)


def teardown_iptables():
    subprocess.check_call(
        'iptables -t mangle -D OUTPUT -p tcp -j NFQUEUE', shell=True)
    subprocess.check_call(
        'iptables -t mangle -D OUTPUT -p udp -j NFQUEUE', shell=True)
    subprocess.check_call(
        'iptables -t mangle -D OUTPUT -p icmp -j NFQUEUE', shell=True)
    subprocess.check_call(
        'iptables -t filter -D INPUT -p icmp --icmp-type 11 -j DROP', shell=True)


def main():
    from netfilterqueue import NetfilterQueue

    signal.signal(signal.SIGTERM, lambda signum, fame: teardown_iptables())
    signal.signal(signal.SIGINT, lambda signum, fame: teardown_iptables())
    atexit.register(teardown_iptables)
    setup_iptables()

    nfqueue = NetfilterQueue()
    nfqueue.bind(0, capture_packet)
    for i in range(64):
        thread.start_new(resend_packet_via_udp, ())
    nfqueue.run()


def capture_packet(nfqueue_element):
    ip_packet = dpkt.ip.IP(nfqueue_element.get_payload())
    if ip_packet.ttl > 200:
        nfqueue_element.accept()
        return
    ip_packet.src_ip = socket.inet_ntoa(ip_packet.src)
    ip_packet.dst_ip = socket.inet_ntoa(ip_packet.dst)
    if ip_packet.dst_ip.startswith('10.'):
        nfqueue_element.accept()
        return
    if should_resend(ip_packet):
        ip_packet.ttl = 3
        ip_packet.sum = 0
        nfqueue_element.set_payload(str(ip_packet))
        ip_packet_queue.put(ip_packet)
        nfqueue_element.accept()
    else:
        nfqueue_element.accept()


def should_resend(ip_packet):
    if hasattr(ip_packet, 'udp'):
        return True
    if hasattr(ip_packet, 'tcp'):
        if ip_packet.dst_ip in ip_blacklist:
            return True
        if ip_packet.tcp.flags == dpkt.tcp.TH_SYN:
            return True
        if ip_packet.tcp.flags & dpkt.tcp.TH_PUSH:
            return True
        if 'HTTP/1.1' in ip_packet.tcp.data:
            return True
        tx_key = (ip_packet.dst_ip, ip_packet.tcp.ack)
        tx_counters[tx_key] = tx_counters.get(tx_key, 0) + 1
        if 3 == tx_counters[tx_key]:
            LOGGER.info('blacklist ip: %s' % ip_packet.dst_ip)
            ip_blacklist.add(ip_packet.dst_ip)
            return True
    return False


def resend_packet_via_udp():
    udp_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
    udp_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, 250)
    while True:
        ip_packet = ip_packet_queue.get()
        ip_packet.src = socket.inet_aton('183.13.102.145')
        ip_packet.ttl = 64
        if hasattr(ip_packet, 'tcp'):
            ip_packet.tcp.sum = 0
        elif hasattr(ip_packet, 'udp'):
            ip_packet.udp.sum = 0
        elif hasattr(ip_packet, 'icmp'):
            ip_packet.icmp.sum = 0
        ip_packet.sum = 0
        print(ip_packet.src_ip, ip_packet.dst_ip)
        print(ip_packet_queue.qsize())
        udp_socket.sendto(str(ip_packet), ('67.222.158.51', 19842))


def resend_packet_via_http():
    http_connection = MyHTTPConnection('198.98.127.199', 1984)
    while True:
        ip_packet = ip_packet_queue.get()
        ip_packet.src = socket.inet_aton('183.13.102.145')
        ip_packet.ttl = 64
        if hasattr(ip_packet, 'tcp'):
            ip_packet.tcp.sum = 0
        elif hasattr(ip_packet, 'udp'):
            ip_packet.udp.sum = 0
        elif hasattr(ip_packet, 'icmp'):
            ip_packet.icmp.sum = 0
        ip_packet.sum = 0
        print(ip_packet.src_ip, ip_packet.dst_ip)
        try:
            body = str(ip_packet)
            body = base64.b64encode(body)
            http_connection._HTTPConnection__state = httplib._CS_IDLE
            http_connection.request('POST', '/', body=body, headers={'Connection': 'keep-alive'})
            # response = http_connection.getresponse()
            print(ip_packet_queue.qsize())
        except:
            LOGGER.exception('failed to resend packet')


class MyHTTPConnection(httplib.HTTPConnection):
    def connect(self):
        LOGGER.info('!!! new connection')
        """Connect to the host and port specified in __init__."""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_IP, socket.IP_TTL, 250)
        if socket._GLOBAL_DEFAULT_TIMEOUT != self.timeout:
            self.sock.settimeout(self.timeout)
        if self.source_address:
            self.sock.bind(self.source_address)
        self.sock.connect((self.host, self.port))
        if self._tunnel_host:
            self._tunnel()