#!/usr/bin/env python

import scapy.all as scapy
import pprint
import optparse


def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="ip", help="network ip to scan")
    (options, arguments) = parser.parse_args()
    if not options.ip:
        parser.error("[-] Please specify an ip , use --help for more info.")
    return options


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    client_list = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        client_list.append(client_dict)
    return client_list


def print_result(result_list):
    print("IP\t\t\tMAC Address\n--------------------------------------------")
    for client in result_list:
        print(client["ip"] + "\t\t" + client["mac"])


opt = get_arguments()
client_list = scan(opt.ip)
print_result(client_list)
