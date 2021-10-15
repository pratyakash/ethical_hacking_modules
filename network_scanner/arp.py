# address_resolution_protocol

# route -n => To get the IP of router.

import scapy.all as scapy

def scan(ip_address):
    scapy.arping(ip_address)

scan('192.168.0.1/24')



