import scapy.all as scapy
import argparse


"""
    Summary
        print(arp_request_packet.summary())
    Show -> Shows the packet details
        print(arp_request_packet.show())
    Parameters
        scapy.ls(scapy.ARP())
"""
def scan(ip_address):
    arp_request_packet = scapy.ARP(pdst=ip_address)
    broadcast_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")

    arp_request_packet = broadcast_packet/arp_request_packet

    # answered_list, unanswered_list = scapy.srp(arp_request_packet, timeout=1)
    answered_list = scapy.srp(arp_request_packet, timeout=1, verbose=False)[0]

    client_list = []

    for element in answered_list:

        client_dict = {
            "ip_address": element[1].psrc,
            "mac_address": element[1].hwsrc
        }

        client_list.append(client_dict)

    return client_list


def print_result_list(client_list):
    # Header
    print('----------------------------------------------')
    print("IP\t\t\tMac Address")
    print('----------------------------------------------')

    for element in client_list:
        print(element["ip_address"] + '\t\t' + element["mac_address"] + '\n')


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Target IP / IP Range ")
    options = parser.parse_args()

    return options

options = get_arguments()

client_list = scan(options.target)

print_result_list(client_list)
