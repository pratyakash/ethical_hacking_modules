import scapy.all as scapy

def scan(ip_address):
    arp_request = scapy.ARP(pdst = ip_address)
    print(arp_request.summary())

    """
        Summary
            print(arp_request.summary())
        Parameters
            scapy.ls(scapy.ARP())
    """


scan("192.168.0.1")
