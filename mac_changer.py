import subprocess
import optparse
import re

MAC_ADDRESS_EXTRACTION_RULE = r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w"


def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-i", "--interface", dest="interface")
    parser.add_option("-a", "--address", dest="mac_address")
    
    (options, arguments) = parser.parse_args()
    
    if not options.interface:
        parser.error("[-] Please specify the Interface")
    elif not options.mac_address:
        parser.error("[-] Please specify the Mac Address")
    
    return options


def change_mac(interface, new_mac_address):
    print(f'[+] Changing MAC Address for {interface} to {new_mac_address}')

    subprocess.call("ifconfig wlan1 down", shell=True)
    subprocess.call(f'ifconfig wlan1 hw ether {new_mac_address}', shell=True)
    subprocess.call("ifconfig wlan1 up ", shell=True)


def get_current_mac_address(interface):
    ifconfig_result = str(subprocess.check_output(["ifconfig", interface]))

    old_mac_address = re.search(MAC_ADDRESS_EXTRACTION_RULE, ifconfig_result)
    
    if old_mac_address:
        return old_mac_address.group(0)
    else:
        print("[-] No MAC Address found")
    
    return None

options = get_arguments()

current_mac = get_current_mac_address(options.interface)

change_mac(options.interface, options.mac_address)

changed_mac = get_current_mac_address(options.interface)

if changed_mac == options.mac_address:
    print("[+] MAC address changed successfully")
else:
    print("[-] MAC address change unsuccessful")
    

