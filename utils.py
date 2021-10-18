import requests

def get_mac_details_from_url(mac_address):
    # We will use an API to get the vendor details
    url = "https://api.macvendors.com/"
      
    # Use get method to fetch details
    response = requests.get(url + mac_address)
    if response.status_code != 200:
        return None

    return response.content.decode()