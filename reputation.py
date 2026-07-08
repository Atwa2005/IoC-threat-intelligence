import requests
from config import API_KEY
headers = {
    "x-apikey": API_KEY
}

def check_ip(ip):

    try:
        print("Checking IP...")

        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"

        response = requests.get(url, headers=headers, timeout=10)

        print("IP request finished")

        if response.status_code != 200:
            print("IP Error:", response.status_code)
            return None

        data = response.json()

        print("IP parsed")

        return data["data"]["attributes"]["last_analysis_stats"]

    except requests.exceptions.RequestException as e:
        print("IP Exception:", e)
        return None

def check_hash(file_hash):

    try:
        print("Checking Hash...")

        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"

        response = requests.get(url, headers=headers, timeout=10)

        print("Hash request finished")

        if response.status_code != 200:
            print("Hash Error:", response.status_code)
            return None

        data = response.json()

        print("Hash parsed")

        return data["data"]["attributes"]["last_analysis_stats"]

    except requests.exceptions.RequestException as e:
        print("Hash Exception:", e)
        return None
def check_domain(domain):

    try:
        print("Checking Domain...")

        url = f"https://www.virustotal.com/api/v3/domains/{domain}"

        response = requests.get(url, headers=headers, timeout=10)

        print("Domain request finished")

        if response.status_code != 200:
            print("Domain Error:", response.status_code)
            return None

        data = response.json()

        print("Domain parsed")

        return data["data"]["attributes"]["last_analysis_stats"]

    except requests.exceptions.RequestException as e:
        print("Domain Exception:", e)
        return None

def calculate_severity(stats):

    if stats is None:
        return "Unknown"

    malicious = stats["malicious"]

    if malicious == 0:
        return "Low"

    elif malicious <= 5:
        return "Medium"

    else:
        return "High"