import os
import requests
import base64
import re

# Load .env file manually and set environment variables
def load_env_variables(file_path):
    with open(file_path) as f:
        for line in f:
            # Remove spaces from the lines and split by '='
            if '=' in line:
                key, value = line.strip().split('=', 1)
                os.environ[key] = value  # Assign the environment variable

# Load the .env file
load_env_variables('.env')

# API Keys
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
GOOGLE_SAFE_BROWSING_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")  # Google Safe Browsing API key
ONLINE_HASH_CRACK_API_KEY = os.getenv("ONLINE_HASH_CRACK_API_KEY")  # OnlineHashCrack API key

def check_ip_reputation(ip):
    # Check IP reputation using AbuseIPDB API
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}"
    headers = {
        "Accept": "application/json",
        "Key": ABUSEIPDB_API_KEY
    }
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        ip_info = data['data']
        
        abuse_confidence_score = ip_info['abuseConfidenceScore']
        country = ip_info.get('countryCode', 'Unknown')
        last_reported = ip_info.get('lastReportedAt', 'Unknown')
        total_reports = ip_info.get('totalReports', 0)
        categories = ip_info.get('categories', [])
        num_of_categories = len(categories)
        activities = ip_info.get('activities', [])
        
        print(f"IP: {ip}")
        print(f"Abuse Confidence Score: {abuse_confidence_score}")
        print(f"Country: {country}")
        print(f"Last Reported: {last_reported}")
        print(f"Total Reports: {total_reports}")
        
        if num_of_categories > 0:
            print(f"Categories: {', '.join(categories)}")
        else:
            print("Categories: None")
        
        if activities:
            print(f"Reported Malicious Activities: {', '.join(activities)}")
        else:
            print("Reported Malicious Activities: None")
        
        if abuse_confidence_score > 80:
            print("This IP has a high risk of abuse.")
        else:
            print("This IP has a low risk of abuse.")
    else:
        print(f"AbuseIPDB Error: {response.status_code} - {response.text}")
    
def check_ip_shodan(ip):
    # Check IP information using Shodan API
    url = f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}"
    response = requests.get(url)

    if response.status_code == 200:
        data = response.json()
        if 'data' in data:
            # IP information
            hostnames = data.get('hostnames', [])
            ip = data.get('ip', 'Unknown')
            org = data.get('org', 'Unknown')
            country = data.get('country_name', 'Unknown')
            city = data.get('city', 'Unknown')
            isp = data.get('isp', 'Unknown')
            ports = data.get('ports', [])
            
            print("\nShodan IP Information:")
            print(f"IP Address: {ip}")
            print(f"Hostnames: {', '.join(hostnames) if hostnames else 'None'}")
            print(f"Organization: {org}")
            print(f"Country: {country}")
            print(f"City: {city}")
            print(f"ISP: {isp}")
            print(f"Open Ports: {', '.join(map(str, ports)) if ports else 'None'}")
        else:
            print(f"Shodan: No IP information found.")
    else:
        print(f"Shodan Error: {response.status_code} - {response.text}")

def check_url_security(url):
    # Check URL security using Google Safe Browsing API
    url = base64.urlsafe_b64encode(url.encode()).decode()  # Encode URL in base64
    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_API_KEY}"
    
    payload = {
        "client": {
            "clientId": "your-client-id",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [
                {"url": url}
            ]
        }
    }
    
    response = requests.post(api_url, json=payload)

    if response.status_code == 200:
        data = response.json()
        if data.get("matches"):
            print(f"\nURL: {url}")
            print("This URL may be harmful.")
        else:
            print(f"\nURL: {url}")
            print("This URL seems safe.")
    else:
        print(f"Google Safe Browsing Error: {response.status_code} - {response.text}")

def check_md5_hash(hash_value, api_key):
    # Check MD5 hash using OnlineHashCrack API
    url = f"https://www.onlinehashcrack.com/api/v1/lookup/{hash_value}?apikey={api_key}"
    response = requests.get(url)

    if response.status_code == 200:
        try:
            data = response.json()
            if 'found' in data and data['found']:
                print(f"\nMD5 Hash: {hash_value}")
                print("This hash may be harmful.")
            else:
                print(f"\nMD5 Hash: {hash_value}")
                print("This hash seems safe.")
        except ValueError:
            print("Response is not in JSON format.")
            print("HTML Response:")
            print(response.text)  # print the HTML content for debugging
    else:
        print(f"OnlineHashCrack Error: {response.status_code} - {response.text}")

# Check if the input value is an IP address
def is_ip_address(value):
    ip_pattern = re.compile(r"^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."  # 0-255.0-255.0-255.0-255
                            r"(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
                            r"(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\."
                            r"(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")
    return re.match(ip_pattern, value) is not None

# Check if the input value is an MD5 hash
def is_md5_hash(value):
    return len(value) == 32 and all(c in "0123456789abcdef" for c in value.lower())

if __name__ == "__main__":
    value_to_check = input("Please enter the IP address or MD5 hash to check: ")
    
    # Check if it's an IP address or hash
    if is_ip_address(value_to_check):
        print(f"{value_to_check} is an IP address.")
        check_ip_reputation(value_to_check)
        check_ip_shodan(value_to_check)
    elif is_md5_hash(value_to_check):
        print(f"{value_to_check} is an MD5 hash.")
        check_md5_hash(value_to_check, ONLINE_HASH_CRACK_API_KEY)
    else:
        print("Invalid IP address or MD5 hash.")
