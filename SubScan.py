import requests
import os
import sys
import argparse
from urllib.parse import urlparse

def fetch_wayback(domain):
    fetch_url = "http://web.archive.org/cdx/search/cdx?url=*.{}/{}&output=json&collapse=urlkey".format(domain, "*")

    try:
        response = requests.get(fetch_url)
        response.raise_for_status()  # Raise an exception for bad status codes
        data = response.json()
        out = []

        skip = True
        for item in data:
            # The first item is always just the string "original",
            # so we should skip the first item
            if skip:
                skip = False
                continue

            if len(item) < 3:
                continue

            u = urlparse(item[2])
            out.append(u.hostname)
        
        return out

    except requests.exceptions.RequestException as e:
        print("Error fetching data: {}".format(e))
        return []

def fetch_virustotal(domain):
    api_key = os.getenv("VT_API_KEY")
    if not api_key:
        # Swallow not having an API key, just don't fetch
        return []

    fetch_url = "https://www.virustotal.com/vtapi/v2/domain/report?domain={}&apikey={}".format(domain, api_key)

    
    try:
        response = requests.get(fetch_url)
        response.raise_for_status()  # Raise an exception for bad status codes
        data = response.json()
        subdomains = data.get("subdomains", [])
        return subdomains

    except requests.exceptions.RequestException as e:
        print("Error fetching data from VirusTotal: {}".format(e))
        return []

def fetch_urlscan(domain):
    try:
        resp = requests.get("https://urlscan.io/api/v1/search/?q=domain:{}".format(domain))
        resp.raise_for_status()  # Raise an exception for bad status codes
        
        output = []

        data = resp.json()
        results = data.get("results", [])

        for result in results:
            task_url = result.get("task", {}).get("url")
            if task_url:
                parsed_url = urlparse(task_url)
                output.append(parsed_url.hostname)

            page_url = result.get("page", {}).get("url")
            if page_url:
                parsed_url = urlparse(page_url)
                output.append(parsed_url.hostname)

        return output

    except requests.exceptions.RequestException as e:
        print("Error fetching data from URLScan: {}".format(e))
        return []

def fetch_crtsh(domain):
    try:
        resp = requests.get("https://crt.sh/?q=%25.{}&output=json".format(domain))
        resp.raise_for_status()  # Raise an exception for bad status codes

        results = resp.json()
        output = [res['name_value'] for res in results]

        return output

    except requests.exceptions.RequestException as e:
        print("Error fetching data from crt.sh: {}".format(e))
        return []

def fetch_hacker_target(domain):
    out = []

    try:
        response = requests.get("https://api.hackertarget.com/hostsearch/?q={}".format(domain))
        response.raise_for_status()  # Raise an exception for bad status codes

        lines = response.text.splitlines()
        for line in lines:
            parts = line.split(',', 1)
            if len(parts) == 2:
                out.append(parts[0])

    except requests.exceptions.RequestException as e:
        print("Error fetching data from HackerTarget: {}".format(e))

    return out

def search_subdomains(url):
    domain = urlparse(url).netloc
    subdomains = []

    print("Searching for subdomains in {}...".format(domain))

    subdomains.extend(fetch_wayback(domain))
    subdomains.extend(fetch_virustotal(domain))
    subdomains.extend(fetch_urlscan(domain))
    subdomains.extend(fetch_crtsh(domain))
    subdomains.extend(fetch_hacker_target(domain))

    return subdomains

def check_url(url, expected_code=200):
    """
    Checks the status code of a URL and prints information.

    Args:
        url: The URL to check.
        expected_code: The expected successful status code (defaults to 200).

    Returns:
        None
    """
    try:
        response = requests.head(url)  # Use HEAD request for efficiency (checks headers only)
        response.raise_for_status()  # Raise exception for non-successful codes
        if response.status_code == expected_code:
            print("[+] {} is live (response code: {})".format(url, response.status_code))
            return True
    except requests.exceptions.RequestException as e:
        # Handle various request exceptions
        pass
        print("[-] {} is not live".format(url))
        return False

def main():
    """
    Reads URLs from a file and checks their status codes.
    """
    parser = argparse.ArgumentParser(description='Check status codes of subdomains from a file.')
    parser.add_argument('file', help='Name of the file containing subdomains')
    parser.add_argument('-l', '--live', action='store_true', help='Check live subdomains')
    parser.add_argument('-f', '--full', action='store_true', help='Perform a full scan')
    args = parser.parse_args()

    try:
        with open(args.file, 'r') as f:
            for line in f:
                url = line.strip()  # Remove trailing newline
                # Prepend "https://" to URLs without a scheme
                if not urlparse(url).scheme:
                    url = "https://" + url
                print("[*] Checking {}...".format(url))
                if args.live:
                    check_url(url)
                else:
                    print("[-] {}".format(url))  # Just print the URL if live check is not requested
    except FileNotFoundError:
        print("[-] Error: File {} not found.".format(args.file))

if __name__ == "__main__":
    if len(sys.argv) == 1 or sys.argv[1] == '-h':
        print("""
       __     __      
     (    / (  _ _   
    __)(/()__)( (//) 
                     
    """)
        print("Usage:")
        print("python script.py [file] [-l] [-f]")
        print("\nOptions:")
        print("file:\tName of the file containing subdomains")
        print("-l, --live:\tCheck live subdomains")
        print("-f, --full:\tPerform a full scan")
        sys.exit(0)
    url = input("Enter the URL: ")
    subdomains = search_subdomains(url)
    if subdomains:
        with open("subdomains.txt", "w") as file:
            for subdomain in set(subdomains):
                file.write(subdomain + "\n")
        print("Subdomains saved to subdomains.txt")
    else:
        print("No subdomains found.")
    main()
