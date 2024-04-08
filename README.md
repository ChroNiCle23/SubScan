# SubScan
The tool is designed to help with reconnaissance tasks related to discovering subdomains of a given target and checking if the status (live or not) of those subdomains

# Requirement
Python: The script is written in Python, so you need to have Python installed on your system. You can download Python from the official website: https://www.python.org/downloads/

Requests Library: The script utilizes the requests library for making HTTP requests. If you don't have it installed, you can install it using pip, the Python package installer. Run the following command in your terminal or command prompt:

```
 copy code
pip3 install requests

```

# Installation
1. Check the Python version
    
    ```
    Copy code
    python3 --version
    
    ```
2.  If Python is not installed, you can install it using your package manager. For example, on Ubuntu, you can install Python with the following command:
    
    ```
    Copy code
    sudo apt-get update
    sudo apt-get install python3
    
    ```
3. Git Clone
   ```

   ```
4. Change the file permission
   ```
   chmod +x SubScan.py
   ```

# Usage
1. Display help menu
   ```
   python3 SubScan.py -h
   ```
2. Full Scan
   ```
   python3 SubScan.py -f
   ```
3. Live Subdomain Scan
   ```
   python3 SubScan.py subdomains.txt -l
   ```

# Source
Implemented
_______________
Wayback Machine(domain))
Virustotal(domain))
Urlscan(domain))
Crt.sh(domain))
Hacker_target(domain))

