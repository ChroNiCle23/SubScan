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
   git clone https://github.com/ChroNiCle23/SubScan.git

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
   Example
   ```
   * python3 SubScan.py -f
   * target url: https://www.example.com
   * ls
   * cat subdomains.txt
   ```
4. Live Subdomain Scan
   ```
   python3 SubScan.py subdomains.txt -l
   ```
   Example
   ```
   * python3 SubScan.py subdomains.txt -l
   * targrt url: https://www.example.com
   ** NOTE: Please use the same url that was implemented for the full scan

# Source
Implemented
_______________
1. Wayback Machine(domain))
2. Virustotal(domain))
3. Urlscan(domain))
4. Crt.sh(domain))
5. Hacker_target(domain))

