#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Termux Multi-Tool by Anonymous Rebel
# Features: WiFi Scanner, Bluetooth Scanner, IP Lookup, Email Lookup, Phone Lookup

import os
import sys
import time
import subprocess
import requests
import re
from datetime import datetime
import socket
import platform
import json
from colorama import init, Fore, Back, Style

# Initialize colorama
init(autoreset=True)

# Banner
BANNER = f"""{Fore.RED}
▓█████▄  ▒█████   ██▀███   ██▓███   ███▄ ▄███▓ ▄▄▄       ███▄    █ 
▒██▀ ██▌▒██▒  ██▒▓██ ▒ ██▒▓██░  ██▒▓██▒▀█▀ ██▒▒████▄     ██ ▀█   █ 
░██   █▌▒██░  ██▒▓██ ░▄█ ▒▓██░ ██▓▒▓██    ▓██░▒██  ▀█▄  ▓██  ▀█ ██▒
░▓█▄   ▌▒██   ██░▒██▀▀█▄  ▒██▄█▓▒ ▒▒██    ▒██ ░██▄▄▄▄██ ▓██▒  ▐▌██▒
░▒████▓ ░ ████▓▒░░██▓ ▒██▒▒██▒ ░  ░▒██▒   ░██▒ ▓█   ▓██▒▒██░   ▓██░
 ▒▒▓  ▒ ░ ▒░▒░▒░ ░ ▒▓ ░▒▓░▒▓▒░ ░  ░░ ▒░   ░  ░ ▒▒   ▓▒█░░ ▒░   ▒ ▒ 
 ░ ▒  ▒   ░ ▒ ▒░   ░▒ ░ ▒░░▒ ░     ░  ░      ░  ▒   ▒▒ ░░ ░░   ░ ▒░
 ░ ░  ░ ░ ░ ░ ▒    ░░   ░ ░░       ░      ░     ░   ▒      ░   ░ ░ 
   ░        ░ ░     ░                    ░         ░  ░         ░ 
 ░                                                                
{Fore.RESET}
{Fore.YELLOW}>>> Termux Advanced Recon Tool <<<
{Fore.CYAN}>>> WiFi Scanner | Bluetooth Scanner | IP Lookup | Email Lookup | Phone Lookup <<<
{Fore.RESET}
"""

# API Keys (You should replace these with your own)
IPAPI_KEY = "6ae8601315f8f9d5b237498df2176945"  # Get from https://ipapi.com/
EMAILREP_KEY = "m9QCxmDwznEz35UjVSjpKDpIAwNyjGfN"  # Get from https://emailrep.io/
NUMVERIFY_KEY = "zs9c7HZlGQWUMc3LSLWs52AU001DCSSu"  # Get from https://numverify.com/

def clear_screen():
    os.system('clear' if os.name == 'posix' else 'cls')

def print_banner():
    clear_screen()
    print(BANNER)

def install_dependencies():
    required_packages = ['requests', 'colorama']
    for package in required_packages:
        try:
            __import__(package)
        except ImportError:
            print(f"{Fore.YELLOW}[!] Installing {package}...{Fore.RESET}")
            subprocess.check_call([sys.executable, "-m", "pip", "install", package])

def wifi_scanner(refresh_time=2):
    print(f"{Fore.GREEN}[+] Starting WiFi Scanner (Refresh: {refresh_time}s){Fore.RESET}")
    try:
        while True:
            clear_screen()
            print_banner()
            print(f"{Fore.CYAN}[*] Scanning nearby WiFi networks...{Fore.RESET}")
            
            # Using Termux API for WiFi scanning
            try:
                result = subprocess.check_output(['termux-wifi-scaninfo'], stderr=subprocess.STDOUT)
                networks = json.loads(result.decode('utf-8'))
                
                if networks:
                    print(f"{Fore.GREEN}[+] Found {len(networks)} WiFi networks:{Fore.RESET}")
                    print(f"{Fore.YELLOW}{'-'*80}{Fore.RESET}")
                    print(f"{Fore.BLUE}SSID{' '*20}BSSID{' '*18}RSSI{' '*5}Channel{Fore.RESET}")
                    print(f"{Fore.YELLOW}{'-'*80}{Fore.RESET}")
                    
                    for network in networks:
                        ssid = network.get('ssid', 'Hidden')
                        bssid = network.get('bssid', 'N/A')
                        rssi = network.get('rssi', 'N/A')
                        channel = network.get('frequency', 'N/A')
                        if isinstance(channel, int):
                            channel = (channel - 2412) // 5 + 1
                        
                        print(f"{Fore.WHITE}{ssid[:24]:<24}{bssid:<24}{rssi:<8}{channel}{Fore.RESET}")
                else:
                    print(f"{Fore.RED}[-] No WiFi networks found{Fore.RESET}")
                
            except (subprocess.CalledProcessError, json.JSONDecodeError) as e:
                print(f"{Fore.RED}[-] Error scanning WiFi: {str(e)}{Fore.RESET}")
                print(f"{Fore.YELLOW}[!] Make sure you have Termux:API installed{Fore.RESET}")
                print(f"{Fore.YELLOW}[!] Run: pkg install termux-api{Fore.RESET}")
                break
            
            print(f"\n{Fore.YELLOW}[*] Press Ctrl+C to stop scanning{Fore.RESET}")
            time.sleep(refresh_time)
            
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] WiFi scanning stopped{Fore.RESET}")

def bluetooth_scanner(refresh_time=2):
    print(f"{Fore.GREEN}[+] Starting Bluetooth Scanner (Refresh: {refresh_time}s){Fore.RESET}")
    try:
        while True:
            clear_screen()
            print_banner()
            print(f"{Fore.CYAN}[*] Scanning nearby Bluetooth devices...{Fore.RESET}")
            
            # Using Termux API for Bluetooth scanning
            try:
                result = subprocess.check_output(['termux-bluetooth-scan'], stderr=subprocess.STDOUT)
                devices = json.loads(result.decode('utf-8'))
                
                if devices:
                    print(f"{Fore.GREEN}[+] Found {len(devices)} Bluetooth devices:{Fore.RESET}")
                    print(f"{Fore.YELLOW}{'-'*80}{Fore.RESET}")
                    print(f"{Fore.BLUE}Name{' '*20}MAC Address{' '*15}RSSI{' '*5}Class{Fore.RESET}")
                    print(f"{Fore.YELLOW}{'-'*80}{Fore.RESET}")
                    
                    for device in devices:
                        name = device.get('name', 'Unknown')
                        address = device.get('address', 'N/A')
                        rssi = device.get('rssi', 'N/A')
                        device_class = device.get('class', 'N/A')
                        
                        print(f"{Fore.WHITE}{name[:24]:<24}{address:<24}{rssi:<8}{device_class}{Fore.RESET}")
                else:
                    print(f"{Fore.RED}[-] No Bluetooth devices found{Fore.RESET}")
                
            except (subprocess.CalledProcessError, json.JSONDecodeError) as e:
                print(f"{Fore.RED}[-] Error scanning Bluetooth: {str(e)}{Fore.RESET}")
                print(f"{Fore.YELLOW}[!] Make sure you have Termux:API installed{Fore.RESET}")
                print(f"{Fore.YELLOW}[!] Run: pkg install termux-api{Fore.RESET}")
                break
            
            print(f"\n{Fore.YELLOW}[*] Press Ctrl+C to stop scanning{Fore.RESET}")
            time.sleep(refresh_time)
            
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Bluetooth scanning stopped{Fore.RESET}")

def ip_lookup(ip_address=""):
    clear_screen()
    print_banner()
    
    if not ip_address:
        ip_address = input(f"{Fore.CYAN}[?] Enter IP address to lookup: {Fore.RESET}").strip()
    
    if not ip_address:
        print(f"{Fore.RED}[-] No IP address provided{Fore.RESET}")
        return
    
    print(f"{Fore.GREEN}[+] Looking up IP: {ip_address}{Fore.RESET}")
    
    try:
        # Using ipapi.co API
        response = requests.get(f"http://api.ipapi.com/{ip_address}?access_key={IPAPI_KEY}")
        data = response.json()
        
        if 'error' in data:
            print(f"{Fore.RED}[-] Error: {data['error']['info']}{Fore.RESET}")
            return
        
        print(f"\n{Fore.YELLOW}{'-'*80}{Fore.RESET}")
        print(f"{Fore.CYAN}[*] IP Information:{Fore.RESET}")
        print(f"{Fore.YELLOW}{'-'*80}{Fore.RESET}")
        print(f"{Fore.WHITE}IP: {data.get('ip', 'N/A')}")
        print(f"Type: {data.get('type', 'N/A')}")
        print(f"Continent: {data.get('continent_name', 'N/A')}")
        print(f"Country: {data.get('country_name', 'N/A')} ({data.get('country_code', 'N/A')})")
        print(f"Region: {data.get('region_name', 'N/A')}")
        print(f"City: {data.get('city', 'N/A')}")
        print(f"ZIP: {data.get('zip', 'N/A')}")
        print(f"Latitude: {data.get('latitude', 'N/A')}")
        print(f"Longitude: {data.get('longitude', 'N/A')}")
        print(f"Time Zone: {data.get('time_zone', {}).get('name', 'N/A')}")
        print(f"Currency: {data.get('currency', {}).get('name', 'N/A')}")
        print(f"ISP: {data.get('connection', {}).get('isp', 'N/A')}")
        print(f"ASN: {data.get('connection', {}).get('asn', 'N/A')}")
        print(f"Organization: {data.get('connection', {}).get('organization', 'N/A')}")
        print(f"{Fore.YELLOW}{'-'*80}{Fore.RESET}")
        
        # Additional checks
        print(f"\n{Fore.CYAN}[*] Additional Checks:{Fore.RESET}")
        print(f"{Fore.YELLOW}{'-'*80}{Fore.RESET}")
        
        # Check if IP is a known proxy/VPN/TOR
        if data.get('security', {}).get('is_proxy', False):
            print(f"{Fore.RED}[!] This IP is a known proxy/VPN/TOR exit node{Fore.RESET}")
        else:
            print(f"{Fore.GREEN}[+] No proxy/VPN/TOR detected{Fore.RESET}")
        
        # Check blacklists
        print(f"\n{Fore.CYAN}[*] Blacklist Check:{Fore.RESET}")
        check_ip_blacklists(ip_address)
        
    except Exception as e:
        print(f"{Fore.RED}[-] Error during IP lookup: {str(e)}{Fore.RESET}")

def check_ip_blacklists(ip_address):
    blacklists = [
        ("Spamhaus", f"https://check.spamhaus.org/query/ip/{ip_address}"),
        ("AbuseIPDB", f"https://www.abuseipdb.com/check/{ip_address}"),
        ("VirusTotal", f"https://www.virustotal.com/gui/ip-address/{ip_address}"),
        ("IBM X-Force", f"https://exchange.xforce.ibmcloud.com/ip/{ip_address}")
    ]
    
    for name, url in blacklists:
        print(f"{Fore.WHITE}{name}: {url}{Fore.RESET}")

def email_lookup(email=""):
    clear_screen()
    print_banner()
    
    if not email:
        email = input(f"{Fore.CYAN}[?] Enter email address to lookup: {Fore.RESET}").strip()
    
    if not email:
        print(f"{Fore.RED}[-] No email address provided{Fore.RESET}")
        return
    
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        print(f"{Fore.RED}[-] Invalid email format{Fore.RESET}")
        return
    
    print(f"{Fore.GREEN}[+] Looking up email: {email}{Fore.RESET}")
    
    try:
        # Using EmailRep API
        headers = {
            'Key': EMAILREP_KEY,
            'User-Agent': 'Termux-Email-Lookup'
        }
        response = requests.get(f"https://emailrep.io/{email}", headers=headers)
        data = response.json()
        
        if 'status' in data and data['status'] == 'fail':
            print(f"{Fore.RED}[-] Error: {data['reason']}{Fore.RESET}")
            return
        
        print(f"\n{Fore.YELLOW}{'-'*80}{Fore.RESET}")
        print(f"{Fore.CYAN}[*] Email Information:{Fore.RESET}")
        print(f"{Fore.YELLOW}{'-'*80}{Fore.RESET}")
        print(f"{Fore.WHITE}Email: {data.get('email', 'N/A')}")
        print(f"Reputation: {data.get('reputation', 'N/A')}")
        print(f"Suspicious: {'Yes' if data.get('suspicious', False) else 'No'}")
        print(f"References: {data.get('references', 'N/A')}")
        
        print(f"\n{Fore.CYAN}[*] Details:{Fore.RESET}")
        print(f"{Fore.YELLOW}{'-'*80}{Fore.RESET}")
        print(f"Known: {'Yes' if data.get('details', {}).get('known', False) else 'No'}")
        print(f"Spam: {'Yes' if data.get('details', {}).get('spam', False) else 'No'}")
        print(f"Malicious: {'Yes' if data.get('details', {}).get('malicious', False) else 'No'}")
        print(f"Disposable: {'Yes' if data.get('details', {}).get('disposable', False) else 'No'}")
        print(f"Free Provider: {'Yes' if data.get('details', {}).get('free_provider', False) else 'No'}")
        print(f"Deliverable: {'Yes' if data.get('details', {}).get('deliverable', False) else 'No'}")
        print(f"Domain Exists: {'Yes' if data.get('details', {}).get('domain_exists', False) else 'No'}")
        print(f"Domain Age: {data.get('details', {}).get('domain_age', 'N/A')}")
        print(f"First Seen: {data.get('details', {}).get('first_seen', 'N/A')}")
        print(f"Last Seen: {data.get('details', {}).get('last_seen', 'N/A')}")
        
        print(f"\n{Fore.CYAN}[*] Breaches:{Fore.RESET}")
        print(f"{Fore.YELLOW}{'-'*80}{Fore.RESET}")
        if data.get('details', {}).get('data_breach', False):
            print(f"{Fore.RED}[!] This email appears in {len(data['details']['data_breach'])} known breaches{Fore.RESET}")
            for breach in data['details']['data_breach']:
                print(f"- {breach}")
        else:
            print(f"{Fore.GREEN}[+] No known breaches found{Fore.RESET}")
        
    except Exception as e:
        print(f"{Fore.RED}[-] Error during email lookup: {str(e)}{Fore.RESET}")

def phone_lookup(phone_number=""):
    clear_screen()
    print_banner()
    
    if not phone_number:
        phone_number = input(f"{Fore.CYAN}[?] Enter phone number (with country code): {Fore.RESET}").strip()
    
    if not phone_number:
        print(f"{Fore.RED}[-] No phone number provided{Fore.RESET}")
        return
    
    print(f"{Fore.GREEN}[+] Looking up phone number: {phone_number}{Fore.RESET}")
    
    try:
        # Using NumVerify API
        response = requests.get(f"http://apilayer.net/api/validate?access_key={NUMVERIFY_KEY}&number={phone_number}")
        data = response.json()
        
        if not data.get('valid', False):
            print(f"{Fore.RED}[-] Invalid phone number{Fore.RESET}")
            return
        
        print(f"\n{Fore.YELLOW}{'-'*80}{Fore.RESET}")
        print(f"{Fore.CYAN}[*] Phone Information:{Fore.RESET}")
        print(f"{Fore.YELLOW}{'-'*80}{Fore.RESET}")
        print(f"{Fore.WHITE}Number: {data.get('number', 'N/A')}")
        print(f"Local Format: {data.get('local_format', 'N/A')}")
        print(f"International Format: {data.get('international_format', 'N/A')}")
        print(f"Country: {data.get('country_name', 'N/A')} ({data.get('country_code', 'N/A')})")
        print(f"Location: {data.get('location', 'N/A')}")
        print(f"Carrier: {data.get('carrier', 'N/A')}")
        print(f"Line Type: {data.get('line_type', 'N/A')}")
        print(f"Valid: {'Yes' if data.get('valid', False) else 'No'}")
        
        # Additional checks
        print(f"\n{Fore.CYAN}[*] Additional Checks:{Fore.RESET}")
        print(f"{Fore.YELLOW}{'-'*80}{Fore.RESET}")
        
        # Check if number is associated with scams
        scam_check_url = f"https://www.whocallsme.com/Phone-Number.aspx/{phone_number}"
        print(f"Scam Check: {scam_check_url}")
        
        # Check social media
        social_media_url = f"https://www.social-searcher.com/search-users/?q={phone_number}"
        print(f"Social Media Check: {social_media_url}")
        
    except Exception as e:
        print(f"{Fore.RED}[-] Error during phone lookup: {str(e)}{Fore.RESET}")

def main_menu():
    install_dependencies()
    
    while True:
        print_banner()
        print(f"{Fore.CYAN}[*] Main Menu:{Fore.RESET}")
        print(f"{Fore.YELLOW}{'-'*80}{Fore.RESET}")
        print(f"{Fore.GREEN}1. WiFi Scanner (Auto-refresh){Fore.RESET}")
        print(f"{Fore.GREEN}2. Bluetooth Scanner (Auto-refresh){Fore.RESET}")
        print(f"{Fore.GREEN}3. IP Lookup{Fore.RESET}")
        print(f"{Fore.GREEN}4. Email Lookup{Fore.RESET}")
        print(f"{Fore.GREEN}5. Phone Lookup{Fore.RESET}")
        print(f"{Fore.RED}0. Exit{Fore.RESET}")
        print(f"{Fore.YELLOW}{'-'*80}{Fore.RESET}")
        
        choice = input(f"{Fore.CYAN}[?] Select an option: {Fore.RESET}").strip()
        
        if choice == "1":
            wifi_scanner()
        elif choice == "2":
            bluetooth_scanner()
        elif choice == "3":
            ip_lookup()
        elif choice == "4":
            email_lookup()
        elif choice == "5":
            phone_lookup()
        elif choice == "0":
            print(f"{Fore.RED}[!] Exiting...{Fore.RESET}")
            break
        else:
            print(f"{Fore.RED}[-] Invalid option{Fore.RESET}")
        
        input(f"\n{Fore.YELLOW}[*] Press Enter to continue...{Fore.RESET}")

if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Script terminated by user{Fore.RESET}")
    except Exception as e:
        print(f"\n{Fore.RED}[-] Fatal error: {str(e)}{Fore.RESET}")