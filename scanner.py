#!/usr/bin/env python3
"""
GHOSTRACE v1.0
Advanced OSINT Username Discovery Tool

Developed by: Chriz
Email: chrizmonsaji@proton.me
GitHub: https://github.com/chriz-3656

License: MIT
"""

import aiohttp
import asyncio
import json
import os
import time
import random
import socket
import ssl
import pyfiglet
from colorama import Fore, Style, init
from datetime import datetime

# Auto-create necessary folders on first run
def ensure_folders():
    folders = ['output', 'logs', 'data']
    for folder in folders:
        if not os.path.exists(folder):
            os.makedirs(folder)
            print(f"   {Fore.GREEN}>> Created folder: {folder}/{Style.RESET_ALL}")

ensure_folders()

init(autoreset=True)

# Tool Info
TOOL_NAME = "GHOSTRACE"
VERSION = "1.0"
CREATOR = "Chriz"
EMAIL = "chrizmonsaji@proton.me"
GITHUB = "https://github.com/chriz-3656"
LICENSE = "MIT"

USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
]

DEFAULT_DELAY = 0.5
MAX_CONCURRENT = 10
TIMEOUT = 10


def print_header():
    banner = pyfiglet.figlet_format("GHOSTRACE", font="big")
    print(Fore.CYAN + banner + Style.RESET_ALL)
    print(Fore.GREEN + f"  v{VERSION} | Developed by {CREATOR}" + Style.RESET_ALL)
    print()


def print_menu():
    print(f"{Fore.GREEN}[1]{Style.RESET_ALL}  Username Scan")
    print(f"{Fore.GREEN}[2]{Style.RESET_ALL}  Email + Breaches")
    print(f"{Fore.GREEN}[3]{Style.RESET_ALL}  WHOIS Lookup")
    print(f"{Fore.GREEN}[4]{Style.RESET_ALL}  Subdomains")
    print(f"{Fore.GREEN}[5]{Style.RESET_ALL}  SSL Check")
    print(f"{Fore.GREEN}[6]{Style.RESET_ALL}  List Sites")
    print(f"{Fore.GREEN}[7]{Style.RESET_ALL}  Settings")
    print(f"{Fore.GREEN}[0]{Style.RESET_ALL}  Exit")
    print()


def get_input(prompt, color=Fore.CYAN):
    return input(color + prompt + Style.RESET_ALL)


def load_sites():
    with open('sites.json', 'r') as f:
        return json.load(f)


class FootprintScanner:
    def __init__(self):
        self.sites = load_sites()
        self.found = []
        self.headers_list = [{'User-Agent': ua} for ua in USER_AGENTS]
        
    def get_headers(self):
        headers = random.choice(self.headers_list).copy()
        headers.update({
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'DNT': '1',
        })
        return headers

    async def check_site(self, session, site, username):
        url = self.sites[site]['url'].format(username)
        try:
            async with session.get(url, headers=self.get_headers(), 
                                   timeout=aiohttp.ClientTimeout(total=TIMEOUT)) as response:
                text = await response.text()
                status = response.status
                expected_status = self.sites[site].get('status_code', 200)
                negative_regex = self.sites[site].get('regex')
                
                if status == expected_status:
                    if negative_regex and negative_regex.lower() in text.lower():
                        return False
                    return True
                return False
        except:
            return False

    async def run(self, username):
        connector = aiohttp.TCPConnector(limit=MAX_CONCURRENT)
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = [self.check_site(session, site, username) for site in self.sites]
            results = await asyncio.gather(*tasks)
            
            for site, found in zip(self.sites.keys(), results):
                if found:
                    self.found.append({'site': site, 'url': self.sites[site]['url'].format(username)})
                    print("   " + Fore.GREEN + "[+]" + Style.RESET_ALL + " " + site)
                else:
                    print("   " + Fore.RED + "[-]" + Style.RESET_ALL + " " + site)
                await asyncio.sleep(DEFAULT_DELAY)
        
        return len(self.found)


class EmailFinder:
    async def check_breach(self, session, email, api_key):
        try:
            import hashlib
            sha1 = hashlib.sha1(email.encode()).hexdigest().upper()
            prefix, suffix = sha1[:5], sha1[5:]
            
            async with session.get(f"https://api.pwnedpasswords.com/range/{prefix}") as resp:
                if resp.status == 200:
                    data = await resp.text()
                    for line in data.split('\n'):
                        h, count = line.split(':')
                        if h == suffix:
                            return int(count)
        except:
            pass
        return 0


class WHOISLookup:
    def lookup(self, domain):
        try:
            import whois
            w = whois.whois(domain)
            return {
                'Domain': domain,
                'Registrar': w.registrar,
                'Created': str(w.creation_date),
                'Expires': str(w.expiration_date),
                'Name Servers': w.name_servers
            }
        except Exception as e:
            return {'Error': str(e)}


class SubdomainEnum:
    def __init__(self):
        self.subdomains = ['www', 'mail', 'ftp', 'webmail', 'smtp', 'pop', 'ns1', 
                          'ns2', 'cpanel', 'whm', 'autodiscover', 'admin', 'forum',
                          'blog', 'dev', 'test', 'ns', 'mx', 'static', 'beta', 'shop']
    
    async def enumerate(self, session, domain):
        found = []
        for sub in self.subdomains:
            url = f"http://{sub}.{domain}"
            try:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=3)) as resp:
                    if resp.status < 400:
                        found.append(url)
                        print("   " + Fore.GREEN + "[+]" + Style.RESET_ALL + " " + url)
            except:
                pass
        return found


class SSLCert:
    def check(self, hostname):
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    return {
                        'Subject': dict(x[0] for x in cert['subject']),
                        'Issuer': dict(x[0] for x in cert['issuer']),
                        'Valid Until': cert['notAfter']
                    }
        except Exception as e:
            return {'Error': str(e)}


def save_results(data, filename='output/results.json'):
    os.makedirs('output', exist_ok=True)
    with open(filename, 'w') as f:
        json.dump(data, f, indent=2)
    print("\n   " + Fore.GREEN + ">> Saved: " + filename + Style.RESET_ALL)


def print_credits():
    print(f"\n   {Fore.CYAN}{TOOL_NAME} v{VERSION}{Style.RESET_ALL}")
    print(f"   {Fore.YELLOW}Developed by: {CREATOR}{Style.RESET_ALL}")
    print(f"   {Fore.CYAN}Email: {EMAIL}{Style.RESET_ALL}")
    print(f"   {Fore.GREEN}GitHub: {GITHUB}{Style.RESET_ALL}")
    print(f"   {Fore.CYAN}License: {LICENSE}{Style.RESET_ALL}\n")


async def scan_username():
    username = get_input("   [?] Enter username > ")
    
    if not username:
        print("\n   " + Fore.RED + ">> Error: Username cannot be empty!" + Style.RESET_ALL)
        return
    
    print("\n   " + Fore.CYAN + ">> Scanning " + str(len(load_sites())) + " sites for: " + username + Style.RESET_ALL + "\n")
    
    scanner = FootprintScanner()
    total = await scanner.run(username)
    
    print("\n   " + Fore.GREEN + ">> Found on " + str(total) + " sites!" + Style.RESET_ALL)
    
    if total > 0:
        save = get_input("\n   [?] Save results? (y/n) > ", Fore.YELLOW)
        if save.lower() == 'y':
            save_results(scanner.found)
    
    get_input("\n   [Press Enter to continue]" + Style.RESET_ALL)


async def scan_email():
    email = get_input("   [?] Enter email > ")
    
    if '@' not in email:
        print("\n   " + Fore.RED + ">> Error: Invalid email!" + Style.RESET_ALL)
        get_input("\n   [Press Enter to continue]" + Style.RESET_ALL)
        return
    
    api_key = get_input("   [?] HIBP API Key (optional) > ")
    
    print("\n   " + Fore.CYAN + ">> Checking breaches..." + Style.RESET_ALL + "\n")
    
    async with aiohttp.ClientSession() as session:
        finder = EmailFinder()
        
        if api_key:
            count = await finder.check_breach(session, email, api_key)
            if count > 0:
                print("\n   " + Fore.RED + ">> Found in " + str(count) + " breaches!" + Style.RESET_ALL)
            else:
                print("\n   " + Fore.GREEN + ">> No breaches found!" + Style.RESET_ALL)
        else:
            print("   " + Fore.YELLOW + ">> Skipping (no API key)" + Style.RESET_ALL)
    
    get_input("\n   [Press Enter to continue]" + Style.RESET_ALL)


def do_whois():
    domain = get_input("   [?] Enter domain > ")
    
    if not domain:
        print("\n   " + Fore.RED + ">> Error: Domain required!" + Style.RESET_ALL)
        get_input("\n   [Press Enter to continue]" + Style.RESET_ALL)
        return
    
    print("\n   " + Fore.CYAN + ">> Looking up..." + Style.RESET_ALL + "\n")
    
    whois = WHOISLookup()
    result = whois.lookup(domain)
    
    for key, value in result.items():
        val = str(value)[:50] if value else 'N/A'
        print("   " + Fore.YELLOW + key + ":" + Style.RESET_ALL + " " + val)
    
    get_input("\n   [Press Enter to continue]" + Style.RESET_ALL)


async def enumerate_subdomains():
    domain = get_input("   [?] Enter domain > ")
    
    if not domain:
        print("\n   " + Fore.RED + ">> Error: Domain required!" + Style.RESET_ALL)
        get_input("\n   [Press Enter to continue]" + Style.RESET_ALL)
        return
    
    print("\n   " + Fore.CYAN + ">> Enumerating..." + Style.RESET_ALL + "\n")
    
    async with aiohttp.ClientSession() as session:
        enum = SubdomainEnum()
        results = await enum.enumerate(session, domain)
    
    print("\n   " + Fore.GREEN + ">> Found " + str(len(results)) + " subdomains!" + Style.RESET_ALL)
    
    if results:
        save = get_input("\n   [?] Save? (y/n) > ", Fore.YELLOW)
        if save.lower() == 'y':
            save_results(results, 'output/subdomains.json')
    
    get_input("\n   [Press Enter to continue]" + Style.RESET_ALL)


def check_ssl():
    hostname = get_input("   [?] Enter hostname > ")
    
    if not hostname:
        print("\n   " + Fore.RED + ">> Error: Hostname required!" + Style.RESET_ALL)
        get_input("\n   [Press Enter to continue]" + Style.RESET_ALL)
        return
    
    print("\n   " + Fore.CYAN + ">> Checking SSL..." + Style.RESET_ALL + "\n")
    
    checker = SSLCert()
    result = checker.check(hostname)
    
    for key, value in result.items():
        print("   " + Fore.YELLOW + key + ":" + Style.RESET_ALL + " " + str(value))
    
    get_input("\n   [Press Enter to continue]" + Style.RESET_ALL)


def list_sites():
    print_header()
    sites = load_sites()
    
    print("   " + Fore.CYAN + ">> Sites (" + str(len(sites)) + "):" + Style.RESET_ALL + "\n")
    
    categories = {
        'Social': ['Facebook', 'Twitter', 'Instagram', 'LinkedIn', 'TikTok', 'Snapchat', 'Discord', 'Telegram', 'Reddit'],
        'Gaming': ['Steam', 'Twitch', 'Roblox', 'EpicGames', 'Xbox', 'PlayStation', 'Minecraft'],
        'Code': ['GitHub', 'GitLab', 'Bitbucket', 'NPM', 'PyPI', 'StackOverflow', 'Replit', 'CodePen'],
        'Crypto': ['OpenSea', 'Rarible', 'Foundation', 'MagicEden', 'Solsea'],
    }
    
    for cat, names in categories.items():
        print("   " + Fore.GREEN + cat + ":" + Style.RESET_ALL)
        for name in names:
            if name in sites:
                print("      * " + name)
        print()
    
    print("   " + Fore.YELLOW + "...and " + str(len(sites) - sum(len(v) for v in categories.values())) + " more!" + Style.RESET_ALL)
    
    get_input("\n   [Press Enter to continue]" + Style.RESET_ALL)


def show_settings():
    print_header()
    print("   " + Fore.CYAN + "Settings" + Style.RESET_ALL + "\n")
    print("   Delay: " + Fore.GREEN + str(DEFAULT_DELAY) + "s" + Style.RESET_ALL)
    print("   Concurrent: " + Fore.GREEN + str(MAX_CONCURRENT) + Style.RESET_ALL)
    print("   Timeout: " + Fore.GREEN + str(TIMEOUT) + "s" + Style.RESET_ALL)
    print("   Sites: " + Fore.GREEN + str(len(load_sites())) + Style.RESET_ALL + "\n")
    print_credits()
    get_input("   [Press Enter to continue]" + Style.RESET_ALL)


async def main():
    while True:
        print_header()
        print_menu()
        
        choice = get_input("   [?] Select > ")
        
        if choice == '1':
            await scan_username()
        elif choice == '2':
            await scan_email()
        elif choice == '3':
            do_whois()
        elif choice == '4':
            await enumerate_subdomains()
        elif choice == '5':
            check_ssl()
        elif choice == '6':
            list_sites()
        elif choice == '7':
            show_settings()
        elif choice == '0':
            print_credits()
            print("   " + Fore.GREEN + ">> Thanks for using " + TOOL_NAME + "!" + Style.RESET_ALL + "\n")
            break
        else:
            print("\n   " + Fore.RED + ">> Invalid option!" + Style.RESET_ALL)
            time.sleep(1)


if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\n   " + Fore.RED + ">> Interrupted!" + Style.RESET_ALL + "\n")
    except Exception as e:
        print("\n   " + Fore.RED + ">> Error: " + str(e) + Style.RESET_ALL)
