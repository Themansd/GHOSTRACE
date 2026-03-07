#!/usr/bin/env python3
"""
GHOSTRACE v1.2
Advanced OSINT Username Discovery Tool

Developed by: Chriz
Email: chrizmonsaji@proton.me
GitHub: https://github.com/chriz-3656

Version: 1.2 - More Features!
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
import csv
import re
import hashlib
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
VERSION = "1.2"
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
    print(f"{Fore.GREEN}[6]{Style.RESET_ALL}  IP Geolocation")
    print(f"{Fore.GREEN}[7]{Style.RESET_ALL}  Phone Lookup")
    print(f"{Fore.GREEN}[8]{Style.RESET_ALL}  DNS Lookup")
    print(f"{Fore.GREEN}[9]{Style.RESET_ALL}  List Sites")
    print(f"{Fore.GREEN}[10]{Style.RESET_ALL} Hash Lookup")
    print(f"{Fore.GREEN}[11]{Style.RESET_ALL} Port Scan")
    print(f"{Fore.GREEN}[12]{Style.RESET_ALL} Reverse DNS")
    print(f"{Fore.GREEN}[13]{Style.RESET_ALL} Web Crawler")
    print(f"{Fore.GREEN}[14]{Style.RESET_ALL} ASN Lookup")
    print(f"{Fore.GREEN}[15]{Style.RESET_ALL} HTTP Headers")
    print(f"{Fore.GREEN}[16]{Style.RESET_ALL} Domain Age")
    print(f"{Fore.GREEN}[17]{Style.RESET_ALL} Content Discovery")
    print(f"{Fore.GREEN}[18]{Style.RESET_ALL} Pastebin Search")
    print(f"{Fore.GREEN}[19]{Style.RESET_ALL} Cloud Storage")
    print(f"{Fore.GREEN}[20]{Style.RESET_ALL} Technology Detect")
    print(f"{Fore.GREEN}[21]{Style.RESET_ALL} Dark Web Search")
    print(f"{Fore.GREEN}[22]{Style.RESET_ALL} Settings")
    print(f"{Fore.GREEN}[0]{Style.RESET_ALL} Exit")
    print()


def get_input(prompt, color=Fore.CYAN):
    return input(color + prompt + Style.RESET_ALL)


def load_sites():
    with open('sites.json', 'r') as f:
        return json.load(f)


def save_results(data, filename='output/results.json'):
    os.makedirs('output', exist_ok=True)
    with open(filename, 'w') as f:
        json.dump(data, f, indent=2)
    print("\n   " + Fore.GREEN + ">> Saved: " + filename + Style.RESET_ALL)


def save_results_csv(data, filename='output/results.csv'):
    os.makedirs('output', exist_ok=True)
    if not data:
        return
    fields = list(data[0].keys())
    with open(filename, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(data)
    print("\n   " + Fore.GREEN + ">> Saved CSV: " + filename + Style.RESET_ALL)


# ============= SCANNER CLASSES =============

class FootprintScanner:
    def __init__(self):
        self.sites = load_sites()
        self.found = []
        
    async def check_site(self, session, site, username):
        url = self.sites[site]['url'].format(username)
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=TIMEOUT)) as response:
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


class ASNLookup:
    """ASN lookup using BGPView API (free)"""
    async def lookup(self, asn_or_ip):
        try:
            async with aiohttp.ClientSession() as session:
                # If it's an IP, first get ASN
                if not asn_or_ip.startswith('AS'):
                    # Use ip-api to get ASN info
                    url = f"http://ip-api.com/json/{asn_or_ip}"
                else:
                    # Direct ASN lookup
                    asn_num = asn_or_ip.replace('AS', '')
                    url = f"https://api.bgpview.io/asn/{asn_num}/prefixes"
                
                async with session.get(url) as resp:
                    if resp.status == 200:
                        return await resp.json()
        except Exception as e:
            return {'error': str(e)}
        return {'error': 'Failed to fetch'}


class HTTPHeaders:
    """Get HTTP headers from a website"""
    async def get_headers(self, url):
        try:
            if not url.startswith('http'):
                url = 'https://' + url
            async with aiohttp.ClientSession() as session:
                async with session.head(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    return dict(resp.headers)
        except Exception as e:
            return {'error': str(e)}


class DomainAge:
    """Check domain age using WHOIS"""
    def check_age(self, domain):
        try:
            import whois
            w = whois.whois(domain)
            created = w.creation_date
            if created:
                if isinstance(created, list):
                    created = created[0]
                age = datetime.now() - created
                return {
                    'domain': domain,
                    'created': str(created),
                    'age_days': age.days,
                    'registrar': str(w.registrar)
                }
        except Exception as e:
            return {'error': str(e)}
        return {'error': 'Could not determine age'}


class ContentDiscovery:
    """Discover interesting content on websites"""
    async def discover(self, url):
        findings = {
            'emails': [], 'phones': [], 'socials': [],
            'files': [], 'apis': [], 'comments': []
        }
        try:
            if not url.startswith('http'):
                url = 'https://' + url
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                    if resp.status == 200:
                        text = await resp.text()
                        
                        # Emails
                        emails = re.findall(r'[\w\.-]+@[\w\.-]+\.\w+', text)
                        findings['emails'] = list(set(emails))[:20]
                        
                        # Phone numbers
                        phones = re.findall(r'\+?[\d\s\-\(\)]{10,}', text)
                        findings['phones'] = list(set(phones))[:10]
                        
                        # Social media
                        socials = re.findall(r'(twitter\.com|facebook\.com|instagram\.com|linkedin\.com|github\.com)/[\w/]+', text)
                        findings['socials'] = list(set(socials))[:10]
                        
                        # Files
                        files = re.findall(r'\.(pdf|docx?|xlsx?|pptx?|zip|rar|tar|gz)\b', text, re.I)
                        findings['files'] = list(set(files))[:15]
                        
                        # API endpoints
                        apis = re.findall(r'/api/[\w/]+|/api\?[\w=&]+', text)
                        findings['apis'] = list(set(apis))[:15]
                        
                        # Comments
                        comments = re.findall(r'<!--[\s\S]*?-->', text)
                        findings['comments'] = comments[:5]
        except Exception as e:
            findings['error'] = str(e)
        return findings


class PastebinSearch:
    """Search Pastebin dumps (using DuckDuckGo)"""
    async def search(self, query):
        results = []
        try:
            # Using a public pastebin search API
            async with aiohttp.ClientSession() as session:
                url = f"https://psbdmp.ws/api/search/{query}"
                async with session.get(url) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        if 'dump' in data:
                            for dump in data['dump'][:10]:
                                results.append({
                                    'time': dump.get('time'),
                                    'size': dump.get('size'),
                                    'link': f"https://pastebin.com/{dump.get('id')}"
                                })
        except:
            pass
        return results


class CloudStorage:
    """Check for exposed cloud storage"""
    async def check_bucket(self, domain):
        findings = []
        # Extract domain name
        name = domain.split('.')[0] if '.' in domain else domain
        
        prefixes = [name, 'www', 'files', 'data', 'assets', 'uploads', 'media']
        providers = [
            ('s3.amazonaws.com/', 'AWS S3'),
            ('.blob.core.windows.net/', 'Azure'),
            ('.storage.googleapis.com/', 'GCP'),
            ('.digitaloceanspaces.com/', 'DO Spaces'),
        ]
        
        async with aiohttp.ClientSession() as session:
            for prefix in prefixes:
                for provider, name in providers:
                    url = f"https://{prefix}{provider}"
                    try:
                        async with session.get(url, timeout=aiohttp.ClientTimeout(total=3)) as resp:
                            if resp.status != 404:
                                findings.append({'url': url, 'provider': name, 'status': resp.status})
                                print("   " + Fore.GREEN + "[+]" + Style.RESET_ALL + f" {url}")
                    except:
                        pass
        return findings


class TechnologyDetect:
    """Detect website technologies"""
    async def detect(self, url):
        try:
            if not url.startswith('http'):
                url = 'https://' + url
            
            technologies = []
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    headers = dict(resp.headers)
                    server = headers.get('Server', '')
                    powered = headers.get('X-Powered-By', '')
                    
                    # Check headers
                    if 'nginx' in server.lower():
                        technologies.append('Nginx')
                    if 'apache' in server.lower():
                        technologies.append('Apache')
                    if 'cloudflare' in server.lower():
                        technologies.append('Cloudflare')
                    if 'php' in powered.lower():
                        technologies.append('PHP')
                    if 'express' in powered.lower():
                        technologies.append('Express.js')
                    
                    # Check cookies
                    cookies = headers.get('Set-Cookie', '')
                    if '__cf_bm' in cookies:
                        technologies.append('Cloudflare Bot')
                    
                    # Check for common JS frameworks in response
                    text = await resp.text()
                    if 'react' in text.lower():
                        technologies.append('React')
                    if 'vue' in text.lower():
                        technologies.append('Vue.js')
                    if 'jquery' in text.lower():
                        technologies.append('jQuery')
                    if 'bootstrap' in text.lower():
                        technologies.append('Bootstrap')
                    if 'wordpress' in text.lower():
                        technologies.append('WordPress')
                    if 'drupal' in text.lower():
                        technologies.append('Drupal')
                    
            return {'url': url, 'technologies': technologies}
        except Exception as e:
            return {'error': str(e)}


class DarkWebSearch:
    """Search dark web (via Ahmia - free Tor search)"""
    async def search(self, query):
        results = []
        try:
            async with aiohttp.ClientSession() as session:
                url = f"https://ahmia.fi/search/?q={query}"
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                    if resp.status == 200:
                        text = await resp.text()
                        # Extract onion links
                        links = re.findall(r'onion/[\w]+', text)
                        for link in list(set(links))[:10]:
                            results.append(f"http://{link}.onion")
        except Exception as e:
            return {'error': str(e)}
        return results


def print_credits():
    print(f"\n   {Fore.CYAN}{TOOL_NAME} v{VERSION}{Style.RESET_ALL}")
    print(f"   {Fore.YELLOW}Developed by: {CREATOR}{Style.RESET_ALL}")
    print(f"   {Fore.CYAN}Email: {EMAIL}{Style.RESET_ALL}")
    print(f"   {Fore.GREEN}GitHub: {GITHUB}{Style.RESET_ALL}")
    print(f"   {Fore.CYAN}License: {LICENSE}{Style.RESET_ALL}\n")


# ============= MENU FUNCTIONS =============

async def scan_username():
    username = get_input("   [?] Enter username > ")
    if not username:
        return
    
    print("\n   " + Fore.CYAN + ">> Scanning..." + Style.RESET_ALL + "\n")
    scanner = FootprintScanner()
    total = await scanner.run(username)
    print("\n   " + Fore.GREEN + f">> Found on {total} sites!" + Style.RESET_ALL)
    
    if total > 0:
        save = get_input("\n   [?] Save? (y/json/csv) > ", Fore.YELLOW)
        if save.lower() == 'y':
            save_results(scanner.found)
        elif save.lower() == 'c':
            save_results_csv(scanner.found)
    
    get_input("\n   [Press Enter]" + Style.RESET_ALL)


async def scan_email():
    email = get_input("   [?] Enter email > ")
    if '@' not in email:
        print(Fore.RED + "Invalid email!")
        return
    
    print("\n   " + Fore.CYAN + ">> Checking breaches..." + Style.RESET_ALL)
    
    try:
        sha1 = hashlib.sha1(email.encode()).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]
        async with aiohttp.ClientSession() as session:
            async with session.get(f"https://api.pwnedpasswords.com/range/{prefix}") as resp:
                if resp.status == 200:
                    data = await resp.text()
                    for line in data.split('\n'):
                        h, count = line.split(':')
                        if h == suffix:
                            print(Fore.RED + f">> Found in {count} breaches!")
                            break
                    else:
                        print(Fore.GREEN + ">> No breaches found!")
    except Exception as e:
        print(Fore.RED + f"Error: {e}")
    
    get_input("\n   [Press Enter]" + Style.RESET_ALL)


def do_whois():
    domain = get_input("   [?] Enter domain > ")
    if not domain:
        return
    
    try:
        import whois
        w = whois.whois(domain)
        print(f"\n   Domain: {w.domain}")
        print(f"   Registrar: {w.registrar}")
        print(f"   Created: {w.creation_date}")
        print(f"   Expires: {w.expiration_date}")
    except Exception as e:
        print(Fore.RED + f"Error: {e}")
    
    get_input("\n   [Press Enter]" + Style.RESET_ALL)


async def enumerate_subdomains():
    domain = get_input("   [?] Enter domain > ")
    if not domain:
        return
    
    subdomains = ['www', 'mail', 'ftp', 'webmail', 'smtp', 'pop', 'ns1', 'ns2', 
                  'cpanel', 'whm', 'admin', 'forum', 'blog', 'dev', 'test', 'ns', 
                  'mx', 'static', 'beta', 'shop', 'cdn', 'api', 'app', 'cloud']
    
    found = []
    async with aiohttp.ClientSession() as session:
        for sub in subdomains:
            url = f"http://{sub}.{domain}"
            try:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=3)) as resp:
                    if resp.status < 400:
                        found.append(url)
                        print("   " + Fore.GREEN + "[+]" + Style.RESET_ALL + " " + url)
            except:
                pass
    
    print(Fore.GREEN + f"\n   >> Found {len(found)} subdomains!")
    get_input("\n   [Press Enter]" + Style.RESET_ALL)


def check_ssl():
    hostname = get_input("   [?] Enter hostname > ")
    if not hostname:
        return
    
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                print(Fore.GREEN + "\n   Subject:", dict(x[0] for x in cert['subject']))
                print(Fore.CYAN + "   Issuer:", dict(x[0] for x in cert['issuer']))
                print(Fore.YELLOW + "   Valid until:", cert['notAfter'])
    except Exception as e:
        print(Fore.RED + f"Error: {e}")
    
    get_input("\n   [Press Enter]" + Style.RESET_ALL)


async def ip_geo():
    ip_addr = get_input("   [?] Enter IP > ")
    if not ip_addr:
        return
    
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(f"http://ip-api.com/json/{ip_addr}") as resp:
                if resp.status == 200:
                    data = await resp.json()
                    print(Fore.GREEN + f"\n   Country: {data.get('country')}")
                    print(f"   City: {data.get('city')}")
                    print(f"   ISP: {data.get('isp')}")
                    print(f"   Org: {data.get('org')}")
    except Exception as e:
        print(Fore.RED + f"Error: {e}")
    
    get_input("\n   [Press Enter]" + Style.RESET_ALL)


async def asn_lookup():
    target = get_input("   [?] Enter IP or ASN > ")
    if not target:
        return
    
    lookup = ASNLookup()
    result = await lookup.lookup(target)
    print(Fore.GREEN + f"\n   Result: {result}")
    get_input("\n   [Press Enter]" + Style.RESET_ALL)


async def http_headers():
    url = get_input("   [?] Enter URL > ")
    if not url:
        return
    
    h = HTTPHeaders()
    headers = await h.get_headers(url)
    print(Fore.GREEN + "\n   HTTP Headers:")
    for k, v in headers.items():
        print(f"   {k}: {v}")
    get_input("\n   [Press Enter]" + Style.RESET_ALL)


def domain_age():
    domain = get_input("   [?] Enter domain > ")
    if not domain:
        return
    
    d = DomainAge()
    result = d.check_age(domain)
    print(Fore.GREEN + f"\n   Created: {result.get('created')}")
    print(f"   Age (days): {result.get('age_days')}")
    get_input("\n   [Press Enter]" + Style.RESET_ALL)


async def content_discovery():
    url = get_input("   [?] Enter URL > ")
    if not url:
        return
    
    cd = ContentDiscovery()
    result = await cd.discover(url)
    
    print(Fore.GREEN + "\n   Emails found:")
    for e in result.get('emails', [])[:10]:
        print(f"      {e}")
    
    print(Fore.CYAN + "\n   Files found:")
    for f in result.get('files', [])[:10]:
        print(f"      {f}")
    
    get_input("\n   [Press Enter]" + Style.RESET_ALL)


async def pastebin_search():
    query = get_input("   [?] Enter search query > ")
    if not query:
        return
    
    print(Fore.CYAN + "\n   Searching Pastebin..." + Style.RESET_ALL)
    p = PastebinSearch()
    results = await p.search(query)
    
    for r in results:
        print(f"   {r}")
    
    get_input("\n   [Press Enter]" + Style.RESET_ALL)


async def cloud_storage():
    domain = get_input("   [?] Enter domain > ")
    if not domain:
        return
    
    print(Fore.CYAN + "\n   Checking cloud storage..." + Style.RESET_ALL)
    c = CloudStorage()
    results = await c.check_bucket(domain)
    print(Fore.GREEN + f"\n   Found {len(results)} potential buckets")
    get_input("\n   [Press Enter]" + Style.RESET_ALL)


async def tech_detect():
    url = get_input("   [?] Enter URL > ")
    if not url:
        return
    
    t = TechnologyDetect()
    result = await t.detect(url)
    
    print(Fore.GREEN + "\n   Technologies detected:")
    for tech in result.get('technologies', []):
        print(f"      - {tech}")
    
    get_input("\n   [Press Enter]" + Style.RESET_ALL)


async def dark_web():
    query = get_input("   [?] Enter search query > ")
    if not query:
        return
    
    print(Fore.CYAN + "\n   Searching dark web (Tor)..." + Style.RESET_ALL)
    d = DarkWebSearch()
    results = await d.search(query)
    
    for r in results[:10]:
        print(f"   {r}")
    
    get_input("\n   [Press Enter]" + Style.RESET_ALL)


def show_settings():
    print_header()
    print("   " + Fore.CYAN + "Settings" + Style.RESET_ALL)
    print("   Delay: " + Fore.GREEN + str(DEFAULT_DELAY) + "s")
    print("   Concurrent: " + Fore.GREEN + str(MAX_CONCURRENT))
    print("   Sites: " + Fore.GREEN + str(len(load_sites())))
    print_credits()
    get_input("   [Press Enter]" + Style.RESET_ALL)


# ============= MAIN =============

async def main():
    while True:
        print_header()
        print_menu()
        
        choice = get_input("   [?] Select > ")
        
        actions = {
            '1': scan_username,
            '2': scan_email,
            '3': do_whois,
            '4': enumerate_subdomains,
            '5': check_ssl,
            '6': ip_geo,
            '7': lambda: (print("Use option 8 for DNS"), get_input("\n[Press Enter]"))[1],
            '8': dns_lookup_menu,
            '9': list_sites,
            '10': hash_lookup,
            '11': port_scan_menu,
            '12': reverse_dns_menu,
            '13': web_crawler_menu,
            '14': asn_lookup,
            '15': http_headers,
            '16': domain_age,
            '17': content_discovery,
            '18': pastebin_search,
            '19': cloud_storage,
            '20': tech_detect,
            '21': dark_web,
            '22': show_settings,
        }
        
        if choice == '0':
            print_credits()
            print(Fore.GREEN + "   >> Thanks for using " + TOOL_NAME + "!" + Style.RESET_ALL + "\n")
            break
        elif choice in actions:
            await actions[choice]()
        else:
            print(Fore.RED + "\n   >> Invalid option!" + Style.RESET_ALL)
            time.sleep(1)


# Quick placeholder functions
async def dns_lookup_menu():
    domain = get_input("   [?] Enter domain > ")
    print(Fore.YELLOW + "   Use DNS tools from web interface for full DNS lookup")

async def hash_lookup():
    hash_val = get_input("   [?] Enter hash > ")
    print(Fore.YELLOW + "   Hash lookup available in web interface")

async def port_scan_menu():
    host = get_input("   [?] Enter host > ")
    print(Fore.YELLOW + "   Port scan available in web interface")

async def reverse_dns_menu():
    ip = get_input("   [?] Enter IP > ")
    print(Fore.YELLOW + "   Reverse DNS available in web interface")

async def web_crawler_menu():
    url = get_input("   [?] Enter URL > ")
    print(Fore.YELLOW + "   Web crawler available in web interface")

def list_sites():
    print_header()
    sites = load_sites()
    print(Fore.GREEN + f"   Total sites: {len(sites)}")
    get_input("   [Press Enter]" + Style.RESET_ALL)


if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\n   " + Fore.RED + ">> Interrupted!" + Style.RESET_ALL)
    except Exception as e:
        print("\n   " + Fore.RED + f">> Error: {e}" + Style.RESET_ALL)
