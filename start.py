#!/usr/bin/env python3
"""
GHOSTRACE v1.0
Main Launcher - Choose Interface

Developed by: Chriz
Email: chrizmonsaji@proton.me
GitHub: https://github.com/chriz-3656

License: MIT
"""

import os
import sys
import pyfiglet
from colorama import Fore, Style, init

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

def print_header():
    banner = pyfiglet.figlet_format("GHOSTRACE", font="big")
    print(Fore.CYAN + banner + Style.RESET_ALL)
    print(Fore.GREEN + f"  v{VERSION} | Developed by {CREATOR}" + Style.RESET_ALL)
    print()

def print_menu():
    print_header()
    print(f"{Fore.GREEN}[1]{Style.RESET_ALL}  Terminal Interface")
    print(f"{Fore.GREEN}[2]{Style.RESET_ALL}  Web Interface")
    print(f"{Fore.GREEN}[0]{Style.RESET_ALL}  Exit")
    print()

def print_credits():
    print(f"\n   {Fore.CYAN}{TOOL_NAME} v{VERSION}{Style.RESET_ALL}")
    print(f"   {Fore.YELLOW}Developed by: {CREATOR}{Style.RESET_ALL}")
    print(f"   {Fore.CYAN}Email: {EMAIL}{Style.RESET_ALL}")
    print(f"   {Fore.GREEN}GitHub: {GITHUB}{Style.RESET_ALL}")
    print(f"   {Fore.CYAN}License: {LICENSE}{Style.RESET_ALL}\n")

def main():
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        print_menu()
        
        choice = input(Fore.CYAN + "  [?] Select > " + Style.RESET_ALL)
        
        if choice == '1':
            # Replace current process with scanner.py
            os.execl(sys.executable, sys.executable, 'scanner.py')
        elif choice == '2':
            os.system('cls' if os.name == 'nt' else 'clear')
            print(Fore.YELLOW + "\n  >> Starting Web..." + Style.RESET_ALL)
            print(Fore.GREEN + "\n  >> Open: http://localhost:5000" + Style.RESET_ALL + "\n")
            import web
            web.run_web()
            break
        elif choice == '0':
            print(Fore.CYAN + "\n" + "="*50 + Style.RESET_ALL)
            print_credits()
            print(Fore.GREEN + "  >> Thanks for using " + TOOL_NAME + "!" + Style.RESET_ALL + "\n")
            break
        else:
            print(Fore.RED + "\n  >> Invalid option!" + Style.RESET_ALL)
            import time
            time.sleep(1)

if __name__ == '__main__':
    main()
