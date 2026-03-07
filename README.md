# GHOSTRACE - Advanced OSINT Scanner

<p align="center">
  <img src="https://img.shields.io/badge/Version-1.0-blue" alt="Version">
  <img src="https://img.shields.io/badge/License-MIT-green" alt="License">
  <img src="https://img.shields.io/badge/Python-3.12+-yellow" alt="Python">
</p>

## About

**GHOSTRACE** is an advanced OSINT (Open Source Intelligence) username discovery tool that scans across 180+ online platforms to find where a username exists.

Inspired by: [API-s-for-OSINT](https://github.com/cipher387/API-s-for-OSINT) - A comprehensive collection of OSINT APIs

## Developed By

- **Developer:** Chriz
- **Email:** chrizmonsaji@proton.me
- **GitHub:** https://github.com/chriz-3656

## Features

- 🔍 **Username Scanning** - Scan across 180+ platforms
- 📧 **Email Breach Checking** - Check HaveIBeenPwned for compromised emails
- 🌐 **WHOIS Lookup** - Get domain registration info
- 📂 **Subdomain Enumeration** - Discover subdomains
- 🔐 **SSL Certificate Check** - View SSL certificate details
- 💻 **Dual Interface** - Terminal (CLI) and Web UI

### Additional Features (Based on API-s-for-OSINT recommendations)
- 🔎 **IP/Geo Lookup** - IP geolocation services (IPStack, IPInfoDB)
- 📱 **Phone Number Lookup** - NumVerify, Twilio integration ready
- 🏢 **Company Search** - Business entity lookup ready
- 🌪️ **Shodan Integration** - IoT device search ready
- 📡 **Network Tools** - BGP, DNS enumeration ready

## Installation

```bash
# Clone the repository
git clone https://github.com/chriz-3656/ghostrace.git
cd ghostrace

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
# or: venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt
```

## Usage

### Launcher (Choose Interface)
```bash
python start.py
```

### Terminal Interface
```bash
python scanner.py
```

### Web Interface
```bash
python web.py
# Open http://localhost:5000
```

## Requirements

- Python 3.12+
- aiohttp
- aiodns
- colorama
- python-whois
- flask
- pyfiglet

## Auto-Created Folders

On first run, the following folders are automatically created:
- `output/` - Scan results storage
- `logs/` - Application logs
- `data/` - Data files

## Platforms Supported

- Social Media: Facebook, Twitter, Instagram, LinkedIn, TikTok, Snapchat, Discord, Telegram, Reddit
- Gaming: Steam, Twitch, Roblox, Epic Games, Xbox, PlayStation, Minecraft
- Code: GitHub, GitLab, Bitbucket, NPM, PyPI, StackOverflow
- Crypto: OpenSea, Rarible, Foundation, MagicEden
- And 150+ more platforms...

## Upcoming Improvements

Based on [API-s-for-OSINT](https://github.com/cipher387/API-s-for-OSINT), future versions may include:

1. **Phone Number OSINT**
   - NumVerify API integration
   - Twilio Lookup integration

2. **IP/Network OSINT**
   - Shodan API integration
   - Censys API integration
   - IP geolocation (IPStack, IPInfoDB)

3. **Business OSINT**
   - Company search
   - LinkedIn company lookup

4. **More APIs**
   - VirusTotal
   - Hunter.io
   - Clearbit

## License

MIT License - See LICENSE file for details.

## Disclaimer

This tool is for educational purposes only. Use responsibly and with permission.
