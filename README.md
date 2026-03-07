# GHOSTRACE - Advanced OSINT Scanner

<p align="center">
  <img src="https://img.shields.io/badge/Version-1.2-blue" alt="Version">
  <img src="https://img.shields.io/badge/License-MIT-green" alt="License">
  <img src="https://img.shields.io/badge/Python-3.12+-yellow" alt="Python">
</p>

## About

**GHOSTRACE** is an advanced OSINT (Open Source Intelligence) tool for discovering information across multiple data sources.

## Developed By

- **Developer:** Chriz
- **Email:** chrizmonsaji@proton.me
- **GitHub:** https://github.com/chriz-3656

## Features (22 Options!)

### Core Scanning
| # | Feature | Description |
|---|---------|-------------|
| 1 | Username Scan | Find username across 181+ sites |
| 2 | Email + Breaches | Check HaveIBeenPwned |
| 3 | WHOIS Lookup | Domain registration info |
| 4 | Subdomains | Enumerate subdomains |
| 5 | SSL Check | SSL certificate details |

### Network Tools
| # | Feature | Description |
|---|---------|-------------|
| 6 | IP Geolocation | IP location lookup |
| 7 | Phone Lookup | Phone number info |
| 8 | DNS Lookup | A, MX, TXT, NS records |
| 11 | Port Scan | Scan common ports |
| 12 | Reverse DNS | IP to hostname |
| 14 | ASN Lookup | Autonomous System Number |

### Web Analysis
| # | Feature | Description |
|---|---------|-------------|
| 13 | Web Crawler | Extract emails/links |
| 15 | HTTP Headers | Server header analysis |
| 17 | Content Discovery | Emails, files, APIs |
| 20 | Technology Detect | CMS, frameworks detection |

### Threat Intelligence
| # | Feature | Description |
|---|---------|-------------|
| 10 | Hash Lookup | Check hash in breaches |
| 16 | Domain Age | Domain creation date |
| 18 | Pastebin Search | Search leaked data |
| 19 | Cloud Storage | AWS S3, Azure, GCP |
| 21 | Dark Web Search | Tor/Ahmia search |

## Installation

```bash
git clone https://github.com/chriz-3656/GHOSTRACE.git
cd GHOSTRACE
pip install -r requirements.txt
python scanner.py
```

## Requirements

- Python 3.12+
- aiohttp, aiodns
- colorama, python-whois
- flask, pyfiglet, dnspython

## Menu

```
GHOSTRACE v1.2

[1]  Username Scan      [12] Reverse DNS
[2]  Email + Breaches [13] Web Crawler
[3]  WHOIS Lookup      [14] ASN Lookup
[4]  Subdomains        [15] HTTP Headers
[5]  SSL Check         [16] Domain Age
[6]  IP Geolocation    [17] Content Discovery
[7]  Phone Lookup      [18] Pastebin Search
[8]  DNS Lookup        [19] Cloud Storage
[9]  List Sites        [20] Technology Detect
[10] Hash Lookup       [21] Dark Web Search
[11] Port Scan         [22] Settings
[0]  Exit
```

## Export

Results can be saved as JSON or CSV format.

## License

MIT License

## Disclaimer

For educational purposes only. Use responsibly.
