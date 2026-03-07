# GHOSTRACE - API Requirements

## Free APIs (No Key Required) ✅

These features work WITHOUT any API key:

| Feature | API Used | Status |
|---------|----------|--------|
| Username Scan | Direct HTTP requests | ✅ Free |
| Email Breaches | HaveIBeenPwned (k-anonymity) | ✅ Free |
| WHOIS Lookup | python-whois | ✅ Free |
| Subdomains | DNS enumeration | ✅ Free |
| SSL Check | socket/SSL | ✅ Free |
| IP Geolocation | ip-api.com | ✅ Free (rate limited) |
| DNS Lookup | dnspython | ✅ Free |
| Port Scan | socket | ✅ Free |
| Reverse DNS | socket | ✅ Free |
| Web Crawler | aiohttp | ✅ Free |
| ASN Lookup | BGPView API | ✅ Free |
| HTTP Headers | aiohttp | ✅ Free |
| Domain Age | WHOIS | ✅ Free |
| Content Discovery | aiohttp | ✅ Free |
| Cloud Storage | AWS/Azure/GCP checks | ✅ Free |
| Technology Detect | aiohttp | ✅ Free |
| Dark Web Search | Ahmia (Tor) | ✅ Free |

---

## Paid/Tiered APIs (Optional) 🔑

These features can use optional API keys for more detailed results:

| Feature | API | Free Tier | Paid Tier |
|---------|-----|-----------|------------|
| Email Breaches | HaveIBeenPwned | Limited | Full API |
| IP Intelligence | Shodan | Limited | $5+/month |
| IP Intelligence | Censys | Limited | $100+/month |
| IP Intelligence | BinaryEdge | 100/month | $50+/month |
| Passive DNS | SecurityTrails | 250/month | $50+/month |
| Email Discovery | Hunter.io | 25/month | $50+/month |
| Company Data | Clearbit | Limited | $99+/month |
| Email Enrichment | FullContact | Limited | $99+/month |
| Threat Intel | AlienVault OTX | Limited | $100+/month |
| Threat Intel | VirusTotal | 4/minute | $15+/month |
| Breach Data | Dehashed | - | $99+/month |
| Person Search | Spokeo | - | Subscription |

---

## Quick Start (No API Needed)

You can use all basic features without any API key:

```bash
pip install -r requirements.txt
python scanner.py
```

### What Works Free:
- ✅ Username scanning (181+ sites)
- ✅ Email breach checking (basic)
- ✅ WHOIS lookup
- ✅ Subdomain enumeration
- ✅ SSL certificate analysis
- ✅ IP geolocation (ip-api.com - 45 requests/min)
- ✅ Port scanning
- ✅ Reverse DNS
- ✅ Web content extraction
- ✅ Technology detection

---

## Optional API Keys (For Power Users)

Get API keys for enhanced results:

1. **HaveIBeenPwned** - https://haveibeenpwned.com/API
2. **Shodan** - https://developer.shodan.io
3. **Hunter.io** - https://hunter.io/api
4. **SecurityTrails** - https://securitytrails.com
5. **Clearbit** - https://clearbit.com
6. **VirusTotal** - https://www.virustotal.com

---

## Summary

**GHOSTRACE works fully without any API keys!**

The tool uses free services and direct scanning techniques. API keys are optional for:
- Higher rate limits
- More detailed results
- Historical data
- Advanced threat intelligence
