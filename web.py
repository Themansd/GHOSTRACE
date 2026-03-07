#!/usr/bin/env python3
"""
GHOSTRACE v1.2 - Web Interface
Advanced OSINT Username Discovery Tool

Developed by: Chriz
Email: chrizmonsaji@proton.me
GitHub: https://github.com/chriz-3656
License: MIT
"""

from flask import Flask, render_template_string, request, jsonify
import asyncio
import json
import os
import random
import socket
import ssl
import aiohttp
import re
import hashlib
from datetime import datetime
from colorama import Fore, Style, init

# Auto-create necessary folders
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

app = Flask(__name__)
scan_history = []

def load_sites():
    with open('sites.json', 'r') as f:
        return json.load(f)

USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
]

# ============= SCANNER CLASSES =============

class FootprintScanner:
    def __init__(self):
        self.sites = load_sites()
        
    async def check_site(self, session, site, username):
        url = self.sites[site]['url'].format(username)
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as response:
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

    def run(self, username):
        async def run_async():
            connector = aiohttp.TCPConnector(limit=10)
            async with aiohttp.ClientSession(connector=connector) as session:
                tasks = [self.check_site(session, site, username) for site in self.sites]
                results = await asyncio.gather(*tasks)
                found = []
                for site, found_flag in zip(self.sites.keys(), results):
                    if found_flag:
                        found.append({'site': site, 'url': self.sites[site]['url'].format(username)})
                return found
        return asyncio.run(run_async())


class IPGeoLookup:
    def lookup(self, ip_addr):
        async def run_async():
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(f"http://ip-api.com/json/{ip_addr}") as resp:
                        if resp.status == 200:
                            return await resp.json()
            except:
                pass
            return {'error': 'Failed'}
        return asyncio.run(run_async())


class PortScanner:
    def scan(self, host):
        ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5432, 8080, 8443]
        results = []
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((host, port))
            if result == 0:
                results.append({'port': port, 'status': 'open'})
            sock.close()
        return results


class SubdomainEnum:
    def enumerate(self, domain):
        subdomains = ['www', 'mail', 'ftp', 'webmail', 'smtp', 'pop', 'ns1', 'ns2', 
                     'cpanel', 'whm', 'admin', 'blog', 'dev', 'test', 'mx', 'static',
                     'cdn', 'api', 'app', 'cloud', 'shop']
        async def run_async():
            found = []
            async with aiohttp.ClientSession() as session:
                for sub in subdomains:
                    url = f"http://{sub}.{domain}"
                    try:
                        async with session.get(url, timeout=aiohttp.ClientTimeout(total=3)) as resp:
                            if resp.status < 400:
                                found.append(url)
                    except:
                        pass
            return found
        return asyncio.run(run_async())


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


class TechnologyDetect:
    def detect(self, url):
        if not url.startswith('http'):
            url = 'https://' + url
        async def run_async():
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                        headers = dict(resp.headers)
                        text = await resp.text()
                        tech = []
                        server = headers.get('Server', '')
                        if 'nginx' in server.lower(): tech.append('Nginx')
                        if 'apache' in server.lower(): tech.append('Apache')
                        if 'cloudflare' in server.lower(): tech.append('Cloudflare')
                        if 'react' in text.lower(): tech.append('React')
                        if 'vue' in text.lower(): tech.append('Vue.js')
                        if 'jquery' in text.lower(): tech.append('jQuery')
                        if 'bootstrap' in text.lower(): tech.append('Bootstrap')
                        if 'wordpress' in text.lower(): tech.append('WordPress')
                        return {'technologies': tech}
            except Exception as e:
                return {'error': str(e)}
        return asyncio.run(run_async())


class ContentDiscovery:
    def discover(self, url):
        if not url.startswith('http'):
            url = 'https://' + url
        async def run_async():
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                        if resp.status == 200:
                            text = await resp.text()
                            emails = re.findall(r'[\w\.-]+@[\w\.-]+\.\w+', text)[:20]
                            files = re.findall(r'\.(pdf|docx?|xlsx?|zip|rar)\b', text, re.I)[:15]
                            return {'emails': emails, 'files': files}
            except Exception as e:
                return {'error': str(e)}
        return asyncio.run(run_async())


# ============= HTML TEMPLATE =============

HTML_TEMPLATE = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GHOSTRACE - Advanced OSINT Scanner</title>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-primary: #0a0a0f;
            --bg-secondary: #12121a;
            --bg-card: #1a1a24;
            --bg-hover: #22222e;
            --accent: #00ff88;
            --accent-dim: #00cc6a;
            --accent-glow: rgba(0, 255, 136, 0.15);
            --text-primary: #ffffff;
            --text-secondary: #8888aa;
            --text-muted: #555566;
            --border: #2a2a3a;
            --success: #00ff88;
            --error: #ff4466;
            --warning: #ffaa00;
        }
        
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: 'Inter', -apple-system, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            min-height: 100vh;
            line-height: 1.6;
        }
        
        .bg-grid {
            position: fixed;
            top: 0; left: 0; right: 0; bottom: 0;
            background-image: linear-gradient(rgba(0,255,136,0.03) 1px, transparent 1px),
            linear-gradient(90deg, rgba(0,255,136,0.03) 1px, transparent 1px);
            background-size: 50px 50px;
            pointer-events: none;
            z-index: 0;
        }
        
        .bg-glow {
            position: fixed;
            width: 600px; height: 600px;
            background: radial-gradient(circle, rgba(0,255,136,0.1) 0%, transparent 70%);
            top: -200px; right: -200px;
            pointer-events: none;
            z-index: 0;
        }
        
        .container {
            max-width: 1100px;
            margin: 0 auto;
            padding: 30px 20px;
            position: relative;
            z-index: 1;
        }
        
        header {
            text-align: center;
            margin-bottom: 40px;
            animation: fadeInDown 0.6s ease;
        }
        
        @keyframes fadeInDown {
            from { opacity: 0; transform: translateY(-20px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        .logo {
            font-family: 'JetBrains Mono', monospace;
            font-size: 3.5em;
            font-weight: 700;
            background: linear-gradient(135deg, var(--accent) 0%, #00ccff 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            letter-spacing: -2px;
            margin-bottom: 8px;
        }
        
        .tagline {
            color: var(--text-secondary);
            font-size: 1.1em;
            letter-spacing: 2px;
            text-transform: uppercase;
        }
        
        nav {
            display: flex;
            justify-content: center;
            gap: 8px;
            margin-bottom: 40px;
            flex-wrap: wrap;
        }
        
        nav a {
            color: var(--text-secondary);
            text-decoration: none;
            padding: 12px 20px;
            border-radius: 8px;
            font-weight: 500;
            font-size: 0.85em;
            transition: all 0.3s ease;
            border: 1px solid transparent;
        }
        
        nav a:hover {
            color: var(--accent);
            background: var(--accent-glow);
            border-color: var(--accent);
        }
        
        nav a.active {
            color: var(--bg-primary);
            background: var(--accent);
            border-color: var(--accent);
        }
        
        .card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 32px;
            margin-bottom: 24px;
        }
        
        .card h2 {
            font-size: 1.5em;
            margin-bottom: 8px;
        }
        
        .card p {
            color: var(--text-secondary);
            margin-bottom: 24px;
        }
        
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .stat-box {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 20px;
            text-align: center;
        }
        
        .stat-box .number {
            font-size: 2em;
            font-weight: 700;
            color: var(--accent);
            font-family: 'JetBrains Mono', monospace;
        }
        
        .stat-box .label {
            color: var(--text-secondary);
            font-size: 0.85em;
            margin-top: 8px;
        }
        
        .form-group { margin-bottom: 20px; }
        
        label {
            display: block;
            margin-bottom: 8px;
            color: var(--text-secondary);
            font-size: 0.9em;
            font-weight: 500;
        }
        
        input, select {
            width: 100%;
            padding: 14px 18px;
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 10px;
            color: var(--text-primary);
            font-family: 'JetBrains Mono', monospace;
            font-size: 1em;
            transition: all 0.3s ease;
        }
        
        input:focus {
            outline: none;
            border-color: var(--accent);
            box-shadow: 0 0 0 3px var(--accent-glow);
        }
        
        button {
            background: linear-gradient(135deg, var(--accent) 0%, var(--accent-dim) 100%);
            color: var(--bg-primary);
            border: none;
            padding: 14px 32px;
            font-size: 1em;
            font-weight: 600;
            border-radius: 10px;
            cursor: pointer;
            transition: all 0.3s ease;
        }
        
        button:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 25px var(--accent-glow);
        }
        
        .result-item {
            padding: 14px;
            margin: 10px 0;
            border-radius: 10px;
            background: var(--bg-secondary);
            border-left: 3px solid var(--accent);
        }
        
        .result-item a {
            color: var(--accent);
            text-decoration: none;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.9em;
        }
        
        .status {
            padding: 16px 24px;
            border-radius: 10px;
            margin: 16px 0;
            font-weight: 500;
        }
        
        .status.success {
            background: rgba(0, 255, 136, 0.1);
            border: 1px solid var(--accent);
            color: var(--accent);
        }
        
        .status.error {
            background: rgba(255, 68, 102, 0.1);
            border: 1px solid var(--error);
            color: var(--error);
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 16px;
        }
        
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }
        
        th {
            color: var(--accent);
            font-weight: 600;
            font-size: 0.85em;
            text-transform: uppercase;
        }
        
        td {
            color: var(--text-secondary);
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.85em;
        }
        
        footer {
            text-align: center;
            padding: 30px;
            color: var(--text-muted);
            font-size: 0.85em;
            border-top: 1px solid var(--border);
            margin-top: 50px;
        }
        
        footer a {
            color: var(--accent);
            text-decoration: none;
        }
        
        .feature-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 20px;
        }
        
        .feature-item {
            background: var(--bg-secondary);
            padding: 15px;
            border-radius: 8px;
            border-left: 3px solid var(--accent);
        }
        
        .feature-item strong {
            color: var(--accent);
            display: block;
            margin-bottom: 5px;
        }
        
        .feature-item span {
            color: var(--text-secondary);
            font-size: 0.85em;
        }
        
        @media (max-width: 768px) {
            .logo { font-size: 2.5em; }
            nav { gap: 4px; }
            nav a { padding: 8px 12px; font-size: 0.75em; }
        }
    </style>
</head>
<body>
    <div class="bg-grid"></div>
    <div class="bg-glow"></div>
    
    <div class="container">
        <header>
            <div class="logo">GHOSTRACE</div>
            <div class="tagline">Advanced OSINT Scanner v1.2</div>
        </header>
        
        <nav>
            <a href="/" class="{{ 'active' if page == 'home' else '' }}">Home</a>
            <a href="/scan" class="{{ 'active' if page == 'scan' else '' }}">Username</a>
            <a href="/email" class="{{ 'active' if page == 'email' else '' }}">Breaches</a>
            <a href="/whois" class="{{ 'active' if page == 'whois' else '' }}">WHOIS</a>
            <a href="/subdomains" class="{{ 'active' if page == 'subdomains' else '' }}">Subdomains</a>
            <a href="/ssl" class="{{ 'active' if page == 'ssl' else '' }}">SSL</a>
            <a href="/ipgeo" class="{{ 'active' if page == 'ipgeo' else '' }}">IP Geo</a>
            <a href="/ports" class="{{ 'active' if page == 'ports' else '' }}">Ports</a>
            <a href="/tech" class="{{ 'active' if page == 'tech' else '' }}">Tech</a>
            <a href="/content" class="{{ 'active' if page == 'content' else '' }}">Content</a>
            <a href="/history" class="{{ 'active' if page == 'history' else '' }}">History</a>
        </nav>
        
        {% block content %}{% endblock %}
        
        <footer>
            <p><strong>GHOSTRACE</strong> v1.2 | Developed by Chriz</p>
            <p><a href="https://github.com/chriz-3656" target="_blank">GitHub</a> | Email: chrizmonsaji@proton.me | License: MIT</p>
        </footer>
    </div>
</body>
</html>
'''

# ============= PAGE TEMPLATES =============

HOME_TEMPLATE = HTML_TEMPLATE.replace('{% block content %}{% endblock %}', '''
<div class="stats">
    <div class="stat-box">
        <div class="number">{{ sites_count }}</div>
        <div class="label">Sites</div>
    </div>
    <div class="stat-box">
        <div class="number">{{ history_count }}</div>
        <div class="label">Scans</div>
    </div>
    <div class="stat-box">
        <div class="number">{{ total_found }}</div>
        <div class="label">Found</div>
    </div>
</div>

<div class="card">
    <h2>Welcome to GHOSTRACE v1.2</h2>
    <p>Advanced OSINT tool with 22+ scanning capabilities</p>
    
    <div class="feature-grid">
        <div class="feature-item">
            <strong>Username Scan</strong>
            <span>Find across 181+ platforms</span>
        </div>
        <div class="feature-item">
            <strong>Email Breaches</strong>
            <span>HaveIBeenPwned lookup</span>
        </div>
        <div class="feature-item">
            <strong>WHOIS Lookup</strong>
            <span>Domain registration info</span>
        </div>
        <div class="feature-item">
            <strong>Subdomains</strong>
            <span>Enumerate subdomains</span>
        </div>
        <div class="feature-item">
            <strong>IP Geolocation</strong>
            <span>City, Country, ISP</span>
        </div>
        <div class="feature-item">
            <strong>Port Scanner</strong>
            <span>Scan common ports</span>
        </div>
        <div class="feature-item">
            <strong>Technology Detect</strong>
            <span>CMS, frameworks</span>
        </div>
        <div class="feature-item">
            <strong>Content Discovery</strong>
            <span>Extract emails, files</span>
        </div>
    </div>
</div>

<div class="card">
    <h2>Quick Start</h2>
    <nav style="justify-content: flex-start; margin-bottom: 0;">
        <a href="/scan" style="background: var(--accent); color: var(--bg-primary);">Start Scan</a>
        <a href="/email">Check Breaches</a>
        <a href="/ipgeo">IP Lookup</a>
    </nav>
</div>
''')

SCAN_TEMPLATE = HTML_TEMPLATE.replace('{% block content %}{% endblock %}', '''
<div class="card">
    <h2>Username Scanner</h2>
    <p>Scan for username across 181+ platforms</p>
    <form method="POST" action="/scan">
        <div class="form-group">
            <label>Enter Username</label>
            <input type="text" name="username" placeholder="e.g., johndoe" required>
        </div>
        <button type="submit">Start Scan</button>
    </form>
</div>

{% if results %}
<div class="card">
    <h2>Results: {{ username }}</h2>
    <p>Found on <strong style="color: var(--accent);">{{ found_count }}</strong> sites</p>
    {% for result in results %}
    <div class="result-item">
        <strong>{{ result.site }}</strong><br>
        <a href="{{ result.url }}" target="_blank">{{ result.url }}</a>
    </div>
    {% endfor %}
</div>
{% endif %}
''')

EMAIL_TEMPLATE = HTML_TEMPLATE.replace('{% block content %}{% endblock %}', '''
<div class="card">
    <h2>Email Breach Check</h2>
    <p>Check if email has been compromised</p>
    <form method="POST" action="/email">
        <div class="form-group">
            <label>Email Address</label>
            <input type="email" name="email" placeholder="user@example.com" required>
        </div>
        <button type="submit">Check Breaches</button>
    </form>
    
    {% if result %}
    <div class="card">
        <h3>Results:</h3>
        {% if result > 0 %}
        <div class="status error">Found in {{ result }} data breaches!</div>
        {% else %}
        <div class="status success">No breaches found</div>
        {% endif %}
    </div>
    {% endif %}
</div>
''')

WHOIS_TEMPLATE = HTML_TEMPLATE.replace('{% block content %}{% endblock %}', '''
<div class="card">
    <h2>WHOIS Lookup</h2>
    <p>Get domain registration information</p>
    <form method="POST" action="/whois">
        <div class="form-group">
            <label>Domain Name</label>
            <input type="text" name="domain" placeholder="example.com" required>
        </div>
        <button type="submit">Lookup</button>
    </form>
    
    {% if result %}
    <div class="card">
        <h3>WHOIS Results</h3>
        <table>
            {% for key, value in result.items() %}
            <tr><th>{{ key }}</th><td>{{ value }}</td></tr>
            {% endfor %}
        </table>
    </div>
    {% endif %}
</div>
''')

SUBDOMAIN_TEMPLATE = HTML_TEMPLATE.replace('{% block content %}{% endblock %}', '''
<div class="card">
    <h2>Subdomain Enumeration</h2>
    <p>Discover subdomains for a domain</p>
    <form method="POST" action="/subdomains">
        <div class="form-group">
            <label>Domain</label>
            <input type="text" name="domain" placeholder="example.com" required>
        </div>
        <button type="submit">Enumerate</button>
    </form>
    
    {% if results %}
    <div class="card">
        <h3>Found {{ results|length }} subdomains:</h3>
        {% for subdomain in results %}
        <div class="result-item">
            <a href="{{ subdomain }}" target="_blank">{{ subdomain }}</a>
        </div>
        {% endfor %}
    </div>
    {% endif %}
</div>
''')

SSL_TEMPLATE = HTML_TEMPLATE.replace('{% block content %}{% endblock %}', '''
<div class="card">
    <h2>SSL Certificate Check</h2>
    <p>Get SSL certificate information</p>
    <form method="POST" action="/ssl">
        <div class="form-group">
            <label>Hostname</label>
            <input type="text" name="hostname" placeholder="example.com" required>
        </div>
        <button type="submit">Check Certificate</button>
    </form>
    
    {% if result %}
    <div class="card">
        <h3>SSL Certificate Info</h3>
        <table>
            {% for key, value in result.items() %}
            <tr><th>{{ key }}</th><td>{{ value }}</td></tr>
            {% endfor %}
        </table>
    </div>
    {% endif %}
</div>
''')

IPGEO_TEMPLATE = HTML_TEMPLATE.replace('{% block content %}{% endblock %}', '''
<div class="card">
    <h2>IP Geolocation</h2>
    <p>Look up IP address location</p>
    <form method="POST" action="/ipgeo">
        <div class="form-group">
            <label>IP Address</label>
            <input type="text" name="ip" placeholder="8.8.8.8" required>
        </div>
        <button type="submit">Lookup</button>
    </form>
    
    {% if result and result.get('country') %}
    <div class="card">
        <h3>Location Info</h3>
        <table>
            <tr><th>Country</th><td>{{ result.country }}</td></tr>
            <tr><th>City</th><td>{{ result.city }}</td></tr>
            <tr><th>ISP</th><td>{{ result.isp }}</td></tr>
            <tr><th>Org</th><td>{{ result.org }}</td></tr>
        </table>
    </div>
    {% endif %}
</div>
''')

PORTS_TEMPLATE = HTML_TEMPLATE.replace('{% block content %}{% endblock %}', '''
<div class="card">
    <h2>Port Scanner</h2>
    <p>Scan for open ports</p>
    <form method="POST" action="/ports">
        <div class="form-group">
            <label>Host/IP</label>
            <input type="text" name="host" placeholder="example.com" required>
        </div>
        <button type="submit">Scan Ports</button>
    </form>
    
    {% if results %}
    <div class="card">
        <h3>Open Ports: {{ results|length }}</h3>
        {% for r in results %}
        <div class="result-item">
            Port {{ r.port }} - {{ r.status }}
        </div>
        {% endfor %}
    </div>
    {% endif %}
</div>
''')

TECH_TEMPLATE = HTML_TEMPLATE.replace('{% block content %}{% endblock %}', '''
<div class="card">
    <h2>Technology Detection</h2>
    <p>Detect website technologies (CMS, frameworks)</p>
    <form method="POST" action="/tech">
        <div class="form-group">
            <label>URL</label>
            <input type="text" name="url" placeholder="https://example.com" required>
        </div>
        <button type="submit">Detect</button>
    </form>
    
    {% if result and result.technologies %}
    <div class="card">
        <h3>Detected Technologies:</h3>
        {% for tech in result.technologies %}
        <span style="background: var(--accent); color: var(--bg-primary); padding: 5px 15px; border-radius: 20px; margin: 5px; display: inline-block;">{{ tech }}</span>
        {% endfor %}
    </div>
    {% endif %}
</div>
''')

CONTENT_TEMPLATE = HTML_TEMPLATE.replace('{% block content %}{% endblock %}', '''
<div class="card">
    <h2>Content Discovery</h2>
    <p>Extract emails and files from website</p>
    <form method="POST" action="/content">
        <div class="form-group">
            <label>URL</label>
            <input type="text" name="url" placeholder="https://example.com" required>
        </div>
        <button type="submit">Discover</button>
    </form>
    
    {% if result and result.emails %}
    <div class="card">
        <h3>Emails Found:</h3>
        {% for email in result.emails[:20] %}
        <div class="result-item">{{ email }}</div>
        {% endfor %}
    </div>
    {% endif %}
</div>
''')

HISTORY_TEMPLATE = HTML_TEMPLATE.replace('{% block content %}{% endblock %}', '''
<div class="card">
    <h2>Scan History</h2>
    {% if history %}
    <table>
        <thead><tr><th>Type</th><th>Query</th><th>Results</th><th>Date</th></tr></thead>
        <tbody>
        {% for item in history %}
        <tr><td>{{ item.type }}</td><td>{{ item.query }}</td><td>{{ item.results }}</td><td>{{ item.date }}</td></tr>
        {% endfor %}
        </tbody>
    </table>
    {% else %}
    <p style="color: var(--text-secondary);">No scan history yet.</p>
    {% endif %}
</div>
''')


# ============= ROUTES =============

@app.route('/')
def home():
    sites = len(load_sites())
    return render_template_string(HOME_TEMPLATE, page='home', 
                                sites_count=sites,
                                history_count=len(scan_history),
                                total_found=sum(item.get('results', 0) for item in scan_history if item.get('type') == 'username'))

@app.route('/scan', methods=['GET', 'POST'])
def scan():
    if request.method == 'POST':
        username = request.form.get('username')
        if username:
            scanner = FootprintScanner()
            results = scanner.run(username)
            scan_history.insert(0, {'type': 'username', 'query': username, 'results': len(results), 'date': datetime.now().strftime('%Y-%m-%d %H:%M')})
            return render_template_string(SCAN_TEMPLATE, page='scan', username=username, results=results, found_count=len(results))
    return render_template_string(SCAN_TEMPLATE, page='scan')

@app.route('/email', methods=['GET', 'POST'])
def email():
    if request.method == 'POST':
        email = request.form.get('email')
        if email:
            import hashlib
            sha1 = hashlib.sha1(email.encode()).hexdigest().upper()
            prefix, suffix = sha1[:5], sha1[5:]
            result = 0
            async def check():
                nonlocal result
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.get(f"https://api.pwnedpasswords.com/range/{prefix}") as resp:
                            if resp.status == 200:
                                data = await resp.text()
                                for line in data.split('\n'):
                                    h, count = line.split(':')
                                    if h == suffix:
                                        result = int(count)
                except:
                    pass
            asyncio.run(check())
            scan_history.insert(0, {'type': 'email', 'query': email, 'results': result, 'date': datetime.now().strftime('%Y-%m-%d %H:%M')})
            return render_template_string(EMAIL_TEMPLATE, page='email', result=result)
    return render_template_string(EMAIL_TEMPLATE, page='email')

@app.route('/whois', methods=['GET', 'POST'])
def whois():
    if request.method == 'POST':
        domain = request.form.get('domain')
        if domain:
            try:
                import whois
                w = whois.whois(domain)
                result = {'Domain': domain, 'Registrar': str(w.registrar), 'Created': str(w.creation_date), 'Expires': str(w.expiration_date)}
            except Exception as e:
                result = {'Error': str(e)}
            scan_history.insert(0, {'type': 'whois', 'query': domain, 'results': 'N/A', 'date': datetime.now().strftime('%Y-%m-%d %H:%M')})
            return render_template_string(WHOIS_TEMPLATE, page='whois', result=result)
    return render_template_string(WHOIS_TEMPLATE, page='whois')

@app.route('/subdomains', methods=['GET', 'POST'])
def subdomains():
    if request.method == 'POST':
        domain = request.form.get('domain')
        if domain:
            enum = SubdomainEnum()
            results = enum.enumerate(domain)
            scan_history.insert(0, {'type': 'subdomains', 'query': domain, 'results': len(results), 'date': datetime.now().strftime('%Y-%m-%d %H:%M')})
            return render_template_string(SUBDOMAIN_TEMPLATE, page='subdomains', results=results)
    return render_template_string(SUBDOMAIN_TEMPLATE, page='subdomains')

@app.route('/ssl', methods=['GET', 'POST'])
def ssl():
    if request.method == 'POST':
        hostname = request.form.get('hostname')
        if hostname:
            checker = SSLCert()
            result = checker.check(hostname)
            scan_history.insert(0, {'type': 'ssl', 'query': hostname, 'results': 'N/A', 'date': datetime.now().strftime('%Y-%m-%d %H:%M')})
            return render_template_string(SSL_TEMPLATE, page='ssl', result=result)
    return render_template_string(SSL_TEMPLATE, page='ssl')

@app.route('/ipgeo', methods=['GET', 'POST'])
def ipgeo():
    if request.method == 'POST':
        ip = request.form.get('ip')
        if ip:
            lookup = IPGeoLookup()
            result = lookup.lookup(ip)
            scan_history.insert(0, {'type': 'ipgeo', 'query': ip, 'results': 'N/A', 'date': datetime.now().strftime('%Y-%m-%d %H:%M')})
            return render_template_string(IPGEO_TEMPLATE, page='ipgeo', result=result)
    return render_template_string(IPGEO_TEMPLATE, page='ipgeo')

@app.route('/ports', methods=['GET', 'POST'])
def ports():
    if request.method == 'POST':
        host = request.form.get('host')
        if host:
            scanner = PortScanner()
            results = scanner.scan(host)
            scan_history.insert(0, {'type': 'ports', 'query': host, 'results': len(results), 'date': datetime.now().strftime('%Y-%m-%d %H:%M')})
            return render_template_string(PORTS_TEMPLATE, page='ports', results=results)
    return render_template_string(PORTS_TEMPLATE, page='ports')

@app.route('/tech', methods=['GET', 'POST'])
def tech():
    if request.method == 'POST':
        url = request.form.get('url')
        if url:
            detector = TechnologyDetect()
            result = detector.detect(url)
            scan_history.insert(0, {'type': 'tech', 'query': url, 'results': len(result.get('technologies', [])), 'date': datetime.now().strftime('%Y-%m-%d %H:%M')})
            return render_template_string(TECH_TEMPLATE, page='tech', result=result)
    return render_template_string(TECH_TEMPLATE, page='tech')

@app.route('/content', methods=['GET', 'POST'])
def content():
    if request.method == 'POST':
        url = request.form.get('url')
        if url:
            disc = ContentDiscovery()
            result = disc.discover(url)
            scan_history.insert(0, {'type': 'content', 'query': url, 'results': len(result.get('emails', [])), 'date': datetime.now().strftime('%Y-%m-%d %H:%M')})
            return render_template_string(CONTENT_TEMPLATE, page='content', result=result)
    return render_template_string(CONTENT_TEMPLATE, page='content')

@app.route('/history')
def history():
    return render_template_string(HISTORY_TEMPLATE, page='history', history=scan_history)


def run_web():
    print(Fore.CYAN + "="*60 + Style.RESET_ALL)
    print(Fore.GREEN + "  GHOSTRACE Web Interface v1.2" + Style.RESET_ALL)
    print(Fore.CYAN + "="*60 + Style.RESET_ALL)
    print(Fore.YELLOW + "\n  Starting server..." + Style.RESET_ALL)
    print(Fore.CYAN + "\n  Access at:" + Style.RESET_ALL)
    print(Fore.GREEN + "    http://localhost:5000" + Style.RESET_ALL + "\n")
    app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False)


if __name__ == '__main__':
    run_web()
