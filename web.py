#!/usr/bin/env python3
"""
GHOSTRACE v1.0 - Web Interface
Advanced OSINT Username Discovery Tool

Developed by: Chriz
Email: chrizmonsaji@proton.me
GitHub: https://github.com/chriz-3656
License: MIT
"""

from flask import Flask, render_template_string, request, jsonify, redirect, url_for
import threading
import asyncio
import json
import os
import random
import socket
import ssl
import aiohttp
from datetime import datetime
import time
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

app = Flask(__name__)

# Store scan results and status
scan_results = {}
scan_history = []

# Load sites
def load_sites():
    with open('sites.json', 'r') as f:
        return json.load(f)

# User agents
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
]

# Scanner classes
class WebFootprintScanner:
    def __init__(self):
        self.sites = load_sites()
        self.found = []
        
    def get_headers(self):
        return {
            'User-Agent': random.choice(USER_AGENTS),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'DNT': '1',
        }

    async def check_site(self, session, site, username):
        url = self.sites[site]['url'].format(username)
        try:
            async with session.get(url, headers=self.get_headers(), 
                                   timeout=aiohttp.ClientTimeout(total=10)) as response:
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

    async def run_async(self, username):
        connector = aiohttp.TCPConnector(limit=10)
        async with aiohttp.ClientSession(connector=connector) as session:
            tasks = [self.check_site(session, site, username) for site in self.sites]
            results = await asyncio.gather(*tasks)
            
            for site, found in zip(self.sites.keys(), results):
                if found:
                    self.found.append({'site': site, 'url': self.sites[site]['url'].format(username)})
        
        return self.found

    def run(self, username):
        return asyncio.run(self.run_async(username))


class WebEmailFinder:
    async def check_breach_async(self, session, email, api_key):
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

    def check_breach(self, email, api_key=None):
        return asyncio.run(self.check_breach_async(aiohttp.ClientSession(), email, api_key))


class WebWHOISLookup:
    def lookup(self, domain):
        try:
            import whois
            w = whois.whois(domain)
            return {
                'Domain': domain,
                'Registrar': str(w.registrar) if w.registrar else 'N/A',
                'Created': str(w.creation_date) if w.creation_date else 'N/A',
                'Expires': str(w.expiration_date) if w.expiration_date else 'N/A',
                'Name Servers': str(w.name_servers) if w.name_servers else 'N/A'
            }
        except Exception as e:
            return {'Error': str(e)}


class WebSubdomainEnum:
    def __init__(self):
        self.subdomains = ['www', 'mail', 'ftp', 'webmail', 'smtp', 'pop', 'ns1', 
                          'ns2', 'cpanel', 'whm', 'admin', 'blog', 'dev', 'test', 'mx', 'static']

    async def enumerate_async(self, session, domain):
        found = []
        for sub in self.subdomains:
            url = f"http://{sub}.{domain}"
            try:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=3)) as resp:
                    if resp.status < 400:
                        found.append(url)
            except:
                pass
        return found

    def enumerate(self, domain):
        return asyncio.run(self.enumerate_async(aiohttp.ClientSession(), domain))


class WebSSLCert:
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


# Modern HTML Template
HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GHOSTRACE - OSINT Scanner</title>
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
        
        /* Background Effect */
        .bg-grid {
            position: fixed;
            top: 0; left: 0; right: 0; bottom: 0;
            background-image: 
                linear-gradient(rgba(0,255,136,0.03) 1px, transparent 1px),
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
        
        /* Header */
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
            text-shadow: 0 0 40px var(--accent-glow);
        }
        
        .tagline {
            color: var(--text-secondary);
            font-size: 1.1em;
            letter-spacing: 2px;
            text-transform: uppercase;
        }
        
        /* Navigation */
        nav {
            display: flex;
            justify-content: center;
            gap: 8px;
            margin-bottom: 40px;
            flex-wrap: wrap;
            animation: fadeIn 0.8s ease 0.2s both;
        }
        
        @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }
        
        nav a {
            color: var(--text-secondary);
            text-decoration: none;
            padding: 12px 24px;
            border-radius: 8px;
            font-weight: 500;
            font-size: 0.9em;
            transition: all 0.3s ease;
            border: 1px solid transparent;
        }
        
        nav a:hover {
            color: var(--accent);
            background: var(--accent-glow);
            border-color: var(--accent);
            transform: translateY(-2px);
        }
        
        nav a.active {
            color: var(--bg-primary);
            background: var(--accent);
            border-color: var(--accent);
        }
        
        /* Cards */
        .card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 16px;
            padding: 32px;
            margin-bottom: 24px;
            animation: fadeInUp 0.6s ease both;
        }
        
        @keyframes fadeInUp {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
        }
        
        .card h2 {
            font-size: 1.5em;
            margin-bottom: 8px;
            color: var(--text-primary);
        }
        
        .card p {
            color: var(--text-secondary);
            margin-bottom: 24px;
        }
        
        /* Stats */
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .stat-box {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 24px;
            text-align: center;
            transition: all 0.3s ease;
        }
        
        .stat-box:hover {
            border-color: var(--accent);
            transform: translateY(-4px);
            box-shadow: 0 8px 30px var(--accent-glow);
        }
        
        .stat-box .number {
            font-size: 2.5em;
            font-weight: 700;
            color: var(--accent);
            font-family: 'JetBrains Mono', monospace;
        }
        
        .stat-box .label {
            color: var(--text-secondary);
            font-size: 0.9em;
            margin-top: 8px;
        }
        
        /* Forms */
        .form-group { margin-bottom: 20px; }
        
        label {
            display: block;
            margin-bottom: 8px;
            color: var(--text-secondary);
            font-size: 0.9em;
            font-weight: 500;
        }
        
        input[type="text"], input[type="email"] {
            width: 100%;
            padding: 16px 20px;
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
        
        input::placeholder {
            color: var(--text-muted);
        }
        
        button {
            background: linear-gradient(135deg, var(--accent) 0%, var(--accent-dim) 100%);
            color: var(--bg-primary);
            border: none;
            padding: 16px 40px;
            font-size: 1em;
            font-weight: 600;
            border-radius: 10px;
            cursor: pointer;
            transition: all 0.3s ease;
            font-family: 'Inter', sans-serif;
        }
        
        button:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 25px var(--accent-glow);
        }
        
        /* Results */
        .result-item {
            padding: 16px;
            margin: 12px 0;
            border-radius: 10px;
            background: var(--bg-secondary);
            border-left: 3px solid var(--accent);
            transition: all 0.3s ease;
        }
        
        .result-item:hover {
            background: var(--bg-hover);
            transform: translateX(4px);
        }
        
        .result-item a {
            color: var(--accent);
            text-decoration: none;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.9em;
        }
        
        .result-item a:hover {
            text-decoration: underline;
        }
        
        /* Status */
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
        
        /* Table */
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 16px;
        }
        
        th, td {
            padding: 14px;
            text-align: left;
            border-bottom: 1px solid var(--border);
        }
        
        th {
            color: var(--accent);
            font-weight: 600;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        
        td {
            color: var(--text-secondary);
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.9em;
        }
        
        /* Footer */
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
        
        /* Responsive */
        @media (max-width: 768px) {
            .logo { font-size: 2.5em; }
            nav { gap: 4px; }
            nav a { padding: 10px 16px; font-size: 0.8em; }
            .card { padding: 20px; }
        }
        
        /* Loading Animation */
        .loader {
            display: inline-block;
            width: 20px;
            height: 20px;
            border: 2px solid var(--accent);
            border-radius: 50%;
            border-top-color: transparent;
            animation: spin 1s linear infinite;
            margin-right: 10px;
        }
        
        @keyframes spin {
            to { transform: rotate(360deg); }
        }
    </style>
</head>
<body>
    <div class="bg-grid"></div>
    <div class="bg-glow"></div>
    
    <div class="container">
        <header>
            <div class="logo">GHOSTRACE</div>
            <div class="tagline">Advanced OSINT Scanner</div>
        </header>
        
        <nav>
            <a href="/" class="{{ 'active' if page == 'home' else '' }}">Home</a>
            <a href="/scan" class="{{ 'active' if page == 'scan' else '' }}">Username</a>
            <a href="/email" class="{{ 'active' if page == 'email' else '' }}">Breaches</a>
            <a href="/whois" class="{{ 'active' if page == 'whois' else '' }}">WHOIS</a>
            <a href="/subdomains" class="{{ 'active' if page == 'subdomains' else '' }}">Subdomains</a>
            <a href="/ssl" class="{{ 'active' if page == 'ssl' else '' }}">SSL</a>
            <a href="/history" class="{{ 'active' if page == 'history' else '' }}">History</a>
        </nav>
        
        {% block content %}{% endblock %}
        
        <footer>
            <p><strong>GHOSTRACE</strong> v1.0 | Developed by Chriz</p>
            <p><a href="https://github.com/chriz-3656" target="_blank">GitHub</a> | Email: chrizmonsaji@proton.me | License: MIT</p>
        </footer>
    </div>
</body>
</html>
'''

HOME_TEMPLATE = HTML_TEMPLATE.replace('{% block content %}{% endblock %}', '''
<div class="stats">
    <div class="stat-box">
        <div class="number">{{ sites_count }}</div>
        <div class="label">Sites Configured</div>
    </div>
    <div class="stat-box">
        <div class="number">{{ history_count }}</div>
        <div class="label">Total Scans</div>
    </div>
    <div class="stat-box">
        <div class="number">{{ total_found }}</div>
        <div class="label">Accounts Found</div>
    </div>
</div>

<div class="card" style="animation-delay: 0.1s;">
    <h2>Welcome to GHOSTRACE</h2>
    <p>Advanced OSINT tool for discovering username footprints across 180+ online platforms.</p>
    
    <h3 style="color: var(--accent); margin: 20px 0 10px;">Features:</h3>
    <ul style="color: var(--text-secondary); margin-left: 20px; line-height: 2;">
        <li>Scan username across 181+ platforms</li>
        <li>Check email breaches with HaveIBeenPwned</li>
        <li>WHOIS domain lookups</li>
        <li>Subdomain enumeration</li>
        <li>SSL certificate analysis</li>
    </ul>
</div>

<div class="card" style="animation-delay: 0.2s;">
    <h2>Quick Actions</h2>
    <nav style="justify-content: flex-start; margin-bottom: 0;">
        <a href="/scan" style="background: var(--accent); color: var(--bg-primary);">Start Scan</a>
        <a href="/email">Check Breaches</a>
    </nav>
</div>
''')

SCAN_TEMPLATE = HTML_TEMPLATE.replace('{% block content %}{% endblock %}', '''
<div class="card">
    <h2>Username Scanner</h2>
    <p>Scan for username across 180+ platforms</p>
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
    <h2>Results for: {{ username }}</h2>
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
    <p>Check if email has been compromised in data breaches</p>
    <form method="POST" action="/email">
        <div class="form-group">
            <label>Email Address</label>
            <input type="email" name="email" placeholder="user@example.com" required>
        </div>
        <div class="form-group">
            <label>HaveIBeenPwned API Key (optional)</label>
            <input type="text" name="api_key" placeholder="Enter API key for detailed results">
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
            <tr>
                <th>{{ key }}</th>
                <td>{{ value }}</td>
            </tr>
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
    <p>Get SSL certificate information for a domain</p>
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
            <tr>
                <th>{{ key }}</th>
                <td>{{ value }}</td>
            </tr>
            {% endfor %}
        </table>
    </div>
    {% endif %}
</div>
''')

HISTORY_TEMPLATE = HTML_TEMPLATE.replace('{% block content %}{% endblock %}', '''
<div class="card">
    <h2>Scan History</h2>
    {% if history %}
    <table>
        <thead>
            <tr>
                <th>Type</th>
                <th>Query</th>
                <th>Results</th>
                <th>Date</th>
            </tr>
        </thead>
        <tbody>
            {% for item in history %}
            <tr>
                <td>{{ item.type }}</td>
                <td>{{ item.query }}</td>
                <td>{{ item.results }}</td>
                <td>{{ item.date }}</td>
            </tr>
            {% endfor %}
        </tbody>
    </table>
    {% else %}
    <p style="color: var(--text-secondary);">No scan history yet.</p>
    {% endif %}
</div>
''')


@app.route('/')
def home():
    sites_count = len(load_sites())
    history_count = len(scan_history)
    total_found = sum(item.get('results', 0) for item in scan_history if item.get('type') == 'username')
    return render_template_string(HOME_TEMPLATE, 
                                page='home', 
                                sites_count=sites_count,
                                history_count=history_count,
                                total_found=total_found)


@app.route('/scan', methods=['GET', 'POST'])
def scan():
    sites_count = len(load_sites())
    if request.method == 'POST':
        username = request.form.get('username')
        if username:
            scanner = WebFootprintScanner()
            results = scanner.run(username)
            found_count = len(results)
            
            scan_history.insert(0, {
                'type': 'username',
                'query': username,
                'results': found_count,
                'date': datetime.now().strftime('%Y-%m-%d %H:%M')
            })
            
            return render_template_string(SCAN_TEMPLATE, 
                                       page='scan',
                                       username=username,
                                       results=results,
                                       found_count=found_count,
                                       sites_count=sites_count)
    
    return render_template_string(SCAN_TEMPLATE, page='scan', sites_count=sites_count)


@app.route('/email', methods=['GET', 'POST'])
def email():
    if request.method == 'POST':
        email = request.form.get('email')
        api_key = request.form.get('api_key')
        if email:
            finder = WebEmailFinder()
            result = finder.check_breach(email, api_key)
            
            scan_history.insert(0, {
                'type': 'email_breach',
                'query': email,
                'results': result,
                'date': datetime.now().strftime('%Y-%m-%d %H:%M')
            })
            
            return render_template_string(EMAIL_TEMPLATE, page='email', result=result)
    
    return render_template_string(EMAIL_TEMPLATE, page='email')


@app.route('/whois', methods=['GET', 'POST'])
def whois():
    if request.method == 'POST':
        domain = request.form.get('domain')
        if domain:
            lookup = WebWHOISLookup()
            result = lookup.lookup(domain)
            
            scan_history.insert(0, {
                'type': 'whois',
                'query': domain,
                'results': 'N/A',
                'date': datetime.now().strftime('%Y-%m-%d %H:%M')
            })
            
            return render_template_string(WHOIS_TEMPLATE, page='whois', result=result, domain=domain)
    
    return render_template_string(WHOIS_TEMPLATE, page='whois')


@app.route('/subdomains', methods=['GET', 'POST'])
def subdomains():
    if request.method == 'POST':
        domain = request.form.get('domain')
        if domain:
            enum = WebSubdomainEnum()
            results = enum.enumerate(domain)
            
            scan_history.insert(0, {
                'type': 'subdomains',
                'query': domain,
                'results': len(results),
                'date': datetime.now().strftime('%Y-%m-%d %H:%M')
            })
            
            return render_template_string(SUBDOMAIN_TEMPLATE, page='subdomains', results=results)
    
    return render_template_string(SUBDOMAIN_TEMPLATE, page='subdomains')


@app.route('/ssl', methods=['GET', 'POST'])
def ssl_check():
    if request.method == 'POST':
        hostname = request.form.get('hostname')
        if hostname:
            checker = WebSSLCert()
            result = checker.check(hostname)
            
            scan_history.insert(0, {
                'type': 'ssl',
                'query': hostname,
                'results': 'N/A',
                'date': datetime.now().strftime('%Y-%m-%d %H:%M')
            })
            
            return render_template_string(SSL_TEMPLATE, page='ssl', result=result)
    
    return render_template_string(SSL_TEMPLATE, page='ssl')


@app.route('/history')
def history():
    return render_template_string(HISTORY_TEMPLATE, page='history', history=scan_history)


def run_web():
    """Run the web server"""
    print(Fore.CYAN + "="*60 + Style.RESET_ALL)
    print(Fore.GREEN + "  GHOSTRACE Web Interface" + Style.RESET_ALL)
    print(Fore.CYAN + "="*60 + Style.RESET_ALL)
    print(Fore.YELLOW + "\n  Starting server..." + Style.RESET_ALL)
    print(Fore.CYAN + "\n  Access at:" + Style.RESET_ALL)
    print(Fore.GREEN + "    http://localhost:5000" + Style.RESET_ALL)
    print(Fore.YELLOW + "\n  Press CTRL+C to stop" + Style.RESET_ALL)
    print(Fore.CYAN + "="*60 + Style.RESET_ALL + "\n")
    app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False)


if __name__ == '__main__':
    run_web()
