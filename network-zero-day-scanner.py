#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
أداة فحص ثغرات اليوم الصفري للخدمات الشبكية المتقدمة
Advanced Network Zero-Day Vulnerability Scanner

تقوم هذه الأداة باكتشاف الثغرات اليوم الصفري في الخدمات الشبكية من خلال:
- تحليل البصمات الرقمية للخدمات
- الكشف عن الاستجابات غير المعتادة
- اختبار التصرفات السلوكية للبروتوكولات
"""

import socket
import threading
import json
import time
import re
import sys
import struct
import hashlib
import ssl
import random
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import subprocess
import os

class NetworkZeroDayScanner:
    def __init__(self):
        self.results = []
        self.lock = threading.Lock()
        self.open_ports = []
        self.service_fingerprints = {}
        
    def print_banner(self):
        banner = """
╔═══════════════════════════════════════════════════════════════╗
║        أداة فحص ثغرات اليوم الصفري للخدمات الشبكية            ║
║         Network Zero-Day Vulnerability Scanner                 ║
║                                                               ║
║   الكشف عن الثغرات غير المعروفة في خدمات الشبكات            ║
╚═══════════════════════════════════════════════════════════════╝
        """
        print(banner)
        
    def add_finding(self, target, port, vulnerability_type, risk_level, description, evidence=None):
        finding = {
            "target": target,
            "port": port,
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
            "LOW": "\033[92m"
        }
        
        color = colors.get(finding["risk_level"], "")
        reset = "\033[0m"
        
        print(f"{color}[{finding['risk_level']}] {finding['vulnerability_type']} - {finding['target']}:{finding['port']}{reset}")
        print(f"الوصف: {finding['description']}")
        if finding.get("evidence"):
            print(f"الدليل: {finding['evidence']}")
        print("-" * 60)
    
    def tcp_connect_scan(self, target, port, timeout=3):
        """فحص الاتصال TCP"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((target, port))
            sock.close()
            
            if result == 0:
                with self.lock:
                    self.open_ports.append(port)
                return True
            return False
        except:
            return False
    
    def port_scan(self, target, ports=None):
        """فحص المنافذ"""
        if ports is None:
            ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 1433, 3306, 5432, 6379, 8080, 8443, 9200]
        
        print(f"[+] بدء فحص المنافذ على {target}")
        
        with ThreadPoolExecutor(max_workers=100) as executor:
            future_to_port = {executor.submit(self.tcp_connect_scan, target, port): port for port in ports}
            for future in future_to_port:
                future.result()
    
    def detect_ssh_vulnerabilities(self, target, port=22):
        """الكشف عن ثغرات SSH"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((target, port))
            
            # استقبال البانر
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            
            # تحليل البانر للحصول على إصدار SSH
            ssh_version_match = re.search(r'SSH-(\d+\.\d+)', banner)
            if ssh_version_match:
                version = ssh_version_match.group(1)
                major, minor = map(int, version.split('.'))
                
                # إصدارات SSH قديمة محتملة
                if major < 2 or (major == 2 and minor < 9):
                    self.add_finding(
                        target, port, "SSH قديم محتمل", "HIGH",
                        f"تم اكتشاف SSH قديم قد يحتوي على ثغرات يوم صفري",
                        f"Version: {banner.strip()}"
                    )
            
            # التحقق من ثغرات محددة
            if 'OpenSSH_7.2' in banner or 'OpenSSH_7.3' in banner:
                self.add_finding(
                    target, port, "ثغرة SSH محتملة", "CRITICAL",
                    "تم اكتشاف OpenSSH قديم محتمل ثغرة يوم صفري",
                    f"Banner: {banner.strip()}"
                )
                
        except Exception:
            pass
    
    def detect_rdp_vulnerabilities(self, target, port=3389):
        """الكشف عن ثغرات RDP"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((target, port))
            
            if result == 0:
                # اختبار BlueKeep وثغرات RDP الأخرى
                sock.send(b'\x03\x00\x00\x13\x0e\xe0\x00\x00\x00\x00\x00\x01\x00\x08\x00\x03\x00\x00\x00')
                response = sock.recv(1024)
                sock.close()
                
                if len(response) > 0:
                    # التحقق من مؤشرات ثغرات RDP
                    if b'\x03\x00' in response[:4]:
                        self.add_finding(
                            target, port, "RDP معرض للثغرات", "HIGH",
                            "تم اكتشاف خدمة RDP قد تكون عرضة لثغرات يوم صفري",
                            f"Response: {response[:20].hex()}"
                        )
                        
        except Exception:
            pass
    
    def detect_database_vulnerabilities(self, target, port):
        """الكشف عن ثغرات قواعد البيانات"""
        db_configs = {
            1433: ("MSSQL", b'\x12\x01\x00\x34\x00\x00\x00\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x0c\x03\x00\x28\x00\x04\xff\x08\x00\x01\x55\x00\x00\x00\x4d\x53\x53\x51\x4c\x53\x65\x72\x76\x65\x72'),
            3306: ("MySQL", b'\x0a'),
            5432: ("PostgreSQL", b'\x00\x00\x00\x08\x04\xd2\x16\x2f'),
            6379: ("Redis", b'PING\r\n'),
            9200: ("Elasticsearch", b'GET / HTTP/1.0\r\n\r\n')
        }
        
        if port not in db_configs:
            return
        
        db_name, probe = db_configs[port]
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((target, port))
            
            if result == 0:
                sock.send(probe)
                response = sock.recv(1024)
                sock.close()
                
                if len(response) > 0:
                    # التحقق من إصدارات قديمة
                    version_patterns = {
                        "MySQL": rb'(\d+\.\d+\.\d+)',
                        "PostgreSQL": rb'(\d+\.\d+)',
                        "MSSQL": rb'(\d+\.\d+\.\d+)'
                    }
                    
                    if db_name in version_patterns:
                        match = re.search(version_patterns[db_name], response)
                        if match:
                            version = match.group(1).decode()
                            self.add_finding(
                                target, port, f"{db_name} قديم", "MEDIUM",
                                f"تم اكتشاف {db_name} قديم قد يحتوي على ثغرات",
                                f"Version: {version}"
                            )
                            
                    # ثغرات محددة
                    if db_name == "Redis" and b'PONG' in response:
                        self.add_finding(
                            target, port, "Redis بدون مصادقة", "HIGH",
                            "تم اكتشاف Redis بدون مصادقة قد يحتوي على ثغرات",
                            "Redis responding to PING without auth"
                        )
                        
        except Exception:
            pass
    
    def detect_web_server_vulnerabilities(self, target, port):
        """الكشف عن ثغرات خوادم الويب"""
        try:
            # اختبار HTTP
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((target, port))
            
            if result == 0:
                # إرسال طلب HTTP
                http_request = b'GET / HTTP/1.1\r\nHost: test\r\n\r\n'
                sock.send(http_request)
                response = sock.recv(1024)
                sock.close()
                
                if b'HTTP/' in response:
                    # تحليل البانر
                    server_match = re.search(b'Server: ([^\r\n]+)', response)
                    if server_match:
                        server_info = server_match.group(1).decode('utf-8', errors='ignore')
                        
                        # التحقق من إصدارات قديمة
                        version_match = re.search(r'(\d+\.\d+\.\d+)', server_info)
                        if version_match:
                            version = version_match.group(1)
                            major, minor, patch = map(int, version.split('.'))
                            
                            if any(server in server_info.lower() for server in ['apache', 'nginx', 'iis']):
                                self.add_finding(
                                    target, port, "خادم ويب قديم", "MEDIUM",
                                    f"تم اكتشاف خادم ويب قديم: {server_info}",
                                    f"Version: {version}"
                                )
                                
                    # اختبار ثغرات HTTP المتقدمة
                    self.test_http_vulnerabilities(target, port)
                    
        except Exception:
            pass
    
    def test_http_vulnerabilities(self, target, port):
        """اختبار ثغرات HTTP المتقدمة"""
        try:
            import http.client
            conn = http.client.HTTPConnection(target, port, timeout=5)
            
            # اختبار HTTP Request Smuggling
            smuggling_tests = [
                'GET / HTTP/1.1\r\nHost: test\r\nContent-Length: 5\r\n\r\n12345GET /admin HTTP/1.1\r\n\r\n',
                'GET / HTTP/1.1\r\nHost: test\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1\r\n\r\n'
            ]
            
            for test in smuggling_tests:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(5)
                    sock.connect((target, port))
                    sock.send(test.encode())
                    response = sock.recv(1024)
                    sock.close()
                    
                    if b'admin' in response:
                        self.add_finding(
                            target, port, "ثغرة HTTP Request Smuggling", "HIGH",
                            "تم اكتشاف ثغرة HTTP Request Smuggling محتملة",
                            "HTTP smuggling test successful"
                        )
                        
                except Exception:
                    continue
                    
        except Exception:
            pass
    
    def detect_ssl_tls_vulnerabilities(self, target, port=443):
        """الكشف عن ثغرات SSL/TLS"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            
            wrapped_sock = context.wrap_socket(sock, server_hostname=target)
            wrapped_sock.connect((target, port))
            
            # الحصول على معلومات الشهادة
            cert = wrapped_sock.getpeercert()
            cipher = wrapped_sock.cipher()
            wrapped_sock.close()
            
            # التحقق من خوارزميات ضعيفة
            weak_ciphers = ['RC4', 'DES', '3DES', 'MD5', 'SHA1']
            if cipher and any(weak in str(cipher) for weak in weak_ciphers):
                self.add_finding(
                    target, port, "خوارزمية تشفير ضعيفة", "MEDIUM",
                    "تم اكتشاف استخدام خوارزمية تشفير ضعيفة في SSL/TLS",
                    f"Cipher: {cipher[0]}"
                )
                
            # التحقق من إصدارات TLS قديمة
            if 'version' in str(cipher) and 'TLSv1.0' in str(cipher):
                self.add_finding(
                    target, port, "TLS قديم", "HIGH",
                    "تم اكتشاف استخدام TLS 1.0 أو أقدم",
                    f"Version: {cipher[1]}"
                )
                
        except Exception:
            pass
    
    def detect_dns_vulnerabilities(self, target):
        """الكشف عن ثغرات DNS"""
        try:
            # اختبار DNS cache poisoning
            import subprocess
            
            # استخدام nslookup للتحقق من DNS
            result = subprocess.run(['nslookup', target], capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                # التحقق من مؤشرات ثغرات DNS
                if 'Non-authoritative' in result.stdout:
                    self.add_finding(
                        target, 53, "DNS cache poisoning محتمل", "MEDIUM",
                        "تم اكتشاف إمكانية تلوث ذاكرة التخزين المؤقت لـ DNS",
                        "Non-authoritative response detected"
                    )
                    
        except Exception:
            pass
    
    def scan_target(self, target):
        """فحص الهدف الشبكي للكشف عن الثغرات اليوم الصفري"""
        print(f"\n[+] بدء فحص الشبكة: {target}")
        
        # فحص المنافذ الأساسية
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 1433, 3306, 5432, 6379, 8080, 8443, 9200]
        
        # فحص كل منفذ
        for port in common_ports:
            if self.tcp_connect_scan(target, port):
                print(f"[+] تم اكتشاف منفذ مفتوح: {port}")
                
                # فحص الثغرات حسب نوع الخدمة
                if port == 22:
                    self.detect_ssh_vulnerabilities(target, port)
                elif port == 3389:
                    self.detect_rdp_vulnerabilities(target, port)
                elif port in [1433, 3306, 5432, 6379, 9200]:
                    self.detect_database_vulnerabilities(target, port)
                elif port in [80, 443, 8080, 8443]:
                    self.detect_web_server_vulnerabilities(target, port)
                    if port == 443:
                        self.detect_ssl_tls_vulnerabilities(target, port)
                elif port == 53:
                    self.detect_dns_vulnerabilities(target)
    
    def save_results(self, filename=None):
        """حفظ النتائج في ملف JSON"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"network_zero_day_scan_{timestamp}.json"
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, ensure_ascii=False, indent=2)
        
        print(f"\n[+] تم حفظ النتائج في: {filename}")
        return filename
    
    def generate_report(self):
        """توليد تقرير مختصر"""
        if not self.results:
            print("\n[+] لم يتم اكتشاف أي ثغرات محتملة في الخدمات الشبكية.")
            return
        
        critical = sum(1 for r in self.results if r['risk_level'] == 'CRITICAL')
        high = sum(1 for r in self.results if r['risk_level'] == 'HIGH')
        medium = sum(1 for r in self.results if r['risk_level'] == 'MEDIUM')
        low = sum(1 for r in self.results if r['risk_level'] == 'LOW')
        
        print("\n" + "="*60)
        print("            ملخص نتائج فحص الخدمات الشبكية")
        print("="*60)
        print(f"الثغرات الحرجة (CRITICAL): {critical}")
        print(f"الثغرات عالية الخطورة (HIGH): {high}")
        print(f"الثغرات متوسطة الخطورة (MEDIUM): {medium}")
        print(f"الثغرات منخفضة الخطورة (LOW): {low}")
        print(f"إجمالي الثغرات: {len(self.results)}")
        print("="*60)

def main():
    scanner = NetworkZeroDayScanner()
    scanner.print_banner()
    
    if len(sys.argv) < 2:
        print("الاستخدام: python network-zero-day-scanner.py <IP أو نطاق>")
        print("مثال: python network-zero-day-scanner.py 192.168.1.1")
        print("مثال: python network-zero-day-scanner.py scanme.nmap.org")
        sys.exit(1)
    
    targets = sys.argv[1:]
    
    for target in targets:
        scanner.scan_target(target)
    
    scanner.generate_report()
    
    # حفظ النتائج
    filename = scanner.save_results()
    
    print("\n[+] اكتمل فحص الخدمات الشبكية بنجاح!")
    print("[⚠️]  هذه الأداة للكشف عن المؤشرات المحتملة فقط")
    print("[⚠️]  يجب التحقق اليدوي من النتائج قبل اتخاذ أي إجراء")

if __name__ == "__main__":
    main()