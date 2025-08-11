#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cloud Security Scanner - AWS/Azure/GCP Configuration Security Tool
أداة فحص أمني للسحابات AWS/Azure/GCP واكتشاف التهيئة الخاطئة والثغرات الأمنية
"""

import requests
import json
import time
import socket
import subprocess
from urllib.parse import urlparse
import re
import sys
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import dns.resolver
import ssl

class CloudSecurityScanner:
    def __init__(self):
        self.results = []
        self.vulnerabilities = []
        
    def banner(self):
        banner = """
    ╔═══════════════════════════════════════════════════════════════╗
    ║                    Cloud Security Scanner                    ║
    ║               AWS / Azure / GCP Security Audit              ║
    ║                                                              ║
    ║  أداة فحص أمني شامل للسحابات واكتشاف التهيئة الخاطئة       ║
    ║  والثغرات الأمنية في AWS، Azure، و Google Cloud Platform   ║
    ╚═══════════════════════════════════════════════════════════════╝
        """
        print(banner)
    
    def scan_aws_s3_buckets(self, target_domain):
        """فحص حاويات S3 المعرضة"""
        print(f"🔍 فحص حاويات S3 لـ {target_domain}...")
        
        common_buckets = [
            f"{target_domain}-backup",
            f"{target_domain}-assets",
            f"{target_domain}-uploads",
            f"{target_domain}-static",
            f"{target_domain}-media",
            f"{target_domain}-files",
            f"{target_domain}-data",
            f"{target_domain}-logs",
            f"{target_domain}-public",
            f"{target_domain}-private",
            f"{target_domain}-dev",
            f"{target_domain}-prod",
            f"{target_domain}-test",
            f"{target_domain}-staging",
            f"{target_domain}-images",
            f"{target_domain}-documents",
            f"{target_domain}-resources"
        ]
        
        exposed_buckets = []
        
        for bucket in common_buckets:
            try:
                # فحص S3 bucket
                url = f"https://{bucket}.s3.amazonaws.com"
                response = requests.get(url, timeout=10)
                
                if response.status_code == 200:
                    exposed_buckets.append({
                        'service': 'AWS S3',
                        'bucket': bucket,
                        'url': url,
                        'status': 'EXPOSED',
                        'risk_level': 'HIGH',
                        'description': f'حاوية S3 {bucket} متاحة للوصول العام'
                    })
                elif response.status_code == 403:
                    exposed_buckets.append({
                        'service': 'AWS S3',
                        'bucket': bucket,
                        'url': url,
                        'status': 'FORBIDDEN',
                        'risk_level': 'MEDIUM',
                        'description': f'حاوية S3 {bucket} موجودة لكن محظورة'
                    })
                    
            except Exception as e:
                pass
        
        return exposed_buckets
    
    def scan_azure_storage(self, target_domain):
        """فحص حسابات Azure Storage المعرضة"""
        print(f"🔍 فحص حسابات Azure Storage لـ {target_domain}...")
        
        common_containers = [
            f"{target_domain}storage",
            f"{target_domain}files",
            f"{target_domain}data",
            f"{target_domain}assets",
            f"{target_domain}backup",
            f"{target_domain}media",
            f"{target_domain}static",
            f"{target_domain}uploads"
        ]
        
        exposed_storage = []
        
        for container in common_containers:
            try:
                # فحص Azure Blob Storage
                url = f"https://{container}.blob.core.windows.net"
                response = requests.get(url, timeout=10)
                
                if response.status_code == 200:
                    exposed_storage.append({
                        'service': 'Azure Blob Storage',
                        'container': container,
                        'url': url,
                        'status': 'EXPOSED',
                        'risk_level': 'HIGH',
                        'description': f'حاوية Azure Storage {container} متاحة للوصول العام'
                    })
                    
            except Exception as e:
                pass
        
        return exposed_storage
    
    def scan_gcp_storage(self, target_domain):
        """فحص حاويات Google Cloud Storage المعرضة"""
        print(f"🔍 فحص حسابات Google Cloud Storage لـ {target_domain}...")
        
        common_buckets = [
            f"{target_domain}-storage",
            f"{target_domain}-assets",
            f"{target_domain}-data",
            f"{target_domain}-files",
            f"{target_domain}-media",
            f"{target_domain}-backup",
            f"{target_domain}-uploads"
        ]
        
        exposed_buckets = []
        
        for bucket in common_buckets:
            try:
                # فحص Google Cloud Storage
                url = f"https://storage.googleapis.com/{bucket}"
                response = requests.get(url, timeout=10)
                
                if response.status_code == 200:
                    exposed_buckets.append({
                        'service': 'Google Cloud Storage',
                        'bucket': bucket,
                        'url': url,
                        'status': 'EXPOSED',
                        'risk_level': 'HIGH',
                        'description': f'حاوية GCS {bucket} متاحة للوصول العام'
                    })
                    
            except Exception as e:
                pass
        
        return exposed_buckets
    
    def scan_exposed_services(self, target_domain):
        """فحص الخدمات المعرضة في السحابات"""
        print(f"🔍 فحص الخدمات المعرضة لـ {target_domain}...")
        
        exposed_services = []
        
        # فحص الخدمات الشائعة
        services = [
            {'service': 'AWS EC2', 'pattern': f'ec2-*.{target_domain}'},
            {'service': 'AWS RDS', 'pattern': f'rds.{target_domain}'},
            {'service': 'AWS Lambda', 'pattern': f'lambda.{target_domain}'},
            {'service': 'Azure VM', 'pattern': f'vm.{target_domain}'},
            {'service': 'Azure SQL', 'pattern': f'sql.{target_domain}'},
            {'service': 'GCP Compute', 'pattern': f'compute.{target_domain}'},
            {'service': 'GCP SQL', 'pattern': f'sql.{target_domain}'}
        ]
        
        # فحص المنافذ المفتوحة
        common_ports = [22, 80, 443, 3389, 5432, 3306, 1433, 27017, 6379, 9200]
        
        for service in services:
            try:
                # DNS lookup
                socket.gethostbyname(service['pattern'])
                exposed_services.append({
                    'service': service['service'],
                    'hostname': service['pattern'],
                    'status': 'EXPOSED',
                    'risk_level': 'MEDIUM',
                    'description': f'خدمة {service["service"]} مكشوفة عبر DNS'
                })
            except:
                pass
        
        return exposed_services
    
    def scan_ssl_misconfigurations(self, target_domain):
        """فحص أخطاء SSL/TLS في السحابات"""
        print(f"🔍 فحص أخطاء SSL/TLS لـ {target_domain}...")
        
        ssl_issues = []
        
        try:
            # فحص شهادة SSL
            context = ssl.create_default_context()
            with socket.create_connection((target_domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=target_domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    # فحص انتهاء الصلاحية
                    not_after = cert.get('notAfter')
                    if not_after:
                        ssl_issues.append({
                            'service': 'SSL Certificate',
                            'issue': 'Certificate Expiry',
                            'risk_level': 'HIGH',
                            'description': f'شهادة SSL تنتهي في: {not_after}'
                        })
                        
        except Exception as e:
            ssl_issues.append({
                'service': 'SSL Certificate',
                'issue': 'SSL Error',
                'risk_level': 'HIGH',
                'description': f'خطأ في SSL: {str(e)}'
            })
        
        return ssl_issues
    
    def scan_dns_misconfigurations(self, target_domain):
        """فحص أخطاء DNS والتهيئة الخاطئة"""
        print(f"🔍 فحص أخطاء DNS لـ {target_domain}...")
        
        dns_issues = []
        
        try:
            # فحص DNS records
            resolver = dns.resolver.Resolver()
            
            # فحص MX records
            try:
                mx_records = resolver.resolve(target_domain, 'MX')
            except:
                dns_issues.append({
                    'service': 'DNS MX',
                    'issue': 'No MX Records',
                    'risk_level': 'LOW',
                    'description': 'لا توجد سجلات MX للنطاق'
                })
            
            # فحص TXT records (SPF/DKIM)
            try:
                txt_records = resolver.resolve(target_domain, 'TXT')
                spf_found = False
                for record in txt_records:
                    if 'v=spf1' in str(record):
                        spf_found = True
                        break
                
                if not spf_found:
                    dns_issues.append({
                        'service': 'DNS SPF',
                        'issue': 'No SPF Record',
                        'risk_level': 'MEDIUM',
                        'description': 'لا توجد سجلات SPF لحماية البريد الإلكتروني'
                    })
                    
            except:
                dns_issues.append({
                    'service': 'DNS TXT',
                    'issue': 'No TXT Records',
                    'risk_level': 'LOW',
                    'description': 'لا توجد سجلات TXT للنطاق'
                })
                
        except Exception as e:
            dns_issues.append({
                'service': 'DNS',
                'issue': 'DNS Error',
                'risk_level': 'HIGH',
                'description': f'خطأ في DNS: {str(e)}'
            })
        
        return dns_issues
    
    def run_cloud_scan(self, target_domain):
        """تشغيل فحص شامل للسحابات"""
        self.banner()
        
        print(f"🎯 بدء فحص أمني شامل للسحابات: {target_domain}")
        print("=" * 60)
        
        all_findings = []
        
        # فحص AWS S3
        s3_results = self.scan_aws_s3_buckets(target_domain)
        all_findings.extend(s3_results)
        
        # فحص Azure Storage
        azure_results = self.scan_azure_storage(target_domain)
        all_findings.extend(azure_results)
        
        # فحص Google Cloud Storage
        gcp_results = self.scan_gcp_storage(target_domain)
        all_findings.extend(gcp_results)
        
        # فحص الخدمات المعرضة
        services_results = self.scan_exposed_services(target_domain)
        all_findings.extend(services_results)
        
        # فحص SSL
        ssl_results = self.scan_ssl_misconfigurations(target_domain)
        all_findings.extend(ssl_results)
        
        # فحص DNS
        dns_results = self.scan_dns_misconfigurations(target_domain)
        all_findings.extend(dns_results)
        
        # عرض النتائج
        self.display_results(all_findings)
        
        return all_findings
    
    def display_results(self, findings):
        """عرض النتائج النهائية"""
        print("\n" + "=" * 60)
        print("📊 تقرير فحص أمن السحابات")
        print("=" * 60)
        
        if not findings:
            print("✅ لم يتم اكتشاف أي مشاكل أمنية")
            return
        
        # تجميع النتائج حسب مستوى الخطورة
        high_risk = [f for f in findings if f.get('risk_level') == 'HIGH']
        medium_risk = [f for f in findings if f.get('risk_level') == 'MEDIUM']
        low_risk = [f for f in findings if f.get('risk_level') == 'LOW']
        
        print(f"🚨 مخاطر عالية: {len(high_risk)}")
        print(f"⚠️  مخاطر متوسطة: {len(medium_risk)}")
        print(f"ℹ️  مخاطر منخفضة: {len(low_risk)}")
        
        if high_risk:
            print("\n🔴 المخاطر العالية:")
            for finding in high_risk:
                print(f"   • {finding['description']}")
        
        if medium_risk:
            print("\n🟡 المخاطر المتوسطة:")
            for finding in medium_risk:
                print(f"   • {finding['description']}")
        
        if low_risk:
            print("\n🟢 المخاطر المنخفضة:")
            for finding in low_risk:
                print(f"   • {finding['description']}")
        
        # حفظ النتائج
        with open(f'cloud_security_scan_{int(time.time())}.json', 'w', encoding='utf-8') as f:
            json.dump(findings, f, indent=2, ensure_ascii=False)
        
        print(f"\n💾 تم حفظ النتائج في ملف JSON")

def main():
    parser = argparse.ArgumentParser(description='Cloud Security Scanner - أداة فحص أمني للسحابات')
    parser.add_argument('-t', '--target', required=True, help='النطاق المستهدف')
    parser.add_argument('-o', '--output', help='ملف الإخراج')
    
    args = parser.parse_args()
    
    scanner = CloudSecurityScanner()
    findings = scanner.run_cloud_scan(args.target)
    
    if args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            json.dump(findings, f, indent=2, ensure_ascii=False)

if __name__ == "__main__":
    main()