#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Google Cloud Platform Security Scanner - فحص أمني متخصص لخدمات GCP
"""

import json
import time
import sys
import argparse
from google.cloud import storage
from google.cloud import compute_v1
from google.cloud import sql
from google.cloud import iam
from google.cloud import secretmanager
from google.oauth2 import service_account
import socket

class GCPSecurityScanner:
    def __init__(self, project_id):
        self.project_id = project_id
        self.findings = []
        
    def scan_storage_buckets(self):
        """فحص حاويات Cloud Storage للأمان"""
        print("🔍 فحص حاويات Cloud Storage...")
        
        try:
            client = storage.Client(project=self.project_id)
            buckets = client.list_buckets()
            
            for bucket in buckets:
                bucket_name = bucket.name
                
                # فحص الوصول العام
                iam_policy = bucket.get_iam_policy()
                for binding in iam_policy.bindings:
                    if 'allUsers' in binding['members'] or 'allAuthenticatedUsers' in binding['members']:
                        self.findings.append({
                            'service': 'Cloud Storage',
                            'resource': bucket_name,
                            'issue': 'Public Access',
                            'risk_level': 'HIGH',
                            'description': f'حاوية {bucket_name} تسمح بالوصول العام'
                        })
                
                # فحص التشفير
                if not bucket.default_kms_key_name:
                    self.findings.append({
                        'service': 'Cloud Storage',
                        'resource': bucket_name,
                        'issue': 'No CMEK Encryption',
                        'risk_level': 'MEDIUM',
                        'description': f'حاوية {bucket_name} بدون تشفير CMEK'
                    })
                
                # فحص logging
                if not bucket.logging:
                    self.findings.append({
                        'service': 'Cloud Storage',
                        'resource': bucket_name,
                        'issue': 'No Access Logging',
                        'risk_level': 'LOW',
                        'description': f'حاوية {bucket_name} بدون سجلات الوصول'
                    })
        
        except Exception as e:
            print(f"خطأ في فحص Cloud Storage: {e}")
    
    def scan_compute_instances(self):
        """فحص الآلات الافتراضية للأمان"""
        print("🔍 فحص الآلات الافتراضية...")
        
        try:
            client = compute_v1.InstancesClient()
            zones = self._get_all_zones()
            
            for zone in zones:
                instances = client.list(project=self.project_id, zone=zone)
                for instance in instances:
                    instance_name = instance.name
                    
                    # فحص التشفير
                    if not instance.disks[0].disk_encryption_key:
                        self.findings.append({
                            'service': 'Compute Engine',
                            'resource': instance_name,
                            'issue': 'Disk Not Encrypted',
                            'risk_level': 'HIGH',
                            'description': f'الآلة الافتراضية {instance_name} بدون تشفير القرص'
                        })
                    
                    # فحص الميتاداتا
                    if instance.metadata.get('items'):
                        for item in instance.metadata['items']:
                            if item['key'] == 'ssh-keys':
                                self.findings.append({
                                    'service': 'Compute Engine',
                                    'resource': instance_name,
                                    'issue': 'SSH Keys in Metadata',
                                    'risk_level': 'MEDIUM',
                                    'description': f'مفاتيح SSH مخزنة في ميتاداتا الآلة {instance_name}'
                                })
                    
                    # فحص الخدمات الموقفة
                    if instance.status == 'RUNNING':
                        # فحص منافذ الوصول
                        for interface in instance.network_interfaces:
                            if interface.access_configs:
                                for config in interface.access_configs:
                                    if config.type_ == 'ONE_TO_ONE_NAT':
                                        self.findings.append({
                                            'service': 'Compute Engine',
                                            'resource': instance_name,
                                            'issue': 'External IP',
                                            'risk_level': 'MEDIUM',
                                            'description': f'الآلة {instance_name} لديها IP خارجي'
                                        })
        
        except Exception as e:
            print(f"خطأ في فحص الآلات الافتراضية: {e}")
    
    def scan_sql_instances(self):
        """فحص Cloud SQL للأمان"""
        print("🔍 فحص Cloud SQL...")
        
        try:
            client = sql.SqlInstancesClient()
            instances = client.list(project=self.project_id)
            
            for instance in instances:
                instance_name = instance.name
                
                # فحص الوصول العام
                if instance.settings.ip_configuration.ipv4_enabled:
                    self.findings.append({
                        'service': 'Cloud SQL',
                        'resource': instance_name,
                        'issue': 'Public IP Enabled',
                        'risk_level': 'HIGH',
                        'description': f'مثيل Cloud SQL {instance_name} يستخدم IP عام'
                    })
                
                # فحص التشفير
                if not instance.disk_encryption_status:
                    self.findings.append({
                        'service': 'Cloud SQL',
                        'resource': instance_name,
                        'issue': 'Disk Not Encrypted',
                        'risk_level': 'HIGH',
                        'description': f'مثيل Cloud SQL {instance_name} بدون تشفير القرص'
                    })
                
                # فحص النسخ الاحتياطي
                if not instance.settings.backup_configuration.enabled:
                    self.findings.append({
                        'service': 'Cloud SQL',
                        'resource': instance_name,
                        'issue': 'Backup Disabled',
                        'risk_level': 'MEDIUM',
                        'description': f'النسخ الاحتياطي معطل لمثيل {instance_name}'
                    })
        
        except Exception as e:
            print(f"خطأ في فحص Cloud SQL: {e}")
    
    def scan_iam_policies(self):
        """فحص سياسات IAM للأمان"""
        print("🔍 فحص سياسات IAM...")
        
        try:
            client = iam.IAMClient()
            
            # فحص أدوار المشروع
            policy = client.get_iam_policy(resource=f"projects/{self.project_id}")
            
            for binding in policy.bindings:
                if 'allUsers' in binding['members'] or 'allAuthenticatedUsers' in binding['members']:
                    self.findings.append({
                        'service': 'IAM',
                        'resource': self.project_id,
                        'issue': 'Public IAM Binding',
                        'risk_level': 'CRITICAL',
                        'description': f'ربط IAM عام في المشروع {self.project_id}'
                    })
            
            # فحص المفاتيح القديمة
            service_accounts = client.list_service_accounts(project=self.project_id)
            for sa in service_accounts.accounts:
                if sa.disabled:
                    self.findings.append({
                        'service': 'IAM Service Account',
                        'resource': sa.email,
                        'issue': 'Disabled Service Account',
                        'risk_level': 'LOW',
                        'description': f'حساب الخدمة {sa.email} معطل'
                    })
        
        except Exception as e:
            print(f"خطأ في فحص IAM: {e}")
    
    def scan_firewall_rules(self):
        """فحص قواعد جدار الحماية للثغرات"""
        print("🔍 فحص قواعد جدار الحماية...")
        
        try:
            client = compute_v1.FirewallsClient()
            firewalls = client.list(project=self.project_id)
            
            for firewall in firewalls:
                firewall_name = firewall.name
                
                # فحص القواعد المفتوحة
                for rule in firewall.allowed:
                    sensitive_ports = [22, 3389, 1433, 3306, 5432, 27017, 6379]
                    
                    for port in rule.ports or []:
                        port_num = int(port.split('-')[0])
                        
                        if port_num in sensitive_ports:
                            for source_range in firewall.source_ranges or []:
                                if source_range == '0.0.0.0/0':
                                    self.findings.append({
                                        'service': 'Firewall',
                                        'resource': firewall_name,
                                        'issue': 'Open Sensitive Port',
                                        'risk_level': 'HIGH',
                                        'description': f'منفذ {port_num} مفتوح للعام في {firewall_name}'
                                    })
        
        except Exception as e:
            print(f"خطأ في فحص جدار الحماية: {e}")
    
    def scan_secret_manager(self):
        """فحص مدير الأسرار للأمان"""
        print("🔍 فحص مدير الأسرار...")
        
        try:
            client = secretmanager.SecretManagerServiceClient()
            parent = f"projects/{self.project_id}"
            secrets = client.list_secrets(parent=parent)
            
            for secret in secrets:
                secret_name = secret.name
                
                # فحص سياسة الوصول
                policy = client.get_iam_policy(resource=secret_name)
                
                for binding in policy.bindings:
                    if 'allUsers' in binding['members'] or 'allAuthenticatedUsers' in binding['members']:
                        self.findings.append({
                            'service': 'Secret Manager',
                            'resource': secret_name,
                            'issue': 'Public Secret',
                            'risk_level': 'CRITICAL',
                            'description': f'السر {secret_name} متاح للعام'
                        })
        
        except Exception as e:
            print(f"خطأ في فحص مدير الأسرار: {e}")
    
    def scan_dns_configurations(self):
        """فحص تكوينات DNS للثغرات"""
        print("🔍 فحص تكوينات DNS...")
        
        try:
            from google.cloud import dns
            client = dns.Client(project=self.project_id)
            zones = client.list_zones()
            
            for zone in zones:
                zone_name = zone.name
                
                # فحص DNSSEC
                if not zone.dnssec_config or not zone.dnssec_config.state == 'on':
                    self.findings.append({
                        'service': 'Cloud DNS',
                        'resource': zone_name,
                        'issue': 'DNSSEC Disabled',
                        'risk_level': 'MEDIUM',
                        'description': f'DNSSEC معطل للمنطقة {zone_name}'
                    })
        
        except Exception as e:
            print(f"خطأ في فحص DNS: {e}")
    
    def _get_all_zones(self):
        """الحصول على جميع المناطق المتاحة"""
        try:
            client = compute_v1.ZonesClient()
            zones = client.list(project=self.project_id)
            return [zone.name for zone in zones]
        except:
            return ['us-central1-a', 'us-central1-b', 'us-central1-c']
    
    def run_gcp_scan(self, project_id):
        """تشغيل فحص GCP شامل"""
        print("🎯 بدء فحص GCP الأمني...")
        
        self.project_id = project_id
        self.scan_storage_buckets()
        self.scan_compute_instances()
        self.scan_sql_instances()
        self.scan_iam_policies()
        self.scan_firewall_rules()
        self.scan_secret_manager()
        self.scan_dns_configurations()
        
        return self.findings
    
    def display_results(self):
        """عرض النتائج"""
        print("\n" + "=" * 60)
        print("📊 تقرير فحص GCP الأمني")
        print("=" * 60)
        
        if not self.findings:
            print("✅ لم يتم اكتشاف مشاكل أمنية في GCP")
            return
        
        critical = [f for f in self.findings if f['risk_level'] == 'CRITICAL']
        high = [f for f in self.findings if f['risk_level'] == 'HIGH']
        medium = [f for f in self.findings if f['risk_level'] == 'MEDIUM']
        low = [f for f in self.findings if f['risk_level'] == 'LOW']
        
        print(f"🚨 مخاطر حرجة: {len(critical)}")
        print(f"🔴 مخاطر عالية: {len(high)}")
        print(f"🟡 مخاطر متوسطة: {len(medium)}")
        print(f"🟢 مخاطر منخفضة: {len(low)}")
        
        for finding in self.findings:
            print(f"\n[{finding['risk_level']}] {finding['service']}: {finding['description']}")

def main():
    parser = argparse.ArgumentParser(description='GCP Security Scanner')
    parser.add_argument('--project', required=True, help='معرف مشروع GCP')
    
    args = parser.parse_args()
    
    scanner = GCPSecurityScanner(args.project)
    findings = scanner.run_gcp_scan(args.project)
    scanner.display_results()
    
    # حفظ النتائج
    with open(f'gcp_security_scan_{int(time.time())}.json', 'w', encoding='utf-8') as f:
        json.dump(findings, f, indent=2, ensure_ascii=False)

if __name__ == "__main__":
    main()