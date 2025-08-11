#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Azure Security Scanner - فحص أمني متخصص لخدمات Microsoft Azure
"""

import requests
import json
import time
import sys
import argparse
from azure.identity import DefaultAzureCredential
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.sql import SqlManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.keyvault import KeyVaultManagementClient
from azure.storage.blob import BlobServiceClient
import socket

class AzureSecurityScanner:
    def __init__(self, subscription_id):
        self.subscription_id = subscription_id
        self.credential = DefaultAzureCredential()
        self.findings = []
        
    def scan_storage_accounts(self):
        """فحص حسابات Azure Storage للأمان"""
        print("🔍 فحص حسابات Azure Storage...")
        
        try:
            storage_client = StorageManagementClient(self.credential, self.subscription_id)
            storage_accounts = storage_client.storage_accounts.list()
            
            for account in storage_accounts:
                account_name = account.name
                resource_group = account.id.split('/')[4]
                
                # فحص التشفير
                if not account.encryption:
                    self.findings.append({
                        'service': 'Azure Storage',
                        'resource': account_name,
                        'issue': 'No Encryption',
                        'risk_level': 'HIGH',
                        'description': f'حساب التخزين {account_name} بدون تشفير'
                    })
                
                # فحص الوصول العام
                if account.allow_blob_public_access:
                    self.findings.append({
                        'service': 'Azure Storage',
                        'resource': account_name,
                        'issue': 'Public Access Enabled',
                        'risk_level': 'HIGH',
                        'description': f'حساب التخزين {account_name} يسمح بالوصول العام'
                    })
                
                # فحص HTTPS فقط
                if not account.enable_https_traffic_only:
                    self.findings.append({
                        'service': 'Azure Storage',
                        'resource': account_name,
                        'issue': 'HTTP Not Enforced',
                        'risk_level': 'MEDIUM',
                        'description': f'حساب التخزين {account_name} يسمح بالاتصال HTTP'
                    })
        
        except Exception as e:
            print(f"خطأ في فحص حسابات التخزين: {e}")
    
    def scan_virtual_machines(self):
        """فحص الآلات الافتراضية للأمان"""
        print("🔍 فحص الآلات الافتراضية...")
        
        try:
            compute_client = ComputeManagementClient(self.credential, self.subscription_id)
            vms = compute_client.virtual_machines.list_all()
            
            for vm in vms:
                vm_name = vm.name
                resource_group = vm.id.split('/')[4]
                
                # فحص تشفير القرص
                if not vm.storage_profile.os_disk.encryption_settings:
                    self.findings.append({
                        'service': 'Azure VM',
                        'resource': vm_name,
                        'issue': 'Disk Not Encrypted',
                        'risk_level': 'HIGH',
                        'description': f'الآلة الافتراضية {vm_name} بدون تشفير القرص'
                    })
                
                # فحص إدارة الهوية
                if not vm.identity:
                    self.findings.append({
                        'service': 'Azure VM',
                        'resource': vm_name,
                        'issue': 'No Managed Identity',
                        'risk_level': 'MEDIUM',
                        'description': f'الآلة الافتراضية {vm_name} بدون هوية مدارة'
                    })
        
        except Exception as e:
            print(f"خطأ في فحص الآلات الافتراضية: {e}")
    
    def scan_sql_databases(self):
        """فحص قواعد بيانات SQL للأمان"""
        print("🔍 فحص قواعد بيانات SQL...")
        
        try:
            sql_client = SqlManagementClient(self.credential, self.subscription_id)
            servers = sql_client.servers.list()
            
            for server in servers:
                server_name = server.name
                resource_group = server.id.split('/')[4]
                
                # فحص جدار الحماية
                firewall_rules = sql_client.firewall_rules.list_by_server(
                    resource_group, server_name
                )
                
                for rule in firewall_rules:
                    if rule.start_ip_address == '0.0.0.0' and rule.end_ip_address == '255.255.255.255':
                        self.findings.append({
                            'service': 'Azure SQL',
                            'resource': server_name,
                            'issue': 'Open Firewall Rule',
                            'risk_level': 'CRITICAL',
                            'description': f'خادم SQL {server_name} يسمح بالوصول من أي IP'
                        })
                
                # فحص التشفير
                if not server.encryption_protector:
                    self.findings.append({
                        'service': 'Azure SQL',
                        'resource': server_name,
                        'issue': 'No TDE Encryption',
                        'risk_level': 'HIGH',
                        'description': f'خادم SQL {server_name} بدون تشفير TDE'
                    })
        
        except Exception as e:
            print(f"خطأ في فحص قواعد بيانات SQL: {e}")
    
    def scan_key_vaults(self):
        """فحص خزائن المفاتيح للأمان"""
        print("🔍 فحص خزائن المفاتيح...")
        
        try:
            kv_client = KeyVaultManagementClient(self.credential, self.subscription_id)
            vaults = kv_client.vaults.list()
            
            for vault in vaults:
                vault_name = vault.name
                resource_group = vault.id.split('/')[4]
                
                # فحص سياسة الوصول
                if vault.properties.enable_rbac_authorization is False:
                    self.findings.append({
                        'service': 'Azure Key Vault',
                        'resource': vault_name,
                        'issue': 'RBAC Not Enabled',
                        'risk_level': 'HIGH',
                        'description': f'خزانة المفاتيح {vault_name} لا تستخدم RBAC'
                    })
                
                # فحص التشفير
                if not vault.properties.enabled_for_disk_encryption:
                    self.findings.append({
                        'service': 'Azure Key Vault',
                        'resource': vault_name,
                        'issue': 'Disk Encryption Disabled',
                        'risk_level': 'MEDIUM',
                        'description': f'خزانة المفاتيح {vault_name} غير ممكلة لتشفير القرص'
                    })
        
        except Exception as e:
            print(f"خطأ في فحص خزائن المفاتيح: {e}")
    
    def scan_network_security_groups(self):
        """فحص مجموعات أمان الشبكة"""
        print("🔍 فحص مجموعات أمان الشبكة...")
        
        try:
            network_client = NetworkManagementClient(self.credential, self.subscription_id)
            nsg_list = network_client.network_security_groups.list_all()
            
            for nsg in nsg_list:
                nsg_name = nsg.name
                resource_group = nsg.id.split('/')[4]
                
                # فحص القواعد
                for rule in nsg.security_rules:
                    if rule.direction == 'Inbound' and rule.access == 'Allow':
                        # فحص المنافذ الحساسة
                        sensitive_ports = [22, 3389, 1433, 3306, 5432, 27017]
                        
                        if rule.destination_port_range in [str(port) for port in sensitive_ports]:
                            for ip_range in rule.source_address_prefixes or [rule.source_address_prefix]:
                                if ip_range == '*' or ip_range == '0.0.0.0/0':
                                    self.findings.append({
                                        'service': 'Network Security Group',
                                        'resource': nsg_name,
                                        'issue': 'Open Sensitive Port',
                                        'risk_level': 'HIGH',
                                        'description': f'منفذ {rule.destination_port_range} مفتوح للعام في {nsg_name}'
                                    })
        
        except Exception as e:
            print(f"خطأ في فحص مجموعات الأمان: {e}")
    
    def scan_app_services(self):
        """فحص خدمات التطبيقات"""
        print("🔍 فحص خدمات التطبيقات...")
        
        try:
            from azure.mgmt.web import WebSiteManagementClient
            web_client = WebSiteManagementClient(self.credential, self.subscription_id)
            apps = web_client.web_apps.list()
            
            for app in apps:
                app_name = app.name
                
                # فحص HTTPS فقط
                if not app.https_only:
                    self.findings.append({
                        'service': 'Azure App Service',
                        'resource': app_name,
                        'issue': 'HTTPS Not Enforced',
                        'risk_level': 'MEDIUM',
                        'description': f'خدمة التطبيق {app_name} لا تفرض HTTPS'
                    })
                
                # فحص التشفير
                if not app.client_cert_enabled:
                    self.findings.append({
                        'service': 'Azure App Service',
                        'resource': app_name,
                        'issue': 'Client Certificate Disabled',
                        'risk_level': 'LOW',
                        'description': f'خدمة التطبيق {app_name} بدون مصادقة شهادة العميل'
                    })
        
        except Exception as e:
            print(f"خطأ في فحص خدمات التطبيقات: {e}")
    
    def run_azure_scan(self, subscription_id):
        """تشغيل فحص Azure شامل"""
        print("🎯 بدء فحص Azure الأمني...")
        
        self.scan_storage_accounts()
        self.scan_virtual_machines()
        self.scan_sql_databases()
        self.scan_key_vaults()
        self.scan_network_security_groups()
        self.scan_app_services()
        
        return self.findings
    
    def display_results(self):
        """عرض النتائج"""
        print("\n" + "=" * 60)
        print("📊 تقرير فحص Azure الأمني")
        print("=" * 60)
        
        if not self.findings:
            print("✅ لم يتم اكتشاف مشاكل أمنية في Azure")
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
    parser = argparse.ArgumentParser(description='Azure Security Scanner')
    parser.add_argument('--subscription', required=True, help='معرف الاشتراك Azure')
    
    args = parser.parse_args()
    
    scanner = AzureSecurityScanner(args.subscription)
    findings = scanner.run_azure_scan(args.subscription)
    scanner.display_results()
    
    # حفظ النتائج
    with open(f'azure_security_scan_{int(time.time())}.json', 'w', encoding='utf-8') as f:
        json.dump(findings, f, indent=2, ensure_ascii=False)

if __name__ == "__main__":
    main()