#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AWS Security Scanner - فحص أمني متخصص لخدمات AWS
"""

import requests
import json
import boto3
from botocore.exceptions import ClientError
import sys
import argparse
import time
from concurrent.futures import ThreadPoolExecutor
import socket

class AWSSecurityScanner:
    def __init__(self):
        self.findings = []
        
    def scan_s3_buckets(self, profile_name=None):
        """فحص حاويات S3 للأمان والتهيئة الخاطئة"""
        print("🔍 فحص حاويات S3...")
        
        try:
            if profile_name:
                session = boto3.Session(profile_name=profile_name)
                s3 = session.client('s3')
            else:
                s3 = boto3.client('s3')
            
            buckets = s3.list_buckets()['Buckets']
            
            for bucket in buckets:
                bucket_name = bucket['Name']
                
                # فحص سياسة الوصول
                try:
                    policy = s3.get_bucket_policy(Bucket=bucket_name)
                    self.check_bucket_policy(bucket_name, policy)
                except ClientError:
                    pass
                
                # فحص ACL
                try:
                    acl = s3.get_bucket_acl(Bucket=bucket_name)
                    self.check_bucket_acl(bucket_name, acl)
                except ClientError:
                    pass
                
                # فحص التشفير
                try:
                    encryption = s3.get_bucket_encryption(Bucket=bucket_name)
                    self.check_bucket_encryption(bucket_name, encryption)
                except ClientError as e:
                    if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                        self.findings.append({
                            'service': 'S3',
                            'resource': bucket_name,
                            'issue': 'No Encryption',
                            'risk_level': 'HIGH',
                            'description': f'حاوية S3 {bucket_name} بدون تشفير جانب الخادم'
                        })
        
        except Exception as e:
            print(f"خطأ في فحص S3: {e}")
    
    def check_bucket_policy(self, bucket_name, policy):
        """فحص سياسة حاوية S3"""
        if 'Policy' in policy:
            policy_json = json.loads(policy['Policy'])
            
            # فحص الوصول العام
            for statement in policy_json.get('Statement', []):
                if statement.get('Effect') == 'Allow' and '*' in str(statement.get('Principal', {})):
                    self.findings.append({
                        'service': 'S3',
                        'resource': bucket_name,
                        'issue': 'Public Access',
                        'risk_level': 'HIGH',
                        'description': f'حاوية S3 {bucket_name} تسمح بالوصول العام'
                    })
    
    def check_bucket_acl(self, bucket_name, acl):
        """فحص ACL للحاوية"""
        for grant in acl.get('Grants', []):
            grantee = grant.get('Grantee', {})
            if grantee.get('Type') == 'Group' and 'AllUsers' in str(grantee):
                self.findings.append({
                    'service': 'S3',
                    'resource': bucket_name,
                    'issue': 'Public ACL',
                    'risk_level': 'HIGH',
                    'description': f'حاوية S3 {bucket_name} لديها ACL عام'
                })
    
    def check_bucket_encryption(self, bucket_name, encryption):
        """فحص تشفير الحاوية"""
        if 'ServerSideEncryptionConfiguration' not in encryption:
            self.findings.append({
                'service': 'S3',
                'resource': bucket_name,
                'issue': 'No Encryption',
                'risk_level': 'HIGH',
                'description': f'حاوية S3 {bucket_name} بدون تشفير'
            })
    
    def scan_iam_policies(self, profile_name=None):
        """فحص سياسات IAM للأمان"""
        print("🔍 فحص سياسات IAM...")
        
        try:
            if profile_name:
                session = boto3.Session(profile_name=profile_name)
                iam = session.client('iam')
            else:
                iam = boto3.client('iam')
            
            # فحص المستخدمين
            users = iam.list_users()['Users']
            for user in users:
                user_name = user['UserName']
                
                # فحص المفاتيح القديمة
                if 'PasswordLastUsed' in user:
                    last_used = user['PasswordLastUsed']
                    # يمكن إضافة منطق للتحقق من المفاتيح القديمة
                
                # فحص سياسات المستخدم
                policies = iam.list_user_policies(UserName=user_name)['PolicyNames']
                for policy in policies:
                    self.check_user_policy(user_name, policy)
            
            # فحص المجموعات
            groups = iam.list_groups()['Groups']
            for group in groups:
                group_name = group['GroupName']
                self.check_group_policies(group_name)
                
        except Exception as e:
            print(f"خطأ في فحص IAM: {e}")
    
    def check_user_policy(self, user_name, policy_name):
        """فحص سياسة المستخدم"""
        try:
            iam = boto3.client('iam')
            policy = iam.get_user_policy(UserName=user_name, PolicyName=policy_name)
            
            # تحليل السياسة للبحث عن أذونات مفرطة
            policy_doc = policy['PolicyDocument']
            
            for statement in policy_doc.get('Statement', []):
                if statement.get('Effect') == 'Allow' and '*' in str(statement.get('Action', '')):
                    self.findings.append({
                        'service': 'IAM',
                        'resource': f'User: {user_name}',
                        'issue': 'Excessive Permissions',
                        'risk_level': 'HIGH',
                        'description': f'المستخدم {user_name} لديه أذونات مفرطة'
                    })
        
        except Exception as e:
            print(f"خطأ في فحص سياسة المستخدم: {e}")
    
    def scan_exposed_databases(self):
        """فحص قواعد البيانات المعرضة"""
        print("🔍 فحص قواعد البيانات المعرضة...")
        
        # RDS scanning
        try:
            rds = boto3.client('rds')
            instances = rds.describe_db_instances()['DBInstances']
            
            for instance in instances:
                if instance['PubliclyAccessible']:
                    self.findings.append({
                        'service': 'RDS',
                        'resource': instance['DBInstanceIdentifier'],
                        'issue': 'Publicly Accessible',
                        'risk_level': 'CRITICAL',
                        'description': f'قاعدة بيانات RDS {instance["DBInstanceIdentifier"]} متاحة للعام'
                    })
        
        except Exception as e:
            print(f"خطأ في فحص RDS: {e}")
    
    def scan_security_groups(self):
        """فحص مجموعات الأمان للثغرات"""
        print("🔍 فحص مجموعات الأمان...")
        
        try:
            ec2 = boto3.client('ec2')
            groups = ec2.describe_security_groups()['SecurityGroups']
            
            for group in groups:
                group_name = group['GroupName']
                
                # فحص القواعد المفتوحة
                for rule in group.get('IpPermissions', []):
                    if rule.get('IpProtocol') == 'tcp':
                        from_port = rule.get('FromPort')
                        to_port = rule.get('ToPort')
                        
                        # فحص المنافذ الحساسة المفتوحة
                        sensitive_ports = [22, 3389, 5432, 3306, 1433, 27017, 6379]
                        
                        if from_port in sensitive_ports and to_port in sensitive_ports:
                            for ip_range in rule.get('IpRanges', []):
                                if ip_range.get('CidrIp') == '0.0.0.0/0':
                                    self.findings.append({
                                        'service': 'Security Group',
                                        'resource': group_name,
                                        'issue': 'Open Port',
                                        'risk_level': 'HIGH',
                                        'description': f'منفذ {from_port} مفتوح للعام في مجموعة {group_name}'
                                    })
        
        except Exception as e:
            print(f"خطأ في فحص مجموعات الأمان: {e}")
    
    def run_aws_scan(self, profile_name=None):
        """تشغيل فحص AWS شامل"""
        print("🎯 بدء فحص AWS الأمني...")
        
        self.scan_s3_buckets(profile_name)
        self.scan_iam_policies(profile_name)
        self.scan_exposed_databases()
        self.scan_security_groups()
        
        return self.findings
    
    def display_results(self):
        """عرض النتائج"""
        print("\n" + "=" * 60)
        print("📊 تقرير فحص AWS الأمني")
        print("=" * 60)
        
        if not self.findings:
            print("✅ لم يتم اكتشاف مشاكل أمنية في AWS")
            return
        
        critical = [f for f in self.findings if f['risk_level'] == 'CRITICAL']
        high = [f for f in self.findings if f['risk_level'] == 'HIGH']
        medium = [f for f in self.findings if f['risk_level'] == 'MEDIUM']
        
        print(f"🚨 مخاطر حرجة: {len(critical)}")
        print(f"🔴 مخاطر عالية: {len(high)}")
        print(f"🟡 مخاطر متوسطة: {len(medium)}")
        
        for finding in self.findings:
            print(f"\n[{finding['risk_level']}] {finding['service']}: {finding['description']}")

def main():
    parser = argparse.ArgumentParser(description='AWS Security Scanner')
    parser.add_argument('--profile', help='اسم ملف تعريف AWS')
    
    args = parser.parse_args()
    
    scanner = AWSSecurityScanner()
    findings = scanner.run_aws_scan(args.profile)
    scanner.display_results()
    
    # حفظ النتائج
    with open(f'aws_security_scan_{int(time.time())}.json', 'w') as f:
        json.dump(findings, f, indent=2)

if __name__ == "__main__":
    main()