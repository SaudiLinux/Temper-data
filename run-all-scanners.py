#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
البرنامج التلقائي لتشغيل جميع أدوات الأمن السيبراني المتقدمة
Automated Advanced Cybersecurity Tools Suite Runner

هذا البرنامج يقوم بتشغيل جميع أدوات المسح الأمني بالتوالي مع واجهة مستخدم واضحة
"""

import os
import sys
import subprocess
import json
import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse
import time

class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class SecurityToolsRunner:
    def __init__(self):
        self.base_dir = os.path.dirname(os.path.abspath(__file__))
        self.results_dir = os.path.join(self.base_dir, "scan_results")
        self.timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # قائمة الأدوات المتاحة
        self.tools = {
            "zero-day-scanner.py": {
                "name": "ماسح الثغرات الصفرية (Zero-Day)",
                "description": "كشف الثغرات الصفرية والاستغلالات النشطة",
                "category": "ثغرات اليوم الصفري"
            },
            "web-zero-day-scanner.py": {
                "name": "ماسح تطبيقات الويب للثغرات الصفرية",
                "description": "كشف ثغرات تطبيقات الويب المتقدمة",
                "category": "أمن تطبيقات الويب"
            },
            "network-zero-day-scanner.py": {
                "name": "ماسح شبكات الثغرات الصفرية",
                "description": "كشف الثغرات في خدمات الشبكة",
                "category": "أمن الشبكات"
            },
            "cloud-security-scanner.py": {
                "name": "ماسح أمن السحابة",
                "description": "فحص أمن خدمات الحوسبة السحابية",
                "category": "أمن السحابة"
            },
            "aws-security-scanner.py": {
                "name": "ماسح أمن AWS",
                "description": "فحص أمن خدمات Amazon Web Services",
                "category": "أمن AWS"
            },
            "azure-security-scanner.py": {
                "name": "ماسح أمن Azure",
                "description": "فحص أمن خدمات Microsoft Azure",
                "category": "أمن Azure"
            },
            "gcp-security-scanner.py": {
                "name": "ماسح أمن GCP",
                "description": "فحص أمن خدمات Google Cloud Platform",
                "category": "أمن GCP"
            },
            "platform-vulnerability-scanner.py": {
                "name": "ماسح ثغرات المنصات",
                "description": "كشف الثغرات في المنصات المختلفة",
                "category": "ثغرات المنصات"
            },
            "exchange-vulnerability-scanner.py": {
                "name": "ماسح ثغرات Exchange",
                "description": "كشف ثغرات Microsoft Exchange Server",
                "category": "ثغرات Exchange"
            },
            "zoom-vulnerability-scanner.py": {
                "name": "ماسح ثغرات Zoom",
                "description": "كشف ثغرات منصة Zoom",
                "category": "ثغرات Zoom"
            },
            "temper-data.py": {
                "name": "ماسح ثغرات Joomla وWordPress",
                "description": "كشف الثغرات في أنظمة إدارة المحتوى",
                "category": "ثغرات CMS"
            }
        }
        
        self.create_results_dir()
    
    def create_results_dir(self):
        """إنشاء مجلد لحفظ النتائج"""
        if not os.path.exists(self.results_dir):
            os.makedirs(self.results_dir)
    
    def check_tool_exists(self, tool_name):
        """التحقق من وجود الأداة"""
        tool_path = os.path.join(self.base_dir, tool_name)
        return os.path.exists(tool_path)
    
    def run_tool(self, tool_name, target, options=None):
        """تشغيل أداة معينة"""
        tool_path = os.path.join(self.base_dir, tool_name)
        
        if not self.check_tool_exists(tool_name):
            return {
                "status": "error",
                "message": "الأداة {} غير موجودة".format(tool_name),
                "tool": tool_name
            }
        
        cmd = [sys.executable, tool_path, "-u", target]
        if options:
            cmd.extend(options)
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            return {
                "status": "success",
                "tool": tool_name,
                "return_code": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr
            }
        except subprocess.TimeoutExpired:
            return {
                "status": "timeout",
                "message": "انتهت مهلة التنفيذ",
                "tool": tool_name
            }
        except Exception as e:
            return {
                "status": "error",
                "message": str(e),
                "tool": tool_name
            }
    
    def display_tools_menu(self):
        """عرض قائمة الأدوات"""
        print("\nالأدوات المتاحة:")
        print("=" * 60)
        
        for i, (tool_name, info) in enumerate(self.tools.items(), 1):
            status = "✅" if self.check_tool_exists(tool_name) else "❌"
            print("{}. {} {}".format(i, status, info['name']))
            print("   الوصف: {}".format(info['description']))
            print("   التصنيف: {}".format(info['category']))
            print()
    
    def run_all_tools(self, target, max_workers=3):
        """تشغيل جميع الأدوات المتاحة"""
        print("\nبدء تشغيل جميع الأدوات على الهدف: {}".format(target))
        print("=" * 60)
        
        available_tools = [tool for tool in self.tools.keys() if self.check_tool_exists(tool)]
        
        if not available_tools:
            print("لا توجد أدوات متاحة للتشغيل")
            return
        
        results = {}
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_tool = {
                executor.submit(self.run_tool, tool, target): tool 
                for tool in available_tools
            }
            
            for future in as_completed(future_to_tool):
                tool = future_to_tool[future]
                try:
                    result = future.result()
                    results[tool] = result
                    
                    if result["status"] == "success":
                        print("✅ {} - تم بنجاح".format(self.tools[tool]['name']))
                    else:
                        error_msg = result.get('message', 'خطأ غير معروف')
                        print("❌ {} - فشل: {}".format(self.tools[tool]['name'], error_msg))
                        
                except Exception as e:
                    results[tool] = {
                        "status": "error",
                        "message": str(e),
                        "tool": tool
                    }
                    print("❌ {} - خطأ: {}".format(self.tools[tool]['name'], str(e)))
        
        return results

def main():
    parser = argparse.ArgumentParser(description="البرنامج التلقائي لتشغيل أدوات الأمن السيبراني")
    parser.add_argument("-u", "--url", help="الهدف للفحص (URL أو IP)")
    parser.add_argument("-t", "--tools", nargs="*", help="الأدوات المحددة للتشغيل")
    parser.add_argument("-w", "--workers", type=int, default=3, help="عدد العمليات المتوازية")
    parser.add_argument("--list", action="store_true", help="عرض قائمة الأدوات المتاحة")
    
    args = parser.parse_args()
    
    runner = SecurityToolsRunner()
    
    if args.list:
        runner.display_tools_menu()
        return
    
    if not args.url:
        print("استخدام: python run-all-scanners.py -u <URL> [خيارات]")
        print("استخدم --help للمساعدة أو --list لعرض الأدوات")
        return
    
    if args.tools:
        results = runner.run_selected_tools(args.url, args.tools)
    else:
        results = runner.run_all_tools(args.url, args.workers)

if __name__ == "__main__":
    main()