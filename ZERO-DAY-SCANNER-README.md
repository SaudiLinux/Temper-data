# أدوات فحص ثغرات اليوم الصفري المتقدمة
# Advanced Zero-Day Vulnerability Scanners

## نظرة عامة | Overview

مجموعة متكاملة من أدوات فحص الثغرات اليوم الصفري (Zero-Day) مصممة للكشف عن الثغرات غير المعروفة والاستغلالات المشبوهة في مختلف البيئات التقنية.

A comprehensive toolkit of zero-day vulnerability scanners designed to detect unknown vulnerabilities and suspicious exploits across various technical environments.

## الأدوات المتوفرة | Available Tools

### 1. أداة فحص الثغرات اليوم الصفري العامة
**zero-day-scanner.py**
- الكشف عن ثغرات Log4Shell (CVE-2021-44228)
- اختبار SSRF وRCE
- فحص deserialization vulnerabilities
- اختبار WAF bypass techniques

### 2. أداة فحص التطبيقات الويب
**web-zero-day-scanner.py**
- فحص Parameter Pollution
- اختبار SSTI (Server-Side Template Injection)
- كشف NoSQL Injection
- فحص GraphQL vulnerabilities
- اختبار API version disclosure

### 3. أداة فحص الخدمات الشبكية
**network-zero-day-scanner.py**
- فحص SSH vulnerabilities
- اختبار RDP (BlueKeep)
- كشف ثغرات قواعد البيانات
- فحص SSL/TLS vulnerabilities
- DNS vulnerability detection

## التثبيت | Installation

### المتطلبات الأساسية | Requirements
```bash
# تحديث pip
python -m pip install --upgrade pip

# تثبيت المكتبات المطلوبة
pip install requests urllib3

# أو استخدام ملف المتطلبات
pip install -r zero-day-requirements.txt
```

### ملف المتطلبات | Requirements File
```bash
# zero-day-requirements.txt
requests>=2.28.0
urllib3>=1.26.0
dnspython>=2.2.0
cryptography>=3.4.0
```

## الاستخدام | Usage

### الأداة العامة للثغرات اليوم الصفري
```bash
# فحص هدف واحد
python zero-day-scanner.py http://example.com

# فحص عدة أهداف
python zero-day-scanner.py http://example.com https://test.com 192.168.1.100

# مثال عملي
python zero-day-scanner.py scanme.nmap.org
```

### أداة فحص التطبيقات الويب
```bash
# فحص تطبيق ويب
python web-zero-day-scanner.py http://example.com

# فحص عدة تطبيقات
python web-zero-day-scanner.py http://site1.com https://site2.com
```

### أداة فحص الخدمات الشبكية
```bash
# فحص خادم شبكي
python network-zero-day-scanner.py 192.168.1.1

# فحص عدة خوادم
python network-zero-day-scanner.py 192.168.1.1 10.0.0.1 scanme.nmap.org
```

## أمثلة على النتائج | Sample Results

### مثال نتيجة فحص ثغرات اليوم الصفري
```json
[
  {
    "target": "http://example.com",
    "vulnerability_type": "ثغرة Log4Shell (CVE-2021-44228)",
    "risk_level": "CRITICAL",
    "description": "تم اكتشاف ثغرة Log4Shell النقدية",
    "evidence": "Header: User-Agent - Payload: \${jndi:ldap://127.0.0.1:1389/a}",
    "timestamp": "2024-01-15T10:30:00"
  },
  {
    "target": "http://example.com",
    "vulnerability_type": "ثغرة SSRF",
    "risk_level": "HIGH",
    "description": "تم اكتشاف ثغرة SSRF محتملة",
    "evidence": "Payload: http://169.254.169.254/latest/meta-data/ - Indicator: ami-id",
    "timestamp": "2024-01-15T10:30:05"
  }
]
```

### مثال نتيجة فحص التطبيق الويب
```json
[
  {
    "target": "http://example.com",
    "vulnerability_type": "ثغرة SSTI محتملة",
    "risk_level": "CRITICAL",
    "description": "تم اكتشاف ثغرة حقن قوالب الخادم",
    "evidence": "Payload: {{7*7}} - Indicator: 49",
    "timestamp": "2024-01-15T10:35:00"
  }
]
```

### مثال نتيجة فحص الخدمة الشبكية
```json
[
  {
    "target": "192.168.1.1",
    "port": 22,
    "vulnerability_type": "SSH قديم محتمل",
    "risk_level": "HIGH",
    "description": "تم اكتشاف SSH قديم قد يحتوي على ثغرات يوم صفري",
    "evidence": "Version: SSH-2.0-OpenSSH_7.2",
    "timestamp": "2024-01-15T10:40:00"
  }
]
```

## تصنيف المخاطر | Risk Classification

### CRITICAL (حرج)
- ثغرات يمكن استغلالها عن بُعد للسيطرة الكاملة
- Log4Shell, RCE, SSTI

### HIGH (عالي)
- ثغرات يمكن استغلالها للحصول على وصول غير مصرح به
- SSRF, Path Traversal, Database exposure

### MEDIUM (متوسط)
- ثغرات قد تؤدي إلى تسريب معلومات
- API disclosure, Weak SSL/TLS

### LOW (منخفض)
- مشكلات تكوين أو معلومات فنية
- Version disclosure, DNS issues

## ميزات متقدمة | Advanced Features

### الفحص المتزامن | Concurrent Scanning
- يدعم فحص عدة أهداف في وقت واحد
- استخدام ThreadPoolExecutor للأداء الأمثل

### التقارير التفصيلية | Detailed Reporting
- JSON output للتكامل مع أدوات أخرى
- تقارير عربية واضحة
- دليل إثبات لكل ثغرة

### التحقق الذكي | Smart Detection
- تحليل السلوك غير المعتاد
- اكتشاف الأنماط المشبوهة
- تقليل الإيجابيات الكاذبة

## التحذيرات الأمنية | Security Warnings

⚠️ **ملاحظات مهمة:**
- هذه الأدوات للكشف عن المؤشرات المحتملة فقط
- يجب التحقق اليدوي من النتائج قبل اتخاذ أي إجراء
- لا تستخدم هذه الأدوات على أنظمة لا تملك صلاحية اختبارها
- الاستخدام غير المصرح به قد يكون غير قانوني

## استكشاف الأخطاء | Troubleshooting

### مشاكل شائعة | Common Issues

#### مشكلة الاتصال
```bash
# تأكد من أن الهدف متاح
ping target.com

# تحقق من جدار الحماية
nmap -p 80,443 target.com
```

#### مشكلة Python
```bash
# تأكد من إصدار Python
python --version  # يجب أن يكون 3.6 أو أحدث

# إعادة تثبيت المكتبات
pip uninstall requests urllib3
pip install requests urllib3
```

#### مشكلة الأذونات
```bash
# في Linux/Mac
chmod +x zero-day-scanner.py

# تشغيل مع sudo إذا لزم الأمر
sudo python zero-day-scanner.py target.com
```

## التكامل مع أدوات أخرى | Integration

### مع أدوات الأتمتة
```python
# استخدام النتائج JSON في سكربتات أخرى
import json

with open('zero_day_scan_results.json') as f:
    results = json.load(f)
    
for finding in results:
    if finding['risk_level'] == 'CRITICAL':
        print(f"تحذير: {finding['description']}")
```

### مع أنظمة الإدارة
- يمكن تكامل النتائج مع SIEM systems
- دعم تنسيق JSON للتكامل مع ELK stack
- إمكانية إرسال تنبيهات عبر webhook

## الدعم والمساعدة | Support

### التواصل
- للإبلاغ عن مشاكل أو اقتراحات
- مشاركة النتائج والاكتشافات

### تحديثات الأمان
- تابع التحديثات الأمنية الجديدة
- قم بتحديث الأدوات بانتظام

## الاعتمادات | Credits

تم تطوير هذه الأدوات للكشف عن الثغرات اليوم الصفري باستخدام:
- تقنيات تحليل السلوك المتقدمة
- خوارزميات اكتشاف الأنماط
- تحليل الاستجابات غير المعتادة

---

**ملاحظة**: هذه الأدوات مصممة للأغراض التعليمية والأمنية فقط. استخدمها بمسؤولية واخلاقية.