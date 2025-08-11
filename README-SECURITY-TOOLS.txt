# دليل استخدام أدوات الأمن السيبراني المتقدمة
# Advanced Cyber Security Tools Usage Guide

===============================================
## 🚀 المقدمة السريعة
## Quick Start Guide

هذا الدليل يشرح كيفية استخدام جميع أدوات الأمن السيبراني المتقدمة التي تم تطويرها،
بما في ذلك أدوات الثغرات الصفرية، فحص المنصات، والأمن السحابي.

This guide explains how to use all advanced cyber security tools developed,
including zero-day vulnerability scanners, platform scanners, and cloud security tools.

===============================================
## 📋 قائمة الأدوات الكاملة
## Complete Tools List

### 🔍 **أدوات الثغرات الصفرية** (Zero-Day Detection)
- `zero-day-scanner.py` - فحص الثغرات الصفرية العامة
- `web-zero-day-scanner.py` - فحص تطبيقات الويب
- `network-zero-day-scanner.py` - فحص خدمات الشبكة

### 🌐 **أدوات فحص المنصات** (Platform Vulnerability)
- `platform-vulnerability-scanner.py` - فحص شامل للمنصات
- `exchange-vulnerability-scanner.py` - فحص Microsoft Exchange
- `zoom-vulnerability-scanner.py` - فحص Zoom

### ☁️ **أدوات الأمن السحابي** (Cloud Security)
- `aws-security-scanner.py` - فحص Amazon AWS
- `azure-security-scanner.py` - فحص Microsoft Azure
- `gcp-security-scanner.py` - فحص Google Cloud Platform

### 🎯 **أداة CMS المخصصة**
- `temper-data.py` - فحص WordPress وJoomla

===============================================
## ⚡ خطوات التثبيت السريعة
## Quick Installation Steps

### 1️⃣ المتطلبات الأساسية:
- Python 3.7 أو أحدث
- Windows / Linux / macOS
- اتصال إنترنت نشط

### 2️⃣ التثبيت السريع:
```bash
# الانتقال إلى المجلد
cd C:\Users\Dell\Desktop\TemparData

# تثبيت جميع المتطلبات
type requirements.txt cloud-requirements.txt platform-requirements.txt zero-day-requirements.txt > all-requirements.txt
pip install -r all-requirements.txt
```

### 3️⃣ التحقق من التثبيت:
```bash
python --version
pip list
```

===============================================
## 🎯 طريقة الاستخدام لكل أداة
## Usage Instructions for Each Tool

### 🔍 **أدوات الثغرات الصفرية**

#### فحص ثغرات صفرية عامة:
```bash
python zero-day-scanner.py [target]
python zero-day-scanner.py httpbin.org
```

#### فحص تطبيقات الويب:
```bash
python web-zero-day-scanner.py [URL]
python web-zero-day-scanner.py https://target.com
```

#### فحص خدمات الشبكة:
```bash
python network-zero-day-scanner.py [host/IP]
python network-zero-day-scanner.py 192.168.1.1
```

### 🌐 **أدوات فحص المنصات**

#### فحص شامل:
```bash
python platform-vulnerability-scanner.py [target]
python platform-vulnerability-scanner.py example.com
```

#### فحص Exchange:
```bash
python exchange-vulnerability-scanner.py [domain]
python exchange-vulnerability-scanner.py mail.company.com
```

#### فحص Zoom:
```bash
python zoom-vulnerability-scanner.py [domain]
python zoom-vulnerability-scanner.py zoom-target.com
```

### ☁️ **أدوات الأمن السحابي**

#### فحص AWS:
```bash
python aws-security-scanner.py [domain]
python aws-security-scanner.py company.com
```

#### فحص Azure:
```bash
python azure-security-scanner.py [domain]
python azure-security-scanner.py target.org
```

#### فحص GCP:
```bash
python gcp-security-scanner.py [domain]
python gcp-security-scanner.py site.com
```

### 🎯 **أداة CMS**

#### الاستخدام الأساسي:
```bash
python temper-data.py -u [URL]
python temper-data.py -u https://wordpress-site.com
```

#### الاستخدام المتقدم:
```bash
python temper-data.py -u https://joomla-site.com -o results.json -t 15
```

===============================================
## ⚙️ الخيارات المتقدمة
## Advanced Options

### خيارات مشتركة لجميع الأدوات:
- `--threads N` - عدد الخيوط (افتراضي: 10)
- `--timeout N` - مهلة الاتصال (افتراضي: 30 ثانية)
- `--output FILE` - اسم ملف النتائج المخصص
- `--verbose` - عرض تفاصيل إضافية

### أمثلة متقدمة:
```bash
# فحص مع خيارات متقدمة
python zero-day-scanner.py target.com --threads 20 --timeout 60 --verbose

# فحص مع حفظ النتائج
python aws-security-scanner.py company.com --output aws-results.json
```

===============================================
## 📊 فهم النتائج
## Understanding Results

### تصنيفات المخاطر:
- **CRITICAL/حرج** - ثغرات خطيرة جداً
- **HIGH/عالي** - مخاطر كبيرة
- **MEDIUM/متوسط** - مخاطر متوسطة
- **LOW/منخفض** - مخاطر بسيطة

### ملفات النتائج:
- تُحفظ في صيغة JSON
- تُنشأ تلقائياً بالتاريخ والوقت
- مثال: `zero_day_scan_target.com_20250811_132320.json`

===============================================
## 🎯 أمثلة عملية
## Practical Examples

### مثال 1: فحص موقع ويب شامل
```bash
# فحص شامل لموقع
python platform-vulnerability-scanner.py website.com
python zero-day-scanner.py website.com
python web-zero-day-scanner.py https://website.com
```

### مثال 2: فحص بنية سحابية
```bash
# فحص جميع الخدمات السحابية
python aws-security-scanner.py company.com
python azure-security-scanner.py company.com
python gcp-security-scanner.py company.com
```

### مثال 3: فحص بنية شبكة داخلية
```bash
# فحص خوادم الشبكة
python network-zero-day-scanner.py 192.168.1.100
python exchange-vulnerability-scanner.py 192.168.1.100
```

===============================================
## ⚠️ تحذيرات أمنية مهمة
## Important Security Warnings

### 🔒 قبل الاستخدام:
- احصل على إذن صريح قبل الفحص
- استخدم فقط في بيئات التطوير أو الاختبار
- احترم القوانين المحلية

### 🚨 أثناء الاستخدام:
- لا تستخدم في أنظمة الإنتاج بدون موافقة
- راجع النتائج يدوياً قبل اتخاذ إجراء
- احتفظ بالنتائج في مكان آمن

### 📋 بعد الانتهاء:
- احذف النتائج الحساسة بعد التحليل
- بلغ عن الثغرات بطريقة مسؤولة
- حدث الأدوات بانتظام

===============================================
## 🔧 حل المشاكل الشائعة
## Troubleshooting Common Issues

### مشكلة: "Module not found"
```bash
pip install requests colorama urllib3
```

### مشكلة: "Connection timeout"
```bash
python tool.py target.com --timeout 60
```

### مشكلة: "Permission denied"
```bash
# Windows: شغل PowerShell كمسؤول
# Linux/Mac: استخدم sudo بحذر
```

### مشكلة: "SSL certificate verify failed"
```bash
pip install --upgrade certifi
```

===============================================
## 📚 المصادر الإضافية
## Additional Resources

### ملفات README المفصلة:
- `CLOUD-SECURITY-README.md` - تفاصيل أدوات السحابة
- `PLATFORM-VULNERABILITY-README.md` - تفاصيل فحص المنصات
- `ZERO-DAY-SCANNER-README.md` - تفاصيل الثغرات الصفرية
- `USAGE-GUIDE.txt` - دليل الاستخدام الشامل

### ملفات المتطلبات:
- `requirements.txt` - المتطلبات الأساسية
- `cloud-requirements.txt` - أدوات السحابة
- `platform-requirements.txt` - أدوات المنصات
- `zero-day-requirements.txt` - أدوات الثغرات الصفرية

===============================================
## 🎓 نصائح للمبتدئين
## Tips for Beginners

1. ابدأ بالأهداف التجريبية مثل httpbin.org
2. اقرأ ملفات README المفصلة
3. جرب الخيارات الافتراضية أولاً
4. تحقق من النتائج يدوياً
5. احتفظ بنسخ احتياطية من النتائج

===============================================
## 📞 الدعم والتواصل
## Support and Contact

### للمشاكل التقنية:
- راجع ملفات README المفصلة
- تحقق من أسماء الملفات الصحيحة
- استخدم `python --help` مع كل أداة

### أفضل الممارسات:
- استخدم VPN عند الاختبار
- احتفظ بسجلات الفحص
- استخدم بيئات اختبار معزولة

===============================================
## 🔄 التحديث والصيانة
## Updates and Maintenance

### تحديث المكتبات:
```bash
pip install --upgrade -r requirements.txt
pip install --upgrade -r cloud-requirements.txt
pip install --upgrade -r platform-requirements.txt
pip install --upgrade -r zero-day-requirements.txt
```

### مراقبة الأداء:
- رصد وقت الفحص
- تحليل دقة النتائج
- مراجعة استخدام الموارد

===============================================
**📅 آخر تحديث: 2025-08-11**
**📧 تم الإنشاء تلقائياً للأدوات الأمنية المتقدمة**

**⚡ ملاحظة**: هذه الأدوات للأغراض التعليمية والاختبارية فقط. استخدمها بمسؤولية وفقاً للقوانين المحلية.
**Note**: These tools are for educational and testing purposes only. Use responsibly and in accordance with local laws.