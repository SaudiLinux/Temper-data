═══════════════════════════════════════════════════════════════
                    دليل استخدام أدوات الأمن السيبراني المتقدمة
═══════════════════════════════════════════════════════════════

مجموعة أدوات متكاملة للكشف عن الثغرات الأمنية في مختلف المنصات والخدمات

مبرمج الأدوات: SayerLinux
الموقع: https://github.com/SaudiLinux
الإيميل: SayerLinux@gmail.com
الإصدار: 3.0

═══════════════════════════════════════════════════════════════

📋 قائمة الأدوات المتوفرة:

1. **أداة Temper-Data** - كشف ثغرات Joomla و WordPress
2. **ماسح الثغرات الصفرية (Zero-Day)** - كشف الثغرات غير المكتشفة
3. **ماسح تطبيقات الويب للثغرات الصفرية** - فحص تطبيقات الويب المتقدمة
4. **ماسح شبكات الثغرات الصفرية** - فحص خدمات الشبكة
5. **ماسح أمن السحابة** - فحص أمن خدمات الحوسبة السحابية
6. **ماسح أمن AWS** - فحص أمن Amazon Web Services
7. **ماسح أمن Azure** - فحص أمن Microsoft Azure
8. **ماسح أمن GCP** - فحص أمن Google Cloud Platform
9. **ماسح ثغرات المنصات** - كشف الثغرات في المنصات المختلفة
10. **ماسح ثغرات Exchange** - كشف ثغرات Microsoft Exchange
11. **ماسح ثغرات Zoom** - كشف ثغرات منصة Zoom
12. **النظام التلقائي** - تشغيل جميع الأدوات بالتوالي

═══════════════════════════════════════════════════════════════

🔧 المتطلبات الأساسية:
- Python 3.6 أو أحدث
- Windows / Linux / macOS
- اتصال إنترنت نشط

═══════════════════════════════════════════════════════════════

📥 خطوات التثبيت السريع:

1. تثبيت Python:
   - تحميل Python من الموقع الرسمي: https://python.org
   - تأكد من إضافة Python إلى PATH أثناء التثبيت

2. تثبيت المتطلبات:
   ```bash
   cd C:\Users\Dell\Desktop\TemparData
   install.bat
   ```

3. أو تثبيت المتطلبات يدوياً:
   ```bash
   pip install -r requirements.txt
   pip install -r cloud-requirements.txt
   pip install -r zero-day-requirements.txt
   ```

═══════════════════════════════════════════════════════════════

🚀 الطرق السريعة للاستخدام:

### الطريقة 1: النظام التلقائي (يوصى به)
```bash
# تشغيل جميع الأدوات على هدف واحد
python run-all-scanners.py -u httpbin.org

# تشغيل أدوات محددة
python run-all-scanners.py -u httpbin.org -t zero-day cloud aws

# عرض قائمة الأدوات المتوفرة
python run-all-scanners.py --list
```

### الطريقة 2: كل أداة على حدة

#### أداة Temper-Data (Joomla/WordPress)
```bash
# استخدام أساسي
python temper-data.py -u https://wordpress-site.com

# استخدام متقدم
python temper-data.py -u https://joomla-site.com -o results.json -t 15
```

#### ماسح الثغرات الصفرية
```bash
python zero-day-scanner.py -u httpbin.org
python web-zero-day-scanner.py -u httpbin.org
python network-zero-day-scanner.py -u httpbin.org
```

#### ماسح أمن السحابة
```bash
python cloud-security-scanner.py -u httpbin.org
python aws-security-scanner.py -u httpbin.org
python azure-security-scanner.py -u httpbin.org
python gcp-security-scanner.py -u httpbin.org
```

#### ماسح ثغرات المنصات
```bash
python platform-vulnerability-scanner.py -u httpbin.org
python exchange-vulnerability-scanner.py -u httpbin.org
python zoom-vulnerability-scanner.py -u httpbin.org
```

### الطريقة 3: استخدام ملف الـ batch (Windows)
```bash
# تشغيل قائمة اختيار الأدوات
run-all-scanners.bat
```

═══════════════════════════════════════════════════════════════

📊 خيارات الأدوات المتقدمة:

#### خيارات مشتركة لجميع الأدوات:
- `-u, --url` : رابط الهدف (إجباري)
- `-o, --output` : اسم ملف النتائج (اختياري)
- `-t, --threads` : عدد الخيوط (افتراضي: 10)
- `--no-auto-save` : تعطيل الحفظ التلقائي

#### خيارات النظام التلقائي:
- `--workers` : عدد الأدوات التي تعمل بالتوازي (افتراضي: 3)
- `--list` : عرض قائمة الأدوات المتوفرة
- `-t, --tools` : تشغيل أدوات محددة فقط

═══════════════════════════════════════════════════════════════

🔍 ما الذي تبحث عنه كل أداة:

### أداة Temper-Data:
✅ كشف نوع CMS (WordPress أو Joomla)
✅ فحص الثغرات الأمنية المعروفة
✅ اكتشاف الملفات والروابط المخفية
✅ البحث عن لوحات تحكم الإدارة
✅ اختبار تخطي جدار الحماية WAF
✅ فحص ملفات النسخ الاحتياطية
✅ البحث عن ملفات الإعدادات المكشوفة

### أدوات الثغرات الصفرية:
✅ SSRF (Server-Side Request Forgery)
✅ RCE (Remote Code Execution)
✅ Log4Shell
✅ Deserialization vulnerabilities
✅ WAF bypass techniques
✅ SSTI (Server-Side Template Injection)
✅ HPP (HTTP Parameter Pollution)
✅ Path traversal
✅ NoSQL injection
✅ GraphQL vulnerabilities

### أدوات أمن السحابة:
✅ فحص إعدادات AWS S3 buckets
✅ اختبار IAM policies
✅ فحص Azure storage
✅ اختبار GCP cloud functions
✅ كشف البيانات المكشوفة
✅ اختبار أذونات الخدمات

### أدوات ثغرات المنصات:
✅ Microsoft Exchange vulnerabilities
✅ Zoom security issues
✅ Platform-specific misconfigurations
✅ Default credentials detection
✅ Service enumeration

═══════════════════════════════════════════════════════════════

📤 تنسيق النتائج:

يتم حفظ جميع النتائج في ملفات JSON مع:
- وقت وتاريخ الفحص
- نوع الأداة المستخدمة
- قائمة الثغرات مع مستوى الخطورة
- تفاصيل كل ثغرة
- توصيات الإصلاح

### مواقع حفظ النتائج:
- `scan_results/` : للنظام التلقائي
- ملفات JSON منفصلة : لكل أداة على حدة
- `temper-data_[النطاق]_[التاريخ].json` : لأداة Temper-Data

### مستويات الخطورة:
- **Critical** : خطر عالٍ جداً - يتطلب إصلاح فوري
- **High** : خطر عالٍ - يجب الإصلاح قريباً
- **Medium** : خطر متوسط - يوصى بالإصلاح
- **Low** : خطر منخفض - يمكن تأجيل الإصلاح
- **Info** : معلومات فقط - لا توجد ثغرات

═══════════════════════════════════════════════════════════════

💡 أمثلة عملية متقدمة:

### مثال 1: فحص شامل لموقع إلكتروني
```bash
# خطوة 1: فحص CMS
python temper-data.py -u https://company-website.com -o cms-scan.json

# خطوة 2: فحص ثغرات صفرية
python zero-day-scanner.py -u https://company-website.com -o zero-day-scan.json

# خطوة 3: فحص شامل باستخدام النظام التلقائي
python run-all-scanners.py -u https://company-website.com --workers 5
```

### مثال 2: فحص خدمات السحابة
```bash
# فحص AWS
python aws-security-scanner.py -u https://aws-service.amazonaws.com

# فحص Azure
python azure-security-scanner.py -u https://azure-service.azurewebsites.net

# فحص GCP
python gcp-security-scanner.py -u https://gcp-service.appspot.com
```

### مثال 3: فحص موقع محلي
```bash
# فحص موقع محلي
python run-all-scanners.py -u http://localhost:8080

# فحص عنوان IP
python run-all-scanners.py -u 192.168.1.100
```

═══════════════════════════════════════════════════════════════

⚠️ تحذيرات أمنية مهمة:

1. **الاستخدام الأخلاقي فقط**: استخدم الأدوات فقط على المواقع التي تمتلك صلاحية اختبارها
2. **الإذن المسبق**: احصل على إذن كتابي قبل اختبار أي نظام
3. **الامتثال القانوني**: احترم قوانين بلدك المتعلقة بالاختبار الأمني
4. **عدم الإضرار**: لا تستخدم الأدوات لإلحاق الضرر بالأنظمة
5. **السرية**: لا تشارك نتائج الفحص مع أطراف غير مصرح بها
6. **الإبلاغ**: أبلغ عن الثغرات بطريقة مسؤولة (Responsible Disclosure)

═══════════════════════════════════════════════════════════════

🆘 حل المشاكل الشائعة:

### مشاكل التثبيت:
**مشكلة**: "python is not recognized"
**الحل**: تأكد من تثبيت Python وإضافته إلى PATH

**مشكلة**: "No module named..."
**الحل**: شغل: `pip install -r requirements.txt`

### مشاكل التشغيل:
**مشكلة**: "Permission denied"
**الحل**: شغل Command Prompt كمسؤول

**مشكلة**: اتصال بطيء
**الحل**: قلل عدد الخيوط باستخدام `-t 5`

**مشكلة**: "Connection timeout"
**الحل**: استخدم خيار `--timeout 30`

### مشاكل النتائج:
**مشكلة**: لا توجد نتائج
**الحل**: تأكد من صحة الرابط المدخل

**مشكلة**: ملفات JSON فارغة
**الحل**: تحقق من وجود اتصال إنترنت نشط

═══════════════════════════════════════════════════════════════

📞 الدعم الفني والمساعدة:

### قنوات الدعم:
- **GitHub**: https://github.com/SaudiLinux/security-tools-suite
- **إيميل**: SayerLinux@gmail.com
- **تويتر**: @SayerLinux
- **وثائق إضافية**: README-SECURITY-TOOLS.txt

### الموارد الإضافية:
- **ملفات README**: كل أداة تحتوي على README خاص بها
- **أمثلة الاستخدام**: example-usage.txt
- **دليل الاستخدام المتقدم**: USAGE-GUIDE.txt

═══════════════════════════════════════════════════════════════

🎓 نصائح للمبتدئين:

### خطوات البداية:
1. ابدأ باختبار موقعك الخاص أو موقع تجريبي
2. استخدم الأداة الأبسطة أولاً (temper-data.py)
3. تعلم من النتائج وافهم معناها
4. انتقل تدريجياً إلى الأدوات الأكثر تقدماً
5. استخدم النظام التلقائي بعد فهم كل أداة على حدة

### أفضل الممارسات:
- احتفظ بسجل لجميع عمليات الفحص
- استخدم أسماء ملفات واضحة للنتائج
- راجع النتائج يدوياً قبل اتخاذ إجراءات
- حدث الأدوات بانتظام
- شارك الخبرة مع مجتمع الأمن السيبراني

═══════════════════════════════════════════════════════════════

🔄 التحديثات والصيانة:

### التحقق من التحديثات:
```bash
git pull origin main
pip install -r requirements.txt --upgrade
```

### إضافة أدوات جديدة:
- تابع GitHub لمزيد من الأدوات الجديدة
- تحقق من ملفات README المحدثة
- اختبر الأدوات الجديدة في بيئة آمنة أولاً

═══════════════════════════════════════════════════════════════

📅 تم التحديث آخر مرة: 2024
🚀 الإصدار الحالي: 3.0
🌟 عدد الأدوات المتوفرة: 12 أداة أمنية متقدمة

═══════════════════════════════════════════════════════════════

**ملاحظة**: هذه الأدوات مصممة للاختبار الأمني الأخلاقي والتعليمي فقط. المسؤولية القانونية تقع على المستخدم في ضمان الاستخدام الصحيح والقانوني.

═══════════════════════════════════════════════════════════════