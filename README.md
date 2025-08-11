# Temper-Data v2.0

أداة متقدمة للكشف عن الثغرات الأمنية في منصات Joomla و WordPress

## معلومات المطور
- **المبرمج**: SayerLinux
- **الموقع**: https://github.com/SaudiLinux
- **الإيميل**: SayerLinux@gmail.com
- **الإصدار**: 2.0

## ✨ المميزات

### 🔍 الكشف المتقدم
- **كشف نوع CMS**: تمييز تلقائي بين Joomla و WordPress
- **فحص الثغرات**: فحص شامل للثغرات المعروفة
- **اكتشاف الروابط المخفية**: البحث عن المسارات والملفات المخفية
- **كشف لوحة التحكم**: العثور على صفحات الإدارة

### 🛡️ تخطي جدار الحماية (WAF)
- تقنيات متعددة لتخطي جدران الحماية
- تغيير User-Agent بشكل عشوائي
- تقنيات IP Spoofing
- محاكاة أجهزة محمولة

### 🚀 الأداء
- دعم التعددية (Multi-threading)
- فحص سريع وفعال
- واجهة ملونة وسهلة الاستخدام

## 🛠️ التثبيت

### المتطلبات
```bash
pip install -r requirements.txt
```

### التشغيل
```bash
# تثبيت الحزم المطلوبة
pip install requests colorama urllib3

# تشغيل الأداة
python temper-data.py -u https://example.com

# مع حفظ النتائج
python temper-data.py -u https://example.com -o results.json

# عدد الخيوط المخصص
python temper-data.py -u https://example.com -t 20
```

## 📋 استخدام الأداة

### الأوامر الأساسية
```bash
python temper-data.py -u [URL الهدف]
```

### الخيارات المتاحة
- `-u, --url`: رابط الموقع المستهدف (إجباري)
- `-o, --output`: اسم ملف النتائج (JSON)
- `-t, --threads`: عدد الخيوط (افتراضي: 10)
- `--no-auto-save`: تعطيل الحفظ التلقائي للنتائج

### أمثلة الاستخدام
```bash
# فحص موقع WordPress
python temper-data.py -u https://wordpress-site.com

# فحص موقع Joomla
python temper-data.py -u https://joomla-site.com

# فحص مع حفظ النتائج
python temper-data.py -u https://target.com -o scan-results.json
```

## 🔍 أنواع الفحص

### 1. فحص CMS
- كشف نوع نظام إدارة المحتوى
- تحديد الإصدار (في الإصدارات المستقبلية)

### 2. فحص الثغرات
- **WordPress**: 
  - wp-json API exposure
  - XML-RPC vulnerabilities
  - Plugin vulnerabilities
  - Theme vulnerabilities

- **Joomla**:
  - Registration bypass
  - Configuration exposure
  - Component vulnerabilities

### 3. اكتشاف المسارات المخفية
- ملفات النسخ الاحتياطية
- الملفات المؤقتة
- لوحات التحكم البديلة
- ملفات الإعدادات

### 4. كشف لوحة الإدارة
- مسارات الإدارة المعروفة
- صفحات تسجيل الدخول
- لوحات التحكم المخصصة

## 🎯 تقنيات تخطي WAF

### التقنيات المستخدمة
1. **تغيير User-Agent**: محاكاة متصفحات مختلفة
2. **IP Spoofing**: تزوير عنوان IP
3. **Mobile Simulation**: محاكاة أجهزة محمولة
4. **Header Manipulation**: تلاعب برؤوس HTTP

### الحمولات المختبرة
- XSS Payloads
- SQL Injection
- Path Traversal
- JNDI Injection
- SVG Payloads

## 📊 تنسيق النتائج

### ملف JSON
يتم حفظ النتائج في ملف JSON يحتوي على:
```json
{
  "target": "https://example.com",
  "cms_type": "WordPress",
  "scan_timestamp": "2024-01-01 12:00:00",
  "vulnerabilities": [...],
  "hidden_urls": [...],
  "admin_panels": [...],
  "waf_bypass_attempts": [...]
}
```

### عرض النتائج
- الألوان لتمييز مستويات الخطورة
- إحصائيات مباشرة أثناء الفحص
- تفاصيل كل ثغرة تم اكتشافها

## ⚠️ إخلاء المسؤولية

هذه الأداة مخصصة للاستخدام القانوني فقط. يجب استخدامها على المواقع التي تمتلك صلاحية اختبارها. المطور غير مسؤول عن أي استخدام غير قانوني.

## 🐛 الإبلاغ عن المشاكل

إذا واجهت أي مشاكل، الرجاء فتح issue في:
https://github.com/SaudiLinux/temper-data/issues

## 🔄 التحديثات

تابع المشروع للحصول على التحديثات الجديدة:
- GitHub: https://github.com/SaudiLinux/temper-data
- تويتر: @SayerLinux

## 📄 الرخصة

هذا المشروع مفتوح المصدر ومتاح للاستخدام والتعديل.

---

**ملاحظة**: هذه الأداة تم تطويرها من قبل SayerLinux كجزء من مشروعات SaudiLinux المفتوحة المصدر.