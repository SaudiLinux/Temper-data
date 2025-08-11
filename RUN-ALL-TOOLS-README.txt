# دليل تشغيل جميع أدوات الأمن السيبراني بالتوالي
# Advanced Cybersecurity Tools Suite - Sequential Runner Guide

## 🎯 نظرة عامة
هذا الدليل يشرح كيفية استخدام النظام التلقائي لتشغيل جميع أدوات الأمن السيبراني المتقدمة بالتوالي على أي هدف.

## 📁 الأدوات المتاحة
تم إنشاء 11 أداة متخصصة:

### أدوات الثغرات الصفرية:
- `zero-day-scanner.py` - ماسح الثغرات الصفرية العام
- `web-zero-day-scanner.py` - ماسح ثغرات تطبيقات الويب
- `network-zero-day-scanner.py` - ماسح ثغرات الشبكات

### أدوات السحابة:
- `cloud-security-scanner.py` - ماسح أمن السحابة العام
- `aws-security-scanner.py` - ماسح أمن AWS
- `azure-security-scanner.py` - ماسح أمن Azure
- `gcp-security-scanner.py` - ماسح أمن GCP

### أدوات المنصات:
- `platform-vulnerability-scanner.py` - ماسح ثغرات المنصات
- `exchange-vulnerability-scanner.py` - ماسح ثغرات Exchange
- `zoom-vulnerability-scanner.py` - ماسح ثغرات Zoom
- `temper-data.py` - ماسح ثغرات Joomla وWordPress

## 🚀 التثبيت السريع

### المتطلبات الأساسية:
```bash
# تثبيت متطلبات الثغرات الصفرية
pip install -r zero-day-requirements.txt

# تثبيت متطلبات السحابة
pip install -r cloud-requirements.txt

# تثبيت متطلبات المنصات
pip install -r platform-requirements.txt
```

## 🔧 طرق التشغيل

### الطريقة 1: استخدام ملف التشغيل التلقائي (الأبسط)
```bash
# على Windows (انقر مرتين على الملف)
run-all-scanners.bat

# أو من سطر الأوامر
python run-all-scanners.py -u https://example.com
```

### الطريقة 2: تشغيل جميع الأدوات مرة واحدة
```bash
# تشغيل جميع الأدوات المتاحة
python run-all-scanners.py -u https://example.com

# مع عدد عمليات متوازية محدد
python run-all-scanners.py -u https://example.com -w 5
```

### الطريقة 3: تشغيل أدوات محددة
```bash
# تشغيل أدوات محددة فقط
python run-all-scanners.py -u https://example.com -t zero-day-scanner.py web-zero-day-scanner.py

# تشغيل أدوات السحابة فقط
python run-all-scanners.py -u https://example.com -t cloud-security-scanner.py aws-security-scanner.py
```

### الطريقة 4: عرض قائمة الأدوات المتاحة
```bash
python run-all-scanners.py --list
```

## 📊 فهم النتائج

### مكان حفظ النتائج:
- **المجلد:** `scan_results/`
- **التنسيق:** JSON مع تقارير ملخصة
- **التسمية:** تحتوي على اسم الأداة والهدف والتاريخ

### مثال على ملف النتائج:
```json
{
  "target": "https://example.com",
  "scan_date": "2024-01-15T10:30:00",
  "total_tools": 11,
  "successful_tools": 10,
  "failed_tools": 1,
  "tools_results": {
    "zero-day-scanner.py": {
      "status": "success",
      "vulnerabilities_found": 8,
      "risk_level": "CRITICAL"
    }
  }
}
```

## 🎯 أمثلة عملية

### مثال 1: فحص موقع ويب
```bash
# فحص شامل لموقع ويب
python run-all-scanners.py -u https://httpbin.org

# النتيجة: سيتم تشغيل جميع الأدوات الملائمة
```

### مثال 2: فحص خادم محلي
```bash
# فحص خادم محلي
python run-all-scanners.py -u http://192.168.1.100

# مع عدد عمليات أكثر للسرعة
python run-all-scanners.py -u http://192.168.1.100 -w 8
```

### مثال 3: فحص سحابة AWS
```bash
# فحص أمن AWS فقط
python run-all-scanners.py -u https://aws.amazon.com -t aws-security-scanner.py
```

## ⚡ نصائح الأداء

### لتحسين الأداء:
- استخدم `-w 5` أو أكثر للأهداف الكبيرة
- استخدم `-w 1` للأهداف الحساسة
- تأكد من اتصال إنترنت مستقر
- استخدم أدوات محددة للفحص السريع

### للفحص الدقيق:
- استخدم `-w 1` لتجنب الحظر
- فصل الأدوات إلى مجموعات صغيرة
- مراجعة النتائج بعد كل تشغيل

## 🔍 استكشاف الأخطاء

### المشاكل الشائعة:

1. **خطأ في تثبيت المكتبات:**
   ```bash
   pip install --upgrade pip
   pip install -r requirements.txt --force-reinstall
   ```

2. **خطأ في الاتصال:**
   - تأكد من اتصال الإنترنت
   - تحقق من جدار الحماية
   - استخدم VPN إذا لزم الأمر

3. **خطأ في الأذونات:**
   - على Windows: شغل كمسؤول
   - على Linux: استخدم `sudo` إذا لزم الأمر

## 📋 قائمة الأوامر السريعة

| الأمر | الوصف |
|-------|---------|
| `python run-all-scanners.py --list` | عرض جميع الأدوات |
| `python run-all-scanners.py -u URL` | تشغيل الكل |
| `python run-all-scanners.py -u URL -t TOOL1 TOOL2` | أدوات محددة |
| `python run-all-scanners.py -u URL -w 10` | 10 عمليات متوازية |
| `run-all-scanners.bat` | واجهة تفاعلية |

## 🛡️ تحذيرات أمنية

### قبل الاستخدام:
- ✅ تأكد من امتلاكك الصلاحية للفحص
- ✅ استخدم فقط على الأهداف التي تمتلك إذنًا لفحصها
- ✅ احترم قوانين الأمن السيبراني المحلية
- ✅ لا تستخدم للأنشطة الضارة

### بعد الفحص:
- 📊 مراجعة النتائج بعناية
- 🔧 تطبيق التصحيحات الموصى بها
- 📋 توثيق النتائج للرجوع إليها
- 🔄 إعادة الفحص بعد التصحيح

## 📞 الدعم

### للمساعدة:
1. تحقق من ملفات `README` لكل أداة
2. استخدم `--help` مع أي أداة
3. تحقق من ملفات السجلات للحصول على تفاصيل الأخطاء

### ملفات المساعدة:
- `README-SECURITY-TOOLS.txt` - دليل عام
- `USAGE-GUIDE.txt` - أمثلة مفصلة
- `ZERO-DAY-SCANNER-README.md` - ماسحات الثغرات الصفرية
- `CLOUD-SECURITY-README.md` - أمن السحابة
- `PLATFORM-VULNERABILITY-README.md` - ثغرات المنصات

---

**ملاحظة:** هذا النظام مصمم للاستخدام الأخلاقي فقط. استخدمه فقط على الأنظمة التي تمتلك صلاحية الفحص لها.