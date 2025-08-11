# 🛡️ Cloud Security Scanner Toolkit
# أدوات فحص أمن السحابات

## 📋 نظرة عامة
مجموعة متكاملة من أدوات فحص الأمن للسحابات AWS، Azure، و Google Cloud Platform لاكتشاف التهيئة الخاطئة والثغرات الأمنية.

## 🎯 المميزات
- ✅ فحص شامل للسحابات الثلاث الرئيسية
- ✅ اكتشاف التهيئة الخاطئة تلقائياً
- ✅ تقييم مستوى الخطورة
- ✅ تقارير مفصلة باللغتين العربية والإنجليزية
- ✅ سهولة الاستخدام مع أوامر CLI

## 📁 الأدوات المتوفرة

### 1. **Cloud Security Scanner** (`cloud-security-scanner.py`)
أداة عامة لفحص جميع السحابات دون الحاجة لاعتمادات خاصة.

**الاستخدام:**
```bash
python cloud-security-scanner.py -t example.com
```

### 2. **AWS Security Scanner** (`aws-security-scanner.py`)
أداة متخصصة لخدمات Amazon Web Services.

**المميزات:**
- ✅ فحص حاويات S3
- ✅ فحص سياسات IAM
- ✅ فحص قواعد البيانات RDS
- ✅ فحص مجموعات الأمان

**الاستخدام:**
```bash
# باستخدام الملف الشخصي الافتراضي
python aws-security-scanner.py

# باستخدام ملف تعريف محدد
python aws-security-scanner.py --profile my-profile
```

### 3. **Azure Security Scanner** (`azure-security-scanner.py`)
أداة متخصصة لخدمات Microsoft Azure.

**المميزات:**
- ✅ فحص حسابات التخزين
- ✅ فحص الآلات الافتراضية
- ✅ فحص قواعد بيانات SQL
- ✅ فحص خزائن المفاتيح
- ✅ فحص مجموعات أمان الشبكة

**الاستخدام:**
```bash
python azure-security-scanner.py --subscription YOUR-SUBSCRIPTION-ID
```

### 4. **GCP Security Scanner** (`gcp-security-scanner.py`)
أداة متخصصة لخدمات Google Cloud Platform.

**المميزات:**
- ✅ فحص حاويات Cloud Storage
- ✅ فحص Compute Engine
- ✅ فحص Cloud SQL
- ✅ فحص سياسات IAM
- ✅ فحص جدار الحماية

**الاستخدام:**
```bash
python gcp-security-scanner.py --project YOUR-PROJECT-ID
```

## 🔧 المتطلبات

### المتطلبات الأساسية:
```bash
pip install -r cloud-requirements.txt
```

### ملف المتطلبات (`cloud-requirements.txt`):
```
boto3
azure-identity
azure-mgmt-storage
azure-mgmt-compute
azure-mgmt-sql
azure-mgmt-network
azure-mgmt-keyvault
google-cloud-storage
google-cloud-compute
google-cloud-sql
google-cloud-iam
google-cloud-secret-manager
google-cloud-dns
dnslib
requests
```

## 🚀 التثبيت والإعداد

### 1. تثبيت الحزم المطلوبة:
```bash
pip install -r cloud-requirements.txt
```

### 2. تكوين الاعتمادات:

#### AWS:
```bash
aws configure
# أو
export AWS_ACCESS_KEY_ID=your-key
export AWS_SECRET_ACCESS_KEY=your-secret
```

#### Azure:
```bash
az login
```

#### GCP:
```bash
gcloud auth login
gcloud config set project YOUR-PROJECT-ID
```

## 📊 أنواع الفحص

### فحص حاويات التخزين:
- **AWS S3**: التهيئة الخاطئة، الوصول العام، التشفير
- **Azure Blob Storage**: التهيئة، الوصول، التشفير
- **Google Cloud Storage**: التهيئة، الوصول، التشفير

### فحص قواعد البيانات:
- **RDS**: الوصول العام، التشفير، النسخ الاحتياطي
- **Azure SQL**: جدار الحماية، التشفير، النسخ الاحتياطي
- **Cloud SQL**: الوصول، التشفير، النسخ الاحتياطي

### فحص الشبكات:
- مجموعات الأمان
- قواعد جدار الحماية
- المنافذ المفتوحة

### فحص IAM:
- سياسات مفرطة
- أذونات عامة
- مفاتيح API القديمة

## 🎯 مستويات الخطورة

| المستوى | الوصف | اللون |
|---------|--------|--------|
| CRITICAL | خطر حرج يتطلب إصلاح فوري | 🔴 |
| HIGH | خطر عالي يجب إصلاحه قريباً | 🟠 |
| MEDIUM | خطر متوسط يجب مراجعته | 🟡 |
| LOW | خطر منخفض للمراجعة | 🟢 |

## 📋 أمثلة الاستخدام

### مثال 1: فحص عام للسحابات
```bash
# فحص عام لنطاق معين
python cloud-security-scanner.py -t company.com

# مع حفظ النتائج
python cloud-security-scanner.py -t company.com -o results.json
```

### مثال 2: فحص AWS متقدم
```bash
# فحص AWS مع ملف تعريف محدد
python aws-security-scanner.py --profile production

# فحص AWS مع منطقة محددة
AWS_DEFAULT_REGION=us-west-2 python aws-security-scanner.py
```

### مثال 3: فحص Azure شامل
```bash
# فحص Azure لاشتراك محدد
python azure-security-scanner.py --subscription 12345678-1234-1234-1234-123456789012
```

### مثال 4: فحص GCP متعدد
```bash
# فحص GCP لمشروع محدد
python gcp-security-scanner.py --project my-gcp-project
```

## 🔍 نتائج الفحص

### تنسيق النتائج:
```json
[
  {
    "service": "S3",
    "resource": "my-bucket",
    "issue": "Public Access",
    "risk_level": "HIGH",
    "description": "حاوية S3 متاحة للوصول العام"
  }
]
```

### ملفات النتائج:
- `cloud_security_scan_TIMESTAMP.json`
- `aws_security_scan_TIMESTAMP.json`
- `azure_security_scan_TIMESTAMP.json`
- `gcp_security_scan_TIMESTAMP.json`

## ⚠️ ملاحظات أمنية

### قبل الاستخدام:
1. تأكد من امتلاكك الأذونات المناسبة
2. لا تشغل الأداة على أنظمة غير مصرح بها
3. احفظ الاعتمادات بأمان
4. راجع تقارير الأمان بانتظام

### بعد الاستخدام:
1. راجع جميع التحذيرات
2. أصلح المشاكل المكتشفة
3. قم بإعادة الفحص بعد الإصلاح
4. حدث الأدوات بانتظام

## 🆘 استكشاف الأخطاء

### مشاكل شائعة:

#### AWS:
```bash
# خطأ في الاعتمادات
export AWS_PROFILE=default
aws sts get-caller-identity
```

#### Azure:
```bash
# خطأ في تسجيل الدخول
az account show
az login --tenant TENANT-ID
```

#### GCP:
```bash
# خطأ في المشروع
gcloud config list
gcloud auth application-default login
```

## 📞 الدعم

للحصول على المساعدة:
1. تحقق من ملفات السجلات
2. راجع وثائق AWS/Azure/GCP
3. تأكد من تحديث الأدوات
4. تحقق من صلاحيات IAM

## 🔄 التحديثات

لتحديث الأدوات:
```bash
git pull origin main
pip install -r cloud-requirements.txt --upgrade
```

---

## 🏁 البدء السريع

1. **تثبيت الحزم:**
   ```bash
   pip install -r cloud-requirements.txt
   ```

2. **تكوين الاعتمادات:**
   ```bash
   # AWS
   aws configure
   
   # Azure
   az login
   
   # GCP
   gcloud auth login
   ```

3. **تشغيل الفحص:**
   ```bash
   # فحص عام
   python cloud-security-scanner.py -t your-domain.com
   
   # فحص AWS
   python aws-security-scanner.py
   
   # فحص Azure
   python azure-security-scanner.py --subscription YOUR-ID
   
   # فحص GCP
   python gcp-security-scanner.py --project YOUR-PROJECT
   ```

4. **مراجعة النتائج:**
   ```bash
   cat *security_scan*.json
   ```

---

**ملاحظة:** هذه الأدوات مصممة لأغراض الأمن والامتثال. استخدمها فقط على الأنظمة التي تمتلك الصلاحية للوصول إليها.