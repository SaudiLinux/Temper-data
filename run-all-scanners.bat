@echo off
chcp 65001 > nul
REM ملف تشغيل أدوات الأمن السيبراني المتقدمة
REM Advanced Cybersecurity Tools Suite Runner

color 0A
echo.
echo ╔══════════════════════════════════════════════════════════════╗
echo ║                  نظام الأمن السيبراني المتقدم              ║
echo ║              Advanced Cybersecurity Tools Suite              ║
echo ╚══════════════════════════════════════════════════════════════╝
echo.
echo مرحباً بك في نظام الأمن السيبراني المتقدم
echo تم إنشاء 11 أداة متخصصة لكشف الثغرات الأمنية
echo.
echo الأدوات المتاحة:
echo 1. ماسح الثغرات الصفرية (Zero-Day)
echo 2. ماسح تطبيقات الويب للثغرات الصفرية
echo 3. ماسح شبكات الثغرات الصفرية
echo 4. ماسح أمن السحابة
echo 5. ماسح أمن AWS
echo 6. ماسح أمن Azure
echo 7. ماسح أمن GCP
echo 8. ماسح ثغرات المنصات
echo 9. ماسح ثغرات Exchange
echo 10. ماسح ثغرات Zoom
echo 11. ماسح ثغرات Joomla وWordPress
echo.
echo.
echo ╔══════════════════════════════════════════════════════════════╗
echo ║                    خيارات الاستخدام                        ║
echo ╚══════════════════════════════════════════════════════════════╝
echo.
echo 1. عرض قائمة الأدوات المتاحة:
echo    python run-all-scanners.py --list
echo.
echo 2. تشغيل جميع الأدوات على هدف معين:
echo    python run-all-scanners.py -u https://example.com
echo.
echo 3. تشغيل أدوات محددة:
echo    python run-all-scanners.py -u https://example.com -t zero-day-scanner.py web-zero-day-scanner.py
echo.
echo 4. التحكم في عدد العمليات المتوازية:
echo    python run-all-scanners.py -u https://example.com -w 5
echo.
echo.
echo لتثبيت المتطلبات أولاً، استخدم:
echo pip install -r zero-day-requirements.txt
echo pip install -r cloud-requirements.txt
echo pip install -r platform-requirements.txt
echo.
echo.
set /p target=أدخل عنوان الموقع أو الIP للفحص: 
if "%target%"=="" (
    echo لم يتم إدخال عنوان، سيتم عرض قائمة الأدوات فقط...
    timeout /t 3 > nul
    python run-all-scanners.py --list
    pause
    goto end
)

echo.
echo هل تريد تشغيل جميع الأدوات أم أدوات محددة؟
echo 1. جميع الأدوات (الموصى بها)
echo 2. أدوات محددة
echo 3. إلغاء
set /p choice=اختر (1-3): 

if "%choice%"=="1" (
    echo.
    echo بدء تشغيل جميع الأدوات على %target%...
    echo الرجاء الانتظار...
    python run-all-scanners.py -u %target%
) else if "%choice%"=="2" (
    echo.
    python run-all-scanners.py --list
    echo.
    set /p selected=أدخل أسماء الأدوات (مثال: zero-day-scanner.py web-zero-day-scanner.py): 
    if not "%selected%"=="" (
        python run-all-scanners.py -u %target% -t %selected%
    )
) else (
    echo تم الإلغاء.
)

:end
echo.
echo تم الانتهاء!
echo.
echo للحصول على مساعدة إضافية، استخدم:
echo python run-all-scanners.py --help
pause