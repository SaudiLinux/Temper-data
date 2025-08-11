@echo off
color 0A
echo.
echo ================================================
echo    Temper-Data Installation Script
echo    Developer: SayerLinux
echo    GitHub: https://github.com/SaudiLinux
echo ================================================
echo.

echo [+] Installing required packages...
pip install -r requirements.txt

echo.
echo [+] Installation completed!
echo.
echo Usage:
echo   python temper-data.py -u https://example.com
echo   python temper-data.py -u https://example.com -o results.json
echo.
pause