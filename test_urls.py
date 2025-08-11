#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
اختبار الروابط المستخرجة من أداة Temper-Data
"""

import requests
import json
from urllib.parse import urljoin

def test_hidden_urls():
    """اختبار الروابط المخفية المستخرجة"""
    
    # قائمة بالروابط المخفية الشائعة للاختبار
    base_urls = [
        'http://httpbin.org',
        'https://jsonplaceholder.typicode.com',
        'https://httpbin.org'
    ]
    
    # الروابط المخفية الشائعة
    hidden_paths = [
        'robots.txt',
        'sitemap.xml',
        '.htaccess',
        'admin',
        'login',
        'wp-admin',
        'wp-login.php',
        'administrator',
        'config.php',
        'phpmyadmin',
        'api',
        'test',
        'backup',
        'old',
        'dev',
        'staging'
    ]
    
    results = []
    
    for base_url in base_urls:
        print(f"\n🔍 فحص الروابط المخفية لـ: {base_url}")
        print("=" * 50)
        
        working_urls = []
        
        for path in hidden_paths:
            url = urljoin(base_url, path)
            try:
                response = requests.get(url, timeout=5, headers={'User-Agent': 'Temper-Data-Scanner/2.0'})
                
                result = {
                    'url': url,
                    'status': response.status_code,
                    'size': len(response.content),
                    'content_type': response.headers.get('content-type', 'unknown'),
                    'working': response.status_code == 200
                }
                
                if response.status_code == 200:
                    print(f"✅ {url} - Status: {response.status_code} - Size: {len(response.content)} bytes")
                    working_urls.append(result)
                elif response.status_code in [301, 302, 403, 404]:
                    print(f"⚠️  {url} - Status: {response.status_code}")
                else:
                    print(f"❌ {url} - Status: {response.status_code}")
                    
                results.append(result)
                
            except requests.exceptions.RequestException as e:
                print(f"❌ {url} - Error: {str(e)}")
                results.append({
                    'url': url,
                    'status': 'Error',
                    'error': str(e),
                    'working': False
                })
    
    # عرض النتائج النهائية
    working_urls = [r for r in results if r.get('working', False)]
    
    print(f"\n📊 ملخص النتائج:")
    print("=" * 50)
    print(f"إجمالي الروابط المفحوصة: {len(results)}")
    print(f"الروابط التي تعمل: {len(working_urls)}")
    
    if working_urls:
        print("\n🔗 الروابط المخفية التي تعمل:")
        for url_info in working_urls:
            print(f"✅ {url_info['url']} - {url_info['size']} bytes - {url_info['content_type']}")
    
    # حفظ النتائج في ملف JSON
    with open('tested_hidden_urls.json', 'w', encoding='utf-8') as f:
        json.dump(working_urls, f, indent=2, ensure_ascii=False)
    
    print(f"\n💾 تم حفظ النتائج في: tested_hidden_urls.json")
    
    return working_urls

if __name__ == "__main__":
    test_hidden_urls()