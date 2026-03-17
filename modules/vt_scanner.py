# Tên file: vt_scanner.py
import requests
import base64
import json
import time

# API key for VirusTotal
VT_API_KEY = "da4c55b552c0c3e834f2d6307c6ebb37f63e3eb3b85f176437e39b0255d484c2"

# header send request
HEADERS = {
    "accept": "application/json",
    "x-apikey": VT_API_KEY
}

def scan_ioc(ioc_type, ioc_value):
    """Hàm đa năng: Quét URL, IP hoặc File Hash"""
    print(f"   [*] VirusTotal đang phân tích {ioc_type.upper()}: {ioc_value}")
    
    # Định tuyến URL cho API v3 tùy theo loại dữ liệu
    if ioc_type == "url":
        url_bytes = ioc_value.encode('utf-8')
        url_id = base64.urlsafe_b64encode(url_bytes).decode('utf-8').strip('=')
        api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    elif ioc_type == "ip":
        api_url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc_value}"
    elif ioc_type == "hash":
        api_url = f"https://www.virustotal.com/api/v3/files/{ioc_value}"
    else:
        return 0

    try:
        response = requests.get(api_url, headers=HEADERS)
        
        if response.status_code == 200:
            data = response.json()
            # Bóc tách số lượng vote độc hại giống y như ý tưởng ban đầu của bạn
            stats = data["data"]["attributes"]["last_analysis_stats"]
            malicious_votes = stats['malicious']
            
            print(f"       -> Kết quả: {malicious_votes} trình duyệt báo ĐỘC HẠI.")
            return malicious_votes
            
        elif response.status_code == 404:
            print("       -> Kết quả: Chưa từng bị report (An toàn).")
            return 0
        elif response.status_code == 429:
            print("       [!] API đang quá tải (Rate limit). Đợi 15 giây rồi thử lại...")
            time.sleep(15)
            # Gọi lại chính nó sau khi đợi xong
            return scan_ioc(ioc_type, ioc_value) 
        else:
            print(f"       [ERROR] Mã lỗi API: {response.status_code}")
            return 0
            
    except Exception as e:
        print(f"       [ERROR] Lỗi hệ thống: {e}")
        return 0
    
# test độc lập
if __name__ == "__main__":
    test_url = "http://testsafebrowsing.appspot.com/s/phishing.html"
    print("=== CHẠY TEST MODULE QUÉT VIRUSTOTAL ===")
    score = scan_ioc("url", test_url)
    print(f"\n[✓] Tổng điểm độc hại trả về: {score}")
