# Tên file: main.py
import mail_reader
import vt_scanner
import telegram_alert
import time

def run_soar_pipeline():
    print("\n" + "="*50)
    print("🚀 KHỞI ĐỘNG HỆ THỐNG SOC AUTOMATION (MINI-SOAR)")
    print("="*50)
    
    # GIAI ĐOẠN 1: Đọc email và bóc tách IOCs
    incidents = mail_reader.get_unread_emails_and_extract_iocs()
    
    if not incidents:
        print("[-] Không có yêu cầu phân tích mới.")
        return

    # GIAI ĐOẠN 2: Phân tích từng email
    for incident in incidents:
        sender_email = incident['sender']
        print(f"\n🚨 ĐANG PHÂN TÍCH SỰ CỐ TỪ: {sender_email}")
        print("-" * 50)
        
        is_safe = True # Cờ đánh dấu an toàn
        total_threats = 0
        
        # 1. Quét URLs
        for url in incident.get('urls', []):
            score = vt_scanner.scan_ioc("url", url)
            
            # MẸO DEMO: Nếu muốn test link an toàn (0 điểm) Bot cũng báo, hãy đổi "> 0" thành ">= 0"
            if score > 0: 
                is_safe = False
                total_threats += 1
                telegram_alert.send_phishing_alert(sender_email, "url", url, score)
            
            time.sleep(15) # Nghỉ làm mát API

        # 2. Quét IPs
        for ip in incident.get('ips', []):
            score = vt_scanner.scan_ioc("ip", ip)
            if score > 0:
                is_safe = False
                total_threats += 1
                telegram_alert.send_phishing_alert(sender_email, "ip", ip, score)
            time.sleep(15)

        # 3. Quét File Hashes
        for file_info in incident.get('file_hashes', []):
            file_hash = file_info['hash']
            score = vt_scanner.scan_ioc("hash", file_hash)
            if score > 0:
                is_safe = False
                total_threats += 1
                telegram_alert.send_phishing_alert(sender_email, "file hash", file_hash, score)
            time.sleep(15)

        # GIAI ĐOẠN 3: KẾT LUẬN CHUNG
        print("\n" + "-"*30)
        if is_safe:
            print(f"✅ KẾT LUẬN: EMAIL AN TOÀN. Các đường link/file đều sạch (Score: 0).")
        else:
            print(f"🔥 KẾT LUẬN: ĐÃ PHÁT HIỆN {total_threats} MỐI ĐE DỌA. Đã bắn thông báo Telegram!")

if __name__ == "__main__":
    while True:
        run_soar_pipeline()
        print("\n[*] Đợi 4 giây trước chu kỳ tiếp theo...")
        time.sleep(4)