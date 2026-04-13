from modules import mail_reader
from modules import vt_scanner
from modules import telegram_alert
from modules import typosquatting_scanner  
from modules import email_auth_checker
import time

TYPOSQUATTING_THRESHOLD = 85   

def run_soar_pipeline():
    print("\n" + "="*50)
    print("KHỞI ĐỘNG HỆ THỐNG SOC AUTOMATION (MINI-SOAR)")
    print("="*50)

    incidents = mail_reader.get_unread_emails_and_extract_iocs()
    if not incidents:
        print("[-] Không có yêu cầu phân tích mới.")
        return

    for incident in incidents:
        sender_email = incident['sender']
        msg_object   = incident.get('msg_object')
        print(f"\nĐANG PHÂN TÍCH SỰ CỐ TỪ: {sender_email}")
        print("-" * 50)

        is_safe = True
        total_vt_threats = 0
        total_typo_threats = 0
        total_auth_threats = 0

        #GIAI ĐOẠN 0: SPF / DKIM / DMARC 
        print("\n[Giai đoạn 0] Kiểm tra Email Authentication...")
        auth_result = email_auth_checker.check_email_authentication(
            sender_email, msg=msg_object
        )
        if auth_result["combined_risk"] in ("LOW", "MEDIUM", "HIGH"):
            is_safe = False
            total_auth_threats += 1
            telegram_alert.send_auth_alert(sender_email, auth_result)

        #GIAI ĐOẠN 1: Quét URLs 
        print("\n[Giai đoạn 1] Quét URLs...")
        for url in incident.get('urls', []):

            #1a. Typosquatting check
            typo_result = typosquatting_scanner.scan_typosquatting(
                url, similarity_threshold=TYPOSQUATTING_THRESHOLD
            )

            #1b. VirusTotal check
            vt_score = vt_scanner.scan_ioc("url", url)
            time.sleep(15)

            #1c. Gửi alert nếu có bất kỳ mối đe dọa nào
            has_typo = typo_result.get("risk_level") in ("LOW", "MEDIUM", "HIGH")
            has_vt   = vt_score > 0

            if has_typo or has_vt:
                is_safe = False
                if has_typo:
                    total_typo_threats += 1
                if has_vt:
                    total_vt_threats += 1

                #Gửi combined alert (gộp cả 2 thông tin vào 1 tin)
                telegram_alert.send_combined_alert(
                    email      = sender_email,
                    url        = url,
                    vt_score   = vt_score,
                    typo_result= typo_result if has_typo else None
                )

        #GIAI ĐOẠN 2: Quét IPs 
        print("\n[Giai đoạn 2] Quét IPs...")
        for ip in incident.get('ips', []):
            score = vt_scanner.scan_ioc("ip", ip)
            if score > 0:
                is_safe = False
                total_vt_threats += 1
                telegram_alert.send_phishing_alert(sender_email, "ip", ip, score)
            time.sleep(15)

        #GIAI ĐOẠN 3: Quét File Hashes
        print("\n[Giai đoạn 3] Quét File Hashes...")
        for file_info in incident.get('file_hashes', []):
            score = vt_scanner.scan_ioc("hash", file_info['hash'])
            if score > 0:
                is_safe = False
                total_vt_threats += 1
                telegram_alert.send_phishing_alert(
                    sender_email, "file hash", file_info['hash'], score
                )
            time.sleep(15)
        print("\n" + "="*50)
        if is_safe:
            print("KẾT LUẬN: EMAIL AN TOÀN")
        else:
            total = total_vt_threats + total_typo_threats + total_auth_threats
            print(f"KẾT LUẬN:PHÁT HIỆN {total} MỐI ĐE DỌA")
            print(f"  ├─ Auth (SPF/DKIM/DMARC): {total_auth_threats}")
            print(f"  ├─ Typosquatting:          {total_typo_threats}")
            print(f"  └─ VirusTotal:             {total_vt_threats}")
            print(f"  → Đã gửi cảnh báo Telegram!")


if __name__ == "__main__":
    try:
        while True:
            run_soar_pipeline()
            print("\n[*] Đợi 4 giây trước chu kỳ tiếp theo...")
            time.sleep(4)
    except KeyboardInterrupt:
        print("\n")