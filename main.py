from modules import mail_reader
from modules import vt_scanner
from modules import telegram_alert
from modules import dnstwist_scanner
from modules import email_auth_checker    # THÊM
import time

MALICIOUS_THRESHOLD    = 3
TYPOSQUATTING_THRESHOLD = 5

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
        msg_object   = incident.get('msg_object')   # lấy msg để đọc header
        print(f"\nĐANG PHÂN TÍCH SỰ CỐ TỪ: {sender_email}")
        print("-" * 50)
        is_safe          = True
        total_vt_threats = 0
        total_typo_threats = 0

        # ══ GIAI ĐOẠN 0: Kiểm tra SPF / DKIM / DMARC ══════════
        auth_result = email_auth_checker.check_email_authentication(
            sender_email, msg=msg_object
        )
        if auth_result["combined_risk"] in ("LOW", "MEDIUM", "HIGH"):
            is_safe = False
            telegram_alert.send_auth_alert(sender_email, auth_result)

        # ══ GIAI ĐOẠN 1: Quét URLs ══════════════════════════════
        for url in incident.get('urls', []):
            # 1a. dnstwist
            typo_result = dnstwist_scanner.scan_typosquatting(url, threshold=TYPOSQUATTING_THRESHOLD)
            if typo_result.get("risk_level") in ("LOW", "MEDIUM", "HIGH"):
                is_safe = False
                total_typo_threats += 1

            # 1b. VirusTotal
            vt_score = vt_scanner.scan_ioc("url", url)
            if vt_score > 0:
                is_safe = False
                total_vt_threats += 1

            # 1c. Gửi 1 combined alert cho cả 2 kết quả
            if typo_result.get("risk_level") in ("LOW", "MEDIUM", "HIGH") or vt_score > 0:
                telegram_alert.send_combined_alert(
                    email=sender_email,
                    url=url,
                    vt_score=vt_score,
                    typo_result=typo_result if typo_result.get("risk_level") in ("LOW","MEDIUM","HIGH") else None
                )

            time.sleep(15)

        # ══ GIAI ĐOẠN 2: Quét IPs ══════════════════════════════
        for ip in incident.get('ips', []):
            score = vt_scanner.scan_ioc("ip", ip)
            if score > 0:
                is_safe = False
                total_vt_threats += 1
                telegram_alert.send_phishing_alert(sender_email, "ip", ip, score)
            time.sleep(15)

        # ══ GIAI ĐOẠN 3: Quét File Hashes ══════════════════════
        for file_info in incident.get('file_hashes', []):
            score = vt_scanner.scan_ioc("hash", file_info['hash'])
            if score > 0:
                is_safe = False
                total_vt_threats += 1
                telegram_alert.send_phishing_alert(sender_email, "file hash", file_info['hash'], score)
            time.sleep(15)

        # ══ KẾT LUẬN ════════════════════════════════════════════
        print("\n" + "-"*30)
        if is_safe:
            print("KẾT LUẬN: EMAIL AN TOÀN.")
        else:
            total = total_vt_threats + total_typo_threats
            print(f"KẾT LUẬN: PHÁT HIỆN {total} MỐI ĐE DỌA "
                  f"(VT={total_vt_threats} | Typo={total_typo_threats}) — Đã gửi Telegram!")

if __name__ == "__main__":
    while True:
        run_soar_pipeline()
        print("\n[*] Đợi 4 giây trước chu kỳ tiếp theo...")
        time.sleep(4)