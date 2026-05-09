from modules import mail_reader
from modules import vt_scanner
from modules import telegram_alert
from modules import typosquatting_scanner
from modules import email_authentication_checker as email_auth_checker
from modules import ai_analyzer
import time

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
        email_id     = incident.get('email_id')      # ← để xử lý thùng rác
        print(f"\nĐANG PHÂN TÍCH SỰ CỐ TỪ: {sender_email}")
        print("-" * 50)

        is_safe            = True
        total_vt_threats   = 0
        total_typo_threats = 0
        total_auth_threats = 0
        total_ai_threats   = 0

        # ══ GIAI ĐOẠN 0: SPF / DKIM / DMARC ════════════════════
        print("\n[Giai đoạn 0] Kiểm tra Email Authentication...")
        auth_result = email_auth_checker.check_email_authentication(
            sender_email, msg=msg_object
        )
        if auth_result["combined_risk"] in ("LOW", "MEDIUM", "HIGH"):
            is_safe = False
            total_auth_threats += 1
            telegram_alert.send_auth_alert(sender_email, auth_result)

        # ══ GIAI ĐOẠN 1: Quét URLs ══════════════════════════════
        print("\n[Giai đoạn 1] Quét URLs...")
        for url in incident.get('urls', []):

            # 1a. Typosquatting — ensemble model, không cần threshold
            typo_result = typosquatting_scanner.scan_typosquatting(url)

            # 1b. VirusTotal
            vt_score = vt_scanner.scan_ioc("url", url)
            time.sleep(15)

            has_typo = typo_result.get("risk_level") in ("LOW", "MEDIUM", "HIGH")
            has_vt   = vt_score > 0

            if has_typo or has_vt:
                is_safe = False
                if has_typo:
                    total_typo_threats += 1
                if has_vt:
                    total_vt_threats += 1
                telegram_alert.send_combined_alert(
                    email       = sender_email,
                    url         = url,
                    vt_score    = vt_score,
                    typo_result = typo_result if has_typo else None
                )

        # ══ GIAI ĐOẠN 2: Quét IPs ═══════════════════════════════
        print("\n[Giai đoạn 2] Quét IPs...")
        for ip in incident.get('ips', []):
            score = vt_scanner.scan_ioc("ip", ip)
            if score > 0:
                is_safe = False
                total_vt_threats += 1
                telegram_alert.send_phishing_alert(sender_email, "ip", ip, score)
            time.sleep(15)

        # ══ GIAI ĐOẠN 3: Quét File Hashes ═══════════════════════
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

        # ══ GIAI ĐOẠN 4: AI Gemini phân tích nội dung ══════════
        print("\n[Giai đoạn 4] AI Gemini đang phân tích nội dung...")
        body = incident.get('body', '')
        if body:
            ai_result = ai_analyzer.analyze_email_intent(body)
            if ai_result.get('is_phishing'):
                is_safe = False
                total_ai_threats += 1
                print(f"   [!] AI PHÁT HIỆN LỪA ĐẢO (Điểm: {ai_result['risk_score']}/10)")
                print(f"   [!] Lý do: {ai_result['reason']}")
            else:
                print("   [✓] AI đánh giá nội dung an toàn.")
        else:
            print("   [-] Email không có văn bản để AI phân tích.")

        # ══ KẾT LUẬN + XỬ LÝ EMAIL ══════════════════════════════
        print("\n" + "="*50)
        if is_safe:
            print("✅ KẾT LUẬN: EMAIL AN TOÀN")
        else:
            total = (total_vt_threats + total_typo_threats
                     + total_auth_threats + total_ai_threats)
            print(f"🔥 KẾT LUẬN: PHÁT HIỆN {total} MỐI ĐE DỌA")
            print(f"  ├─ Auth (SPF/DKIM/DMARC): {total_auth_threats}")
            print(f"  ├─ Typosquatting:          {total_typo_threats}")
            print(f"  ├─ VirusTotal:             {total_vt_threats}")
            print(f"  └─ AI Gemini (Ngữ cảnh):   {total_ai_threats}")
            print("  → Đã gửi cảnh báo Telegram!")

            # ── Gán nhãn + chuyển vào thùng rác ─────────────────
            print("\n🚨 ĐANG KÍCH HOẠT QUY TRÌNH CÁCH LY...")
            if email_id:
                mail_reader.mark_as_phishing(email_id)
            else:
                print("   [!] Không tìm thấy ID email để xử lý.")

if __name__ == "__main__":
    try:
        while True:
            run_soar_pipeline()
            print("\n[*] Đợi 4 giây trước chu kỳ tiếp theo...")
            time.sleep(4)
    except KeyboardInterrupt:
        print("\n[!] Đã dừng hệ thống SOC.")