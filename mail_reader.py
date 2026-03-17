import imaplib
import email
from email.header import decode_header
import re
import hashlib

# ================= CẤU HÌNH =================
USERNAME = "soc.phishing.test@gmail.com"
APP_PASSWORD = "vmhzdqmasrerzgyb" 
IMAP_SERVER = "imap.gmail.com"

# 1. Danh sách trắng (Whitelist)
WHITELIST = ['google.com', 'microsoft.com']
# 2. Từ khóa nhận diện thư quảng cáo/spam hợp pháp
SPAM_KEYWORDS = ['unsubscribe', 'hủy đăng ký', 'từ chối nhận', 'opt out', 'view in browser']

def decode_mime_words(s):
    if not s: return ""
    decoded_words = decode_header(s)
    result = []
    for word, charset in decoded_words:
        if isinstance(word, bytes):
            result.append(word.decode(charset or 'utf-8', errors='ignore'))
        else:
            result.append(word)
    return "".join(result)

def get_unread_emails_and_extract_iocs():
    print("[*] Hệ thống SOC đang kiểm tra hộp thư...")
    try:
        mail = imaplib.IMAP4_SSL(IMAP_SERVER)
        mail.login(USERNAME, APP_PASSWORD)
        mail.select("inbox")
        status, messages = mail.search(None, "UNSEEN")
        email_ids = messages[0].split()

        if not email_ids:
            print("[-] Không có yêu cầu phân tích mới.")
            return []

        extracted_data = []

        for e_id in email_ids:
            res, msg_data = mail.fetch(e_id, "(RFC822)")
            for response_part in msg_data:
                if isinstance(response_part, tuple):
                    msg = email.message_from_bytes(response_part[1])
                    sender = decode_mime_words(msg.get("From"))
                    
                    body = ""
                    attachments_hashes = []
                    
                    # Duyệt qua các phần của email (Body và File đính kèm)
                    for part in msg.walk():
                        content_type = part.get_content_type()
                        disposition = str(part.get("Content-Disposition"))

                        # A. Lấy nội dung văn bản
                        if content_type == "text/plain" and "attachment" not in disposition:
                            body += part.get_payload(decode=True).decode(errors='ignore')
                        
                        # B. Xử lý FILE ĐÍNH KÈM (Attachment)
                        elif "attachment" in disposition:
                            file_data = part.get_payload(decode=True)
                            if file_data:
                                # Tính toán SHA-256 (Dấu vân tay của file)
                                sha256_hash = hashlib.sha256(file_data).hexdigest()
                                filename = decode_mime_words(part.get_filename())
                                attachments_hashes.append({"filename": filename, "hash": sha256_hash})
                                print(f"   [!] Tìm thấy file: {filename} (SHA256: {sha256_hash})")

                    # 3. KIỂM TRA SPAM/QUẢNG CÁO (Filtering)
                    if any(key in body.lower() for key in SPAM_KEYWORDS):
                        print(f"   [i] Bỏ qua email từ {sender} (Nhận diện: Thư quảng cáo/Marketing).")
                        mail.store(e_id, '+FLAGS', '\\Seen')
                        continue

                    # 4. TRÍCH XUẤT URL & IP
                    # Regex cho URL
                    urls = set(re.findall(r'(https?://[^\s<>"\']+)', body))
                    # Regex cho IPv4 trần
                    ips = set(re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', body))
                    
                    # Làm sạch URL và lọc Whitelist
                    clean_urls = [u.rstrip(".,;:]") for u in urls if not any(sd in u for sd in WHITELIST)]

                    # Gói dữ liệu (IOCs)
                    if clean_urls or ips or attachments_hashes:
                        print(f"-> Phân tích email từ: {sender}")
                        extracted_data.append({
                            "sender": sender,
                            "urls": clean_urls,
                            "ips": list(ips),
                            "file_hashes": attachments_hashes
                        })
                        mail.store(e_id, '+FLAGS', '\\Seen')

        mail.logout()
        return extracted_data

    except Exception as e:
        print(f"[ERROR]: {e}")
        return []

if __name__ == "__main__":
    results = get_unread_emails_and_extract_iocs()
    print("\n[✓] DANH SÁCH IOCs CHUYỂN CHO SINH VIÊN B:")
    import json
    print(json.dumps(results, indent=4, ensure_ascii=False))