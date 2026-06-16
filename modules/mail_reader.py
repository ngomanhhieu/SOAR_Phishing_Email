import imaplib
import email
from email.header import decode_header
import re
import hashlib
import json
import os

# ================= CẤU HÌNH =================
def load_config(config_path=None):
    if config_path is None:
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        config_path = os.path.join(base_dir, "config.json")
    with open(config_path, "r", encoding="utf-8") as f:
        return json.load(f)

config       = load_config()
USERNAME     = config["email"]["username"]
APP_PASSWORD = config["email"]["app_password"]
IMAP_SERVER  = config["email"]["imap_server"]

WHITELIST     = []
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


def mark_as_phishing(email_id):
    try:
        mail = imaplib.IMAP4_SSL(IMAP_SERVER)
        mail.login(USERNAME, APP_PASSWORD)
        mail.select("inbox")

        # Gán nhãn Trash — cú pháp đặc trị của Gmail IMAP
        mail.store(email_id, '+X-GM-LABELS', '\\Trash')

        mail.logout()
        print(f"Đã chuyển email vào thùng rác thành công!")
    except Exception as e:
        print(f"   [ERROR] Lỗi khi cách ly email: {e}")


def get_unread_emails_and_extract_iocs():
    print("Hệ thống đang kiểm tra hộp thư...")
    try:
        mail = imaplib.IMAP4_SSL(IMAP_SERVER)
        mail.login(USERNAME, APP_PASSWORD)
        mail.select("inbox")
        status, messages = mail.search(None, "UNSEEN")
        email_ids = messages[0].split()

        if not email_ids:
            print("Không có yêu cầu phân tích mới.")
            return []

        extracted_data = []

        for e_id in email_ids:
            res, msg_data = mail.fetch(e_id, "(RFC822)")
            for response_part in msg_data:
                if isinstance(response_part, tuple):
                    msg    = email.message_from_bytes(response_part[1])
                    sender = decode_mime_words(msg.get("From"))

                    body               = ""
                    attachments_hashes = []

                    for part in msg.walk():
                        content_type = part.get_content_type()
                        disposition  = str(part.get("Content-Disposition"))

                        if content_type == "text/plain" and "attachment" not in disposition:
                            body += part.get_payload(decode=True).decode(errors='ignore')
                        elif "attachment" in disposition:
                            file_data = part.get_payload(decode=True)
                            if file_data:
                                sha256_hash = hashlib.sha256(file_data).hexdigest()
                                filename    = decode_mime_words(part.get_filename())
                                attachments_hashes.append({
                                    "filename": filename,
                                    "hash":     sha256_hash
                                })
                                print(f"Tìm thấy file: {filename} (SHA256: {sha256_hash})")

                    if any(key in body.lower() for key in SPAM_KEYWORDS):
                        print(f"Bỏ qua email từ {sender} (Nhận diện: Thư quảng cáo)")
                        mail.store(e_id, '+FLAGS', '\\Seen')
                        continue

                    url_pattern = r'(?:https?://)?(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?:/[^\s<>"\']*)?'
                    raw_urls    = set(re.findall(url_pattern, body))

                    valid_urls = set()
                    for u in raw_urls:
                        u = u.rstrip(".,;:]")
                        if not u.startswith('http'):
                            u = "http://" + u
                        valid_urls.add(u)

                    ips        = set(re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', body))
                    clean_urls = [u for u in valid_urls if not any(sd in u for sd in WHITELIST)]

                    if clean_urls or ips or attachments_hashes:
                        print(f"Phân tích email từ: {sender}")
                        extracted_data.append({
                            "sender":      sender,
                            "email_id":    e_id,    
                            "msg_object":  msg,
                            "body":        body,
                            "urls":        clean_urls,
                            "ips":         list(ips),
                            "file_hashes": attachments_hashes,
                        })
                        mail.store(e_id, '+FLAGS', '\\Seen')

        mail.logout()
        return extracted_data

    except Exception as e:
        print(f"ERROR: {e}")
        return []


if __name__ == "__main__":
    results = get_unread_emails_and_extract_iocs()
    print("\nDANH SÁCH IOCs:")
    import json
    # Bỏ msg_object và email_id khi print vì không serialize được
    print(json.dumps(
        [{k: v for k, v in r.items() if k not in ('msg_object', 'email_id')}
         for r in results],
        indent=4, ensure_ascii=False
    ))