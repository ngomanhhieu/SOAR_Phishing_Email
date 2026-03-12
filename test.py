import requests

TOKEN = "8677078631:AAFsYmv2iyvNICuf2x3HUl9rwyWpdihe2Gk"
CHAT_ID = "-5216236878"

message = "Phát hiện URL phishing!"

url = f"https://api.telegram.org/bot8677078631:AAFsYmv2iyvNICuf2x3HUl9rwyWpdihe2Gk/sendMessage"

data = {
    "chat_id": CHAT_ID,
    "text": message
}

requests.post(url, data=data)