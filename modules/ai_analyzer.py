import google.generativeai as genai
import json
from google.generativeai.types import HarmCategory, HarmBlockThreshold

# 1. CẤU HÌNH API KEY 
def load_config(config_path=None):
    if config_path is None:
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        config_path = os.path.join(base_dir, "config.json")
    with open(config_path, "r", encoding="utf-8") as f:
        return json.load(f)

config = load_config()
GEMINI_API_KEY = config["gemini_api_key"]
genai.configure(api_key=GEMINI_API_KEY)

def analyze_email_intent(email_body):
    """
    Hàm phân tích ngữ cảnh email bằng AI.
    """
    if not email_body.strip():
        return {"is_phishing": False, "risk_score": 0, "reason": "Email trống"}

    # In ra xem code bóc tách body có bị lỗi font hay html gì không
    print(f"   [DEBUG-AI] Văn bản bóc được: {email_body[:100]}...") 

    prompt = f"""
    Bạn là một chuyên gia An toàn thông tin (SOC Analyst). Hãy phân tích nội dung email sau để tìm dấu hiệu Lừa đảo (Phishing) hoặc Social Engineering:
    - Chú ý các dấu hiệu: Tạo áp lực thời gian, Đe dọa khóa tài khoản/phạt tiền, Dụ dỗ bấm link, Giả mạo phòng ban/ngân hàng.
    
    Hãy trả về kết quả CHÍNH XÁC DUY NHẤT theo 3 dòng sau, tuyệt đối không nói thêm câu nào khác:
    PHISHING: [YES hoặc NO]
    SCORE: [Điểm từ 1 đến 10]
    REASON: [Giải thích 1 câu ngắn gọn]

    NỘI DUNG EMAIL:
    {email_body}
    """
    
    try:
        # ========================================================
        # CỖ MÁY TỰ ĐỘNG TÌM MODEL (KHÔNG BAO GIỜ SỢ SAI TÊN NỮA)
        # ========================================================
        valid_model = "gemini-1.5-flash" # Tên dự phòng
        
        # Hỏi thẳng máy chủ Google: "Tài khoản của tôi được dùng những AI nào?"
        available_models = []
        for m in genai.list_models():
            if 'generateContent' in m.supported_generation_methods:
                available_models.append(m.name.replace("models/", ""))
        
        if available_models:
            # Ưu tiên tìm bản flash hoặc pro, nếu không có thì bốc luôn thằng đầu tiên trong danh sách
            flash_models = [m for m in available_models if 'flash' in m]
            valid_model = flash_models[0] if flash_models else available_models[0]
            print(f" Máy chủ Google cấp phép sử dụng Model: {valid_model}")
        else:
            print("Cảnh báo: Tài khoản API này không có quyền tạo văn bản!")

        # Khởi tạo model với cái tên chuẩn xác 100% vừa lấy được
        model = genai.GenerativeModel(valid_model)
        # ========================================================

        # TẮT BỘ LỌC AN TOÀN ĐỂ CHUYÊN TÂM PHÂN TÍCH SECURITY (Giữ nguyên như cũ)
        safety_settings = {
            HarmCategory.HARM_CATEGORY_HARASSMENT: HarmBlockThreshold.BLOCK_NONE,
            HarmCategory.HARM_CATEGORY_HATE_SPEECH: HarmBlockThreshold.BLOCK_NONE,
            HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT: HarmBlockThreshold.BLOCK_NONE,
            HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT: HarmBlockThreshold.BLOCK_NONE,
        }

    
        # Gọi AI với safety_settings
        response = model.generate_content(prompt, safety_settings=safety_settings)
        text = response.text.strip()
        
        # In ra màn hình xem con AI nó thực sự đang lảm nhảm cái gì
        print(f" Kết quả thô từ Gemini trả về:\n{text}\n")
        
        # Bóc tách kết quả
        is_phishing = "YES" in text.upper().split('\n')[0] # Chỉ quét chữ YES ở dòng đầu
        
        score = 0
        reason = "Có dấu hiệu đáng ngờ."
        
        for line in text.split('\n'):
            if line.upper().startswith("SCORE:"):
                try:
                    score = int(line.upper().replace("SCORE:", "").strip())
                except:
                    pass
            elif line.upper().startswith("REASON:"):
                reason = line.replace("REASON:", "").replace("REASON: ", "").strip()
                
        return {"is_phishing": is_phishing, "risk_score": score, "reason": reason}
        
    except Exception as e:
        print(f"Lỗi khi gọi AI Gemini: {e}")
        return {"is_phishing": False, "risk_score": 0, "reason": "Lỗi kết nối AI"}