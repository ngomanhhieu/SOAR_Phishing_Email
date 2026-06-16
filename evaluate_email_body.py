import csv
import sys
import time
from modules.ai_analyzer import analyze_email_intent

# Increase CSV field size limit to handle extremely long email bodies
# Using 2147483647 (max 32-bit signed integer) to prevent OverflowError on Windows
csv.field_size_limit(2147483647)

dataset_path = "Phishing_Email.csv"

def main():
    print("Running benchmark on first 800 emails only")
    
    dataset = []
    with open(dataset_path, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        for row in reader:
            text = row.get("Email Text", "")
            label_str = row.get("Email Type", "")
            
            label = 1 if label_str == "Phishing Email" else 0
            dataset.append({
                "text": text,
                "label": label
            })
            
    # Slicing
    dataset = dataset[:800]
    total_samples = len(dataset)
    
    tp = 0
    tn = 0
    fp = 0
    fn = 0
    
    false_positives = []
    false_negatives = []
    
    results = []
    
    total_successful = 0
    total_retries = 0
    total_failed = 0
    total_sleep_time = 0
    
    start_time = time.time()
    
    for i, item in enumerate(dataset, start=1):
        print(f"[INFO] Processing email {i}/{total_samples}")
        
        email_text = item["text"]
        actual_label = item["label"]
        
        success = False
        retries = 0
        backoffs = [30, 60, 120]
        result = None
        
        while retries <= 3:
            try:
                result = analyze_email_intent(email_text)
                
                # Treat "Lỗi kết nối AI" from ai_analyzer.py as a failed request / rate limit
                if result and result.get("reason") == "Lỗi kết nối AI":
                    raise Exception("API Error from ai_analyzer")
                    
                success = True
                total_successful += 1
                break
            except Exception as e:
                if retries < 3:
                    wait_time = backoffs[retries]
                    print(f"[WARNING] Rate limit detected, retrying in {wait_time}s")
                    time.sleep(wait_time)
                    total_sleep_time += wait_time
                    retries += 1
                    total_retries += 1
                else:
                    print("[ERROR] Request failed after 3 retries")
                    total_failed += 1
                    result = {
                        "is_phishing": False,
                        "risk_score": 0,
                        "reason": "Quota exceeded"
                    }
                    break
        
        if success:
            print("[INFO] Waiting 15s to respect Gemini Free Tier\n")
            time.sleep(15)
            total_sleep_time += 15
        else:
            print()
            
        predicted_label = 1 if result["is_phishing"] else 0
        correct = (actual_label == predicted_label)
        risk_score = result.get("risk_score", 0)
        reason = result.get("reason", "")
        
        if actual_label == 1 and predicted_label == 1:
            tp += 1
        elif actual_label == 0 and predicted_label == 0:
            tn += 1
        elif actual_label == 0 and predicted_label == 1:
            fp += 1
            false_positives.append({
                "snippet": email_text[:200].replace('\n', ' '),
                "actual_label": actual_label,
                "predicted_label": predicted_label,
                "reason": reason,
                "risk_score": risk_score
            })
        elif actual_label == 1 and predicted_label == 0:
            fn += 1
            false_negatives.append({
                "snippet": email_text[:200].replace('\n', ' '),
                "actual_label": actual_label,
                "predicted_label": predicted_label,
                "reason": reason,
                "risk_score": risk_score
            })
            
        results.append({
            "email_text": email_text,
            "actual_label": actual_label,
            "predicted_label": predicted_label,
            "correct": correct,
            "risk_score": risk_score,
            "reason": reason
        })
            
    end_time = time.time()
    total_time = end_time - start_time
    avg_time = total_time / total_samples if total_samples > 0 else 0
    speed = total_samples / total_time if total_time > 0 else 0
    
    accuracy = (tp + tn) / total_samples if total_samples > 0 else 0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    
    # Save to CSV
    output_csv = "email_body_evaluation_results.csv"
    with open(output_csv, "w", newline="", encoding="utf-8") as f:
        fieldnames = ["email_text", "actual_label", "predicted_label", "correct", "risk_score", "reason"]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)
        
    print("\nFALSE POSITIVES")
    for i, item in enumerate(false_positives[:20]):
        print(f"{i+1}. Snippet: {item['snippet']}")
        print(f"   Actual: {item['actual_label']}, Predicted: {item['predicted_label']}")
        print(f"   Reason: {item['reason']} (Score: {item['risk_score']})\n")
        
    print("FALSE NEGATIVES")
    for i, item in enumerate(false_negatives[:20]):
        print(f"{i+1}. Snippet: {item['snippet']}")
        print(f"   Actual: {item['actual_label']}, Predicted: {item['predicted_label']}")
        print(f"   Reason: {item['reason']} (Score: {item['risk_score']})\n")
        
    print("==================================================")
    print("GEMINI API STATISTICS")
    print("==================================================")
    print(f"Successful Requests : {total_successful}")
    print(f"Retries             : {total_retries}")
    print(f"Failed Requests     : {total_failed}")
    print(f"Rate Limit Sleep    : {total_sleep_time} sec")
    print()
    
    print("==================================================")
    print("OVERALL PERFORMANCE")
    print("==================================================")
    print()
    print(f"Samples   : {total_samples}")
    print()
    print(f"Accuracy  : {accuracy:.4f}")
    print(f"Precision : {precision:.4f}")
    print(f"Recall    : {recall:.4f}")
    print(f"F1-score  : {f1_score:.4f}")
    print()
    print(f"TP: {tp}")
    print(f"TN: {tn}")
    print(f"FP: {fp}")
    print(f"FN: {fn}")
    print()
    print(f"Total Time: {total_time:.2f} s")
    print(f"Avg Time  : {avg_time:.2f} s/email")
    print(f"Speed     : {speed:.2f} emails/s")

if __name__ == "__main__":
    main()
