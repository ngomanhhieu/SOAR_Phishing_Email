
import os
import sys
import time
import logging
import contextlib
import pandas as pd
from tqdm import tqdm
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score, 
    confusion_matrix, classification_report
)
import matplotlib.pyplot as plt
import seaborn as sns

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("vt_evaluation.log")
    ]
)

# Add project root to sys.path to ensure modules can be imported
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from modules.vt_scanner import scan_ioc

REQUEST_DELAY = 15

@contextlib.contextmanager
def suppress_stdout():
    """Suppress stdout to prevent interference with tqdm progress bar."""
    with open(os.devnull, "w", encoding="utf-8") as devnull:
        old_stdout = sys.stdout
        sys.stdout = devnull
        try:  
            yield
        finally:
            sys.stdout = old_stdout

def generate_confusion_matrix_plot(y_true, y_pred, output_path="confusion_matrix.png"):
    """Generates and saves the confusion matrix plot."""
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    
    plt.figure(figsize=(8, 6))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                xticklabels=['Benign (0)', 'Phishing (1)'], 
                yticklabels=['Benign (0)', 'Phishing (1)'])
    plt.xlabel('Predicted Label')
    plt.ylabel('True Label')
    plt.title('VirusTotal Evaluation Confusion Matrix')
    plt.tight_layout()
    plt.savefig(output_path)
    plt.close()
    logging.info(f"Confusion matrix plot saved to {output_path}")

def main():
    dataset_path = "vt_benchmark_dataset.csv"
    output_path = "vt_results.csv"
    
    if not os.path.exists(dataset_path):
        logging.error(f"Dataset not found: {dataset_path}")
        logging.info("Please run build_vt_benchmark_dataset.py first.")
        return

    logging.info(f"Loading benchmark dataset: {dataset_path}")
    try:
        df = pd.read_csv(dataset_path)
    except Exception as e:
        logging.error(f"Failed to load dataset: {e}")
        return

    total_urls = len(df)
    logging.info(f"Starting evaluation on {total_urls} URLs with a delay of {REQUEST_DELAY}s between requests.")

    results = []
    failed_scans = 0
    successfully_scanned = 0

    try:
        for i, row in tqdm(df.iterrows(), total=total_urls, desc="Scanning URLs", unit="url"):
            url = row['url']
            true_label = int(row['label'])
            
            scan_success = False
            malicious_count = 0
            prediction = 0

            try:
                # Call existing VT scanner module
                # Suppressing stdout so that scan_ioc prints don't break the tqdm progress bar
                with suppress_stdout():
                    malicious_count = scan_ioc("url", url)
                
                scan_success = True
                successfully_scanned += 1
                
                # Prediction rule
                if isinstance(malicious_count, int) and malicious_count > 0:
                    prediction = 1
                else:
                    prediction = 0

            except KeyboardInterrupt:
                logging.warning("Evaluation interrupted by user.")
                raise # Re-raise to break the outer loop
            except Exception as e:
                logging.error(f"Error scanning URL {url}: {e}")
                failed_scans += 1
                scan_success = False

            results.append({
                "url": url,
                "true_label": true_label,
                "prediction": prediction,
                "malicious_count": malicious_count,
                "scan_success": scan_success
            })

            # Delay to respect API limits (only if not the last item)
            if i < total_urls - 1:
                time.sleep(REQUEST_DELAY)

    except KeyboardInterrupt:
        logging.info("Gracefully saving results before exiting...")

    # Save detailed results to CSV
    results_df = pd.DataFrame(results)
    results_df.to_csv(output_path, index=False)
    logging.info(f"Detailed results saved to {output_path}")

    # Calculate metrics based only on successfully scanned URLs
    if not results_df.empty and 'scan_success' in results_df.columns:
        successful_results = results_df[results_df['scan_success'] == True]
    else:
        successful_results = pd.DataFrame()
    
    if not successful_results.empty:
        y_true = successful_results['true_label'].tolist()
        y_pred = successful_results['prediction'].tolist()
        
        # Determine sizes
        total_eval = len(y_true)
        phishing_count = sum(1 for y in y_true if y == 1)
        benign_count = sum(1 for y in y_true if y == 0)
        
        acc = accuracy_score(y_true, y_pred)
        prec = precision_score(y_true, y_pred, zero_division=0)
        rec = recall_score(y_true, y_pred, zero_division=0)
        f1 = f1_score(y_true, y_pred, zero_division=0)
        
        cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
        # cm structure:
        # [ TN, FP ]
        # [ FN, TP ]
        tn, fp, fn, tp = cm.ravel()
        
        # Display Final Summary
        summary = f"""
==================================================
VirusTotal Evaluation Summary
==================================================
Dataset Size: {total_eval}
Phishing URLs: {phishing_count}
Benign URLs: {benign_count}

Accuracy: {acc:.4f}
Precision: {prec:.4f}
Recall: {rec:.4f}
F1-Score: {f1:.4f}

True Positives: {tp}
True Negatives: {tn}
False Positives: {fp}
False Negatives: {fn}
==================================================
"""
        print(summary)
        
        with open("vt_evaluation.log", "a", encoding="utf-8") as f:
            f.write(summary)
            f.write("\nClassification Report:\n")
            f.write(classification_report(y_true, y_pred, digits=4, zero_division=0))
            f.write("\n")
            
        # Generate Plot
        generate_confusion_matrix_plot(y_true, y_pred)
    else:
        logging.warning("No successful scans to evaluate.")

if __name__ == "__main__":
    main()
