
import os
import sys
import time
import json
import logging
import contextlib
import pandas as pd
import numpy as np
from datetime import datetime
from tqdm import tqdm
import requests

# Add project root to sys.path to ensure modules can be imported
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from modules.vt_scanner import scan_ioc

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("vt_hash_evaluation.log")
    ]
)

REQUEST_DELAY = 15
MAX_HASHES = 200

# Monkey-patch requests.get to capture the raw response without altering vt_scanner.py
original_get = requests.get

class VTResponseCapture:
    last_response = None
    last_error = None

def patched_get(url, *args, **kwargs):
    VTResponseCapture.last_response = None
    VTResponseCapture.last_error = None
    try:
        response = original_get(url, *args, **kwargs)
        VTResponseCapture.last_response = response
        return response
    except Exception as e:
        VTResponseCapture.last_error = str(e)
        raise e

requests.get = patched_get

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

def is_valid_sha256(h):
    """Check if the string is a valid SHA256 hash."""
    if pd.isna(h) or not isinstance(h, str):
        return False
    h = h.strip()
    return len(h) == 64 and all(c in '0123456789abcdefABCDEF' for c in h)

def main():
    dataset_path = "recent.csv"
    
    # 1. Load recent.csv
    if not os.path.exists(dataset_path):
        logging.error(f"Dataset not found: {dataset_path}")
        return

    logging.info(f"Loading dataset: {dataset_path}")
    column_names = [
        "first_seen_utc", "sha256_hash", "md5_hash", "sha1_hash", "reporter", 
        "file_name", "file_type_guess", "mime_type", "signature", "clamav", 
        "vtpercent", "imphash", "ssdeep", "tlsh"
    ]
    try:
        # MalwareBazaar CSV uses '#' for comments. The header is commented out, so we skip comments and provide names.
        df = pd.read_csv(dataset_path, comment='#', header=None, names=column_names, skipinitialspace=True, quotechar='"')
    except Exception as e:
        logging.error(f"Failed to load dataset: {e}")
        return

    # 2 & 3 & 4. Process hashes
    df['sha256_hash'] = df['sha256_hash'].astype(str).str.strip()
    df.replace("", float("NaN"), inplace=True)
    df.replace("nan", float("NaN"), inplace=True)
    
    # Remove empty, null, duplicates
    df = df.dropna(subset=['sha256_hash'])
    df = df.drop_duplicates(subset=['sha256_hash'])
    
    # Validate 64-char hex
    df = df[df['sha256_hash'].apply(is_valid_sha256)]
    
    # Use only first 200
    df = df.head(MAX_HASHES)
    hashes_to_test = df.to_dict('records')
    total_hashes = len(hashes_to_test)
    logging.info(f"Starting evaluation on {total_hashes} SHA256 hashes.")

    results = []
    raw_results_json = {
        "scan_timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "dataset": "recent.csv",
        "total_hashes": total_hashes,
        "results": []
    }
    
    vendor_stats = []
    fn_analysis = []
    
    failed_scans = 0
    successfully_scanned = 0
    true_positives = 0
    false_negatives = 0

    try:
        for i, row in enumerate(tqdm(hashes_to_test, desc="Scanning Hashes", unit="hash")):
            sha256 = row['sha256_hash']
            file_name = row.get('file_name', 'n/a')
            file_type_guess = row.get('file_type_guess', 'n/a')
            signature = row.get('signature', 'n/a')
            
            scan_success = False
            malicious_count = 0
            prediction = 0
            vt_raw_data = None
            error_msg = None

            try:
                # Call existing VT scanner module
                with suppress_stdout():
                    # scan_ioc returns malicious count (0 if error or safe)
                    malicious_count = scan_ioc("hash", sha256)
                
                scan_success = True
                successfully_scanned += 1
                
                # Determine prediction
                if isinstance(malicious_count, int) and malicious_count > 0:
                    prediction = 1
                    true_positives += 1
                else:
                    prediction = 0
                    false_negatives += 1

                # Capture raw response
                if VTResponseCapture.last_response is not None:
                    if VTResponseCapture.last_response.status_code == 200:
                        try:
                            vt_raw_data = VTResponseCapture.last_response.json()
                        except:
                            error_msg = "Failed to parse JSON from 200 OK"
                    elif VTResponseCapture.last_response.status_code == 404:
                        error_msg = "Not found in VirusTotal"
                        vt_raw_data = {"error": error_msg}
                    else:
                        error_msg = f"HTTP {VTResponseCapture.last_response.status_code}"
                        vt_raw_data = {"error": error_msg}
                else:
                    error_msg = VTResponseCapture.last_error or "Unknown capture error"
                    vt_raw_data = {"error": error_msg}

            except KeyboardInterrupt:
                logging.warning("Evaluation interrupted by user.")
                raise # Re-raise to break the loop
            except Exception as e:
                logging.error(f"Error scanning hash {sha256}: {e}")
                failed_scans += 1
                scan_success = False
                error_msg = str(e)
                vt_raw_data = {"error": error_msg}

            # Append to standard results
            results.append({
                "sha256_hash": sha256,
                "malicious_count": malicious_count,
                "prediction": prediction,
                "scan_success": scan_success
            })
            
            # Append to raw JSON results
            if error_msg and not (vt_raw_data and "data" in vt_raw_data):
                raw_results_json["results"].append({
                    "sha256_hash": sha256,
                    "error": error_msg
                })
            else:
                raw_results_json["results"].append({
                    "sha256_hash": sha256,
                    "vt_response": vt_raw_data
                })

            # Extract vendor stats if available
            suspicious_count = 0
            harmless_count = 0
            undetected_count = 0
            
            if vt_raw_data and "data" in vt_raw_data:
                stats = vt_raw_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                # VT might return malicious count directly, use it to ensure sync
                malicious_count = stats.get("malicious", malicious_count)
                suspicious_count = stats.get("suspicious", 0)
                harmless_count = stats.get("harmless", 0)
                undetected_count = stats.get("undetected", 0)
                
            vendor_stats.append({
                "sha256_hash": sha256,
                "malicious_count": malicious_count,
                "suspicious_count": suspicious_count,
                "harmless_count": harmless_count,
                "undetected_count": undetected_count
            })
            
            # Track false negatives for deep analysis
            if prediction == 0 and scan_success:
                fn_analysis.append({
                    "sha256_hash": sha256,
                    "malicious_count": malicious_count,
                    "suspicious_count": suspicious_count,
                    "harmless_count": harmless_count,
                    "undetected_count": undetected_count,
                    "file_name": file_name,
                    "file_type_guess": file_type_guess,
                    "signature": signature
                })

            # Delay to respect API limits
            if i < total_hashes - 1:
                time.sleep(REQUEST_DELAY)

    except KeyboardInterrupt:
        logging.info("Gracefully saving results before exiting...")

    # Export PART 4: vt_hash_results.csv
    results_df = pd.DataFrame(results)
    if not results_df.empty:
        results_df.to_csv("vt_hash_results.csv", index=False)
        logging.info("Detailed results saved to vt_hash_results.csv")

    # Export PART 5: false_negatives.csv
    if not results_df.empty:
        fn_df = results_df[(results_df['prediction'] == 0) & (results_df['scan_success'] == True)][['sha256_hash', 'malicious_count']]
        fn_df.to_csv("false_negatives.csv", index=False)
        logging.info("False negatives saved to false_negatives.csv")

    # Export PART 9: vt_hash_raw_results.json
    with open("vt_hash_raw_results.json", "w", encoding="utf-8") as f:
        json.dump(raw_results_json, f, indent=2)
    logging.info("Raw VT responses saved to vt_hash_raw_results.json")

    # Export PART 10: vendor_detection_statistics.csv
    vs_df = pd.DataFrame(vendor_stats)
    if not vs_df.empty:
        vs_df.to_csv("vendor_detection_statistics.csv", index=False)
        logging.info("Vendor statistics saved to vendor_detection_statistics.csv")

    # Export PART 11: false_negative_analysis.csv
    fn_analysis_df = pd.DataFrame(fn_analysis)
    if not fn_analysis_df.empty:
        fn_analysis_df.to_csv("false_negative_analysis.csv", index=False)
        logging.info("False negative analysis saved to false_negative_analysis.csv")

    # Calculate metrics based only on successfully scanned URLs
    if not results_df.empty and 'scan_success' in results_df.columns:
        successful_results = results_df[results_df['scan_success'] == True]
    else:
        successful_results = pd.DataFrame()
        
    detection_rate = 0.0
    recall = 0.0
    
    if successfully_scanned > 0:
        detection_rate = true_positives / successfully_scanned
        recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) > 0 else 0

    # Summary
    summary = f"""
==================================================
VirusTotal Hash Evaluation Summary
==================================================
Dataset: MalwareBazaar recent.csv

Hashes Loaded: {total_hashes}
Hashes Scanned: {successfully_scanned}
Failed Scans: {failed_scans}

True Positives: {true_positives}
False Negatives: {false_negatives}

Detection Rate: {detection_rate:.2%}
Recall: {recall:.2%}
==================================================
"""
    print(summary)

    # PART 6 & 10 Additional Analysis
    if not vs_df.empty:
        malicious_counts = vs_df['malicious_count']
        avg_mal = malicious_counts.mean()
        max_mal = malicious_counts.max()
        min_mal = malicious_counts.min()
        med_mal = malicious_counts.median()
        
        analysis_summary = f"""
==================================================
Vendor Detection Analysis
==================================================
Average malicious detections: {avg_mal:.2f}
Maximum malicious detections: {max_mal}
Minimum malicious detections: {min_mal}
Median malicious detections: {med_mal}

Top 10 hashes with highest malicious_count:
"""
        top_10 = vs_df.sort_values(by='malicious_count', ascending=False).head(10)
        for _, r in top_10.iterrows():
            analysis_summary += f"  - {r['sha256_hash']}: {r['malicious_count']} detections\n"
            
        print(analysis_summary)
        summary += analysis_summary

    # PART 11 False Negative Summary
    fn_list = fn_analysis_df['sha256_hash'].tolist() if not fn_analysis_df.empty else []
    fn_summary = f"""
==================================================
False Negative Investigation
==================================================
Total False Negatives: {len(fn_list)}
List of False Negative Hashes:
"""
    for h in fn_list:
        fn_summary += f"  - {h}\n"
    fn_summary += "==================================================\n"
    
    print(fn_summary)
    summary += fn_summary
    
    # Save log
    with open("vt_hash_evaluation.log", "a", encoding="utf-8") as f:
        f.write(summary)

if __name__ == "__main__":
    main()
