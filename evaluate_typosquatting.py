import os
import sys
import csv
import time
import logging
import contextlib
import io
from typing import List, Dict, Any
from collections import defaultdict

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Add modules directory to sys.path to import typosquatting_scanner
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'modules'))

try:
    from typosquatting_scanner import scan_typosquatting
except ImportError as e:
    logger.error(f"Failed to import typosquatting_scanner: {e}")
    sys.exit(1)

def scan_domain(domain: str) -> dict:
    """
    Call the existing typosquatting scanner for a given domain.
    Suppresses standard output to prevent logging flood.
    """
    url = f"http://{domain}"
    
    # Suppress stdout from the scanner to keep evaluation logs clean
    with contextlib.redirect_stdout(io.StringIO()):
        try:
            return scan_typosquatting(url)
        except Exception as e:
            return {
                "domain": domain,
                "risk_level": "UNKNOWN",
                "error": str(e)
            }

def compute_metrics(y_true: List[int], y_pred: List[int]) -> Dict[str, float]:
    """Calculate classification metrics and confusion matrix components."""
    tp = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 1)
    tn = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 0)
    fp = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 1)
    fn = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 0)

    accuracy = (tp + tn) / len(y_true) if y_true else 0.0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    
    return {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1_score": f1_score,
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn
    }

def main():
    dataset_path = "typosquatting_dataset.csv"
    results_path = "evaluation_results.csv"
    metrics_path = "attack_type_metrics.csv"

    if not os.path.exists(dataset_path):
        logger.error(f"Dataset not found: {dataset_path}")
        return

    logger.info(f"Loading dataset from {dataset_path}...")
    dataset = []
    try:
        with open(dataset_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                dataset.append(row)
    except Exception as e:
        logger.error(f"Error loading dataset: {e}")
        return

    total_samples = len(dataset)
    logger.info(f"Loaded {total_samples} samples.")

    results = []
    y_true_all = []
    y_pred_all = []
    
    # Track by attack type
    attack_types = defaultdict(lambda: {"y_true": [], "y_pred": []})
    
    start_time = time.time()
    logger.info("Starting evaluation... This may take a while depending on dataset size.")

    for i, row in enumerate(dataset, 1):
        original_domain = row["original_domain"]
        domain = row["domain"]
        attack_type = row["attack_type"]
        actual_label = int(row["label"])

        # Scan domain using engine
        t0 = time.time()
        scan_result = scan_domain(domain)
        t1 = time.time()
        
        # Binary prediction mapping
        # Legitimate: SAFE, UNKNOWN -> 0
        # Typosquatting: HIGH, MEDIUM, LOW -> 1
        risk = scan_result.get("risk_level", "UNKNOWN")
        predicted_label = 1 if risk in ["HIGH", "MEDIUM", "LOW"] else 0
        correct = (predicted_label == actual_label)

        results.append({
            "original_domain": original_domain,
            "domain": domain,
            "attack_type": attack_type,
            "actual_label": actual_label,
            "predicted_label": predicted_label,
            "correct": correct,
            "scan_time": t1 - t0,
            "risk_level": risk
        })

        y_true_all.append(actual_label)
        y_pred_all.append(predicted_label)
        
        attack_types[attack_type]["y_true"].append(actual_label)
        attack_types[attack_type]["y_pred"].append(predicted_label)

        if i % 100 == 0 or i == total_samples:
            logger.info(f"Processed {i}/{total_samples} domains...")

    end_time = time.time()
    total_time = end_time - start_time
    avg_scan_time = total_time / total_samples if total_samples else 0

    # Overall metrics
    overall_metrics = compute_metrics(y_true_all, y_pred_all)
    
    logger.info(f"\nEvaluation Complete! Total execution time: {total_time:.2f}s, Avg time/domain: {avg_scan_time:.4f}s")
    logger.info("=" * 50)
    logger.info("OVERALL PERFORMANCE (Classification Report)")
    logger.info("=" * 50)
    logger.info(f"Accuracy : {overall_metrics['accuracy']:.4f}")
    logger.info(f"Precision: {overall_metrics['precision']:.4f}")
    logger.info(f"Recall   : {overall_metrics['recall']:.4f}")
    logger.info(f"F1-score : {overall_metrics['f1_score']:.4f}")
    
    logger.info("-" * 50)
    logger.info("CONFUSION MATRIX")
    logger.info("-" * 50)
    logger.info(f"True Positives (TP) : {overall_metrics['tp']}")
    logger.info(f"True Negatives (TN) : {overall_metrics['tn']}")
    logger.info(f"False Positives (FP): {overall_metrics['fp']}")
    logger.info(f"False Negatives (FN): {overall_metrics['fn']}")

    # Save detailed results
    logger.info(f"\nSaving detailed evaluation results to {results_path}...")
    try:
        with open(results_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=[
                "original_domain", "domain", "attack_type", "actual_label", "predicted_label", "correct"
            ])
            writer.writeheader()
            for r in results:
                writer.writerow({
                    "original_domain": r["original_domain"],
                    "domain": r["domain"],
                    "attack_type": r["attack_type"],
                    "actual_label": r["actual_label"],
                    "predicted_label": r["predicted_label"],
                    "correct": r["correct"]
                })
    except Exception as e:
        logger.error(f"Error saving results: {e}")

    # Save attack type metrics
    logger.info(f"Saving attack type metrics to {metrics_path}...")
    try:
        with open(metrics_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=[
                "attack_type", "samples", "accuracy", "precision", "recall", "f1_score"
            ])
            writer.writeheader()
            
            logger.info("\n" + "=" * 50)
            logger.info("METRICS BY ATTACK TYPE")
            logger.info("=" * 50)
            
            for atk_type, data in attack_types.items():
                if atk_type == "legitimate":
                    continue
                metrics = compute_metrics(data["y_true"], data["y_pred"])
                samples = len(data["y_true"])
                
                writer.writerow({
                    "attack_type": atk_type,
                    "samples": samples,
                    "accuracy": f"{metrics['accuracy']:.4f}",
                    "precision": f"{metrics['precision']:.4f}",
                    "recall": f"{metrics['recall']:.4f}",
                    "f1_score": f"{metrics['f1_score']:.4f}"
                })
                logger.info(f"{atk_type.upper():<18} - Acc: {metrics['accuracy']:.4f} | Prec: {metrics['precision']:.4f} | Rec: {metrics['recall']:.4f} | F1: {metrics['f1_score']:.4f}")
    except Exception as e:
        logger.error(f"Error saving attack metrics: {e}")

    # Display some FPs and FNs
    false_positives = [r for r in results if r["actual_label"] == 0 and r["predicted_label"] == 1]
    false_negatives = [r for r in results if r["actual_label"] == 1 and r["predicted_label"] == 0]

    logger.info("\n" + "=" * 80)
    logger.info(f"FALSE POSITIVES (Legitimate classified as Typosquatting) - {len(false_positives)} total")
    logger.info("=" * 80)
    for fp in false_positives[:10]:
        logger.info(f"Domain: {fp['domain']:<25} | Resulted Risk: {fp['risk_level']}")

    logger.info("\n" + "=" * 80)
    logger.info(f"FALSE NEGATIVES (Typosquatting classified as Legitimate) - {len(false_negatives)} total")
    logger.info("=" * 80)
    for fn in false_negatives[:10]:
        logger.info(f"Original: {fn['original_domain']:<20} | Typo: {fn['domain']:<25} | Attack: {fn['attack_type']:<15} | Resulted Risk: {fn['risk_level']}")

if __name__ == "__main__":
    main()
