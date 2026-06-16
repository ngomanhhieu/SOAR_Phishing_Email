"""
build_vt_benchmark_dataset.py

Generates a balanced benchmark dataset of 500 phishing URLs and 500 benign URLs.
"""

import os
import pickle
import logging
import pandas as pd
from sklearn.utils import shuffle
import urllib.parse

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

def is_valid_url(url):
    """Simple check for valid URL structure."""
    if pd.isna(url) or not isinstance(url, str):
        return False
    parsed = urllib.parse.urlparse(url)
    return bool(parsed.scheme and parsed.netloc)

def main():
    phishing_csv = "online-valid.csv"
    benign_pkl = "top_domains_cache.pkl"
    output_csv = "vt_benchmark_dataset.csv"
    
    # 1 & 2. Load 500 phishing URLs and label as 1
    if not os.path.exists(phishing_csv):
        logging.error(f"File not found: {phishing_csv}")
        return
        
    logging.info(f"Loading phishing URLs from {phishing_csv}...")
    phishing_df_full = pd.read_csv(phishing_csv)
    phishing_df_full = phishing_df_full[phishing_df_full['url'].apply(is_valid_url)]
    phishing_df = phishing_df_full.head(500)[['url']].copy()
    phishing_df['label'] = 1
    logging.info(f"Loaded {len(phishing_df)} phishing samples.")

    # 3 & 4. Load legitimate domains and select 500 randomly
    if not os.path.exists(benign_pkl):
        logging.error(f"File not found: {benign_pkl}")
        return
        
    logging.info(f"Loading legitimate domains from {benign_pkl}...")
    with open(benign_pkl, "rb") as f:
        top_domains = pickle.load(f)
        
    # Pick 500 random domains with random_state=42
    # Ensure top_domains is a pandas Series or DataFrame for sample(), or convert it.
    if isinstance(top_domains, list) or isinstance(top_domains, set):
        benign_series = pd.Series(list(top_domains))
    else:
        benign_series = pd.Series(top_domains)
        
    benign_sample = benign_series.sample(n=500, random_state=42).copy()
    
    # 5 & 6. Convert domains to URLs and label as 0
    benign_df = pd.DataFrame({
        'url': benign_sample.apply(lambda domain: f"https://{domain}"),
        'label': 0
    })
    logging.info(f"Loaded {len(benign_df)} benign samples.")

    # 7. Merge phishing and benign samples
    merged_df = pd.concat([phishing_df, benign_df], ignore_index=True)
    
    # 8. Shuffle the dataset
    final_df = shuffle(merged_df, random_state=42).reset_index(drop=True)
    
    # 9. Save the dataset
    final_df.to_csv(output_csv, index=False)
    logging.info(f"Successfully saved balanced benchmark dataset to {output_csv}")
    logging.info(f"Total samples: {len(final_df)}")
    logging.info(f"Class distribution:\n{final_df['label'].value_counts()}")

if __name__ == "__main__":
    main()
