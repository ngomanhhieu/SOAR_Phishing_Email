import os
import pickle
import random
import csv
import string
from collections import defaultdict
from typing import List, Tuple, Dict, Set, Any

# Ensure reproducibility
random.seed(42)

# Constants for typosquatting generation
ADJACENT_KEYS = {
    'q': 'wase', 'w': 'qesad', 'e': 'wrsdf', 'r': 'etdfg', 't': 'ryfgh', 'y': 'tughj',
    'u': 'yihjk', 'i': 'uojkl', 'o': 'ipkl', 'p': 'ol',
    'a': 'qwszx', 's': 'awedxz', 'd': 'serfcx', 'f': 'drtgvc', 'g': 'ftyhbv', 'h': 'gyujnb',
    'j': 'huikmn', 'k': 'jiolm', 'l': 'kop',
    'z': 'asx', 'x': 'zsdc', 'c': 'xdfv', 'v': 'cfgb', 'b': 'vghn', 'n': 'bhjm', 'm': 'njk'
}

HOMOGLYPHS = {
    'a': ['à', 'á', 'â', 'ã', 'ä', 'å', 'ɑ', 'а'],
    'b': ['d', 'lb', 'ib', 'ß', 'ь'],
    'c': ['ϲ', 'с', 'ƈ', 'ċ', 'ć', 'ç'],
    'd': ['b', 'cl', 'dl', 'đ'],
    'e': ['é', 'ê', 'ë', 'ē', 'ĕ', 'ė', 'е', 'є'],
    'f': ['fl', 'fi', 'ƒ'],
    'g': ['q', 'ɢ', 'ɡ', 'ġ'],
    'h': ['lh', 'ih', 'һ', 'հ'],
    'i': ['1', 'l', 'í', 'î', 'ï', 'ı', 'і', 'j'],
    'j': ['i', 'ј', 'ʝ'],
    'k': ['lc', 'lk', 'ik', 'κ', 'к'],
    'l': ['1', 'i', 'I', 'ɫ', 'ł'],
    'm': ['n', 'nn', 'rn', 'rr', 'м'],
    'n': ['m', 'r', 'ո', 'п'],
    'o': ['0', 'ö', 'о', 'ο'],
    'p': ['ρ', 'р', 'þ'],
    'q': ['g', 'զ', 'ԛ'],
    'r': ['n', 'г', 'ʀ'],
    's': ['5', 'ş', 'ѕ'],
    't': ['7', 'ţ', 'т'],
    'u': ['v', 'ü', 'ц', 'ʋ'],
    'v': ['u', 'ν', 'ѵ'],
    'w': ['vv', 'ш', 'ѡ'],
    'x': ['х', 'ҳ'],
    'y': ['v', 'ý', 'ÿ', 'у'],
    'z': ['2', 'ż', 'ž', 'ʐ']
}

def load_domains(filepath: str) -> List[str]:
    """
    Load domains from a pickle file, automatically inspecting its structure.
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"File not found: {filepath}")
        
    with open(filepath, 'rb') as f:
        data = pickle.load(f)
        
    print(f"[*] Detected pickle structure type: {type(data).__name__}")
    
    domains = []
    
    if isinstance(data, list):
        domains = [str(item) for item in data]
    elif isinstance(data, set):
        domains = [str(item) for item in data]
    elif isinstance(data, tuple):
        domains = [str(item) for item in data]
    elif isinstance(data, dict):
        # Assume dict keys are domains
        domains = [str(key) for key in data.keys()]
    else:
        try:
            import pandas as pd
            if isinstance(data, pd.DataFrame):
                print("[*] Pandas DataFrame detected inside pickle.")
                col_names = [c.lower() for c in data.columns]
                if 'domain' in col_names:
                    idx = col_names.index('domain')
                    domains = data.iloc[:, idx].astype(str).tolist()
                else:
                    print(f"[*] No 'domain' column found. Falling back to the first column: {data.columns[0]}")
                    domains = data.iloc[:, 0].astype(str).tolist()
            else:
                raise ValueError(f"Unsupported data type in pickle: {type(data)}")
        except ImportError:
            raise ValueError(f"Unsupported data type in pickle: {type(data)}. pandas could not be imported.")
            
    # Clean domains: lowercase, remove empty, ensure basic validity
    cleaned_domains = []
    for d in domains:
        d = d.strip().lower()
        if d and '.' in d and len(d) > 3:
            cleaned_domains.append(d)
            
    return list(set(cleaned_domains))

def split_domain(domain: str) -> Tuple[str, str]:
    """Split a domain into name and TLD."""
    if '.' in domain:
        parts = domain.rsplit('.', 1)
        return parts[0], parts[1]
    return domain, ""

def validate_typosquat(original: str, generated: str) -> bool:
    """Check if the generated domain is valid and different."""
    return (
        generated != original and 
        len(generated) > 0 and 
        '.' in generated and 
        not generated.startswith('.') and 
        not generated.endswith('.')
    )

def generate_omission(domain: str) -> str:
    """Generate typosquatting by omitting a character."""
    name, tld = split_domain(domain)
    if len(name) > 1:
        idx = random.randint(0, len(name) - 1)
        res = name[:idx] + name[idx+1:] + (f".{tld}" if tld else "")
        if validate_typosquat(domain, res):
            return res
    return domain

def generate_duplication(domain: str) -> str:
    """Generate typosquatting by duplicating a character."""
    name, tld = split_domain(domain)
    if len(name) > 0:
        idx = random.randint(0, len(name) - 1)
        res = name[:idx] + name[idx]*2 + name[idx+1:] + (f".{tld}" if tld else "")
        if validate_typosquat(domain, res):
            return res
    return domain

def generate_substitution(domain: str) -> str:
    """Generate typosquatting by substituting a character."""
    name, tld = split_domain(domain)
    if len(name) > 0:
        idx = random.randint(0, len(name) - 1)
        char = name[idx]
        sub = random.choice(string.ascii_lowercase.replace(char, '')) if char in string.ascii_lowercase else 'a'
        res = name[:idx] + sub + name[idx+1:] + (f".{tld}" if tld else "")
        if validate_typosquat(domain, res):
            return res
    return domain

def generate_adjacent_keyboard(domain: str) -> str:
    """Generate typosquatting by replacing a character with an adjacent keyboard key."""
    name, tld = split_domain(domain)
    candidates = [i for i, c in enumerate(name) if c in ADJACENT_KEYS]
    if candidates:
        idx = random.choice(candidates)
        sub = random.choice(ADJACENT_KEYS[name[idx]])
        res = name[:idx] + sub + name[idx+1:] + (f".{tld}" if tld else "")
        if validate_typosquat(domain, res):
            return res
    return domain

def generate_homoglyph(domain: str) -> str:
    """Generate typosquatting by replacing a character with a look-alike (homoglyph)."""
    name, tld = split_domain(domain)
    candidates = [i for i, c in enumerate(name) if c in HOMOGLYPHS]
    if candidates:
        idx = random.choice(candidates)
        sub = random.choice(HOMOGLYPHS[name[idx]])
        res = name[:idx] + sub + name[idx+1:] + (f".{tld}" if tld else "")
        if validate_typosquat(domain, res):
            return res
    return domain

def generate_transposition(domain: str) -> str:
    """Generate typosquatting by swapping adjacent characters."""
    name, tld = split_domain(domain)
    if len(name) > 1:
        idx = random.randint(0, len(name) - 2)
        res = name[:idx] + name[idx+1] + name[idx] + name[idx+2:] + (f".{tld}" if tld else "")
        if validate_typosquat(domain, res):
            return res
    return domain

def main():
    pickle_path = "top_domains_cache.pkl"
    output_csv = "typosquatting_dataset.csv"
    report_file = "dataset_statistics.txt"
    
    print(f"[*] Starting dataset generation process...")
    try:
        domains = load_domains(pickle_path)
        print(f"[*] Successfully loaded {len(domains)} unique valid domains.")
    except Exception as e:
        print(f"[!] Error loading domains: {e}")
        return

    if len(domains) < 4000:
        print(f"[!] Warning: Less than 4000 domains available. We will use what's available.")
        
    # We need 2000 legitimate and 2000 typosquatting (total 4000 original domains if possible)
    # To avoid duplicates, we'll sample up to 4000 domains.
    sample_size = min(4000, len(domains))
    sampled_domains = random.sample(domains, sample_size)
    
    legit_domains = sampled_domains[:2000]
    typo_base_domains = sampled_domains[2000:4000]
    
    # Attack types mapped to their functions
    attack_functions = {
        "omission": generate_omission,
        "duplication": generate_duplication,
        "substitution": generate_substitution,
        "adjacent_keyboard": generate_adjacent_keyboard,
        "homoglyph": generate_homoglyph,
        "transposition": generate_transposition
    }
    
    attack_names = list(attack_functions.keys())
    dataset = []
    seen_domains = set()
    attack_counts = defaultdict(int)
    examples_by_type = defaultdict(list)
    
    # 1. Add legitimate domains
    for d in legit_domains:
        dataset.append({
            "original_domain": d,
            "domain": d,
            "label": 0,
            "attack_type": "legitimate"
        })
        seen_domains.add(d)
        
    # 2. Generate typosquatting domains
    # Distribute attacks evenly
    for i, base_domain in enumerate(typo_base_domains):
        attack_type = attack_names[i % len(attack_names)]
        func = attack_functions[attack_type]
        
        # Try to generate up to 5 times if domain fails validation or is duplicate
        generated = base_domain
        for _ in range(5):
            generated = func(base_domain)
            if generated != base_domain and generated not in seen_domains:
                break
                
        # If we successfully created a valid typo
        if generated != base_domain and generated not in seen_domains:
            dataset.append({
                "original_domain": base_domain,
                "domain": generated,
                "label": 1,
                "attack_type": attack_type
            })
            seen_domains.add(generated)
            attack_counts[attack_type] += 1
            if len(examples_by_type[attack_type]) < 10:
                examples_by_type[attack_type].append((base_domain, generated))
                
    # Save to CSV
    print(f"[*] Saving dataset to {output_csv}...")
    try:
        with open(output_csv, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=["original_domain", "domain", "label", "attack_type"])
            writer.writeheader()
            writer.writerows(dataset)
    except Exception as e:
        print(f"[!] Error saving CSV: {e}")
        return

    # Calculate final stats
    total_samples = len(dataset)
    num_legit = sum(1 for d in dataset if d['label'] == 0)
    num_typo = sum(1 for d in dataset if d['label'] == 1)
    unique_originals = len(set(d['original_domain'] for d in dataset))
    
    # Generate Summary Report
    report_content = [
        "Dataset Generation Summary Report",
        "=" * 33,
        f"Total samples: {total_samples}",
        f"Number of legitimate domains: {num_legit}",
        f"Number of typosquatting domains: {num_typo}",
        f"Number of unique original domains: {unique_originals}",
        "",
        "Number of samples per attack type:",
        "-" * 34,
        f"  legitimate: {num_legit}"
    ]
    
    for attack_type in attack_names:
        report_content.append(f"  {attack_type}: {attack_counts[attack_type]}")
        
    report_content.extend([
        "",
        "Examples of generated typosquatting domains:",
        "=" * 44
    ])
    
    for attack_type in attack_names:
        report_content.append(f"\nAttack Type: {attack_type}")
        report_content.append("-" * (13 + len(attack_type)))
        for orig, typo in examples_by_type[attack_type]:
            report_content.append(f"  {orig} -> {typo}")
            
    report_text = "\n".join(report_content)
    
    # Save report to file
    print(f"\n[*] Saving report to {report_file}...")
    try:
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(report_text)
    except Exception as e:
        print(f"[!] Error saving report: {e}")

    # Print examples to console
    print("\n[*] Generation Complete! Summary:")
    try:
        print(report_text)
    except UnicodeEncodeError:
        print(report_text.encode('ascii', 'replace').decode('ascii'))

if __name__ == "__main__":
    main()
