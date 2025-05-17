import pandas as pd
import uuid
import re
import os

# Terminal color codes for results/info
class Colors:
    HEADER  = '\033[95m'
    OKBLUE  = '\033[94m'
    OKCYAN  = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL    = '\033[91m'
    ENDC    = '\033[0m'
    

REQUIRED_COLS = ['sender', 'receiver', 'date', 'subject', 'body', 'urls', 'label']

def preprocess_sender_field(email):
    return str(email).strip().lower() if email else "unknown"

def preprocess_body_field(body):
    return str(body).strip().lower()

def extract_url_count(body):
    url_pattern = re.compile(r'http[^\s]+', re.IGNORECASE)
    return len(url_pattern.findall(str(body)))

def extract_subject_length(subject):
    return len(str(subject)) if subject else 0

def load_and_inspect_csv(path):
    df = pd.read_csv(path)
    print(f"\n{Colors.HEADER}File: {os.path.basename(path)}{Colors.ENDC}")
    print(f"Total rows: {len(df)}")
    if 'label' in df.columns:
        label_counts = df['label'].value_counts(dropna=False)
        print("Label distribution (raw):")
        for value, count in label_counts.items():
            print(f"  Value: {value}  Count: {count}")
    return df

def preprocess_csvs(csv_paths):
    dfs = []
    for path in csv_paths:
        df = load_and_inspect_csv(path)
        dfs.append(df)
    df = pd.concat(dfs, ignore_index=True)
    print(f"{Colors.OKBLUE}\nCombined total rows: {len(df)}{Colors.ENDC}")
    before = len(df)
    df = df[df['label'].isin([0, 1])]
    after = len(df)
    print(f"{Colors.WARNING}Removed {before-after} rows with missing or invalid labels (label != 0 or 1).{Colors.ENDC}")
    print(f"{Colors.OKBLUE}Label distribution (after cleaning):\n{df['label'].value_counts()}{Colors.ENDC}")

    missing = [col for col in REQUIRED_COLS if col not in df.columns]
    if missing:
        print(f"{Colors.FAIL}Cannot process: Missing columns: {missing}{Colors.ENDC}")
        return None

    df['sender'] = df['sender'].apply(preprocess_sender_field)
    df['receiver'] = df['receiver'].apply(preprocess_sender_field)
    df['subject'] = df['subject'].apply(preprocess_body_field)
    df['body'] = df['body'].apply(preprocess_body_field)
    df['url_count'] = df['body'].apply(extract_url_count)
    df['subject_length'] = df['subject'].apply(extract_subject_length)
    df['sender'] = df['sender'].replace('', 'unknown').fillna('unknown')
    df['receiver'] = df['receiver'].replace('', 'unknown').fillna('unknown')
    df['urls'] = df['urls'].replace('', 'none').fillna('none')
    df['date'] = df['date'].fillna('unknown')

    random_id = str(uuid.uuid4())[:8]
    output_csv = f"{random_id}_preprocessed.csv"
    df.to_csv(output_csv, index=False)
    print(f"{Colors.OKGREEN}Preprocessed CSV written to: {output_csv}{Colors.ENDC}")
    # Call trainer
    from trainer import train_phishing_model
    train_phishing_model(output_csv, model_path="phishing_model_lr.joblib", vectorizer_path="tfidf_vectorizer.joblib")
    print(f"{Colors.OKGREEN}Model trained and saved in model folder!{Colors.ENDC}")

def main_cli():
    print("Enter the CSV file paths for training, separated by commas:")
    csv_paths = input().strip().split(",")
    csv_paths = [p.strip() for p in csv_paths if p.strip()]
    preprocess_csvs(csv_paths)

if __name__ == "__main__":
    main_cli()