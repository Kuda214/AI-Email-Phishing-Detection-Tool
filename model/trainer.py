import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report, roc_auc_score, confusion_matrix
import joblib
import os

class Colors:
    OKGREEN = '\033[92m'
    OKBLUE  = '\033[94m'
    WARNING = '\033[93m'
    FAIL    = '\033[91m'
    ENDC    = '\033[0m'

def train_phishing_model(preprocessed_csv, model_path="phishing_model_lr.joblib", vectorizer_path="tfidf_vectorizer.joblib"):
    print(f"{Colors.OKCYAN}\n>>> TRAINING & EVALUATION ({preprocessed_csv}) <<<{Colors.ENDC}")
    df = pd.read_csv(preprocessed_csv)
    print(df['label'].value_counts())
    print(df['label'].value_counts(normalize=True))
    print(f"Total examples: {len(df)}")
    df['text'] = df['subject'].astype(str) + " " + df['body'].astype(str)
    X_text = df['text']
    y = df['label'].astype(int)
    vectorizer = TfidfVectorizer(max_features=1000, stop_words='english')
    X_tfidf = vectorizer.fit_transform(X_text)
    import numpy as np
    extra_features = [df[c].values.reshape(-1,1) for c in ['url_count','subject_length'] if c in df.columns]
    if extra_features:
        from scipy.sparse import hstack
        X_all = hstack([X_tfidf] + extra_features)
    else:
        X_all = X_tfidf
    X_train, X_test, y_train, y_test = train_test_split(
        X_all, y, test_size=0.2, random_state=42, stratify=y
    )
    model = LogisticRegression(max_iter=500)
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)
    print(classification_report(y_test, y_pred, digits=4))
    print(f"{Colors.OKBLUE}Accuracy:  {accuracy_score(y_test, y_pred):.4f}{Colors.ENDC}")
    print(f"{Colors.OKBLUE}Precision: {precision_score(y_test, y_pred):.4f}{Colors.ENDC}")
    print(f"{Colors.OKBLUE}Recall:    {recall_score(y_test, y_pred):.4f}{Colors.ENDC}")
    print(f"{Colors.OKBLUE}F1-score:  {f1_score(y_test, y_pred):.4f}{Colors.ENDC}")
    try:
        auc = roc_auc_score(y_test, model.predict_proba(X_test)[:,1])
        print(f"{Colors.OKGREEN}ROC-AUC:   {auc:.4f}{Colors.ENDC}")
    except:
        print(f"{Colors.WARNING}ROC-AUC not available (one class only in test set).{Colors.ENDC}")
    print(f"{Colors.HEADER}Confusion matrix:\n{confusion_matrix(y_test, y_pred)}{Colors.ENDC}")
    joblib.dump(model, os.path.join(os.path.dirname(preprocessed_csv), model_path))
    joblib.dump(vectorizer, os.path.join(os.path.dirname(preprocessed_csv), vectorizer_path))
    print(f"{Colors.OKGREEN}Model and vectorizer saved as {model_path} and {vectorizer_path}.{Colors.ENDC}")
   