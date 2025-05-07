import joblib
import re
import pandas as pd
from pathlib import Path

MODEL_PATH = str(Path("../model/phishing_model_lr.joblib").resolve())
VECTORIZER_PATH = str(Path("../model/tfidf_vectorizer.joblib").resolve())

def load_model_vectorizer():
    model = joblib.load(MODEL_PATH)
    vectorizer = joblib.load(VECTORIZER_PATH)
    return model, vectorizer

def preprocess_email(content):
    lines = content.splitlines()
    sender = receiver = subject = ''
    body_lines = []
    for line in lines:
        low = line.lower()
        if low.startswith("from:"):
            sender = line.split(":",1)[1].strip()
        elif low.startswith("to:"):
            receiver = line.split(":",1)[1].strip()
        elif low.startswith("subject:"):
            subject = line.split(":",1)[1].strip()
        elif low.strip() != '':
            body_lines.append(line)
    body = "\n".join(body_lines)
    url_count = len(re.findall(r'http[^\s]+', body, re.IGNORECASE))
    subject_length = len(subject)
    data = {
        'sender': sender.lower() if sender else 'unknown',
        'receiver': receiver.lower() if receiver else 'unknown',
        'subject': subject.lower(),
        'body': body.lower(),
        'url_count': url_count,
        'subject_length': subject_length
    }
    return pd.DataFrame([data])

def get_global_top_phishing_terms(model, vectorizer, topn=12):
    feature_names = vectorizer.get_feature_names_out()
    topn_idx = model.coef_[0].argsort()[-topn:][::-1]
    return [feature_names[i] for i in topn_idx]

def get_top_contributing_features(email_text, model, vectorizer, topn=6):
    df = preprocess_email(email_text)
    text = df["subject"] + " " + df["body"]
    X_tfidf = vectorizer.transform(text)
    feature_names = vectorizer.get_feature_names_out()
    coef = model.coef_[0]
    nz_idx = X_tfidf.nonzero()[1]
    contribs = [(feature_names[i], coef[i]) for i in nz_idx]
    contribs = sorted(contribs, key=lambda x: abs(x[1]), reverse=True)
    return contribs[:topn] if contribs else []

def highlight_suspicious_model(text, model, vectorizer, sender_addr=None, topn=12):
    # highlight all top phishing terms in input text
    phishing_terms = get_global_top_phishing_terms(model, vectorizer, topn=topn)
    for phrase in sorted(phishing_terms, key=lambda x: -len(x)):
        pattern = re.compile(rf'({re.escape(phrase)})', re.IGNORECASE)
        text = pattern.sub(r'<mark class="orange-mark">\1</mark>', text)
    # suspicious senders: highlight known free/public email and "unknown"
    suspicious_senders = [".ru", ".cn", "qq.com", "163.com", "protonmail", "yopmail", "unknown"]
    if sender_addr:
        for sus in suspicious_senders:
            if sus in sender_addr.lower():
                text = text.replace(sender_addr, f'<span class="sender-meta">{sender_addr}</span>')
    return text

def predict_email(content):
    model, vectorizer = load_model_vectorizer()
    df = preprocess_email(content)
    text = df['subject'] + ' ' + df['body']
    X_tfidf = vectorizer.transform(text)
    import numpy as np
    from scipy.sparse import hstack
    X_extras = np.hstack([df['url_count'].values.reshape(-1,1), df['subject_length'].values.reshape(-1,1)])
    X_pred = hstack([X_tfidf, X_extras])
    pred = model.predict(X_pred)[0]
    conf = model.predict_proba(X_pred)[0].max()
    label = "phishing" if pred == 1 else "legitimate"
    # Explainability
    top_features = get_top_contributing_features(content, model, vectorizer)
    sender = df.loc[0,"sender"]
    highlighted = highlight_suspicious_model(content, model, vectorizer, sender_addr=sender)
    global_phish_terms = get_global_top_phishing_terms(model, vectorizer)
    return label, int(conf * 100), top_features, sender, highlighted, global_phish_terms