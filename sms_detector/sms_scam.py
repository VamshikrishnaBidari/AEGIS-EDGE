"""
Scam SMS Detector — interactive mode.
Run: python scam_detector.py            → asks for SMS text, classifies, loops
     python scam_detector.py --train     → train + evaluate + save model first
"""
import os
import re
import string
from pathlib import Path
import joblib
import pandas as pd
from scipy.sparse import hstack
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.svm import LinearSVC
from sklearn.calibration import CalibratedClassifierCV
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import MultinomialNB
from sklearn.ensemble import VotingClassifier
from sklearn.metrics import (accuracy_score, precision_score, recall_score,
                             f1_score, classification_report, confusion_matrix)

MODULE_DIR = Path(__file__).resolve().parent
MODEL_PATH = str(MODULE_DIR / "scam_model.joblib")
DATA_PATH = str(MODULE_DIR / "spam.csv")
THRESHOLD = 0.5   # raise to e.g. 0.7 to reduce false alarms on legit texts

URL_RE = re.compile(r"http\S+|www\.\S+")
PUNCT_TABLE = str.maketrans("", "", string.punctuation)


def clean(text: str) -> str:
    t = URL_RE.sub(" URLTOKEN ", str(text).lower())
    t = t.translate(PUNCT_TABLE)
    return " ".join(t.split())


def build_vectorizers():
    word = TfidfVectorizer(preprocessor=clean, ngram_range=(1, 2),
                           min_df=2, max_df=0.9, sublinear_tf=True)
    char = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5),
                           min_df=2, max_df=0.9, sublinear_tf=True)
    return word, char


class ScamDetector:
    def __init__(self):
        self.word_vec, self.char_vec = build_vectorizers()
        svm = CalibratedClassifierCV(LinearSVC(class_weight="balanced",
                                               dual="auto", random_state=42))
        lr = LogisticRegression(max_iter=2000, class_weight="balanced",
                                random_state=42)
        nb = MultinomialNB(alpha=0.1)
        self.model = VotingClassifier(
            estimators=[("svm", svm), ("lr", lr), ("nb", nb)],
            voting="soft", weights=[2, 2, 1])

    def _features(self, texts, fit=False):
        if fit:
            W = self.word_vec.fit_transform(texts)
            C = self.char_vec.fit_transform(texts)
        else:
            W = self.word_vec.transform(texts)
            C = self.char_vec.transform(texts)
        return hstack([W, C]).tocsr()

    def fit(self, texts, labels):
        self.model.fit(self._features(texts, fit=True), labels)
        return self

    def predict_proba(self, texts):
        return self.model.predict_proba(self._features(texts))[:, 1]

    def predict(self, texts, threshold=THRESHOLD):
        return (self.predict_proba(texts) >= threshold).astype(int)


LABEL_MAP = {"ham": 0, "spam": 1, "legitimate": 0, "smishing": 1, "scam": 1}


def load_data(path=DATA_PATH):
    df = pd.read_csv(path, encoding="latin-1")
    df = df[["v1", "v2"]].rename(columns={"v1": "label", "v2": "text"})
    df["y"] = df["label"].str.lower().map(lambda s: LABEL_MAP.get(s, 0))
    df = df.dropna(subset=["y"])
    if df["y"].nunique() < 2:
        raise ValueError("Dataset needs both scam and legitimate examples.")
    return df


def train(data_path=DATA_PATH, model_path=MODEL_PATH, test_size=0.2):
    df = load_data(data_path)
    print(f"Loaded {len(df)} messages "
          f"({int(df['y'].sum())} scam / {len(df) - int(df['y'].sum())} legitimate)")

    X_tr, X_te, y_tr, y_te = train_test_split(
        df["text"], df["y"], test_size=test_size,
        stratify=df["y"], random_state=42)

    det = ScamDetector().fit(X_tr, y_tr)
    proba = det.predict_proba(X_te)
    pred = (proba >= THRESHOLD).astype(int)

    print(f"\nAccuracy : {accuracy_score(y_te, pred):.4f}")
    print(f"Precision: {precision_score(y_te, pred):.4f}")
    print(f"Recall   : {recall_score(y_te, pred):.4f}")
    print(f"F1       : {f1_score(y_te, pred):.4f}")
    print("\nConfusion matrix:")
    print(confusion_matrix(y_te, pred))
    print("\n" + classification_report(y_te, pred,
                                       target_names=["legitimate", "scam"]))
    joblib.dump(det, model_path)
    print(f"Model saved to {model_path}\n")
    return det


def classify(det, message, threshold=THRESHOLD):
    p = det.predict_proba([message])[0]
    if p >= 0.9:
        verdict = "SCAM — do not click links or reply"
    elif p >= threshold:
        verdict = "LIKELY SCAM — be careful"
    elif p >= 0.2:
        verdict = "UNCERTAIN — verify with the sender directly"
    else:
        verdict = "legitimate"
    return p, verdict


def interactive_loop(det):
    print("=== Scam SMS Detector (type 'quit' to exit) ===")
    while True:
        try:
            msg = input("\nPaste the SMS text: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nBye.")
            break
        if msg.lower() in ("quit", "exit", "q"):
            break
        if not msg:
            continue
        p, verdict = classify(det, msg)
        print(f"  Scam probability : {p:.3f}")
        print(f"  Verdict          : {verdict}")


if __name__ == "__main__":
    import sys
    if "--train" in sys.argv or not os.path.exists(MODEL_PATH):
        if "--train" not in sys.argv:
            print(f"No saved model found — training first ({DATA_PATH})...")
        det = train()
    else:
        det = joblib.load(MODEL_PATH)
    interactive_loop(det)