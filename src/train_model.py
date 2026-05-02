
import pandas as pd
import joblib

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report


# -------- Load datasets --------
train_path = "../data/splits/train.csv"
val_path = "../data/splits/validation.csv"

train_df = pd.read_csv(train_path)
val_df = pd.read_csv(val_path)

X_train = train_df["text"]
y_train = train_df["label"]

X_val = val_df["text"]
y_val = val_df["label"]


# -------- Build ML pipeline --------
model = Pipeline([
    ("tfidf", TfidfVectorizer(
        lowercase=True,
        stop_words="english",
        max_features=20000,
        ngram_range=(1, 2)
    )),
    ("clf", LogisticRegression(
        max_iter=1000,
        class_weight="balanced"
    ))
])


# -------- Train model --------
print("Training text classification model...")
model.fit(X_train, y_train)


# -------- Validate model --------
print("\nValidation Results:")
y_pred = model.predict(X_val)
print(classification_report(y_val, y_pred))


# -------- Save model --------
joblib.dump(model, "../models/phishing_ai_model.joblib")
print("\nModel saved successfully!")
