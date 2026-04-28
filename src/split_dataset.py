# split_dataset.py
import pandas as pd
from sklearn.model_selection import train_test_split
import os

INPUT_PATH = "../data/phishing_emails_massive.csv"
OUTPUT_DIR = "../data/splits"

print("Loading massive dataset...")
df = pd.read_csv(INPUT_PATH)

# Normalize Kaggle dataset columns to match internal format
if 'Email Text' in df.columns and 'Email Type' in df.columns:
    print("Normalizing Kaggle dataset columns...")
    df = df.rename(columns={'Email Text': 'text', 'Email Type': 'label'})
    # Convert string labels to binary (1 for Phishing, 0 for Legitimate/Safe)
    df['label'] = df['label'].apply(lambda x: 1 if str(x).strip() == 'Phishing Email' else 0)
    # Drop rows with empty text
    df = df.dropna(subset=['text'])

print("Total samples:", len(df))
print("Label distribution:")
print(df['label'].value_counts())

# Create output folder if not exists
os.makedirs(OUTPUT_DIR, exist_ok=True)

# First split: Train (70%) and Temp (30%)
train_df, temp_df = train_test_split(
    df,
    test_size=0.30,
    stratify=df['label'],
    random_state=42
)

# Second split: Validation (15%) and Test (15%)
val_df, test_df = train_test_split(
    temp_df,
    test_size=0.50,
    stratify=temp_df['label'],
    random_state=42
)

# Save splits
train_df.to_csv(f"{OUTPUT_DIR}/train.csv", index=False)
val_df.to_csv(f"{OUTPUT_DIR}/validation.csv", index=False)
test_df.to_csv(f"{OUTPUT_DIR}/test.csv", index=False)

print("\nSplit completed!")
print("Train size:", len(train_df))
print("Validation size:", len(val_df))
print("Test size:", len(test_df))