# clean_dataset.py
import pandas as pd

# Paths
INPUT_PATH = "../data/phishing_legit_dataset_KD_10000.csv"
OUTPUT_PATH = "../data/clean_emails.csv"

print("Loading dataset...")
df = pd.read_csv(INPUT_PATH)

print("Initial shape:", df.shape)

# Keep only required columns
df = df[['text', 'label']]

# Drop empty rows
df = df.dropna()

# Convert label to numeric safely
df['label'] = pd.to_numeric(df['label'], errors='coerce')

# Keep only valid labels (0 and 1)
df = df[df['label'].isin([0, 1])]

# Map numeric labels to text labels (FOR CLARITY)
df['label'] = df['label'].map({
    1: 'phishing',
    0: 'legitimate'
})

# Remove duplicate emails
df = df.drop_duplicates(subset=['text'])

print("Cleaned shape:", df.shape)

# Save cleaned dataset
df.to_csv(OUTPUT_PATH, index=False)

print("Clean dataset saved at:", OUTPUT_PATH)