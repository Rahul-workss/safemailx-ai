# check_dataset.py
import pandas as pd

# Correct path to CSV file
DATA_PATH = "../data/phishing_legit_dataset_KD_10000.csv"

print("Reading CSV dataset...")

# Read CSV file
df = pd.read_csv(DATA_PATH)

print("Dataset loaded successfully!")
print("Total rows:", df.shape[0])
print("Total columns:", df.shape[1])

print("\nColumn names:")
print(list(df.columns))

print("\nFirst 5 rows:")
print(df.head())