import glob
import pandas as pd

files = sorted(glob.glob("data/raw/*.csv"))
print(len(files), "CSV files mili:")
for f in files:
    print("  -", f)

# Sirf pehli file load karo (test ke liye)
df = pd.read_csv(files[0], encoding="latin1", low_memory=False)
df.columns = df.columns.str.strip()      # column names ke aage/peeche ke spaces hatao

print("\nShape (rows, columns):", df.shape)
print("\nPehle 10 column names:", df.columns.tolist()[:10])
print("\nLabel counts:")
print(df["Label"].value_counts())