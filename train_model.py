import pandas as pd
import re
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
import joblib

# Load CSV
df = pd.read_csv("phishing_model.csv")

# Normalize text
df["type"] = df["type"].astype(str).str.lower().str.strip()

# Function to convert ANY label safely
def label_converter(x):
    if "phish" in x:
        return 1
    elif "benign" in x or "legit" in x or x == "0":
        return 0
    else:
        return None

df["label"] = df["type"].apply(label_converter)

# DROP all bad rows safely
df = df.dropna(subset=["label"])

# Clean URL
def clean_url(url):
    url = str(url).lower()
    url = re.sub(r"https?://", "", url)
    url = re.sub(r"www.", "", url)
    return url

df["url"] = df["url"].apply(clean_url)

X = df["url"]
y = df["label"].astype(int)

# DEBUG PRINT (VERY IMPORTANT)
print("Label count:")
print(y.value_counts())

# ML Pipeline
model = Pipeline([
    ("tfidf", TfidfVectorizer(analyzer="char", ngram_range=(3,5))),
    ("clf", LogisticRegression(max_iter=2000))
])

# Train
model.fit(X, y)

# Save
joblib.dump(model, "phishing_model.pkl")

print("✅ MODEL TRAINED SUCCESSFULLY — NO NaN")
