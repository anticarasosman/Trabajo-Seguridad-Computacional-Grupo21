import pandas as pd
import static
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

ruta_dataset = BASE_DIR / "data" / "merged_features_final.csv"

df = pd.read_csv(ruta_dataset, sep=";")

df['static_phishing_score'] = df['url'].map(static.phishing_score)

new_df = df.filter(['url', 'static_phishing_score', 'label'], axis=1)

new_df.to_csv('static_phishing_test.csv')