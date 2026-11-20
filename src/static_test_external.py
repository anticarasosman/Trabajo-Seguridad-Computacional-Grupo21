import pandas as pd
import static
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

ruta_dataset = BASE_DIR / "data" / "external_url_dataset.csv"

df = pd.read_csv(ruta_dataset, sep=",")

print(df.head())

df['static_phishing_score'] = df['url'].map(static.phishing_score)

new_df = df[['url', 'static_phishing_score', 'label']].copy()

print("Columnas de df:", df.columns.tolist())
print("Columnas de new_df:", new_df.columns.tolist())

output_path = BASE_DIR / "outputs" / "static_phishing_external_test.csv"

output_path.parent.mkdir(parents=True, exist_ok=True)

new_df.to_csv(output_path, index=False, float_format="%.17g")

umbral = 0.10


df_test = pd.read_csv(output_path)

print("Columnas de df_test:", df_test.columns.tolist())

legitimate_estimation = df_test[df_test.static_phishing_score <= umbral]
phishing_estimation = df_test[df_test.static_phishing_score > umbral]

TP = len(phishing_estimation[phishing_estimation.label == 'phishing']) #true positive
FP = len(phishing_estimation[phishing_estimation.label == 'legitimate']) # false positive
FN = len(legitimate_estimation[legitimate_estimation.label == 'phishing']) # false negative
TN = len(legitimate_estimation[legitimate_estimation.label == 'legitimate']) # true negative

print("Filas:", len(df))
print("Labels:")
print(df["label"].value_counts())

print("Predicciones:")
print("TP:", TP)
print("FP:", FP)
print("FN:", FN)
print("TN:", TN)

precision = TP / (TP + FP) if TP + FP else 0
recall = TP / (TP + FN) if TP + FN else 0
FPR = FP / (FP + TN) if FP + TN else 0

print("Resultados para el dataset con umbral", umbral)

# La precisión es la tasa de url clasificadas como phishing que realmente lo son
print("Precision", round(precision, 4) * 100, "%")

# El recall es la tasa de casos de phishing que se detectaron
print("Recall", round(recall, 4) * 100, "%")

# FPR es la tasa de falsos positivos
print("False Positive Rate", round(FPR, 4) * 100, "%")