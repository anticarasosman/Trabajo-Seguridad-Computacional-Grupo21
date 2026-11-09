import pandas as pd
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

ruta_dataset = BASE_DIR / "data" / "merged_features_final.csv"

df = pd.read_csv(ruta_dataset, sep=";")

print("Dimensiones del dataset:")
print(df.shape)

print("\nColumnas del dataset:")
print(df.columns.tolist())

print("\nInformación del dataset:")
df.info()

print("\nValores faltantes por columna:")
print(df.isnull().sum())

print("\nRegistros que contienen valores faltantes:")
print(df[df.isnull().any(axis=1)])

print("\nCantidad de URLs duplicadas:")
print(df["url"].duplicated().sum())

print("\nDistribución de las etiquetas:")
print(df["label"].value_counts())

print("\nPorcentaje por etiqueta:")
print(df["label"].value_counts(normalize=True) * 100)

print("\nEstadísticas de las características:")
print(df.describe())

print("\nEstadísticas detalladas:")
print(df.describe().T)


print("\nURL más larga:")
indice = df["url_length"].idxmax()
print("Longitud:", df.loc[indice, "url_length"])
print("Etiqueta:", df.loc[indice, "label"])
print("URL:", df.loc[indice, "url"][:200])

print("\nCantidad de valores -1:")
print("domain_age:", (df["domain_age"] == -1).sum())
print("ttl:", (df["ttl"] == -1).sum())

print("\nRegistro con mayor cantidad de signos '=':")
indice = df["num_eq"].idxmax()
print(df.loc[indice, ["url", "num_eq", "label"]])


print("\nValores distintos de las variables binarias:")

columnas_binarias = [
    "random_domain",
    "prefix_suffix",
    "dns_resolvable"
]

for columna in columnas_binarias:
    print(columna, ":", sorted(df[columna].dropna().unique()))


print("\nPromedio de características por clasificación:")

print(df.groupby("label").mean(numeric_only=True).T)


print("\nMediana de características por clasificación:")
print(df.groupby("label").median(numeric_only=True).T)

tabla = df.groupby("label").describe().T
tabla.to_csv("resumen_caracteristicas.csv")
