"""
Evalúa el sistema de reglas (src/static.py) con un umbral elegido SOLO con el train.

Los umbrales de static.py no se tocan. Lo único que se decide es el umbral de
corte sobre el puntaje: se elige el que maximiza F1 en el train por dominio, y
luego se evalúa una sola vez sobre el test por dominio. Así las reglas y el
Random Forest se comparan sobre el mismo test, sin que el test haya influido
en la elección del umbral.

Genera:
    outputs/predicciones_reglas.csv   (url;prob_phishing, con 1.0 / 0.0)
    outputs/umbral_reglas.csv         (umbral elegido y curva de F1 en train)

Uso (desde la raíz del repositorio):
    python src/umbral_reglas.py
"""

import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import f1_score

sys.path.insert(0, str(Path(__file__).resolve().parent))
import static  # noqa: E402
from entrenar_random_forest import cargar_datos, separar_por_dominio  # noqa: E402

BASE_DIR = Path(__file__).resolve().parent.parent
RUTA_OUTPUTS = BASE_DIR / "outputs"
CANDIDATOS = np.round(np.arange(0.00, 1.001, 0.01), 2)


def main():
    df = cargar_datos()
    df_train, df_test = separar_por_dominio(df)
    print(f"Train: {len(df_train)} | test: {len(df_test)}")

    puntaje_train = df_train["url"].map(static.phishing_score).to_numpy()
    y_train = df_train["y"].to_numpy()

    curva = []
    for umbral in CANDIDATOS:
        pred = (puntaje_train > umbral).astype(int)
        curva.append({"umbral": umbral, "f1_train": f1_score(y_train, pred, zero_division=0)})
    curva = pd.DataFrame(curva)
    mejor = curva.loc[curva["f1_train"].idxmax()]
    umbral = float(mejor["umbral"])
    print(f"Umbral elegido con train: {umbral} (F1 train = {mejor['f1_train']:.4f})")

    puntaje_test = df_test["url"].map(static.phishing_score).to_numpy()
    prob = (puntaje_test > umbral).astype(float)
    pd.DataFrame({"url": df_test["url"].values, "prob_phishing": prob}).to_csv(
        RUTA_OUTPUTS / "predicciones_reglas.csv", index=False, sep=";"
    )
    curva.to_csv(RUTA_OUTPUTS / "umbral_reglas.csv", index=False, sep=";")
    print(f"Predicciones de reglas guardadas en {RUTA_OUTPUTS / 'predicciones_reglas.csv'}")


if __name__ == "__main__":
    main()
