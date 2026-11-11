import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from features_url import CARACTERISTICAS_URL, extraer_caracteristicas  # noqa: E402

BASE_DIR = Path(__file__).resolve().parent.parent
RUTA_DATASET = BASE_DIR / "data" / "merged_features_final.csv"
TOLERANCIA = 1e-6


def main():
    df = pd.read_csv(RUTA_DATASET, sep=";").dropna().reset_index(drop=True)
    calculado = pd.DataFrame([extraer_caracteristicas(u) for u in df["url"]])

    print(f"URLs validadas: {len(df)}")
    total_malas = 0
    for col in CARACTERISTICAS_URL:
        diferencias = np.abs(calculado[col].to_numpy(float) - df[col].to_numpy(float))
        malas = int((diferencias > TOLERANCIA).sum())
        total_malas += malas
        estado = "OK" if malas == 0 else f"{malas} filas distintas"
        print(f"  {col:20s} {estado}")

    if total_malas == 0:
        print("\nTodas las características coinciden con el dataset.")
    else:
        print(f"\nHay {total_malas} diferencias. Revisar antes de usar el modelo.")
        sys.exit(1)


if __name__ == "__main__":
    main()
