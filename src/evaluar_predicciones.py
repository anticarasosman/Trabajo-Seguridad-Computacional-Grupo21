"""
Evaluador común para comparar métodos de detección de phishing.

Cualquier método (Random Forest, sistema de reglas, otro) puede evaluarse
con este script, siempre que entregue un CSV con estas columnas:

    url;prob_phishing

- prob_phishing: número entre 0 y 1. Para métodos de reglas que solo dan
  una clasificación, usar 1.0 si predicen phishing y 0.0 si predicen legítimo.

El script une las predicciones con outputs/test_por_dominio.csv (el test
por dominio, el mismo para todos los métodos) y calcula las mismas métricas.

Uso:
    python src/evaluar_predicciones.py ruta/predicciones.csv --nombre mi_metodo

Genera outputs/metricas_<nombre>.csv con las métricas.
"""

import argparse
from pathlib import Path

import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)

BASE_DIR = Path(__file__).resolve().parent.parent
RUTA_TEST = BASE_DIR / "outputs" / "test_por_dominio.csv"
RUTA_OUTPUTS = BASE_DIR / "outputs"
UMBRAL = 0.5


def evaluar(df: pd.DataFrame) -> dict:
    y = df["y"]
    prob = df["prob_phishing"]
    pred = (prob >= UMBRAL).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    auc = roc_auc_score(y, prob) if y.nunique() > 1 else float("nan")
    return {
        "n": int(len(df)),
        "accuracy": float(accuracy_score(y, pred)),
        "precision": float(precision_score(y, pred, zero_division=0)),
        "recall": float(recall_score(y, pred, zero_division=0)),
        "f1": float(f1_score(y, pred, zero_division=0)),
        "tasa_falsos_positivos": float(fp / (fp + tn)) if (fp + tn) else 0.0,
        "auc": float(auc),
        "tn": int(tn),
        "fp": int(fp),
        "fn": int(fn),
        "tp": int(tp),
    }


def main():
    parser = argparse.ArgumentParser(description="Evalúa predicciones sobre el test por dominio.")
    parser.add_argument("predicciones", type=Path, help="CSV con columnas url;prob_phishing")
    parser.add_argument("--nombre", required=True, help="Nombre del método, para el archivo de salida")
    args = parser.parse_args()

    test = pd.read_csv(RUTA_TEST, sep=";")
    pred = pd.read_csv(args.predicciones, sep=";")

    columnas_requeridas = {"url", "prob_phishing"}
    faltan = columnas_requeridas - set(pred.columns)
    if faltan:
        raise SystemExit(f"Faltan columnas en el archivo de predicciones: {sorted(faltan)}")
    if pred["url"].duplicated().any():
        raise SystemExit("Hay URLs repetidas en el archivo de predicciones")

    union = test.merge(pred[["url", "prob_phishing"]], on="url", how="left")
    faltantes = union["prob_phishing"].isna().sum()
    if faltantes:
        raise SystemExit(
            f"Faltan predicciones para {faltantes} de {len(test)} URLs del test. "
            "Todos los métodos deben predecir el mismo conjunto."
        )
    if not union["prob_phishing"].between(0, 1).all():
        raise SystemExit("prob_phishing debe estar entre 0 y 1")

    m = evaluar(union)
    print(f"Método: {args.nombre} (URLs evaluadas: {m['n']}, umbral {UMBRAL})")
    for k in ["accuracy", "precision", "recall", "f1", "tasa_falsos_positivos", "auc"]:
        print(f"  {k}: {m[k]:.4f}")
    print(f"  matriz: TN={m['tn']} FP={m['fp']} FN={m['fn']} TP={m['tp']}")

    salida = RUTA_OUTPUTS / f"metricas_{args.nombre}.csv"
    pd.DataFrame([{"metodo": args.nombre, **m}]).to_csv(salida, index=False, sep=";")
    print(f"Guardado en {salida}")


if __name__ == "__main__":
    main()
