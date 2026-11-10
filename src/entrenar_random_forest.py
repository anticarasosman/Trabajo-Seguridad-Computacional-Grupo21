"""
Random Forest para detección de phishing a partir de características de URLs.

Qué hace:
1. Carga el dataset (separador ';') y elimina las 2 filas con valores faltantes.
2. Entrena dos modelos:
   - "solo_url": usa solo características léxicas de la URL.
   - "completo": agrega características que requieren consultas DNS/WHOIS
     (domain_age, ttl, dns_resolvable, num_ips, num_name_servers).
3. Separa train/test por DOMINIO REGISTRABLE (no al azar), para evaluar
   sobre dominios que no aparecieron en el entrenamiento.
4. Calcula precisión, recall, F1, tasa de falsos positivos y AUC.
5. Compara con una separación aleatoria estratificada, para mostrar cuánto
   se sobrestima el desempeño cuando hay dominios repetidos.
6. Exporta falsos positivos/negativos para el análisis de errores,
   importancia de características y el modelo entrenado.

Uso (desde la raíz del repositorio):
    pip install -r requirements.txt
    python src/entrenar_random_forest.py
"""

from pathlib import Path
from urllib.parse import urlparse

import joblib
import numpy as np
import pandas as pd
import tldextract
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
    accuracy_score,
)
from sklearn.model_selection import GroupShuffleSplit, train_test_split

RANDOM_STATE = 42
TEST_SIZE = 0.2

BASE_DIR = Path(__file__).resolve().parent.parent
RUTA_DATASET = BASE_DIR / "data" / "merged_features_final.csv"
RUTA_OUTPUTS = BASE_DIR / "outputs"
RUTA_MODELOS = BASE_DIR / "models"

# Características léxicas: se calculan a partir de la URL
FEATURES_URL = [
    "entropy",
    "url_length",
    "num_www",
    "ratio_digits_url",
    "num_subdomains",
    "length_hostname",
    "random_domain",
    "num_dots",
    "num_hyphens",
    "ratio_digits_host",
    "prefix_suffix",
    "num_question_mark",
    "num_eq",
]

# Características que requieren consultas externas (DNS / WHOIS)
FEATURES_EXTERNAS = [
    "domain_age",
    "dns_resolvable",
    "num_ips",
    "ttl",
    "num_name_servers",
]

CONJUNTOS = {
    "solo_url": FEATURES_URL,
    "completo": FEATURES_URL + FEATURES_EXTERNAS,
}

# Usamos la lista de sufijos empaquetada con tldextract (sin descargas)
_extractor = tldextract.TLDExtract(suffix_list_urls=())


def dominio_registrable(url: str) -> str:
    """Devuelve el dominio registrable, p. ej. 'sub.foo.com.br' -> 'foo.com.br'."""
    host = urlparse(url if "://" in url else f"http://{url}").hostname or ""
    ext = _extractor(host)
    if ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    return host.lower()


def cargar_datos() -> pd.DataFrame:
    df = pd.read_csv(RUTA_DATASET, sep=";")
    filas_antes = len(df)
    df = df.dropna().reset_index(drop=True)
    print(f"Filas eliminadas por valores faltantes: {filas_antes - len(df)}")
    df["y"] = (df["label"] == "phishing").astype(int)
    df["dominio"] = df["url"].map(dominio_registrable)
    return df


def metricas(y_true, y_pred, y_prob) -> dict:
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    return {
        "accuracy": accuracy_score(y_true, y_pred),
        "precision": precision_score(y_true, y_pred, zero_division=0),
        "recall": recall_score(y_true, y_pred, zero_division=0),
        "f1": f1_score(y_true, y_pred, zero_division=0),
        "tasa_falsos_positivos": fp / (fp + tn) if (fp + tn) else 0.0,
        "auc": roc_auc_score(y_true, y_prob),
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "tp": tp,
    }


def entrenar(X_train, y_train) -> RandomForestClassifier:
    modelo = RandomForestClassifier(
        n_estimators=300,
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )
    modelo.fit(X_train, y_train)
    return modelo


def main():
    RUTA_OUTPUTS.mkdir(exist_ok=True)
    RUTA_MODELOS.mkdir(exist_ok=True)

    df = cargar_datos()
    print(f"URLs: {len(df)} | dominios registrables: {df['dominio'].nunique()}")

    # Separación por dominio: ningún dominio aparece en train y test a la vez
    gss = GroupShuffleSplit(n_splits=1, test_size=TEST_SIZE, random_state=RANDOM_STATE)
    idx_train_dom, idx_test_dom = next(gss.split(df, df["y"], groups=df["dominio"]))
    df_train_dom = df.iloc[idx_train_dom]
    df_test_dom = df.iloc[idx_test_dom]

    # Separación aleatoria estratificada (solo como referencia)
    df_train_rnd, df_test_rnd = train_test_split(
        df, test_size=TEST_SIZE, stratify=df["y"], random_state=RANDOM_STATE
    )

    # Verificación de que no hay dominios compartidos entre train y test por dominio
    dominios_compartidos = set(df_train_dom["dominio"]) & set(df_test_dom["dominio"])
    assert not dominios_compartidos, "Hay dominios compartidos entre train y test"

    print(
        f"\nSeparación por dominio -> train: {len(df_train_dom)} "
        f"(phishing {df_train_dom['y'].mean():.1%}) | "
        f"test: {len(df_test_dom)} (phishing {df_test_dom['y'].mean():.1%})"
    )
    print(
        f"Separación aleatoria  -> train: {len(df_train_rnd)} | test: {len(df_test_rnd)}"
    )

    resultados = []
    importancias = []

    for nombre, features in CONJUNTOS.items():
        print(f"\n=== Conjunto de características: {nombre} ({len(features)} variables) ===")

        # Modelo principal: evaluado sobre dominios no vistos
        modelo = entrenar(df_train_dom[features], df_train_dom["y"])
        prob = modelo.predict_proba(df_test_dom[features])[:, 1]
        pred = (prob >= 0.5).astype(int)
        m = metricas(df_test_dom["y"], pred, prob)
        resultados.append({"conjunto": nombre, "particion": "por_dominio", **m})
        print("Por dominio (dominios no vistos):")
        print({k: round(v, 4) if isinstance(v, float) else v for k, v in m.items()})

        # Referencia: separación aleatoria (puede tener dominios repetidos)
        modelo_rnd = entrenar(df_train_rnd[features], df_train_rnd["y"])
        prob_rnd = modelo_rnd.predict_proba(df_test_rnd[features])[:, 1]
        pred_rnd = (prob_rnd >= 0.5).astype(int)
        m_rnd = metricas(df_test_rnd["y"], pred_rnd, prob_rnd)
        resultados.append({"conjunto": nombre, "particion": "aleatoria", **m_rnd})
        print(
            f"Aleatoria (referencia): F1={m_rnd['f1']:.4f}, "
            f"recall={m_rnd['recall']:.4f}, FPR={m_rnd['tasa_falsos_positivos']:.4f}"
        )

        importancias.append(
            pd.DataFrame(
                {
                    "conjunto": nombre,
                    "caracteristica": features,
                    "importancia": modelo.feature_importances_,
                }
            ).sort_values("importancia", ascending=False)
        )

        # Análisis de errores (modelo por dominio)
        analisis = df_test_dom[["url", "dominio", "label"]].reset_index(drop=True)
        analisis["prob_phishing"] = prob
        analisis["prediccion"] = np.where(pred == 1, "phishing", "legitimate")
        analisis = pd.concat([analisis, df_test_dom[features].reset_index(drop=True)], axis=1)
        falsos_positivos = analisis[(analisis["label"] == "legitimate") & (pred == 1)]
        falsos_negativos = analisis[(analisis["label"] == "phishing") & (pred == 0)]
        falsos_positivos.sort_values("prob_phishing", ascending=False).to_csv(
            RUTA_OUTPUTS / f"errores_falsos_positivos_{nombre}.csv", index=False, sep=";"
        )
        falsos_negativos.sort_values("prob_phishing").to_csv(
            RUTA_OUTPUTS / f"errores_falsos_negativos_{nombre}.csv", index=False, sep=";"
        )
        print(
            f"Errores guardados: {len(falsos_positivos)} falsos positivos, "
            f"{len(falsos_negativos)} falsos negativos"
        )

        joblib.dump(modelo, RUTA_MODELOS / f"rf_{nombre}.joblib")

    pd.DataFrame(resultados).to_csv(RUTA_OUTPUTS / "metricas.csv", index=False, sep=";")
    pd.concat(importancias).to_csv(
        RUTA_OUTPUTS / "importancia_caracteristicas.csv", index=False, sep=";"
    )
    print(f"\nResultados guardados en {RUTA_OUTPUTS}")


if __name__ == "__main__":
    main()
