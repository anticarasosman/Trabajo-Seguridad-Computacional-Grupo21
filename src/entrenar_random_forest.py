import sys
from pathlib import Path
from urllib.parse import urlparse

import joblib
import numpy as np
import pandas as pd
import tldextract
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import GroupShuffleSplit, train_test_split

RANDOM_STATE = 42
TEST_SIZE = 0.2

UMBRAL_DOMINIO_FRECUENTE = 300

BASE_DIR = Path(__file__).resolve().parent.parent
RUTA_DATASET = BASE_DIR / "data" / "merged_features_final.csv"
RUTA_OUTPUTS = BASE_DIR / "outputs"
RUTA_MODELOS = BASE_DIR / "models"


sys.path.insert(0, str(Path(__file__).resolve().parent))
from features_url import (  
    CARACTERISTICAS_URL as FEATURES_URL,
    extraer_caracteristicas,
    url_a_host,
)

# Características que requieren consultas externas (DNS / WHOIS)
FEATURES_EXTERNAS = [
    "domain_age",
    "dns_resolvable",
    "num_ips",
    "ttl",
    "num_name_servers",
]

def con_caracteristicas_de_host(df: pd.DataFrame) -> pd.DataFrame:
    df_h = df.copy()
    calculadas = pd.DataFrame(
        [extraer_caracteristicas(url_a_host(u)) for u in df["url"]], index=df.index
    )
    for col in FEATURES_URL:
        df_h[col] = calculadas[col]
    return df_h


_extractor = tldextract.TLDExtract(suffix_list_urls=())


def dominio_registrable(url: str) -> str:
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


def separar_por_dominio(df: pd.DataFrame):
    gss = GroupShuffleSplit(n_splits=1, test_size=TEST_SIZE, random_state=RANDOM_STATE)
    idx_train, idx_test = next(gss.split(df, df["y"], groups=df["dominio"]))
    df_train = df.iloc[idx_train]
    df_test = df.iloc[idx_test]
    assert not (set(df_train["dominio"]) & set(df_test["dominio"])), (
        "Hay dominios compartidos entre train y test"
    )
    return df_train, df_test


def metricas(y_true, y_pred, y_prob) -> dict:
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "tasa_falsos_positivos": float(fp / (fp + tn)) if (fp + tn) else 0.0,
        "auc": float(roc_auc_score(y_true, y_prob)),
        "tn": int(tn),
        "fp": int(fp),
        "fn": int(fn),
        "tp": int(tp),
    }


def entrenar(X_train, y_train) -> RandomForestClassifier:
    modelo = RandomForestClassifier(
        n_estimators=300,
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )
    modelo.fit(X_train, y_train)
    return modelo


def evaluar(nombre_conjunto, features, df_train, df_test, particion, guardar=False):
    modelo = entrenar(df_train[features], df_train["y"])
    prob = modelo.predict_proba(df_test[features])[:, 1]
    pred = (prob >= 0.5).astype(int)
    m = metricas(df_test["y"], pred, prob)
    print(f"[{particion}] " + ", ".join(
        f"{k}={m[k]:.4f}" for k in ["accuracy", "precision", "recall", "f1", "tasa_falsos_positivos", "auc"]
    ))

    importancia = pd.DataFrame(
        {
            "conjunto": nombre_conjunto,
            "particion": particion,
            "caracteristica": features,
            "importancia": modelo.feature_importances_,
        }
    ).sort_values("importancia", ascending=False)

    if guardar:
        analisis = df_test[["url", "dominio", "label"]].reset_index(drop=True)
        analisis["prob_phishing"] = prob
        analisis["prediccion"] = np.where(pred == 1, "phishing", "legitimate")
        analisis = pd.concat(
            [analisis, df_test[features].reset_index(drop=True)], axis=1
        )
        fp_df = analisis[(analisis["label"] == "legitimate") & (pred == 1)]
        fn_df = analisis[(analisis["label"] == "phishing") & (pred == 0)]
        fp_df.sort_values("prob_phishing", ascending=False).to_csv(
            RUTA_OUTPUTS / f"errores_falsos_positivos_{nombre_conjunto}.csv",
            index=False, sep=";",
        )
        fn_df.sort_values("prob_phishing").to_csv(
            RUTA_OUTPUTS / f"errores_falsos_negativos_{nombre_conjunto}.csv",
            index=False, sep=";",
        )
        joblib.dump(modelo, RUTA_MODELOS / f"rf_{nombre_conjunto}.joblib")
        print(f"  Errores: {len(fp_df)} falsos positivos, {len(fn_df)} falsos negativos")

    return m, importancia


def main():
    RUTA_OUTPUTS.mkdir(exist_ok=True)
    RUTA_MODELOS.mkdir(exist_ok=True)

    df = cargar_datos()
    print(f"URLs: {len(df)} | dominios registrables: {df['dominio'].nunique()}")

    conteo = df["dominio"].value_counts()
    hosting = conteo[conteo >= UMBRAL_DOMINIO_FRECUENTE]
    pd.DataFrame(
        {
            "dominio": hosting.index,
            "urls": hosting.values,
            "fraccion_phishing": [
                df.loc[df["dominio"] == d, "y"].mean() for d in hosting.index
            ],
        }
    ).to_csv(RUTA_OUTPUTS / "dominios_hosting_excluidos.csv", index=False, sep=";")
    print(f"Dominios de hosting (>= {UMBRAL_DOMINIO_FRECUENTE} URLs): {len(hosting)}")
    df_sin_hosting = df[~df["dominio"].isin(hosting.index)]
    df_host = con_caracteristicas_de_host(df)
    print(f"URLs sin dominios de hosting: {len(df_sin_hosting)}")

    df_train, df_test = separar_por_dominio(df)
    print(
        f"\nSeparación por dominio -> train: {len(df_train)} "
        f"(phishing {df_train['y'].mean():.1%}) | "
        f"test: {len(df_test)} (phishing {df_test['y'].mean():.1%})"
    )

    df_test[["url", "dominio", "label", "y"]].to_csv(
        RUTA_OUTPUTS / "test_por_dominio.csv", index=False, sep=";"
    )

    df_train_rnd, df_test_rnd = train_test_split(
        df, test_size=TEST_SIZE, stratify=df["y"], random_state=RANDOM_STATE
    )

    df_train_sh, df_test_sh = separar_por_dominio(df_sin_hosting)
    print(
        f"Sin hosting -> train: {len(df_train_sh)} | test: {len(df_test_sh)} "
        f"(phishing {df_test_sh['y'].mean():.1%})"
    )

    resultados = []
    importancias = []

    configuraciones = [
        ("solo_url", FEATURES_URL, df),
        ("completo", FEATURES_URL + FEATURES_EXTERNAS, df),
        ("solo_host", FEATURES_URL, df_host),
    ]

    for nombre, features, base in configuraciones:
        print(f"\n=== {nombre} ({len(features)} variables) ===")

        m, imp = evaluar(
            nombre, features,
            base.loc[df_train.index], base.loc[df_test.index],
            "por_dominio", guardar=True,
        )
        resultados.append({"conjunto": nombre, "particion": "por_dominio", **m})
        importancias.append(imp)

        m, _ = evaluar(
            nombre, features,
            base.loc[df_train_sh.index], base.loc[df_test_sh.index],
            "por_dominio_sin_hosting",
        )
        resultados.append({"conjunto": nombre, "particion": "por_dominio_sin_hosting", **m})

        m, _ = evaluar(
            nombre, features,
            base.loc[df_train_rnd.index], base.loc[df_test_rnd.index],
            "aleatoria",
        )
        resultados.append({"conjunto": nombre, "particion": "aleatoria", **m})

    pd.DataFrame(resultados).to_csv(RUTA_OUTPUTS / "metricas.csv", index=False, sep=";")
    pd.concat(importancias).to_csv(
        RUTA_OUTPUTS / "importancia_caracteristicas.csv", index=False, sep=";"
    )
    print(f"\nResultados guardados en {RUTA_OUTPUTS}")


if __name__ == "__main__":
    main()
