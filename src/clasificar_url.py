"""
Clasifica URLs nuevas con el Random Forest entrenado (solo características léxicas).

Usa el modelo "solo_host": calcula las 12 características léxicas solo sobre
esquema://host (la ruta y los parámetros se ignoran) y devuelve la probabilidad
de phishing y un nivel de riesgo.

Advertencia: en la evaluación por dominio no vistos, este modelo detecta solo
alrededor de un 31% del phishing (recall). Usarlo como único criterio dejaría
pasar la mayoría de los ataques.

Uso (desde la raíz del repositorio):
    python src/clasificar_url.py https://ejemplo.com
    python src/clasificar_url.py URL1 URL2 URL3
    python src/clasificar_url.py < archivo_con_urls.txt

Requiere haber ejecutado antes src/entrenar_random_forest.py.
No hace consultas de red: todo se calcula a partir del texto de la URL.
"""

import sys
from pathlib import Path

from urllib.parse import urlparse

import joblib
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from features_url import CARACTERISTICAS_URL, extraer_caracteristicas, url_a_host  # noqa: E402

BASE_DIR = Path(__file__).resolve().parent.parent
RUTA_MODELO = BASE_DIR / "models" / "rf_solo_host.joblib"

# Escala de riesgo sobre la probabilidad de phishing.
# Los umbrales son una decisión del grupo, no un valor estándar.
ESCALA_RIESGO = [
    (0.20, "bajo"),
    (0.50, "medio"),
    (0.80, "alto"),
    (1.01, "muy alto"),
]


def nivel_de_riesgo(probabilidad: float) -> str:
    for limite, nombre in ESCALA_RIESGO:
        if probabilidad < limite:
            return nombre
    return "muy alto"


NOTA_RUTA = "la ruta y los parámetros se ignoran"


def tiene_ruta(url: str) -> bool:
    """True si la URL tiene ruta o parámetros de consulta."""
    p = urlparse(url if "://" in url else f"http://{url}")
    return p.path not in ("", "/") or bool(p.query)


def cargar_modelo():
    if not RUTA_MODELO.exists():
        raise SystemExit(
            f"No encuentro el modelo en {RUTA_MODELO}. "
            "Ejecuta primero: python src/entrenar_random_forest.py"
        )
    return joblib.load(RUTA_MODELO)


def clasificar(urls: list[str], modelo=None) -> pd.DataFrame:
    """Devuelve un DataFrame con la URL, la probabilidad de phishing y el nivel de riesgo."""
    modelo = modelo or cargar_modelo()
    urls = [u.strip() for u in urls if u.strip()]
    if not urls:
        return pd.DataFrame(columns=["url", "prob_phishing", "veredicto", "riesgo", "nota"])

    caracteristicas = pd.DataFrame([extraer_caracteristicas(url_a_host(u)) for u in urls])
    caracteristicas = caracteristicas[CARACTERISTICAS_URL]
    probabilidades = modelo.predict_proba(caracteristicas)[:, 1]

    return pd.DataFrame(
        {
            "url": urls,
            "prob_phishing": probabilidades.round(4),
            "veredicto": ["phishing probable" if p >= 0.5 else "legítima probable" for p in probabilidades],
            "riesgo": [nivel_de_riesgo(p) for p in probabilidades],
            "nota": [NOTA_RUTA if tiene_ruta(u) else "" for u in urls],
        }
    )


def main():
    if len(sys.argv) > 1:
        urls = sys.argv[1:]
    else:
        urls = sys.stdin.read().splitlines()

    resultado = clasificar(urls)
    if resultado.empty:
        print("Uso: python src/clasificar_url.py URL [URL ...]")
        sys.exit(1)

    pd.set_option("display.max_colwidth", 80)
    pd.set_option("display.width", 200)
    print(resultado.to_string(index=False))
    print(
        "\nRecordatorio: el modelo detecta alrededor de un 31% del phishing en dominios nuevos. "
        "Un veredicto 'legítima probable' no garantiza que la URL sea segura."
    )


if __name__ == "__main__":
    main()
