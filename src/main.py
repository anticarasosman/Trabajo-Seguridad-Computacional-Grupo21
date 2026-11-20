"""
Analiza una URL con las dos partes del proyecto:
  1. Sistema de reglas (src/static.py), con puntaje de 0 a 1.
  2. Random Forest solo con características del host (models/rf_solo_host.joblib).

Uso (desde la raíz del repositorio):
    python src/main.py https://ejemplo.com
    python src/main.py            # pide la URL por teclado

Requiere haber ejecutado antes: python src/entrenar_random_forest.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import static  # noqa: E402
from clasificar_url import clasificar  # noqa: E402

UMBRAL_REGLAS = 0.10  # ver outputs/umbral_reglas.csv para la elección con train


def analizar(url: str) -> dict:
    puntaje = static.phishing_score(url)
    resultado_rf = clasificar([url]).iloc[0]
    return {
        "url": url,
        "reglas_puntaje": round(float(puntaje), 3),
        "reglas_veredicto": "phishing" if puntaje > UMBRAL_REGLAS else "legítima",
        "rf_prob_phishing": float(resultado_rf["prob_phishing"]),
        "rf_veredicto": resultado_rf["veredicto"],
        "rf_riesgo": resultado_rf["riesgo"],
    }


def mostrar(r: dict):
    print(f"URL: {r['url']}")
    print(f"  Reglas:        puntaje {r['reglas_puntaje']} -> {r['reglas_veredicto']}")
    print(f"  Random Forest: prob. phishing {r['rf_prob_phishing']:.4f} -> {r['rf_veredicto']} ({r['rf_riesgo']})")
    print("  Nota: el Random Forest solo ve el host; detecta alrededor de 3 de cada 10 phishing en dominios nuevos.")


if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else input("Ingrese una URL... ").strip()
    mostrar(analizar(url))
