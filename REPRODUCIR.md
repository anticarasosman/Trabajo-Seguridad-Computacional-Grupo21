# Reproducir resultados y estructura del código

## Estructura

- `src/static.py`: sistema de reglas. Calcula un puntaje de 0 a 1 para una URL.
- `src/features_url.py`: extrae las 12 características léxicas de una URL. Reproduce las columnas del dataset.
- `src/validar_features.py`: verifica que `features_url` coincide con el dataset (las 59.998 filas).
- `src/entrenar_random_forest.py`: entrena los modelos y genera métricas, errores y predicciones.
- `src/umbral_reglas.py`: elige el umbral del sistema de reglas usando solo el train.
- `src/evaluar_predicciones.py`: evalúa cualquier método sobre el mismo test por dominio.
- `src/clasificar_url.py`: clasifica URLs nuevas con el Random Forest.
- `src/main.py`: analiza una URL con ambos métodos.
- `data/merged_features_final.csv`: dataset.
- `outputs/`: resultados generados por los scripts.
- `models/`: modelos entrenados (no se versionan; se generan con `entrenar_random_forest.py`).

## Instalación

```bash
python -m venv .venv
source .venv/bin/activate        # en Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Reproducir resultados

Desde la raíz del repositorio, en este orden:

```bash
python src/validar_features.py        # debe decir que todas las características coinciden
python src/entrenar_random_forest.py  # genera models/ y outputs/ con métricas y errores
python src/umbral_reglas.py           # elige el umbral de reglas con el train
python src/evaluar_predicciones.py outputs/predicciones_rf_solo_host.csv --nombre rf_solo_host
python src/evaluar_predicciones.py outputs/predicciones_reglas.csv --nombre reglas
```

Las particiones son deterministas (`random_state=42`), así que los resultados deberían coincidir.

## Analizar URLs

```bash
python src/main.py "https://ejemplo.com"
python src/clasificar_url.py "https://ejemplo.com" "http://otra-url.xyz/login"
```

## Notas sobre la evaluación

- La separación principal es por **dominio registrable**: ningún dominio aparece en train y test a la vez.
- El modelo principal usa solo el **host** (`esquema://host`). Con la URL completa, el modelo aprende que
  las URLs con ruta son phishing, porque ninguna URL legítima del dataset tiene ruta. Esa versión se
  reporta en `outputs/metricas.csv` solo como comparación.
- En dominios no vistos, el Random Forest solo-host detecta alrededor de 3 de cada 10 casos de phishing.
- Los umbrales de `static.py` fueron definidos mirando los datos del dataset. El umbral de corte se
  eligió con el train.
- `models/` y las predicciones son reproducibles; los errores se analizan en `outputs/analisis_errores.md`.
