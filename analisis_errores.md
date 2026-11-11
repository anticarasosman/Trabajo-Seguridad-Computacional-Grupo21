# Análisis de errores — Random Forest (solo URL, test por dominio)

Fuente: `outputs/errores_falsos_positivos_solo_url.csv` (25 casos) y
`outputs/errores_falsos_negativos_solo_url.csv` (96 casos), sobre el test
por dominio (11.896 URLs, 6.240 phishing y 5.656 legítimas).

Los conteos por patrón son automáticos (reglas sobre el dominio). Las
agrupaciones de cada caso son lectura manual de los ejemplos; no son
exhaustivas.

## Tasas de error por grupo (dentro del test)

| Grupo | Casos | Errores | Tasa |
|---|---|---|---|
| Phishing sin guiones en el dominio | 5.199 | 79 FN | 1.5% |
| Phishing con guiones en el dominio | 1.041 | 17 FN | 1.6% |
| Legítimas sin guiones en el dominio | 5.374 | 7 FP | 0.13% |
| Legítimas con guiones en el dominio | 282 | 18 FP | 6.4% |

Lectura: los falsos positivos se concentran en dominios legítimos con guiones
(unas 50 veces más errores por caso). Los falsos negativos no dependen de los
guiones: aparecen en proporción similar en ambos grupos.

## Falsos positivos (25): legítimas clasificadas como phishing

Patrones observados:

1. **Guiones en nombres de sitios legítimos** (la mayoría): `digital-photography-school.com`,
   `open-telekom-cloud.com`, `funeral-notices.co.uk`, `science-et-vie.com`, `cambridge-news.co.uk`.
   El modelo asocia guiones con phishing porque en el entrenamiento son frecuentes en phishing.
2. **Nombres comerciales cortos y genéricos**: `marketingautomation.services`,
   `materialdesignicons.com`, `pgatoursuperstore.com`, `shop-orchestra.com`.
3. **Dominios con palabras de juego o apuestas**: `davinci-diamonds-slot.com`,
   `free-slot-machines.com`, `sizzling-hot-deluxe-777.com`. Son sitios de este tipo,
   pero el dataset los etiqueta como legítimos; el modelo los trata como phishing.
   Hay que mencionar que la etiqueta de estos casos es discutible.
4. **Dominios internacionalizados (punycode)**: 2 casos con `xn--`, con 4 guiones en el host.

Nota: el falso positivo con mayor confianza (`digital-photography-school.com`,
0.92) no tiene nada que lo distinga de un phishing salvo los guiones y la longitud.

## Falsos negativos (96): phishing clasificado como legítimo

Patrones observados:

1. **Dominios cortos que imitan marcas conocidas** (typosquatting o suplantación):
   `uhaulpos.com` (imita uHaul), `uhaul2go.com`, `itaucorporate.com` e `itaucl.link`
   (imitan Itaú), `bet365bby.com` (imita bet365). Son los casos más preocupantes:
   el dominio parece normal en su estructura, y solo se detecta por similitud con
   una marca conocida. **El conjunto de características no incluye similitud con dominios legítimos**,
   que la propuesta sí menciona. Es la brecha más clara del modelo.
2. **Nombres aleatorios o sin sentido**: `faslkdomgod.com`, `pplzugang.com`,
   `hutoknepper.de`. La variable `random_domain` casi no los marca (valor 0 en la mayoría).
3. **Dominios muy cortos de pocas letras**: `ulu.so` (2 casos), `eds.eu`, `zrr.kr`,
   `itvopen.net`, `wk.pl`. Con longitud de 12 a 20 caracteres se confunden con
   dominios legítimos cortos.
4. **Subdominios o mayúsculas**: `WWW.OFFICIALPAPER.COM.BR`, `www.smsaes.com`. La
   mayúscula no afecta el resultado porque ya se normaliza, pero el subdominio
   `www` sí suma a la estructura de un sitio legítimo.

78 de los 96 falsos negativos (81%) tienen una URL de 30 caracteres o menos. Es el patrón más fuerte del grupo.

## Causas comunes y qué implica para el informe

- El modelo aprende **estructura superficial**: guiones, longitud, entropía. Eso explica
  tanto los falsos positivos (guiones legítimos) como los falsos negativos
  (phishing corto y limpio).
- La suplantación de marcas es el caso más relevante: un atacante puede evadir el modelo
  eligiendo un nombre corto y sin guiones. Esto no se resuelve con más datos
  sino con una característica nueva (similitud con marcas conocidas).
- La etiqueta de algunos casos es discutible (sitios de apuestas etiquetados como legítimos),
  y conviene mencionarlo al hablar de la calidad del dataset.
- Los errores no dependen de que el dominio aparezca o no en el entrenamiento: el test
  es por dominio, así que estos casos son dominios nuevos para el modelo.

## Pendiente

- Confirmar a mano los casos de suplantación de marca (la lista es de lectura manual).
- Decidir si se agrega una característica de similitud con marcas, o si se deja como
  limitación para discutir en el informe.
