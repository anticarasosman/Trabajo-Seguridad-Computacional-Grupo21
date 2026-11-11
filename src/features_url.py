import math
from collections import Counter
from urllib.parse import urlparse

import tldextract

CARACTERISTICAS_URL = [
    "entropy",
    "url_length",
    "num_www",
    "ratio_digits_url",
    "num_subdomains",
    "length_hostname",
    "num_dots",
    "num_hyphens",
    "ratio_digits_host",
    "prefix_suffix",
    "num_question_mark",
    "num_eq",
]

_extractor = tldextract.TLDExtract(suffix_list_urls=())


def _entropia(datos: bytes) -> float:
    """Entropía de Shannon (base 2) de los bytes de `datos`."""
    if not datos:
        return 0.0
    n = len(datos)
    return -sum((v / n) * math.log2(v / n) for v in Counter(datos).values())


def _normalizar(url: str) -> str:
    return url if "://" in url else f"http://{url}"


def url_a_host(url: str) -> str:
    """Conserva solo esquema y host: descarta ruta, parámetros y fragmento."""
    url = url.strip()
    p = urlparse(_normalizar(url))
    host = p.hostname or ""
    if p.port:
        host = f"{host}:{p.port}"
    return f"{p.scheme or 'http'}://{host}"


def extraer_caracteristicas(url: str) -> dict:
    """Devuelve las 12 características de la URL como diccionario."""
    url_completa = url.strip()
    parseada = urlparse(_normalizar(url_completa))
    host = (parseada.hostname or "").lower()
    ext = _extractor(host)

    largo_url = len(url_completa)
    largo_host = len(host)
    digitos_url = sum(c.isdigit() for c in url_completa)
    digitos_host = sum(c.isdigit() for c in host)

    return {
        "entropy": _entropia(url_completa.encode("utf-8")),
        "url_length": largo_url,
        "num_www": url_completa.lower().count("www"),
        "ratio_digits_url": digitos_url / largo_url if largo_url else 0.0,
        "num_subdomains": len(ext.subdomain.split(".")) if ext.subdomain else 0,
        "length_hostname": largo_host,
        "num_dots": url_completa.count("."),
        "num_hyphens": url_completa.count("-"),
        "ratio_digits_host": digitos_host / largo_host if largo_host else 0.0,
        "prefix_suffix": int("-" in ext.domain),
        "num_question_mark": url_completa.count("?"),
        "num_eq": url_completa.count("="),
    }
