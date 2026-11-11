import re
import math
import urllib.parse
import tldextract
import ipaddress

def get_entropy(url):
    L = len(url)

    if L == 0:
        raise ValueError("Empty String")

    H = 0 

    freqs = dict()

    for char in url:
        if char in freqs:
            freqs[char] += 1
        else:
            freqs[char] = 1

    for n in freqs.values():
        p_i = n / L
        H += p_i * math.log2(p_i)

    return -H



# Funciones de puntaje/score basadas en heurísticas
# Las elecciones se basan en los datos experimentales del dataset

def f_entropy(x):
    if x <= 3.7:
        return 0.1
    elif x <= 4.4:
        return 0.2
    elif x <= 4.8:
        return 0.5
    else:
        return 1

def f_url_length(x):
    if x <= 21:
        return 0.1
    elif x <= 50:
        return 0.2
    elif x <= 64:
        return 0.5
    else:
        return 1

def f_ratio(x):
    if x <= 0.03:
        return 0.1
    elif x <= 0.1:
        return 0.5
    else:
        return 1

def f_num_sus(x):
    if x <= 1:
        return 0.1
    elif x == 2:
        return 0.3
    elif x == 3:
        return 0.5
    else:
        return 1

def f_num_ats(x):
    if x <= 0:
        return 0
    elif x == 1:
        return 0.8
    else:
        return 1

def f_scheme(x):
    if x.lower() == 'https':
        return 0
    else:
        return 1

def f_ip(x):
    if x:
        return 1
    else:
        return 0

def f_subdomains(x):
    if x <= 0:
        return 0.1
    elif x <= 1:
        return 0.3
    else:
        return 1

def f_host_length(x):
    if x <= 13:
        return 0.1
    elif x <= 20:
        return 0.2
    elif x <= 41:
        return 0.5
    else:
        return 1 


# Funciones principales

def validate_url(url):
    if not isinstance(url, str):
        raise TypeError("El input debe ser un string")

    url = url.strip()

    if not url:
        raise ValueError("URL vacía")

    if any(c.isspace() for c in url):
        raise ValueError("URL contiene espacios en blanco")

    try:
        split = urllib.parse.urlsplit(url)
        hostname = split.hostname
        port = split.port 
    except ValueError:
        raise ValueError("URL inválida")

    if split.scheme.lower() not in ("http", "https"):
        raise ValueError("scheme de la URL inválido")

    if not split.netloc or hostname is None:
        raise ValueError("La URL debe contener un hostname")

    return url

def calc_score(features, weights, functions):
    score = 0

    for feature in features:
        score += weights[feature] * functions[feature](features[feature])

    return score


def phishing_score(url):
    url = validate_url(url)

    # Obtener indicadores/features

    split = urllib.parse.urlsplit(url)
    extract = tldextract.extract(url)

    scheme = split.scheme
    hostname = split.hostname

    try:
        hostname_length = len(hostname)
        ratio_digits_host = sum(c.isdigit() for c in hostname) / hostname_length
    except TypeError:
        hostname_length = None
        ratio_digits_host = None

    is_ip_addr = True

    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        is_ip_addr = False

    num_subdomains = len(extract.subdomain.split('.'))

    features = {
        "entropy": get_entropy(url),
        "url_length": len(url),
        "num_www": url.count("www"),
        "ratio_digits": sum(c.isdigit() for c in url) / len(url),
        "num_dots": url.count('.'),
        "num_hyphens": url.count('-'),
        "num_question": url.count('?'),
        "num_eq": url.count('='),
        "num_ats": url.count('@'),
        "scheme": split.scheme,
        "ratio_digits_host": ratio_digits_host,
        "is_ip_addr": is_ip_addr,
        "num_subdomains": num_subdomains,
        "host_length": hostname_length
    }


    # Calcular puntaje

    weights = {         # pesos que suman 1
        "entropy": 0.12,
        "url_length": 0.08,
        "num_www": 0.02,
        "ratio_digits": 0.07,
        "num_dots": 0.04,
        "num_hyphens": 0.04,
        "num_question": 0.04,
        "num_ats": 0.12,
        "num_eq": 0.03,
        "scheme": 0.02,
        "ratio_digits_host": 0.08,
        "is_ip_addr": 0.14,
        "num_subdomains": 0.10,
        "host_length": 0.10
    }

    functions = {
        "entropy": f_entropy,
        "url_length": f_url_length,
        "num_www": f_num_sus,
        "ratio_digits": f_ratio,
        "num_dots": f_num_sus,
        "num_hyphens": f_num_sus,
        "num_question": f_num_sus,
        "num_ats": f_num_ats,
        "num_eq": f_num_sus,
        "scheme": f_scheme,
        "ratio_digits_host": f_ratio,
        "is_ip_addr": f_ip,
        "num_subdomains": f_subdomains,
        "host_length": f_host_length
    }

    score = calc_score(features, weights, functions)

    return score


# Main/test

if __name__ == "__main__":
    while True:
        url = input("Ingrese una URL... ")
        print(phishing_score(url))