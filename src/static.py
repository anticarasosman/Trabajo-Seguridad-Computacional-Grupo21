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

def calc_score(features, weights, functions):
    pass

def phishing_score(url):

    # Obtener indicadores/features

    split = urllib.parse.urlsplit(url)
    extract = tldextract.extract(url)

    scheme = split.scheme
    hostname = split.hostname
    hostname_length = len(hostname)
    ratio_digits_host = sum(c.isdigit() for c in hostname) / hostname_length
    port = split.port

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
        "ratio_digits_host": sum(c.isdigit() for c in split.hostname) / len(split.hostname),
        "port": port,
        "is_ip_addr": is_ip_addr,
        "num_subdomains": num_subdomains
    }


    # Calcular puntaje

    weights = {         # pesos que suman 1
        "entropy": 0,
        "url_length": 0,
        "num_www": 0,
        "ratio_digits": 0,
        "num_dots": 0,
        "num_hyphens": 0,
        "num_question": 0,
        "num_ats": 0,
        "num_eq": 0,
        "scheme": 0,
        "ratio_digits_host": 0,
        "port": 0,
        "is_ip_addr": 0,
        "num_subdomains": 0
    }

    functions = {
        "entropy": f_entropy,
        "url_length": f_url_length,
        "num_www": f_num_www,
        "ratio_digits": f_ratio,
        "num_dots": f_num_sus,
        "num_hyphens": f_num_sus,
        "num_question": f_num_sus,
        "num_ats": f_num_ats,
        "num_eq": f_num_sus,
        "scheme": f_scheme,
        "ratio_digits_host": f_ratio,
        "port": f_port,
        "is_ip_addr": f_ip,
        "num_subdomains": f_subdomains
    }

    score = calc_score(features, weights, functions)

    return score


# Funciones de puntaje/score

def f_entropy(x):
    pass

def f_url_length(x):
    pass

def f_num_www(x):
    pass

def f_ratio(x):
    pass

def f_num_sus(x):
    """
    Para caracteres sospechosos
    """
    pass

def f_num_ats(x):
    pass

def f_scheme(x):
    pass

def f_port(x):
    pass

def f_ip(x):
    pass

def f_subdomains(x):
    pass

def f_host_length(x):
    pass



# Main/test

if __name__ == "__main__":
    while True:
        url = input("Ingrese una URL... ")
        print(get_entropy(url))