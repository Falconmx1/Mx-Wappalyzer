#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Mx-Wappalyzer - Herramienta mexicana para fingerprinting de tecnologías web
Autor: Falconmx1
Versión: 1.0
"""

import requests
import json
import sys
import re
from urllib.parse import urlparse
import argparse
from banner import mostrar_banner

# Colores para output
VERDE = '\033[92m'
ROJO = '\033[91m'
AMARILLO = '\033[93m'
AZUL = '\033[94m'
MORADO = '\033[95m'
CYAN = '\033[96m'
RESET = '\033[0m'
NEGRITA = '\033[1m'

def cargar_tecnologias():
    """Carga la base de datos de tecnologías desde JSON"""
    try:
        with open('technologies.json', 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        print(f"{ROJO}[!] Error: No se encuentra technologies.json{RESET}")
        sys.exit(1)
    except json.JSONDecodeError:
        print(f"{ROJO}[!] Error: technologies.json tiene formato inválido{RESET}")
        sys.exit(1)

def detectar_por_headers(headers, tecnologias):
    """Detecta tecnologías basadas en headers HTTP"""
    detectadas = []
    for tech in tecnologias:
        if 'headers' in tech:
            for header, patron in tech['headers'].items():
                if header in headers:
                    if re.search(patron, headers[header], re.IGNORECASE):
                        detectadas.append(tech['nombre'])
                        break
    return detectadas

def detectar_por_html(html, tecnologias):
    """Detecta tecnologías basadas en el contenido HTML"""
    detectadas = []
    html_lower = html.lower()
    
    for tech in tecnologias:
        if 'patrones' in tech:
            for patron in tech['patrones']:
                if re.search(patron, html_lower, re.IGNORECASE):
                    detectadas.append(tech['nombre'])
                    break
    return detectadas

def detectar_por_cookies(cookies, tecnologias):
    """Detecta tecnologías basadas en cookies"""
    detectadas = []
    for tech in tecnologias:
        if 'cookies' in tech:
            for cookie_name in tech['cookies']:
                if cookie_name in cookies:
                    detectadas.append(tech['nombre'])
                    break
    return detectadas

def detectar_por_meta(html, tecnologias):
    """Detecta tecnologías basadas en meta tags"""
    detectadas = []
    meta_pattern = r'<meta[^>]+name=["\']([^"\']+)["\'][^>]+content=["\']([^"\']+)["\']'
    metas = re.findall(meta_pattern, html, re.IGNORECASE)
    
    for name, content in metas:
        for tech in tecnologias:
            if 'meta' in tech:
                for meta_name, meta_pattern in tech['meta'].items():
                    if name == meta_name and re.search(meta_pattern, content, re.IGNORECASE):
                        detectadas.append(tech['nombre'])
                        break
    return detectadas

def escanear_url(url, tecnologias, timeout=10):
    """Escanea una URL y devuelve todas las tecnologías detectadas"""
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    resultados = {
        'url': url,
        'tecnologias': [],
        'errores': []
    }
    
    try:
        print(f"{AZUL}[*] Escaneando: {url}{RESET}")
        
        # Headers personalizados para evitar bloqueos
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Mx-Wappalyzer/1.0',
            'Accept-Language': 'es-MX,es;q=0.9',
            'Accept': 'text/html,application/xhtml+xml'
        }
        
        response = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
        response.encoding = response.apparent_encoding
        
        # Detecciones
        resultados['tecnologias'].extend(detectar_por_headers(response.headers, tecnologias))
        resultados['tecnologias'].extend(detectar_por_html(response.text, tecnologias))
        resultados['tecnologias'].extend(detectar_por_cookies(response.cookies, tecnologias))
        resultados['tecnologias'].extend(detectar_por_meta(response.text, tecnologias))
        
        # Tecnologías del servidor
        if 'Server' in response.headers:
            resultados['tecnologias'].append(f"Servidor: {response.headers['Server']}")
        
        # Eliminar duplicados manteniendo orden
        resultados['tecnologias'] = list(dict.fromkeys(resultados['tecnologias']))
        
    except requests.exceptions.Timeout:
        resultados['errores'].append(f"Timeout después de {timeout} segundos")
    except requests.exceptions.ConnectionError:
        resultados['errores'].append("Error de conexión - Verifica la URL")
    except Exception as e:
        resultados['errores'].append(f"Error inesperado: {str(e)}")
    
    return resultados

def mostrar_resultados(resultados):
    """Muestra los resultados de forma bonita"""
    print(f"\n{NEGRITA}{CYAN}{'='*60}{RESET}")
    print(f"{NEGRITA}{AZUL}[+] Resultados para: {resultados['url']}{RESET}")
    print(f"{NEGRITA}{CYAN}{'='*60}{RESET}\n")
    
    if resultados['errores']:
        print(f"{ROJO}[!] Errores:{RESET}")
        for error in resultados['errores']:
            print(f"  {ROJO}•{RESET} {error}")
        print()
    
    if resultados['tecnologias']:
        print(f"{VERDE}[✓] Tecnologías detectadas ({len(resultados['tecnologias'])}):{RESET}\n")
        for tech in resultados['tecnologias']:
            if 'Servidor:' in tech:
                print(f"  {AMARILLO}🖥️  {tech}{RESET}")
            elif 'CMS' in tech or 'WordPress' in tech or 'Drupal' in tech:
                print(f"  {MORADO}📰 {tech}{RESET}")
            elif 'Framework' in tech or 'Laravel' in tech or 'Django' in tech:
                print(f"  {AZUL}🔧 {tech}{RESET}")
            elif 'JavaScript' in tech or 'jQuery' in tech or 'React' in tech:
                print(f"  {AMARILLO}⚡ {tech}{RESET}")
            elif 'Analytics' in tech or 'Google' in tech:
                print(f"  {CYAN}📊 {tech}{RESET}")
            else:
                print(f"  {VERDE}•{RESET} {tech}")
    else:
        print(f"{ROJO}[✗] No se detectaron tecnologías conocidas{RESET}")
        print(f"{AMARILLO}[!] Sugerencia: Algunos sitios bloquean escaneos automáticos{RESET}")
    
    print(f"\n{NEGRITA}{CYAN}{'='*60}{RESET}\n")

def modo_masivo(archivo, tecnologias):
    """Escanea múltiples URLs desde un archivo"""
    try:
        with open(archivo, 'r') as f:
            urls = [line.strip() for line in f if line.strip()]
        
        print(f"{VERDE}[+] Cargadas {len(urls)} URLs para escanear{RESET}\n")
        
        for i, url in enumerate(urls, 1):
            print(f"{AMARILLO}[{i}/{len(urls)}]{RESET}")
            resultados = escanear_url(url, tecnologias)
            mostrar_resultados(resultados)
            
            if i < len(urls):
                input(f"{CYAN}[?] Presiona Enter para continuar o Ctrl+C para salir...{RESET}")
    
    except FileNotFoundError:
        print(f"{ROJO}[!] No se encuentra el archivo: {archivo}{RESET}")

def main():
    parser = argparse.ArgumentParser(
        description='Mx-Wappalyzer - Herramienta mexicana para identificar tecnologías web',
        epilog='Ejemplo: python mx_wappalyzer.py -u https://example.com'
    )
    parser.add_argument('-u', '--url', help='URL a escanear')
    parser.add_argument('-l', '--list', help='Archivo con lista de URLs (una por línea)')
    parser.add_argument('-t', '--timeout', type=int, default=10, help='Timeout en segundos (default: 10)')
    
    args = parser.parse_args()
    
    # Mostrar banner
    mostrar_banner()
    
    # Cargar tecnologías
    print(f"{CYAN}[*] Cargando base de datos de tecnologías...{RESET}")
    tecnologias = cargar_tecnologias()
    print(f"{VERDE}[✓] Cargadas {len(tecnologias)} firmas de tecnologías{RESET}\n")
    
    # Modo de escaneo
    if args.url:
        resultados = escanear_url(args.url, tecnologias, args.timeout)
        mostrar_resultados(resultados)
    elif args.list:
        modo_masivo(args.list, tecnologias)
    else:
        # Modo interactivo
        print(f"{AMARILLO}[?] Modo interactivo{RESET}")
        while True:
            url = input(f"{NEGRITA}{CYAN}┌─[{VERDE}Falconmx1@{MORADO}Mx-Wappalyzer{RESET}{NEGRITA}{CYAN}]\n└──╼ $ {RESET}")
            if url.lower() in ['exit', 'quit', 'salir', 'q']:
                print(f"{VERDE}[+] ¡Gracias por usar Mx-Wappalyzer! 🇲🇽{RESET}")
                break
            if url:
                resultados = escanear_url(url, tecnologias, args.timeout)
                mostrar_resultados(resultados)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{AMARILLO}[!] Escaneo interrumpido por el usuario{RESET}")
        sys.exit(0)
