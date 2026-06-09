#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Mx-Wappalyzer - Herramienta mexicana para fingerprinting de tecnologías web
Autor: Falconmx1
Versión: 2.0 - Con detección de versiones, modo sigiloso y exportación
"""

import requests
import json
import sys
import re
import time
import random
from urllib.parse import urlparse
import argparse
from datetime import datetime
from banner import mostrar_banner

# Colores para output
VERDE = '\033[92m'
ROJO = '\033[91m'
AMARILLO = '\033[93m'
AZUL = '\033[94m'
MORADO = '\033[95m'
CYAN = '\033[96m'
BLANCO = '\033[97m'
NEGRITA = '\033[1m'
RESET = '\033[0m'

# User agents para modo sigiloso
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15',
    'Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/119.0'
]

def cargar_tecnologias():
    """Carga la base de datos de tecnologías desde JSON"""
    try:
        with open('technologies.json', 'r', encoding='utf-8') as f:
            data = json.load(f)
            # Soporta ambos formatos
            if isinstance(data, dict) and 'tecnologias' in data:
                return data['tecnologias']
            return data
    except FileNotFoundError:
        print(f"{ROJO}[!] Error: No se encuentra technologies.json{RESET}")
        sys.exit(1)
    except json.JSONDecodeError:
        print(f"{ROJO}[!] Error: technologies.json tiene formato inválido{RESET}")
        sys.exit(1)

def extraer_version(html, headers, tech):
    """Extrae la versión de una tecnología si está disponible"""
    if 'version_pattern' not in tech:
        return None
    
    patron_version = tech['version_pattern']
    texto_completo = html + str(headers)
    
    match = re.search(patron_version, texto_completo, re.IGNORECASE)
    if match:
        # Buscar el primer grupo que no sea None
        for grupo in match.groups():
            if grupo:
                return grupo
    return None

def detectar_por_headers(headers, tecnologias):
    """Detecta tecnologías basadas en headers HTTP"""
    detectadas = []
    for tech in tecnologias:
        if 'headers' in tech:
            for header, patron in tech['headers'].items():
                if header in headers:
                    if re.search(patron, headers[header], re.IGNORECASE):
                        version = extraer_version('', headers, tech)
                        detectadas.append({
                            'nombre': tech['nombre'],
                            'categoria': tech.get('categoria', 'Desconocida'),
                            'version': version
                        })
                        break
    return detectadas

def detectar_por_html(html, headers, tecnologias):
    """Detecta tecnologías basadas en el contenido HTML"""
    detectadas = []
    html_lower = html.lower()
    
    for tech in tecnologias:
        if 'patrones' in tech:
            for patron in tech['patrones']:
                if re.search(patron, html_lower, re.IGNORECASE):
                    version = extraer_version(html, headers, tech)
                    detectadas.append({
                        'nombre': tech['nombre'],
                        'categoria': tech.get('categoria', 'Desconocida'),
                        'version': version
                    })
                    break
    return detectadas

def detectar_por_cookies(cookies, tecnologias):
    """Detecta tecnologías basadas en cookies"""
    detectadas = []
    for tech in tecnologias:
        if 'cookies' in tech:
            for cookie_name in tech['cookies']:
                if cookie_name in cookies:
                    detectadas.append({
                        'nombre': tech['nombre'],
                        'categoria': tech.get('categoria', 'Desconocida'),
                        'version': tech.get('version', None)
                    })
                    break
    return detectadas

def detectar_por_meta(html, headers, tecnologias):
    """Detecta tecnologías basadas en meta tags"""
    detectadas = []
    meta_pattern = r'<meta[^>]+name=["\']([^"\']+)["\'][^>]+content=["\']([^"\']+)["\']'
    metas = re.findall(meta_pattern, html, re.IGNORECASE)
    
    for name, content in metas:
        for tech in tecnologias:
            if 'meta' in tech:
                for meta_name, meta_pattern in tech['meta'].items():
                    if name == meta_name and re.search(meta_pattern, content, re.IGNORECASE):
                        version = extraer_version(html, headers, tech)
                        detectadas.append({
                            'nombre': tech['nombre'],
                            'categoria': tech.get('categoria', 'Desconocida'),
                            'version': version
                        })
                        break
    return detectadas

def escanear_url(url, tecnologias, timeout=10, sigiloso=False):
    """Escanea una URL y devuelve todas las tecnologías detectadas"""
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    resultados = {
        'url': url,
        'timestamp': datetime.now().isoformat(),
        'tecnologias': [],
        'servidor': None,
        'errores': []
    }
    
    try:
        # Headers personalizados
        headers = {
            'User-Agent': random.choice(USER_AGENTS) if sigiloso else 'Mx-Wappalyzer/2.0',
            'Accept-Language': 'es-MX,es;q=0.9',
            'Accept': 'text/html,application/xhtml+xml',
            'Accept-Encoding': 'gzip, deflate, br'
        }
        
        # Si es modo sigiloso, añadir más headers y delay
        if sigiloso:
            headers['Referer'] = 'https://www.google.com/'
            headers['DNT'] = '1'
            time.sleep(random.uniform(0.5, 1.5))
            print(f"{AZUL}[*] Modo sigiloso activado - User-Agent: {headers['User-Agent'][:50]}...{RESET}")
        
        print(f"{AZUL}[*] Escaneando: {url}{RESET}")
        
        response = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
        response.encoding = response.apparent_encoding
        
        # Detectar servidor
        if 'Server' in response.headers:
            resultados['servidor'] = response.headers['Server']
        
        # Detecciones
        resultados['tecnologias'].extend(detectar_por_headers(response.headers, tecnologias))
        resultados['tecnologias'].extend(detectar_por_html(response.text, response.headers, tecnologias))
        resultados['tecnologias'].extend(detectar_por_cookies(response.cookies, tecnologias))
        resultados['tecnologias'].extend(detectar_por_meta(response.text, response.headers, tecnologias))
        
        # Eliminar duplicados (por nombre)
        vistos = set()
        unicos = []
        for tech in resultados['tecnologias']:
            if tech['nombre'] not in vistos:
                vistos.add(tech['nombre'])
                unicos.append(tech)
        resultados['tecnologias'] = unicos
        
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
    
    if resultados['servidor']:
        print(f"{VERDE}🖥️  Servidor:{RESET} {resultados['servidor']}\n")
    
    if resultados['tecnologias']:
        print(f"{VERDE}[✓] Tecnologías detectadas ({len(resultados['tecnologias'])}):{RESET}\n")
        for tech in resultados['tecnologias']:
            version_str = f" v{tech['version']}" if tech['version'] else ""
            categoria = tech.get('categoria', 'General')
            
            # Asignar ícono por categoría
            icono = "•"
            if 'CMS' in categoria:
                icono = "📰"
            elif 'Framework' in categoria:
                icono = "🔧"
            elif 'JavaScript' in categoria or 'Library' in categoria:
                icono = "⚡"
            elif 'Server' in categoria:
                icono = "🖥️"
            elif 'Analytics' in categoria:
                icono = "📊"
            elif 'E-commerce' in categoria:
                icono = "🛒"
            elif 'Database' in categoria:
                icono = "🗄️"
            elif 'Security' in categoria:
                icono = "🛡️"
            
            print(f"  {icono} {tech['nombre']}{version_str} {BLANCO}({categoria}){RESET}")
    else:
        print(f"{ROJO}[✗] No se detectaron tecnologías conocidas{RESET}")
    
    print(f"\n{NEGRITA}{CYAN}{'='*60}{RESET}\n")

def exportar_resultados(resultados, formato='json'):
    """Exporta los resultados a un archivo"""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    nombre_base = f"scan_{timestamp}"
    
    if formato == 'json':
        archivo = f"{nombre_base}.json"
        with open(archivo, 'w', encoding='utf-8') as f:
            json.dump(resultados, f, indent=2, ensure_ascii=False)
        print(f"{VERDE}[✓] Resultados exportados a {archivo}{RESET}")
    
    elif formato == 'txt':
        archivo = f"{nombre_base}.txt"
        with open(archivo, 'w', encoding='utf-8') as f:
            f.write(f"Mx-Wappalyzer Scan Report\n")
            f.write(f"=========================\n")
            f.write(f"URL: {resultados['url']}\n")
            f.write(f"Fecha: {resultados['timestamp']}\n\n")
            
            if resultados['servidor']:
                f.write(f"Servidor: {resultados['servidor']}\n\n")
            
            f.write("Tecnologías Detectadas:\n")
            for tech in resultados['tecnologias']:
                version = f" v{tech['version']}" if tech['version'] else ""
                f.write(f"  - {tech['nombre']}{version} ({tech['categoria']})\n")
        print(f"{VERDE}[✓] Resultados exportados a {archivo}{RESET}")
    
    elif formato == 'csv':
        archivo = f"{nombre_base}.csv"
        import csv
        with open(archivo, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['URL', 'Tecnología', 'Versión', 'Categoría'])
            for tech in resultados['tecnologias']:
                writer.writerow([resultados['url'], tech['nombre'], tech['version'] or '', tech['categoria']])
        print(f"{VERDE}[✓] Resultados exportados a {archivo}{RESET}")

def modo_masivo(archivo, tecnologias, timeout=10, sigiloso=False, exportar=False):
    """Escanea múltiples URLs desde un archivo"""
    try:
        with open(archivo, 'r') as f:
            urls = [line.strip() for line in f if line.strip()]
        
        print(f"{VERDE}[+] Cargadas {len(urls)} URLs para escanear{RESET}\n")
        
        todos_resultados = []
        
        for i, url in enumerate(urls, 1):
            print(f"{AMARILLO}[{i}/{len(urls)}]{RESET}")
            resultados = escanear_url(url, tecnologias, timeout, sigiloso)
            mostrar_resultados(resultados)
            todos_resultados.append(resultados)
            
            if exportar and i == len(urls):
                exportar_resultados({'scans': todos_resultados, 'total': len(todos_resultados)}, 'json')
            
            if i < len(urls):
                input(f"{CYAN}[?] Presiona Enter para continuar o Ctrl+C para salir...{RESET}")
    
    except FileNotFoundError:
        print(f"{ROJO}[!] No se encuentra el archivo: {archivo}{RESET}")

def main():
    parser = argparse.ArgumentParser(
        description='Mx-Wappalyzer - Herramienta mexicana para identificar tecnologías web',
        epilog='Ejemplo: python mx_wappalyzer.py -u https://example.com -s -o json'
    )
    parser.add_argument('-u', '--url', help='URL a escanear')
    parser.add_argument('-l', '--list', help='Archivo con lista de URLs (una por línea)')
    parser.add_argument('-t', '--timeout', type=int, default=10, help='Timeout en segundos (default: 10)')
    parser.add_argument('-s', '--sigiloso', action='store_true', help='Modo sigiloso (evita bloqueos)')
    parser.add_argument('-o', '--output', choices=['json', 'txt', 'csv'], help='Exportar resultados a archivo')
    
    args = parser.parse_args()
    
    # Mostrar banner
    mostrar_banner()
    
    # Cargar tecnologías
    print(f"{CYAN}[*] Cargando base de datos de tecnologías...{RESET}")
    tecnologias = cargar_tecnologias()
    print(f"{VERDE}[✓] Cargadas {len(tecnologias)} firmas de tecnologías{RESET}\n")
    
    # Modo de escaneo
    if args.url:
        resultados = escanear_url(args.url, tecnologias, args.timeout, args.sigiloso)
        mostrar_resultados(resultados)
        if args.output:
            exportar_resultados(resultados, args.output)
    elif args.list:
        modo_masivo(args.list, tecnologias, args.timeout, args.sigiloso, bool(args.output))
    else:
        # Modo interactivo
        print(f"{AMARILLO}[?] Modo interactivo (usa -s para sigiloso, -o json para exportar){RESET}")
        while True:
            url = input(f"{NEGRITA}{CYAN}┌─[{VERDE}Falconmx1@{MORADO}Mx-Wappalyzer{RESET}{NEGRITA}{CYAN}]\n└──╼ $ {RESET}")
            if url.lower() in ['exit', 'quit', 'salir', 'q']:
                print(f"{VERDE}[+] ¡Gracias por usar Mx-Wappalyzer! 🇲🇽{RESET}")
                break
            if url:
                resultados = escanear_url(url, tecnologias, args.timeout, args.sigiloso)
                mostrar_resultados(resultados)
                if args.output:
                    exportar_resultados(resultados, args.output)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{AMARILLO}[!] Escaneo interrumpido por el usuario{RESET}")
        sys.exit(0)
