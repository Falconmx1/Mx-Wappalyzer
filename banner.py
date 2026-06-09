#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys

# Colores RGB para el banner
VERDE = '\033[92m'
ROJO = '\033[91m'
AMARILLO = '\033[93m'
AZUL = '\033[94m'
MORADO = '\033[95m'
CYAN = '\033[96m'
BLANCO = '\033[97m'
NEGRITA = '\033[1m'
RESET = '\033[0m'

def limpiar_pantalla():
    """Limpia la pantalla según el SO"""
    os.system('cls' if os.name == 'nt' else 'clear')

def mostrar_banner():
    """Muestra el banner principal de Mx-Wappalyzer"""
    limpiar_pantalla()
    
    banner = f"""
{NEGRITA}{VERDE}
    ╔═══════════════════════════════════════════════════════════════════╗
    ║                                                                   ║
    ║   {ROJO}███╗   ███╗██╗  ██╗{VERDE}                                    ║
    ║   {ROJO}████╗ ████║╚██╗██╔╝{VERDE}  {AMARILLO}██╗    ██╗{VERDE}                        ║
    ║   {ROJO}██╔████╔██║ ╚███╔╝ {VERDE}   {AMARILLO}██║    ██║{VERDE}                        ║
    ║   {ROJO}██║╚██╔╝██║ ██╔██╗ {VERDE}   {AMARILLO}██║    ██║{VERDE}                        ║
    ║   {ROJO}██║ ╚═╝ ██║██╔╝ ██╗{VERDE}  {AMARILLO}███████╗██╗{VERDE}                        ║
    ║   {ROJO}╚═╝     ╚═╝╚═╝  ╚═╝{VERDE}  {AMARILLO}╚══════╝╚═╝{VERDE}                        ║
    ║                                                                   ║
    ║   {NEGRITA}{CYAN}        Mx-Wappalyzer v1.0 - Por: Falconmx1{VERDE}                     ║
    ║   {NEGRITA}{AMARILLO}        "Tecnologías web al estilo mexicano"{VERDE}                 ║
    ║                                                                   ║
    ║   {NEGRITA}{BLANCO}┌─────────────────────────────────────────────────────┐{VERDE}        ║
    ║   {BLANCO}│{VERDE}  🇲🇽  {CYAN}OSINT{VERDE} | {CYAN}Pentesting{VERDE} | {CYAN}Fingerprinting{VERDE}  {BLANCO}│{VERDE}        ║
    ║   {BLANCO}└─────────────────────────────────────────────────────┘{VERDE}        ║
    ║                                                                   ║
    ╚═══════════════════════════════════════════════════════════════════╝{RESET}
    
    {AMARILLO}[!] Uso exclusivamente para fines educativos y autorizados{RESET}
    {CYAN}[*] Detecta: CMS | Frameworks | Librerías JS | Servidores | Analytics{RESET}
    """
    
    print(banner)

if __name__ == "__main__":
    mostrar_banner()
