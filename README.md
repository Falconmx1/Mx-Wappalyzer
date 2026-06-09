# 🇲🇽 Mx-Wappalyzer

<div align="center">

![Python Version](https://img.shields.io/badge/python-3.6+-blue.svg)
![License](https://img.shields.io/badge/license-GPLv3-red.svg)
![Status](https://img.shields.io/badge/status-stable-green.svg)
![Mexico](https://img.shields.io/badge/made%20in-mexico-green?logo=mexico)

**Herramienta mexicana para fingerprinting de tecnologías web**  
*CMS, Frameworks, Librerías JS, Servidores, Analytics y más*

[![Banner](https://img.shields.io/badge/Mx--Wappalyzer-v1.0-ff69b4)](https://github.com/Falconmx1/Mx-Wappalyzer)

</div>

---

## 🎯 Características

- ✅ **Detección automática** de más de 25 tecnologías web
- 🔍 **Análisis por headers**, HTML, cookies y meta tags
- 🎨 **Banner estilo tool/hack** con colores verde/rojo
- 📊 **Soporte para escaneo masivo** (lista de URLs)
- ⚡ **Rápido y eficiente** con timeouts configurables
- 🇲🇽 **Interfaz en español** con colores personalizados
- 🛡️ **Modo interactivo** para escaneos rápidos

---

## 📋 Tecnologías Detectadas

### CMS
- WordPress, Drupal, Joomla

### E-commerce
- Magento, PrestaShop

### Frameworks
- Laravel, Django, Ruby on Rails

### Librerías JS
- React, Vue.js, Angular, jQuery

### CSS Frameworks
- Bootstrap, Font Awesome

### Servidores Web
- Apache, Nginx, IIS

### CDN & Seguridad
- CloudFlare

### Analytics
- Google Analytics, Facebook Pixel

### Payments
- Stripe, PayPal

### Herramientas
- phpMyAdmin, cPanel

---

## 🚀 Instalación

### Requisitos previos
- Python 3.6 o superior
- pip (gestor de paquetes de Python)
- git

### Pasos de instalación

```bash
# Clonar el repositorio
git clone https://github.com/Falconmx1/Mx-Wappalyzer.git
cd Mx-Wappalyzer

# Instalar dependencias
pip install -r requirements.txt

# Dar permisos de ejecución (Linux/Mac)
chmod +x mx_wappalyzer.py

💻 Uso
Modo interactivo (recomendado)
python mx_wappalyzer.py

Escanear una URL específica
python mx_wappalyzer.py -u https://example.com

Escaneo masivo desde archivo
# Crear archivo urls.txt con una URL por línea
python mx_wappalyzer.py -l urls.txt

Configurar timeout
python mx_wappalyzer.py -u https://example.com -t 15

Ejemplos prácticos
# Escanear sitio mexicano
python mx_wappalyzer.py -u https://www.gob.mx

# Escaneo rápido con timeout de 5 segundos
python mx_wappalyzer.py -u https://google.com -t 5
