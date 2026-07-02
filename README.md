# 🛡️ Recon Toolkit

Una herramienta de **reconocimiento (OSINT) y auditoría básica de seguridad** desarrollada en Python. Reúne múltiples módulos para obtener información sobre dominios, direcciones IP y aplicaciones web desde una única interfaz de consola.

> ⚠️ **Aviso:** Esta herramienta está diseñada exclusivamente para fines educativos, de investigación y auditorías autorizadas. Utilízala únicamente sobre sistemas propios o con permiso explícito.

---

## ✨ Características

El toolkit incluye los siguientes módulos:

| # | Módulo |
|---|---------|
| 1 | 🌍 Geolocalización de IP |
| 2 | 📄 Consulta WHOIS de dominios |
| 3 | 🌐 DNS Lookup (Dominio → IP) |
| 4 | 🌎 Obtener IP pública |
| 5 | 🔎 Fuzzing de subdominios |
| 6 | 🚪 Escaneo de puertos comunes |
| 7 | 📡 Obtención de headers HTTP (Banner Grab) |
| 8 | 🔐 Información del certificado SSL |
| 9 | 🔄 Reverse DNS (IP → Hostname) |
| 10 | 📂 Fuzzing de directorios web |
| 11 | 📋 Consulta completa de registros DNS |
| 12 | 🛡️ Auditoría de Security Headers |
| 13 | ⚙️ Métodos HTTP permitidos |
| 14 | 🖥️ Fingerprinting de tecnologías |
| 15 | 🤖 Recon mediante robots.txt y sitemap.xml |
| 16 | 🐞 Búsqueda de CVEs |
| 17 | 🔑 Identificación de hashes |
| 18 | 🌐 Consulta a Shodan InternetDB |
| 19 | 🏢 ASN y Organización de una IP |
| 20 | 🔀 Verificación de configuración CORS |
| 21 | 🍪 Auditoría de Cookies |
| 22 | ☁️ Detección de WAF/CDN |
| 23 | 🕰️ URLs históricas mediante Wayback Machine |
| 24 | 📜 Extracción de endpoints JavaScript |
| 25 | 📍 Traceroute |

---

## 🚀 Instalación

Clona el repositorio:

```bash
git clone https://github.com/delitosvirtuales/bliss-recon-toolkit.git
cd bliss-recon-toolkit
```

Instala las dependencias:

```bash
pip install -r requirements.txt
```

Ejecuta la herramienta:

```bash
python main.py
```

---

## 📷 Menú principal

```text
--- MODULOS ---

 1) IP geolocation
 2) WHOIS de dominio
 3) DNS lookup
 4) Ver mi IP pública
 5) Fuzz de subdominios
 6) Port scanner
 7) HTTP headers
 8) Certificado SSL
 9) Reverse DNS
10) Fuzz de directorios
11) Registros DNS
12) Security Headers
13) HTTP OPTIONS
14) Fingerprint
15) robots.txt / sitemap.xml
16) Buscar CVEs
17) Identificar Hash
18) Shodan InternetDB
19) ASN Lookup
20) CORS Check
21) Auditoría de Cookies
22) Detección WAF/CDN
23) Wayback Machine
24) JS Endpoint Scraper
25) Traceroute

0) Salir
```

---

## 📦 Dependencias

Algunos módulos utilizan librerías y APIs públicas como:

- requests
- dnspython
- python-whois
- socket
- ssl
- ipwhois
- Shodan InternetDB
- Wayback Machine
- APIs públicas de OSINT

---

## ⚠️ Descargo de responsabilidad

El autor no se responsabiliza por el uso indebido de esta herramienta.

Todas las pruebas deben realizarse únicamente sobre sistemas propios o con autorización expresa del propietario.

---

## 📄 Licencia

Este proyecto se distribuye bajo la licencia MIT.
