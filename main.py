r"""
 ____  _     ___ ____ ____
| __ )| |   |_ _/ ___/ ___|
|  _ \| |    | |\___ \___ \
| |_) | |___ | | ___) |__) |
|____/|_____|___|____/____/

- Proyecto: multitool.py
- Descripción: Toolkit de recon / OSINT pasivo para pentesting autorizado -
  IP geo, WHOIS, DNS, fuzz de sub/dirs, port scanner, HTTP headers, SSL,
  reverse DNS, security headers, tech fingerprint, CVE lookup, hash ID,
  Shodan InternetDB, ASN lookup, CORS check, cookie audit, WAF detection,
  Wayback URLs, JS endpoint scraper, traceroute
- Autor: Bliss
- Entorno: Termux / Linux
- Dependencias clave: requests, python-whois, dnspython (opcional)
- Uso: SOLO en sistemas propios o con autorizacion explicita del dueño.
"""

import re
import sys
import socket
import ssl
import shutil
import subprocess
import datetime
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin

try:
    import whois
except ImportError:
    whois = None

try:
    import dns.resolver
except ImportError:
    dns = None

# Wordlists remotas de SecLists (GitHub) - nada local
SUBDOMAINS_WORDLIST_URL = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt"
DIRS_WORDLIST_URL = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt"

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443,
                445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443]

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "X-XSS-Protection",
]

RISKY_HTTP_METHODS = {"PUT", "DELETE", "TRACE", "CONNECT"}

HASH_PATTERNS = [
    (r"^[a-f0-9]{32}$", "MD5 o NTLM (32 hex chars, ambiguo sin contexto)"),
    (r"^[a-f0-9]{40}$", "SHA1"),
    (r"^[a-f0-9]{64}$", "SHA256"),
    (r"^[a-f0-9]{128}$", "SHA512"),
    (r"^\$2[aby]\$.{56}$", "bcrypt"),
    (r"^\$1\$.{0,8}\$.{22}$", "MD5 crypt (Unix)"),
    (r"^\$6\$.{0,16}\$.{86}$", "SHA512 crypt (Unix)"),
    (r"^[A-Fa-f0-9]{56}$", "SHA224"),
]

# Firmas simples para deteccion de WAF (header/cookie -> nombre)
WAF_SIGNATURES = {
    "cf-ray": "Cloudflare",
    "__cfduid": "Cloudflare",
    "x-sucuri-id": "Sucuri",
    "sucuri-cloudproxy": "Sucuri",
    "x-akamai": "Akamai",
    "akamaighost": "Akamai",
    "incap_ses": "Incapsula",
    "visid_incap": "Incapsula",
    "x-iinfo": "Incapsula",
    "barracuda": "Barracuda",
    "x-waf-event-info": "AWS WAF",
    "awselb": "AWS ELB/WAF",
    "x-cdn": "Generico CDN/WAF",
    "server: bigip": "F5 BIG-IP ASM",
}


# ---------- Utilidades ----------

def _linea(titulo):
    print(f"\n--- {titulo} ---")


def _normalize_url(target):
    if not target.startswith(("http://", "https://")):
        return f"https://{target}"
    return target


def fetch_wordlist(url, limit=None):
    """Descarga una wordlist desde GitHub (raw) y la devuelve como lista de palabras."""
    try:
        r = requests.get(url, timeout=15)
        r.raise_for_status()
    except requests.RequestException as e:
        print(f"[!] No se pudo descargar la wordlist: {e}")
        return []

    words = [w.strip() for w in r.text.splitlines() if w.strip() and not w.startswith("#")]
    if limit:
        words = words[:limit]
    return words


# ---------- IP / Geo ----------

def ip_geo(ip):
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=8)
        data = r.json()
    except requests.RequestException as e:
        print(f"[!] Error de conexion: {e}")
        return

    if data.get("status") == "fail":
        print(f"[!] No se pudo geolocalizar: {data.get('message')}")
        return

    _linea(f"Geolocalizacion de {ip}")
    print(f"Pais:      {data.get('country')} ({data.get('countryCode')})")
    print(f"Region:    {data.get('regionName')}")
    print(f"Ciudad:    {data.get('city')}")
    print(f"ISP:       {data.get('isp')}")
    print(f"Org:       {data.get('org')}")
    print(f"Lat/Lon:   {data.get('lat')}, {data.get('lon')}")
    print(f"Zona hor.: {data.get('timezone')}")


def my_ip():
    try:
        r = requests.get("https://api.ipify.org?format=json", timeout=8)
        ip = r.json().get("ip")
        print(f"\nTu IP publica es: {ip}")
        return ip
    except requests.RequestException as e:
        print(f"[!] Error de conexion: {e}")
        return None


def asn_lookup(ip):
    """Info de ASN / bloque de red al que pertenece una IP."""
    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,message,query,as,asname,isp,org,country"},
            timeout=8,
        )
        data = r.json()
    except requests.RequestException as e:
        print(f"[!] Error de conexion: {e}")
        return

    if data.get("status") == "fail":
        print(f"[!] {data.get('message')}")
        return

    _linea(f"ASN / Org de {ip}")
    print(f"ASN:      {data.get('as')}")
    print(f"AS Name:  {data.get('asname')}")
    print(f"ISP:      {data.get('isp')}")
    print(f"Org:      {data.get('org')}")
    print(f"Pais:     {data.get('country')}")


# ---------- WHOIS / DNS ----------

def domain_whois(domain):
    if whois is None:
        print("[!] Falta la libreria python-whois. Instala con:")
        print("    pip install python-whois")
        return

    try:
        data = whois.whois(domain)
    except Exception as e:
        print(f"[!] Error consultando WHOIS: {e}")
        return

    _linea(f"WHOIS de {domain}")
    print(f"Registrar:      {data.registrar}")
    print(f"Creado:         {data.creation_date}")
    print(f"Expira:         {data.expiration_date}")
    print(f"Actualizado:    {data.updated_date}")
    print(f"Name servers:   {data.name_servers}")
    print(f"Estado:         {data.status}")


def dns_lookup(domain):
    try:
        ip = socket.gethostbyname(domain)
        _linea(f"DNS lookup de {domain}")
        print(f"IP: {ip}")
    except socket.gaierror as e:
        print(f"[!] No se pudo resolver {domain}: {e}")


def dns_records(domain):
    """Dump completo de registros DNS (A, AAAA, MX, NS, TXT, CNAME)."""
    if dns is None:
        print("[!] Falta la libreria dnspython. Instala con:")
        print("    pip install dnspython")
        return

    _linea(f"Registros DNS de {domain}")
    tipos = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
    for tipo in tipos:
        try:
            respuestas = dns.resolver.resolve(domain, tipo)
            print(f"\n{tipo}:")
            for r in respuestas:
                print(f"  {r.to_text()}")
        except dns.resolver.NoAnswer:
            continue
        except dns.resolver.NXDOMAIN:
            print(f"[!] El dominio {domain} no existe.")
            return
        except Exception:
            continue


def reverse_dns(ip):
    try:
        host, aliases, _ = socket.gethostbyaddr(ip)
        _linea(f"Reverse DNS de {ip}")
        print(f"Hostname: {host}")
        if aliases:
            print(f"Alias:    {', '.join(aliases)}")
    except socket.herror as e:
        print(f"[!] No se encontro PTR para {ip}: {e}")


def traceroute(target):
    """Traceroute usando el binario del sistema (traceroute/tracert) si esta disponible."""
    binario = shutil.which("traceroute") or shutil.which("tracert")
    if not binario:
        print("[!] No se encontro 'traceroute' instalado.")
        print("    En Termux: pkg install traceroute")
        return

    _linea(f"Traceroute a {target}")
    try:
        proceso = subprocess.run(
            [binario, target], capture_output=True, text=True, timeout=60
        )
        print(proceso.stdout or proceso.stderr)
    except subprocess.TimeoutExpired:
        print("[!] Traceroute tardo demasiado, cortado.")
    except Exception as e:
        print(f"[!] Error ejecutando traceroute: {e}")


# ---------- Port scanner ----------

def _scan_port(ip, port, timeout=1.5):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        result = s.connect_ex((ip, port))
        if result == 0:
            try:
                banner = s.recv(64).decode(errors="ignore").strip()
            except Exception:
                banner = ""
            return (port, banner)
    return None


def port_scan(target, ports=None, workers=40):
    ports = ports or COMMON_PORTS
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror as e:
        print(f"[!] No se pudo resolver {target}: {e}")
        return

    _linea(f"Port scan de {target} ({ip})")
    print(f"Probando {len(ports)} puertos...\n")
    abiertos = []

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(_scan_port, ip, p): p for p in ports}
        for future in as_completed(futures):
            result = future.result()
            if result:
                port, banner = result
                info = f"[+] Puerto {port} ABIERTO"
                if banner:
                    info += f" | banner: {banner[:40]}"
                print(info)
                abiertos.append(port)

    print(f"\n--- Scan terminado: {len(abiertos)}/{len(ports)} puertos abiertos ---")


def shodan_internetdb(ip):
    """Consulta InternetDB de Shodan (gratis, sin API key): puertos, CPEs y CVEs conocidos."""
    try:
        r = requests.get(f"https://internetdb.shodan.io/{ip}", timeout=10)
    except requests.RequestException as e:
        print(f"[!] Error de conexion: {e}")
        return

    if r.status_code == 404:
        print(f"[!] Shodan no tiene datos indexados para {ip}.")
        return
    if r.status_code != 200:
        print(f"[!] Error consultando InternetDB (status {r.status_code}).")
        return

    data = r.json()
    _linea(f"Shodan InternetDB de {ip}")
    print(f"Hostnames: {data.get('hostnames') or '-'}")
    print(f"Puertos:   {data.get('ports') or '-'}")
    print(f"CPEs:      {data.get('cpes') or '-'}")
    vulns = data.get("vulns") or []
    if vulns:
        print(f"[!] CVEs conocidos asociados: {', '.join(vulns)}")
    else:
        print("CVEs conocidos: ninguno indexado")
    print(f"Tags:      {data.get('tags') or '-'}")


# ---------- HTTP ----------

def http_headers(target):
    url = _normalize_url(target)
    try:
        r = requests.get(url, timeout=10, allow_redirects=True)
    except requests.RequestException as e:
        print(f"[!] Error consultando {url}: {e}")
        return

    _linea(f"HTTP headers de {url}")
    print(f"Status: {r.status_code}")
    print(f"URL final: {r.url}")
    for header, valor in r.headers.items():
        print(f"{header}: {valor}")


def http_methods(target):
    """Chequea que metodos HTTP acepta el servidor (OPTIONS) y marca los riesgosos."""
    url = _normalize_url(target)
    try:
        r = requests.options(url, timeout=8)
    except requests.RequestException as e:
        print(f"[!] Error consultando {url}: {e}")
        return

    allow = r.headers.get("Allow", "")
    metodos = [m.strip().upper() for m in allow.split(",") if m.strip()]

    _linea(f"Metodos HTTP permitidos en {url}")
    if not metodos:
        print("[!] El servidor no devolvio header 'Allow' (puede que OPTIONS este bloqueado).")
        return

    for m in metodos:
        flag = " [!] RIESGOSO" if m in RISKY_HTTP_METHODS else ""
        print(f"{m}{flag}")


def security_headers(target):
    """Audita los headers de seguridad presentes/ausentes, estilo securityheaders.com."""
    url = _normalize_url(target)
    try:
        r = requests.get(url, timeout=10)
    except requests.RequestException as e:
        print(f"[!] Error consultando {url}: {e}")
        return

    _linea(f"Auditoria de security headers de {url}")
    presentes = 0
    for h in SECURITY_HEADERS:
        if h in r.headers:
            print(f"[OK]   {h}: {r.headers[h]}")
            presentes += 1
        else:
            print(f"[FALTA] {h}")

    score = round((presentes / len(SECURITY_HEADERS)) * 100)
    print(f"\nScore: {presentes}/{len(SECURITY_HEADERS)} headers presentes ({score}%)")


def cors_check(target):
    """Testea si el servidor refleja cualquier Origin (misconfiguracion clasica de CORS)."""
    url = _normalize_url(target)
    origen_test = "https://evil-test-domain.com"
    try:
        r = requests.get(url, headers={"Origin": origen_test}, timeout=10)
    except requests.RequestException as e:
        print(f"[!] Error consultando {url}: {e}")
        return

    acao = r.headers.get("Access-Control-Allow-Origin")
    acac = r.headers.get("Access-Control-Allow-Credentials")

    _linea(f"CORS check de {url}")
    print(f"Origin enviado:                {origen_test}")
    print(f"Access-Control-Allow-Origin:   {acao or '(ausente)'}")
    print(f"Access-Control-Allow-Credentials: {acac or '(ausente)'}")

    if acao == origen_test:
        print("[!] VULNERABLE: el servidor refleja cualquier Origin arbitrario.")
        if acac == "true":
            print("[!] CRITICO: ademas permite credenciales (cookies/auth) con ese origin.")
    elif acao == "*":
        print("[i] CORS abierto a cualquier origen (*), revisar si expone datos sensibles.")
    else:
        print("[OK] No parece reflejar origenes arbitrarios.")


def cookie_audit(target):
    """Audita las flags de seguridad de las cookies que setea el servidor."""
    url = _normalize_url(target)
    try:
        r = requests.get(url, timeout=10)
    except requests.RequestException as e:
        print(f"[!] Error consultando {url}: {e}")
        return

    _linea(f"Auditoria de cookies de {url}")
    cookies_raw = r.raw.headers.get_all("Set-Cookie") if hasattr(r.raw.headers, "get_all") else None
    if not cookies_raw:
        cookies_raw = [v for k, v in r.headers.items() if k.lower() == "set-cookie"]

    if not cookies_raw:
        print("El servidor no seteo cookies en esta respuesta.")
        return

    for c in cookies_raw:
        nombre = c.split("=")[0]
        print(f"\nCookie: {nombre}")
        for flag in ("Secure", "HttpOnly", "SameSite"):
            estado = "OK" if flag.lower() in c.lower() else "[!] FALTA"
            print(f"  {flag}: {estado}")


def waf_detect(target):
    """Deteccion pasiva de WAF/CDN por firmas conocidas en headers y cookies."""
    url = _normalize_url(target)
    try:
        r = requests.get(url, timeout=10)
    except requests.RequestException as e:
        print(f"[!] Error consultando {url}: {e}")
        return

    _linea(f"Deteccion de WAF en {url}")
    blob = (str(r.headers).lower() + " " + str(r.cookies.get_dict()).lower())
    detectados = set()

    for firma, nombre in WAF_SIGNATURES.items():
        if firma in blob:
            detectados.add(nombre)

    if detectados:
        print(f"[!] Posible WAF/CDN detectado: {', '.join(sorted(detectados))}")
    else:
        print("No se detecto firma de WAF conocida (no significa que no haya uno).")


def tech_fingerprint(target):
    """Detecta tecnologia (server, CMS, frameworks) por headers y HTML."""
    url = _normalize_url(target)
    try:
        r = requests.get(url, timeout=10)
    except requests.RequestException as e:
        print(f"[!] Error consultando {url}: {e}")
        return

    _linea(f"Fingerprint tecnologico de {url}")

    server = r.headers.get("Server")
    powered = r.headers.get("X-Powered-By")
    if server:
        print(f"Server:        {server}")
    if powered:
        print(f"X-Powered-By:  {powered}")

    html = r.text.lower()
    detecciones = []

    firmas = {
        "wordpress": "wp-content",
        "joomla": "joomla",
        "drupal": "drupal",
        "shopify": "cdn.shopify.com",
        "wix": "wix.com",
        "react": "react-dom",
        "next.js": "__next",
        "vue.js": "__vue__",
        "angular": "ng-version",
        "laravel": "laravel_session",
        "django": "csrfmiddlewaretoken",
        "cloudflare": "cloudflare",
    }
    for nombre, firma in firmas.items():
        if firma in html or firma in str(r.headers).lower():
            detecciones.append(nombre)

    generator = re.search(r'<meta name="generator" content="([^"]+)"', r.text, re.IGNORECASE)
    if generator:
        print(f"Generator tag: {generator.group(1)}")

    if detecciones:
        print(f"Tecnologias detectadas: {', '.join(sorted(set(detecciones)))}")
    else:
        print("No se detectaron firmas de tecnologia conocidas.")


def robots_sitemap(target):
    """Revisa robots.txt y sitemap.xml en busca de rutas interesantes."""
    base = _normalize_url(target).rstrip("/")

    _linea(f"robots.txt de {base}")
    try:
        r = requests.get(f"{base}/robots.txt", timeout=8)
        if r.status_code == 200 and r.text.strip():
            print(r.text[:2000])
        else:
            print(f"[!] No hay robots.txt accesible (status {r.status_code})")
    except requests.RequestException as e:
        print(f"[!] Error: {e}")

    _linea(f"sitemap.xml de {base}")
    try:
        r = requests.get(f"{base}/sitemap.xml", timeout=8)
        if r.status_code == 200 and r.text.strip():
            print(r.text[:2000])
        else:
            print(f"[!] No hay sitemap.xml accesible (status {r.status_code})")
    except requests.RequestException as e:
        print(f"[!] Error: {e}")


def wayback_urls(domain, limit=100):
    """Trae URLs historicas indexadas por Wayback Machine para el dominio."""
    _linea(f"Wayback Machine URLs de {domain}")
    try:
        r = requests.get(
            "http://web.archive.org/cdx/search/cdx",
            params={
                "url": f"{domain}/*",
                "output": "json",
                "fl": "original",
                "collapse": "urlkey",
                "limit": limit,
            },
            timeout=20,
        )
        r.raise_for_status()
        data = r.json()
    except requests.RequestException as e:
        print(f"[!] Error consultando Wayback: {e}")
        return
    except ValueError:
        print("[!] Respuesta invalida de Wayback Machine.")
        return

    if len(data) <= 1:
        print("No se encontraron URLs archivadas para este dominio.")
        return

    urls = [fila[0] for fila in data[1:]]
    print(f"{len(urls)} URLs encontradas:\n")
    for u in urls:
        print(u)


def js_endpoint_scraper(target, max_js=5):
    """Extrae archivos .js de una pagina y busca rutas/endpoints dentro de ellos."""
    url = _normalize_url(target)
    try:
        r = requests.get(url, timeout=10)
    except requests.RequestException as e:
        print(f"[!] Error consultando {url}: {e}")
        return

    scripts = re.findall(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', r.text, re.IGNORECASE)
    if not scripts:
        print("No se encontraron archivos .js enlazados en la pagina.")
        return

    scripts = scripts[:max_js]
    _linea(f"JS endpoint scraper de {url} ({len(scripts)} archivos)")

    endpoint_pattern = re.compile(r'''["'](/[a-zA-Z0-9_\-/]{2,60}(?:\.[a-zA-Z]{2,5})?)["']''')
    encontrados = set()

    for src in scripts:
        js_url = urljoin(url, src)
        try:
            jr = requests.get(js_url, timeout=10)
        except requests.RequestException:
            continue
        print(f"\n[{js_url}]")
        matches = endpoint_pattern.findall(jr.text)
        rutas_utiles = sorted(set(
            m for m in matches
            if not m.endswith((".png", ".jpg", ".jpeg", ".svg", ".css", ".woff", ".woff2"))
        ))[:30]
        for ruta in rutas_utiles:
            print(f"  {ruta}")
            encontrados.add(ruta)

    print(f"\n--- Total de rutas unicas encontradas: {len(encontrados)} ---")


# ---------- SSL / TLS ----------
def ssl_info(domain, port=443):
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((domain, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
    except (socket.gaierror, socket.timeout, ssl.SSLError, ConnectionRefusedError) as e:
        print(f"[!] Error obteniendo certificado: {e}")
        return

    _linea(f"Certificado SSL de {domain}")
    subject = dict(x[0] for x in cert.get("subject", []))
    issuer = dict(x[0] for x in cert.get("issuer", []))
    print(f"Emitido a:      {subject.get('commonName')}")
    print(f"Emisor:         {issuer.get('organizationName')} ({issuer.get('commonName')})")
    print(f"Valido desde:   {cert.get('notBefore')}")
    print(f"Valido hasta:   {cert.get('notAfter')}")

    try:
        expira = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        dias = (expira - datetime.datetime.utcnow()).days
        if dias < 0:
            print("Estado:         [!] CERTIFICADO EXPIRADO")
        elif dias < 15:
            print(f"Estado:         [!] Expira en {dias} dias, ojo")
        else:
            print(f"Estado:         OK ({dias} dias restantes)")
    except Exception:
        pass


# ---------- Fuzzing (sub/dirs) ----------

def _try_resolve(sub, domain):
    fqdn = f"{sub}.{domain}"
    try:
        ip = socket.gethostbyname(fqdn)
        return (fqdn, ip)
    except socket.gaierror:
        return None


def fuzz_subdomains(domain, limit=300, workers=30):
    print("\n[+] Descargando wordlist de subdominios desde GitHub...")
    words = fetch_wordlist(SUBDOMAINS_WORDLIST_URL, limit=limit)
    if not words:
        return

    print(f"[+] {len(words)} palabras cargadas. Fuzzeando {domain} (workers={workers})...\n")
    encontrados = []

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(_try_resolve, w, domain): w for w in words}
        for future in as_completed(futures):
            result = future.result()
            if result:
                fqdn, ip = result
                print(f"[+] {fqdn} -> {ip}")
                encontrados.append((fqdn, ip))

    print(f"\n--- Fuzz terminado: {len(encontrados)} subdominios encontrados de {len(words)} probados ---")


def _try_path(base_url, path, timeout=6):
    url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
    try:
        r = requests.get(url, timeout=timeout, allow_redirects=False)
        if r.status_code != 404:
            return (url, r.status_code)
    except requests.RequestException:
        return None
    return None


def fuzz_directories(target, limit=300, workers=20):
    base_url = _normalize_url(target)

    print("\n[+] Descargando wordlist de directorios desde GitHub...")
    words = fetch_wordlist(DIRS_WORDLIST_URL, limit=limit)
    if not words:
        return

    print(f"[+] {len(words)} rutas cargadas. Fuzzeando {base_url} (workers={workers})...\n")
    encontrados = []

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(_try_path, base_url, w): w for w in words}
        for future in as_completed(futures):
            result = future.result()
            if result:
                url, status = result
                print(f"[+] {status} -> {url}")
                encontrados.append((url, status))

    print(f"\n--- Fuzz terminado: {len(encontrados)} rutas encontradas de {len(words)} probadas ---")


# ---------- CVE lookup ----------

def cve_lookup(keyword, limit=10):
    """Busca CVEs recientes relacionados a un producto/keyword via API publica de NVD."""
    _linea(f"CVEs relacionados a '{keyword}'")
    try:
        r = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"keywordSearch": keyword, "resultsPerPage": limit},
            timeout=15,
        )
        r.raise_for_status()
        data = r.json()
    except requests.RequestException as e:
        print(f"[!] Error consultando NVD: {e}")
        return

    vulns = data.get("vulnerabilities", [])
    if not vulns:
        print("No se encontraron CVEs para ese termino.")
        return

    for v in vulns:
        cve = v.get("cve", {})
        cve_id = cve.get("id")
        descs = cve.get("descriptions", [])
        desc_en = next((d["value"] for d in descs if d.get("lang") == "en"), "")
        metrics = cve.get("metrics", {})
        severidad = "N/A"
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics:
                severidad = metrics[key][0]["cvssData"].get("baseSeverity", "N/A")
                break
        print(f"\n{cve_id} | Severidad: {severidad}")
        print(f"{desc_en[:200]}...")


# ---------- Hash identifier ----------

def hash_identify(hash_str):
    """Identifica el tipo probable de un hash por longitud/patron. No crackea nada."""
    hash_str = hash_str.strip()
    _linea(f"Identificacion de hash")
    print(f"Input: {hash_str}")
    coincidencias = [nombre for patron, nombre in HASH_PATTERNS if re.match(patron, hash_str)]

    if coincidencias:
        print("Posibles tipos:")
        for c in coincidencias:
            print(f"  - {c}")
    else:
        print("No coincide con ningun patron conocido (puede ser un hash custom o salted).")


# ---------- Menu ----------

def banner():
    print(r"""
 ____  _     ___ ____ ____
| __ )| |   |_ _/ ___/ ___|
|  _ \| |    | |\___ \___ \
| |_) | |___ | | ___) |__) |
|____/|_____|___|____/____/
       multitool - recon & OSINT toolkit
""")
    print("[!] Uso exclusivo en sistemas propios o con autorizacion explicita.")
    print("[!] El autor no se responsabiliza por el mal uso de esta herramienta.\n")


def menu():
    print("--- MODULOS ---")
    print(" 1) IP geolocation")
    print(" 2) WHOIS de dominio")
    print(" 3) DNS lookup (dominio -> IP)")
    print(" 4) Ver mi IP publica")
    print(" 5) Fuzz de subdominios (wordlist de GitHub)")
    print(" 6) Port scanner (puertos comunes)")
    print(" 7) HTTP headers / banner grab")
    print(" 8) Info de certificado SSL")
    print(" 9) Reverse DNS (IP -> hostname)")
    print("10) Fuzz de directorios/rutas HTTP (wordlist de GitHub)")
    print("11) Registros DNS completos (A/AAAA/MX/NS/TXT/CNAME)")
    print("12) Auditoria de security headers")
    print("13) Metodos HTTP permitidos (OPTIONS)")
    print("14) Fingerprint de tecnologia (CMS/framework/server)")
    print("15) robots.txt / sitemap.xml recon")
    print("16) Buscar CVEs por producto/keyword")
    print("17) Identificar tipo de hash")
    print("18) Shodan InternetDB (puertos/CVEs de una IP)")
    print("19) ASN / Org lookup de una IP")
    print("20) CORS misconfiguration check")
    print("21) Auditoria de cookies (Secure/HttpOnly/SameSite)")
    print("22) Deteccion de WAF/CDN")
    print("23) Wayback Machine URLs historicas")
    print("24) JS endpoint scraper")
    print("25) Traceroute")
    print(" 0) Salir")


def main():
    banner()
    while True:
        menu()
        op = input("\n> Elegi una opcion: ").strip()

        if op == "1":
            ip = input("IP a consultar (vacio = tu propia IP): ").strip()
            if not ip:
                ip = my_ip()
                if not ip:
                    continue
            ip_geo(ip)

        elif op == "2":
            d = input("Dominio (ej: google.com): ").strip()
            if d:
                domain_whois(d)

        elif op == "3":
            d = input("Dominio a resolver: ").strip()
            if d:
                dns_lookup(d)

        elif op == "4":
            my_ip()

        elif op == "5":
            d = input("Dominio a fuzzear (ej: google.com): ").strip()
            if not d:
                continue
            limit_in = input("Cantidad de palabras a probar (enter = 300): ").strip()
            limit = int(limit_in) if limit_in.isdigit() else 300
            fuzz_subdomains(d, limit=limit)

        elif op == "6":
            t = input("Host o IP a escanear: ").strip()
            if t:
                port_scan(t)

        elif op == "7":
            t = input("Dominio o URL: ").strip()
            if t:
                http_headers(t)

        elif op == "8":
            d = input("Dominio (ej: google.com): ").strip()
            if d:
                ssl_info(d)

        elif op == "9":
            ip = input("IP a resolver: ").strip()
            if ip:
                reverse_dns(ip)

        elif op == "10":
            t = input("Host o URL a fuzzear (ej: ejemplo.com): ").strip()
            if not t:
                continue
            limit_in = input("Cantidad de rutas a probar (enter = 300): ").strip()
            limit = int(limit_in) if limit_in.isdigit() else 300
            fuzz_directories(t, limit=limit)

        elif op == "11":
            d = input("Dominio: ").strip()
            if d:
                dns_records(d)

        elif op == "12":
            t = input("Dominio o URL: ").strip()
            if t:
                security_headers(t)

        elif op == "13":
            t = input("Dominio o URL: ").strip()
            if t:
                http_methods(t)

        elif op == "14":
            t = input("Dominio o URL: ").strip()
            if t:
                tech_fingerprint(t)

        elif op == "15":
            t = input("Dominio o URL: ").strip()
            if t:
                robots_sitemap(t)

        elif op == "16":
            k = input("Producto/keyword (ej: apache 2.4, wordpress): ").strip()
            if k:
                cve_lookup(k)

        elif op == "17":
            h = input("Hash a identificar: ").strip()
            if h:
                hash_identify(h)

        elif op == "18":
            ip = input("IP a consultar en Shodan InternetDB: ").strip()
            if ip:
                shodan_internetdb(ip)

        elif op == "19":
            ip = input("IP a consultar: ").strip()
            if ip:
                asn_lookup(ip)

        elif op == "20":
            t = input("Dominio o URL: ").strip()
            if t:
                cors_check(t)

        elif op == "21":
            t = input("Dominio o URL: ").strip()
            if t:
                cookie_audit(t)

        elif op == "22":
            t = input("Dominio o URL: ").strip()
            if t:
                waf_detect(t)

        elif op == "23":
            d = input("Dominio (ej: ejemplo.com): ").strip()
            if d:
                wayback_urls(d)

        elif op == "24":
            t = input("Dominio o URL: ").strip()
            if t:
                js_endpoint_scraper(t)

        elif op == "25":
            t = input("Host o IP: ").strip()
            if t:
                traceroute(t)

        elif op == "0":
            print("Chau.")
            sys.exit(0)

        else:
            print("[!] Opcion invalida.")

        input("\n(enter para continuar) ")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nCortado.")
