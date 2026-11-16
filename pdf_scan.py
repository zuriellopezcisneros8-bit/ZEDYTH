"""pdf_scan.py — Escáner estático de PDFs para el ZEDYTH OPS VAULT.

Analiza la ESTRUCTURA del PDF (no lo abre ni lo ejecuta) y busca los indicadores que usa el malware en PDFs:
JavaScript, acciones automáticas al abrir, lanzamiento de programas, archivos incrustados, formularios que
envían datos, enlaces externos, nombres ofuscados, contenido escondido dentro de streams comprimidos, etc.

Capas (todas opcionales salvo la primera):
  1. Análisis estructural propio (sin dependencias).
  2. ClamAV, si el servidor lo tiene (comando `clamscan` o `clamdscan`, o CLAMD_HOST/CLAMD_PORT).
  3. VirusTotal por HASH (variable VT_API_KEY). Solo se envía el SHA-256, NUNCA el archivo.

Ningún escáner puede garantizar que un archivo sea 100 % seguro: el veredicto «LIMPIO» significa
«no se encontró nada sospechoso con estas pruebas».
"""
import hashlib
import os
import re
import shutil
import socket
import struct
import subprocess
import tempfile
import zlib

MAX_BYTES = 25 * 1024 * 1024          # tamaño máximo aceptado
MAX_DESCOMPRIMIDO = 40 * 1024 * 1024  # tope total al descomprimir (anti «zip bomb»)
MAX_STREAM = 8 * 1024 * 1024          # tope por stream

# (patrón, clave, descripción, puntos, severidad)
INDICADORES = [
    (rb"/JavaScript\b", "javascript", "Contiene JavaScript", 40, "alta"),
    (rb"/JS\b", "js", "Tiene un campo /JS (código JavaScript)", 40, "alta"),
    (rb"/OpenAction\b", "openaction", "Ejecuta una acción automáticamente al abrir el documento", 25, "alta"),
    (rb"/AA\b", "aa", "Tiene acciones adicionales automáticas (/AA)", 15, "media"),
    (rb"/Launch\b", "launch", "Puede lanzar programas del sistema (/Launch)", 60, "critica"),
    (rb"/EmbeddedFile\b", "embedded", "Lleva archivos incrustados", 35, "alta"),
    (rb"/RichMedia\b", "richmedia", "Contiene multimedia/Flash incrustado (/RichMedia)", 35, "alta"),
    (rb"/XFA\b", "xfa", "Usa formularios XFA (vector histórico de ataques)", 25, "media"),
    (rb"/SubmitForm\b", "submitform", "Puede enviar datos a un servidor (/SubmitForm)", 25, "media"),
    (rb"/ImportData\b", "importdata", "Puede importar datos externos (/ImportData)", 15, "media"),
    (rb"/GoToR\b", "gotor", "Salta a otro archivo remoto (/GoToR)", 20, "media"),
    (rb"/GoToE\b", "gotoe", "Abre un archivo incrustado (/GoToE)", 25, "media"),
    (rb"/URI\b", "uri", "Contiene enlaces web (/URI)", 4, "baja"),
    (rb"/AcroForm\b", "acroform", "Tiene formulario interactivo", 3, "baja"),
    (rb"/JBIG2Decode\b", "jbig2", "Usa JBIG2 (historial de vulnerabilidades en lectores)", 12, "media"),
    (rb"/Encrypt\b", "encrypt", "Está cifrado: su contenido no se puede inspeccionar", 20, "media"),
]

# Patrones de código malicioso en JavaScript (se buscan en el JS extraído)
PATRONES_JS = [
    (rb"eval\s*\(", "eval()", 25),
    (rb"unescape\s*\(", "unescape()", 20),
    (rb"String\.fromCharCode", "fromCharCode (ofuscación)", 15),
    (rb"util\.printf", "util.printf (exploits de formato)", 30),
    (rb"collab\.(getIcon|collectEmailInfo)", "collab.* (exploits conocidos)", 35),
    (rb"app\.launchURL|this\.exportDataObject|submitForm|getURL", "abre URLs / exporta datos", 25),
    (rb"spray|nop\s*sled|%u9090|0x90909090", "heap spray / NOP sled", 40),
    (rb"ActiveXObject|WScript\.|Shell\(", "intenta usar componentes del sistema", 40),
    (rb"app\.alert\s*\(", "app.alert (común en pruebas de PoC)", 3),
]

RE_URL = re.compile(rb"/URI\s*\(([^)]{1,300})\)")
RE_OBJ = re.compile(rb"(\d+)\s+(\d+)\s+obj\b")
RE_STREAM = re.compile(rb"stream\r?\n(.*?)\r?\n?endstream", re.S)
RE_NOMBRE_OFUSCADO = re.compile(rb"/[A-Za-z]*#[0-9A-Fa-f]{2}[A-Za-z#0-9]*")


def hashes(datos):
    return {"md5": hashlib.md5(datos).hexdigest(), "sha1": hashlib.sha1(datos).hexdigest(),
            "sha256": hashlib.sha256(datos).hexdigest()}


def _deshex_nombres(b):
    """Reemplaza #xx dentro de los nombres PDF (así se disfraza /JavaScript como /Java#53cript)."""
    def r(m):
        return bytes([int(m.group(1), 16)])
    return re.sub(rb"#([0-9A-Fa-f]{2})", r, b)


def _inflar(blob):
    """Descomprime un stream Flate con tope de tamaño. Devuelve bytes o None."""
    try:
        d = zlib.decompressobj()
        salida = d.decompress(blob, MAX_STREAM)
        return salida
    except Exception:
        try:
            d = zlib.decompressobj(-zlib.MAX_WBITS)
            return d.decompress(blob, MAX_STREAM)
        except Exception:
            return None


def _streams_descomprimidos(datos):
    """Todo el contenido de los streams, ya descomprimido cuando es posible (donde se esconde el JS)."""
    total, salida = 0, []
    for m in RE_STREAM.finditer(datos):
        blob = m.group(1)
        inf = _inflar(blob)
        if inf is None:
            inf = blob
        total += len(inf)
        if total > MAX_DESCOMPRIMIDO:
            salida.append(b"")   # marca de tope superado
            return salida, True
        salida.append(inf)
    return salida, False


def _veredicto(puntos, critico):
    if critico or puntos >= 60:
        return "PELIGROSO"
    if puntos >= 20:
        return "SOSPECHOSO"
    return "LIMPIO"


def analizar_estructura(datos):
    hallazgos, puntos, critico = [], 0, False

    def add(clave, texto, pts, sev, extra=None):
        nonlocal puntos, critico
        puntos += pts
        if sev == "critica":
            critico = True
        h = {"clave": clave, "texto": texto, "puntos": pts, "severidad": sev}
        if extra:
            h["detalle"] = extra
        hallazgos.append(h)

    # --- Cabecera y estructura básica ---
    inicio = datos[:1024]
    pos = inicio.find(b"%PDF-")
    if pos == -1:
        add("sin_cabecera", "No empieza con la firma %PDF-: puede ser otro tipo de archivo disfrazado", 50, "alta")
    elif pos > 0:
        add("cabecera_desplazada", f"Hay {pos} bytes antes de la firma %PDF- (truco para evadir filtros)", 25, "media")
    for firma, nombre in ((b"MZ", "ejecutable de Windows (.exe/.dll)"), (b"\x7fELF", "ejecutable de Linux"),
                          (b"PK\x03\x04", "archivo ZIP/Office"), (b"#!", "script")):
        if datos.startswith(firma):
            add("firma_otro", f"El archivo realmente es un {nombre}, no un PDF", 80, "critica")
    if b"%%EOF" not in datos[-2048:]:
        add("sin_eof", "No termina con %%EOF: archivo truncado o manipulado", 8, "baja")
    eofs = datos.count(b"%%EOF")
    if eofs > 3:
        add("muchos_eof", f"Tiene {eofs} marcas %%EOF (actualizaciones incrementales; se usa para ocultar contenido)", 8, "baja")
    ultimo = datos.rfind(b"%%EOF")
    if ultimo != -1 and len(datos) - (ultimo + 5) > 1024:
        extra = len(datos) - (ultimo + 5)
        add("datos_tras_eof", f"{extra} bytes de datos después del final del PDF (puede esconder otro archivo)", 20, "media")

    # --- Objetos y streams ---
    contenido, tope = _streams_descomprimidos(datos)
    if tope:
        add("zip_bomb", "Al descomprimir supera el tamaño máximo permitido (posible «bomba de descompresión»)", 40, "alta")
    cuerpo_total = datos + b"\n" + b"\n".join(contenido)

    # Los nombres ofuscados se normalizan para detectar /Java#53cript
    ofuscados = RE_NOMBRE_OFUSCADO.findall(datos)
    normal = _deshex_nombres(cuerpo_total)
    if ofuscados:
        add("nombres_ofuscados", f"{len(ofuscados)} nombres con caracteres codificados (#xx): técnica de ofuscación", 25, "alta",
            [o.decode("latin-1")[:40] for o in ofuscados[:5]])

    objs_stream = len(re.findall(rb"/ObjStm\b", datos))
    if objs_stream:
        add("objstm", f"{objs_stream} flujos de objetos comprimidos (se inspeccionaron por dentro)", 0, "info")

    filtros = re.findall(rb"/Filter\s*\[?([^\]>]{0,120})", datos)
    encadenados = [f for f in filtros if len(re.findall(rb"/[A-Za-z0-9]+Decode|/Fl\b|/LZW\b", f)) >= 3]
    if encadenados:
        add("filtros_encadenados", "Streams con 3 o más filtros encadenados (ofuscación típica de malware)", 20, "alta")

    # --- Indicadores principales ---
    for patron, clave, texto, pts, sev in INDICADORES:
        n = len(re.findall(patron, normal))
        if not n:
            continue
        # /URI y /AcroForm son frecuentes en PDFs normales: no sumar por repetición
        add(clave, f"{texto} ({n}×)" if n > 1 else texto, pts, sev)

    # --- JavaScript: inspección del código ---
    if any(h["clave"] in ("javascript", "js", "openaction") for h in hallazgos):
        for patron, nombre, pts in PATRONES_JS:
            if re.search(patron, normal, re.I):
                add("js_" + nombre.split()[0], f"En el JavaScript: {nombre}", pts, "alta")
        if re.search(rb"/(JavaScript|JS)\b", normal) and re.search(rb"/OpenAction\b", normal):
            add("js_auto", "JavaScript que se ejecuta solo al abrir (combinación muy usada por malware)", 20, "alta")

    # --- URLs ---
    urls = []
    for m in RE_URL.finditer(normal):
        u = m.group(1).decode("latin-1", "replace").strip()
        if u and u not in urls:
            urls.append(u)
    sospechosas = [u for u in urls if re.search(r"^https?://\d{1,3}(\.\d{1,3}){3}|\.(exe|scr|bat|cmd|ps1|js|vbs|jar|msi|zip|rar)(\?|$)|bit\.ly|tinyurl|goo\.gl|t\.co/", u, re.I)]
    if sospechosas:
        add("urls_sospechosas", f"{len(sospechosas)} enlace(s) a IPs directas, acortadores o descargas de ejecutables", 30, "alta", sospechosas[:8])

    # --- Archivos incrustados: nombre/tipo ---
    nombres = [m.decode("latin-1", "replace") for m in re.findall(rb"/F\s*\(([^)]{1,120}\.(?:exe|dll|scr|bat|cmd|ps1|vbs|js|jar|msi|lnk|hta|docm|xlsm))\)", normal, re.I)]
    if nombres:
        add("incrustado_peligroso", "Archivo ejecutable o con macros incrustado", 60, "critica", nombres[:5])
    for inf in contenido:
        if inf[:2] == b"MZ" and b"This program" in inf[:512]:
            add("pe_incrustado", "Dentro de un stream hay un ejecutable de Windows (MZ/PE)", 80, "critica")
            break

    # --- Tamaño anómalo ---
    n_obj = len(RE_OBJ.findall(datos))
    if len(datos) > 100_000 and n_obj < 4:
        add("pocos_objetos", "Archivo grande con muy pocos objetos (probable carga útil escondida)", 15, "media")

    return {"puntos": puntos, "critico": critico, "hallazgos": hallazgos, "urls": urls[:30],
            "objetos": n_obj, "paginas": len(re.findall(rb"/Type\s*/Page\b", datos))}


# --- Capa 2: ClamAV ----------------------------------------------------------
def clamav(datos):
    """Devuelve {'disponible': bool, 'firma': str|None, 'motor': str}."""
    host = os.environ.get("CLAMD_HOST")
    if host:                       # demonio remoto/local por INSTREAM
        try:
            s = socket.create_connection((host, int(os.environ.get("CLAMD_PORT", "3310"))), timeout=15)
            s.sendall(b"zINSTREAM\0")
            for i in range(0, len(datos), 8192):
                trozo = datos[i:i + 8192]
                s.sendall(struct.pack("!I", len(trozo)) + trozo)
            s.sendall(struct.pack("!I", 0))
            resp = s.recv(4096).decode("latin-1", "replace").strip("\0\n ")
            s.close()
            if resp.endswith("FOUND"):
                return {"disponible": True, "firma": resp.split(":", 1)[1].replace("FOUND", "").strip(), "motor": "clamd"}
            return {"disponible": True, "firma": None, "motor": "clamd"}
        except Exception:
            return {"disponible": False, "firma": None, "motor": "clamd"}
    exe = shutil.which("clamscan")
    if not exe:
        return {"disponible": False, "firma": None, "motor": "clamscan"}
    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
        f.write(datos)
        ruta = f.name
    try:
        r = subprocess.run([exe, "--no-summary", ruta], capture_output=True, text=True, timeout=60)
        if r.returncode == 1:
            linea = (r.stdout or "").strip().splitlines()[-1] if r.stdout.strip() else ""
            firma = linea.split(":", 1)[1].replace("FOUND", "").strip() if ":" in linea else "detectado"
            return {"disponible": True, "firma": firma, "motor": "clamscan"}
        return {"disponible": r.returncode == 0, "firma": None, "motor": "clamscan"}
    except Exception:
        return {"disponible": False, "firma": None, "motor": "clamscan"}
    finally:
        try:
            os.unlink(ruta)
        except OSError:
            pass


# --- Capa 3: VirusTotal por hash ---------------------------------------------
def virustotal(sha256):
    """Consulta solo el hash. Devuelve {'disponible', 'conocido', 'maliciosos', 'sospechosos', 'total', 'enlace'}."""
    clave = (os.environ.get("VT_API_KEY") or "").strip()
    if not clave:
        return {"disponible": False}
    try:
        import requests
        r = requests.get(f"https://www.virustotal.com/api/v3/files/{sha256}", headers={"x-apikey": clave}, timeout=12)
        enlace = f"https://www.virustotal.com/gui/file/{sha256}"
        if r.status_code == 404:
            return {"disponible": True, "conocido": False, "enlace": enlace}
        if r.status_code != 200:
            return {"disponible": False}
        est = r.json()["data"]["attributes"]["last_analysis_stats"]
        return {"disponible": True, "conocido": True, "maliciosos": est.get("malicious", 0),
                "sospechosos": est.get("suspicious", 0), "total": sum(est.values()), "enlace": enlace}
    except Exception:
        return {"disponible": False}


# --- Función principal -------------------------------------------------------
def escanear(datos, nombre="", usar_vt=True):
    if not isinstance(datos, (bytes, bytearray)):
        raise TypeError("datos debe ser bytes")
    datos = bytes(datos)
    if not datos:
        raise ValueError("El archivo está vacío")
    if len(datos) > MAX_BYTES:
        raise ValueError(f"El archivo supera {MAX_BYTES // (1024 * 1024)} MB")

    h = hashes(datos)
    est = analizar_estructura(datos)
    clam = clamav(datos)
    vt = virustotal(h["sha256"]) if usar_vt else {"disponible": False}

    puntos, critico = est["puntos"], est["critico"]
    hallazgos = list(est["hallazgos"])
    if clam.get("firma"):
        critico = True
        hallazgos.insert(0, {"clave": "clamav", "texto": f"ClamAV lo identificó como: {clam['firma']}", "puntos": 100, "severidad": "critica"})
    if vt.get("disponible") and vt.get("conocido") and (vt.get("maliciosos", 0) >= 3):
        critico = True
        hallazgos.insert(0, {"clave": "virustotal", "texto": f"VirusTotal: {vt['maliciosos']} de {vt['total']} motores lo marcan como malicioso", "puntos": 100, "severidad": "critica"})
    elif vt.get("disponible") and vt.get("conocido") and (vt.get("maliciosos", 0) + vt.get("sospechosos", 0)) >= 1:
        puntos += 25
        hallazgos.insert(0, {"clave": "virustotal", "texto": f"VirusTotal: {vt['maliciosos']} malicioso(s) y {vt['sospechosos']} sospechoso(s) de {vt['total']} motores", "puntos": 25, "severidad": "media"})

    hallazgos.sort(key=lambda x: -x["puntos"])
    veredicto = _veredicto(puntos, critico)
    capas = ["Análisis estructural"] + (["ClamAV"] if clam.get("disponible") else []) + (["VirusTotal (hash)"] if vt.get("disponible") else [])
    return {"nombre": os.path.basename(nombre or "")[:120], "bytes": len(datos), "hashes": h, "veredicto": veredicto,
            "puntaje": min(puntos if not critico else max(puntos, 100), 100), "hallazgos": hallazgos, "urls": est["urls"],
            "paginas": est["paginas"], "objetos": est["objetos"], "capas": capas,
            "clamav": clam.get("disponible", False), "virustotal": vt}
