"""pdf_scan.py — escáner de PDFs para el Vault (análisis estático + ClamAV + VirusTotal por hash).

Solo usa la librería estándar (no requiere agregar nada a requirements.txt).
El PDF se analiza en memoria; nunca se escribe a disco.

Contrato usado por vault.py / vault.html:
    MAX_BYTES                      tamaño máximo (bytes)
    escanear(datos, nombre, usar_vt=True) -> dict con:
        veredicto  LIMPIO | SOSPECHOSO | PELIGROSO
        puntaje    0-100
        nombre, bytes, paginas, objetos
        capas      lista de pruebas realizadas
        hallazgos  [{severidad: critica|alta|media|baja|info, texto, detalle: [str]}]
        urls       URLs encontradas
        hashes     {md5, sha1, sha256}
    Lanza ValueError si el archivo no parece un PDF.

Variables de entorno opcionales:
    VT_API_KEY                     activa la consulta a VirusTotal (solo se envía el hash SHA-256)
    CLAMD_HOST, CLAMD_PORT         ClamAV por TCP (puerto por defecto 3310)
    CLAMD_SOCKET                   ClamAV por socket unix (ej. /var/run/clamav/clamd.ctl)
"""
import hashlib
import json
import os
import re
import socket
import struct
import urllib.error
import urllib.request
import zlib

MAX_BYTES = 25 * 1024 * 1024
_MAX_STREAM = 8 * 1024 * 1024      # tope al descomprimir un stream (anti zip-bomb)
_MAX_STREAMS = 400                 # streams que se inspeccionan
_PESO = {"critica": 45, "alta": 25, "media": 10, "baja": 3, "info": 0}

# nombre PDF -> (severidad, descripción)
_RIESGOS = {
    "JavaScript": ("alta", "Contiene JavaScript (/JavaScript)"),
    "JS": ("alta", "Contiene código JavaScript (/JS)"),
    "Launch": ("critica", "Acción /Launch: puede ejecutar programas del sistema"),
    "OpenAction": ("media", "Acción automática al abrir el documento (/OpenAction)"),
    "AA": ("media", "Acciones adicionales automáticas (/AA)"),
    "EmbeddedFile": ("alta", "Tiene archivos incrustados (/EmbeddedFile)"),
    "RichMedia": ("alta", "Contenido multimedia/Flash incrustado (/RichMedia)"),
    "XFA": ("media", "Formularios XFA (superficie de ataque histórica)"),
    "SubmitForm": ("media", "Envía datos de formulario a una URL (/SubmitForm)"),
    "ImportData": ("media", "Importa datos externos (/ImportData)"),
    "GoToR": ("media", "Enlaza a otro archivo remoto (/GoToR)"),
    "GoToE": ("media", "Abre un archivo incrustado (/GoToE)"),
    "JBIG2Decode": ("baja", "Usa el filtro JBIG2 (vector de exploits conocidos)"),
    "Encrypt": ("baja", "Está cifrado: no se pudo inspeccionar todo su contenido"),
    "URI": ("info", "Contiene enlaces (/URI)"),
}

# patrones sospechosos dentro de JavaScript / contenido descomprimido
_JS_PATRONES = [
    (r"\beval\s*\(", "eval()"), (r"\bunescape\s*\(", "unescape()"),
    (r"String\.fromCharCode", "String.fromCharCode"), (r"\bapp\.launchURL", "app.launchURL"),
    (r"\bthis\.exportDataObject", "exportDataObject"), (r"\butil\.printf\b", "util.printf"),
    (r"\bCollab\.(collectEmailInfo|getIcon)", "Collab.* (CVE históricos)"),
    (r"\bmedia\.newPlayer", "media.newPlayer"), (r"\bsetTimeOut|\bsetInterval", "setTimeOut/setInterval"),
    (r"\bActiveXObject|WScript\.Shell|powershell|cmd\.exe", "ejecución de sistema"),
    (r"(%u[0-9a-fA-F]{4}){8,}", "shellcode con %u"), (r"\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){15,}", "bytes hex largos"),
    (r"https?://[^\s\"')]+\.(exe|dll|scr|bat|ps1|js|vbs|jar)\b", "descarga de ejecutable"),
]
_RE_URL = re.compile(rb"https?://[^\s<>()\"'\\\]]{4,300}", re.I)


def _decodificar_nombres(b):
    """Resuelve la ofuscación /J#61vaScript -> /JavaScript."""
    return re.sub(rb"#([0-9a-fA-F]{2})", lambda m: bytes([int(m.group(1), 16)]), b)


def _inflar(raw):
    try:
        d = zlib.decompressobj()
        out = d.decompress(raw, _MAX_STREAM)
        return out
    except Exception:
        return b""


def _streams(datos):
    """Devuelve contenido de streams (descomprimiendo Flate cuando se puede)."""
    res = []
    for m in re.finditer(rb"<<(.{0,1500}?)>>\s*stream\r?\n", datos, re.S):
        if len(res) >= _MAX_STREAMS:
            break
        ini = m.end()
        fin = datos.find(b"endstream", ini)
        if fin < 0:
            continue
        cuerpo = datos[ini:fin]
        dic = m.group(1)
        if b"FlateDecode" in dic or b"/Fl" in dic:
            cuerpo = _inflar(cuerpo) or cuerpo
        res.append(cuerpo[:_MAX_STREAM])
    return res


def _agregar(hall, sev, texto, detalle=None):
    hall.append({"severidad": sev, "texto": texto, "detalle": [str(x)[:300] for x in (detalle or [])][:8]})


def _clamav(datos):
    """Devuelve (estado, firma): estado in {'limpio','infectado','error',None}. None = ClamAV no configurado."""
    sock_path, host = os.environ.get("CLAMD_SOCKET"), os.environ.get("CLAMD_HOST")
    if not sock_path and not host:
        return None, ""
    try:
        if sock_path:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(30)
            s.connect(sock_path)
        else:
            s = socket.create_connection((host, int(os.environ.get("CLAMD_PORT", "3310") or 3310)), timeout=30)
        with s:
            s.sendall(b"zINSTREAM\0")
            for i in range(0, len(datos), 65536):
                trozo = datos[i:i + 65536]
                s.sendall(struct.pack("!I", len(trozo)) + trozo)
            s.sendall(struct.pack("!I", 0))
            resp = b""
            while not resp.endswith(b"\0") and len(resp) < 4096:
                p = s.recv(4096)
                if not p:
                    break
                resp += p
        txt = resp.strip(b"\0\n ").decode("utf-8", "replace")
        if txt.endswith("FOUND"):
            return "infectado", txt.split(":", 1)[-1].replace("FOUND", "").strip()
        if txt.endswith("OK"):
            return "limpio", ""
        return "error", txt
    except Exception as e:
        return "error", str(e)


def _virustotal(sha256):
    """Devuelve (estado, datos). estado: None (sin clave) | 'desconocido' | 'ok' | 'error'."""
    clave = os.environ.get("VT_API_KEY", "").strip()
    if not clave:
        return None, {}
    req = urllib.request.Request(f"https://www.virustotal.com/api/v3/files/{sha256}", headers={"x-apikey": clave})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            j = json.loads(r.read().decode("utf-8", "replace"))
        st = j["data"]["attributes"]["last_analysis_stats"]
        return "ok", {"malicious": int(st.get("malicious", 0)), "suspicious": int(st.get("suspicious", 0)),
                      "harmless": int(st.get("harmless", 0)), "undetected": int(st.get("undetected", 0))}
    except urllib.error.HTTPError as e:
        return ("desconocido", {}) if e.code == 404 else ("error", {"msg": f"HTTP {e.code}"})
    except Exception as e:
        return "error", {"msg": str(e)}


def escanear(datos, nombre="", usar_vt=True):
    if not datos:
        raise ValueError("El archivo está vacío")
    if len(datos) > MAX_BYTES:
        raise ValueError(f"El archivo supera {MAX_BYTES // (1024 * 1024)} MB")
    cabecera = datos[:1024].find(b"%PDF-")
    if cabecera < 0:
        raise ValueError("El archivo no parece un PDF (falta la cabecera %PDF-)")

    hashes = {"md5": hashlib.md5(datos).hexdigest(), "sha1": hashlib.sha1(datos).hexdigest(),
              "sha256": hashlib.sha256(datos).hexdigest()}
    hall, capas = [], ["análisis estático"]
    norm = _decodificar_nombres(datos)

    # --- estructura ---
    if cabecera > 0:
        _agregar(hall, "media", f"Hay {cabecera} bytes de basura antes de la cabecera %PDF (técnica de evasión)")
    if b"%%EOF" not in datos[-2048:]:
        _agregar(hall, "baja", "Falta el marcador %%EOF al final (archivo truncado o manipulado)")
    if datos.count(b"%%EOF") > 3:
        _agregar(hall, "baja", f"{datos.count(b'%%EOF')} actualizaciones incrementales (puede ocultar contenido previo)")
    objetos = len(re.findall(rb"\d+\s+\d+\s+obj\b", datos))
    paginas = len(re.findall(rb"/Type\s*/Page(?![a-zA-Z])", norm))
    if objetos == 0:
        _agregar(hall, "media", "No se encontraron objetos PDF legibles (estructura dañada o muy ofuscada)")

    # --- ofuscación de nombres ---
    ofusc = re.findall(rb"/[A-Za-z]*#[0-9a-fA-F]{2}[A-Za-z0-9#]*", datos)
    ofusc_riesgo = [o for o in ofusc if _decodificar_nombres(o)[1:].decode("latin1") in _RIESGOS]
    if ofusc_riesgo:
        _agregar(hall, "alta", "Nombres de acciones ofuscados con #hex para evadir antivirus",
                 [f"{o.decode('latin1')} → {_decodificar_nombres(o).decode('latin1')}" for o in ofusc_riesgo[:6]])
    if re.search(rb"/Filter\s*\[[^\]]*\]", norm):
        for m in re.finditer(rb"/Filter\s*\[([^\]]*)\]", norm):
            if len(re.findall(rb"/[A-Za-z0-9]+", m.group(1))) >= 3:
                _agregar(hall, "media", "Cadena de 3 o más filtros anidados en un stream (ofuscación)")
                break

    # --- palabras clave de riesgo ---
    for nom, (sev, texto) in _RIESGOS.items():
        n = len(re.findall(rb"/" + nom.encode() + rb"(?![A-Za-z0-9])", norm))
        if n:
            _agregar(hall, sev, f"{texto}" + (f" · {n} vez/veces" if n > 1 else ""))

    # --- contenido de streams (JS oculto, shellcode, ejecutables incrustados) ---
    capas.append("inspección de streams")
    contenido = b"\n".join(_streams(datos)) + b"\n" + norm
    texto = contenido.decode("latin1", "ignore")
    hits = []
    for pat, etiqueta in _JS_PATRONES:
        if re.search(pat, texto, re.I):
            hits.append(etiqueta)
    if hits:
        tiene_js = bool(re.search(rb"/(JavaScript|JS)(?![A-Za-z])", norm))
        graves = [h for h in hits if h in ("ejecución de sistema", "shellcode con %u", "bytes hex largos", "descarga de ejecutable", "eval()", "unescape()")]
        _agregar(hall, "critica" if graves and tiene_js else "media",
                 "Patrones de código malicioso/ofuscado en el contenido", hits)
    if b"MZ\x90\x00" in contenido or re.search(rb"MZ.{0,64}This program cannot be run in DOS mode", contenido, re.S):
        _agregar(hall, "critica", "Hay un ejecutable de Windows (PE/MZ) dentro del PDF")
    if contenido.startswith(b"PK\x03\x04") or b"PK\x03\x04" in contenido[:2_000_000] and b"EmbeddedFile" in norm:
        _agregar(hall, "media", "Contiene un archivo comprimido (ZIP) incrustado")

    # --- URLs ---
    urls = []
    for u in _RE_URL.findall(norm):
        s = u.decode("latin1", "ignore").rstrip(".,;")
        if s not in urls:
            urls.append(s)
    urls = urls[:50]
    exe = [u for u in urls if re.search(r"\.(exe|dll|scr|bat|ps1|vbs|jar|msi|hta)(\?|$)", u, re.I)]
    if exe:
        _agregar(hall, "alta", "Enlaces que apuntan a ejecutables", exe)
    ip = [u for u in urls if re.match(r"https?://\d{1,3}(\.\d{1,3}){3}", u)]
    if ip:
        _agregar(hall, "media", "Enlaces a direcciones IP directas (sin dominio)", ip)

    # --- ClamAV ---
    puntaje_extra = 0
    est, firma = _clamav(datos)
    if est is not None:
        capas.append("ClamAV")
        if est == "infectado":
            _agregar(hall, "critica", "ClamAV detectó malware", [firma])
        elif est == "error":
            _agregar(hall, "info", "ClamAV no pudo analizar el archivo", [firma])

    # --- VirusTotal (solo hash) ---
    if usar_vt:
        est, vt = _virustotal(hashes["sha256"])
        if est is not None:
            capas.append("VirusTotal (hash)")
            if est == "ok":
                m, s = vt["malicious"], vt["suspicious"]
                tot = m + s + vt["harmless"] + vt["undetected"]
                if m >= 3:
                    _agregar(hall, "critica", f"VirusTotal: {m} de {tot} motores lo marcan como malicioso")
                elif m + s > 0:
                    _agregar(hall, "alta", f"VirusTotal: {m} maliciosos y {s} sospechosos de {tot} motores")
                else:
                    _agregar(hall, "info", f"VirusTotal: 0 detecciones en {tot} motores")
            elif est == "desconocido":
                _agregar(hall, "info", "VirusTotal no conoce este archivo (nunca se había subido)")
            else:
                _agregar(hall, "info", "No se pudo consultar VirusTotal", [vt.get("msg", "")])

    # --- puntaje y veredicto ---
    orden = {"critica": 0, "alta": 1, "media": 2, "baja": 3, "info": 4}
    hall.sort(key=lambda h: orden[h["severidad"]])
    puntaje = min(100, sum(_PESO[h["severidad"]] for h in hall) + puntaje_extra)
    if any(h["severidad"] == "critica" for h in hall):
        puntaje = max(puntaje, 80)
    veredicto = "PELIGROSO" if puntaje >= 70 else "SOSPECHOSO" if puntaje >= 20 else "LIMPIO"

    return {"veredicto": veredicto, "puntaje": int(puntaje), "nombre": os.path.basename(nombre or "")[:120],
            "bytes": len(datos), "paginas": paginas, "objetos": objetos, "capas": capas,
            "hallazgos": hall, "urls": urls, "hashes": hashes}
