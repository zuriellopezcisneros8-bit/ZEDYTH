"""zedyth_llaves.py — Cliente para pedir llaves de Gemini al panel de ZEDYTH. Copia este archivo a cada plataforma
(Zelecte, Zmarthket...). Solo usa la librería estándar.

Variables de entorno de la plataforma (Render → Environment):
    ZEDYTH_PANEL_URL      https://<tu-panel>.onrender.com        (sin / al final)
    ZEDYTH_PANEL_TOKEN    zlk_...                                (el que genera el panel en /llaves; es un secreto)
    GEMINI_KEY_1, _2...   (RECOMENDADO: 2 o 3 propias) respaldo si el panel no responde

Cómo funciona:
    * Pide al panel hasta 5 llaves al azar y las guarda en memoria CACHE_SEG segundos: el panel (y su base) no se
      consultan en cada mensaje. Reparte la carga entre ellas.
    * Si Google responde 429/400/401/403, avisa al panel (fallo): la llave descansa o se revisa y se pasa a otra.
    * El consumo se manda por lotes cada ~60 s.
    * Si el panel no responde o no hay token, usa las GEMINI_KEY_N de esta misma plataforma. Nunca se queda sin llaves
      mientras tenga al menos una propia.

Uso:
    from zedyth_llaves import obtener, fallo, uso

    lid, llave = obtener()                       # lid es None si la llave es de respaldo local
    r = requests.post(URL_GEMINI, headers={"x-goog-api-key": llave}, json=cuerpo, timeout=30)
    if r.status_code in (400, 401, 403, 429):
        fallo(lid, r.status_code, r.text)        # y reintenta con obtener() para recibir otra
    else:
        uso(lid, peticiones=1, tokens_in=..., tokens_out=...)
"""
import json
import os
import random
import re
import threading
import time
from urllib import error as _err, request as _req

CACHE_SEG = 300          # cuánto se reutilizan las llaves recibidas
PEDIR_N = 5              # llaves por consulta (el panel entrega máximo 5)
TIMEOUT = 4              # segundos esperando al panel antes de usar el respaldo
REINTENTO_SEG = 30       # tras un fallo del panel, no insistir antes de esto
ENVIO_USO_SEG = 60

_lock = threading.Lock()
_cache = {"t": 0.0, "llaves": [], "caido_hasta": 0.0}      # llaves: [(id, llave)]
_pend = {}                                                 # id -> [peticiones, tokens_in, tokens_out]
_ultimo_envio = [time.time()]


def _cfg():
    url = (os.environ.get("ZEDYTH_PANEL_URL") or "").strip().rstrip("/")
    token = (os.environ.get("ZEDYTH_PANEL_TOKEN") or "").strip()
    return (url, token) if url.startswith("https://") and token else (None, None)


def _llamar(metodo, ruta, cuerpo=None):
    url, token = _cfg()
    if not url:
        raise RuntimeError("sin configuración del panel")
    req = _req.Request(url + ruta, method=metodo, data=json.dumps(cuerpo).encode() if cuerpo is not None else None,
                       headers={"Authorization": "Bearer " + token, "Content-Type": "application/json",
                                "User-Agent": "zedyth-llaves-cliente/1.0"})
    with _req.urlopen(req, timeout=TIMEOUT) as r:
        return json.loads(r.read().decode("utf-8") or "null")


def _respaldo():
    """GEMINI_KEY_N / GEMINI_API_KEY(S) de esta plataforma."""
    out = []
    for k in sorted(os.environ):
        if re.match(r"^GEMINI_KEY_?\d+$", k):
            out.append(os.environ[k])
    for nombre in ("GEMINI_KEYS", "GEMINI_API_KEYS", "GEMINI_API_KEY"):
        out += re.split(r"[,;\s]+", os.environ.get(nombre) or "")
    return [v.strip().strip('"').strip("'") for v in out if len(v.strip()) >= 8]


def _refrescar():
    """Pide llaves al panel. Con el panel caído no insiste durante REINTENTO_SEG."""
    ahora = time.time()
    if ahora < _cache["caido_hasta"]:
        return
    try:
        j = _llamar("GET", f"/api/llaves/v1/gemini?n={PEDIR_N}")
        llaves = [(int(x["id"]), str(x["llave"])) for x in (j or {}).get("llaves", []) if x.get("llave")]
        if llaves:
            _cache.update(t=ahora, llaves=llaves, caido_hasta=0.0)
            return
    except (_err.URLError, _err.HTTPError, ValueError, KeyError, RuntimeError, OSError):
        pass
    _cache["caido_hasta"] = ahora + REINTENTO_SEG


def obtener():
    """(id_en_el_panel, llave). id None = llave de respaldo local. (None, None) si no hay ninguna."""
    with _lock:
        if not _cache["llaves"] or time.time() - _cache["t"] > CACHE_SEG:
            _refrescar()
        if _cache["llaves"]:
            return random.choice(_cache["llaves"])
    prop = _respaldo()
    return (None, random.choice(prop)) if prop else (None, None)


def _en_hilo(f, *a):
    def _t():
        try:
            f(*a)
        except Exception:
            pass          # avisar al panel nunca debe romper la petición del usuario
    threading.Thread(target=_t, daemon=True).start()


def fallo(llave_id, codigo, cuerpo=""):
    """Avisa al panel de un error de Google (400/401/403/429) y deja de usar esa llave aquí."""
    if llave_id is None:
        return
    with _lock:
        _cache["llaves"] = [x for x in _cache["llaves"] if x[0] != llave_id]
    _en_hilo(_llamar, "POST", "/api/llaves/v1/reportar",
             {"llave_id": llave_id, "codigo": int(codigo), "cuerpo": str(cuerpo or "")[:2000]})


def _enviar_uso(lote):
    for lid, (p, ti, to) in lote.items():
        _llamar("POST", "/api/llaves/v1/uso", {"llave_id": lid, "peticiones": p, "tokens_in": ti, "tokens_out": to})


def uso(llave_id, peticiones=1, tokens_in=0, tokens_out=0):
    """Acumula el consumo y lo manda al panel por lotes (~cada minuto mientras haya actividad)."""
    if llave_id is None:
        return
    with _lock:
        a = _pend.setdefault(llave_id, [0, 0, 0])
        a[0] += int(peticiones)
        a[1] += int(tokens_in)
        a[2] += int(tokens_out)
        if time.time() - _ultimo_envio[0] < ENVIO_USO_SEG:
            return
        lote = dict(_pend)
        _pend.clear()
        _ultimo_envio[0] = time.time()
    _en_hilo(_enviar_uso, lote)
