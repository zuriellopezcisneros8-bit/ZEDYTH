"""conectores.py — Lector genérico de APIs de SOLO LECTURA de tus plataformas (Zmarthket y las que vengan).

UN solo módulo para todas: cada plataforma nueva se da de alta desde la pantalla /conectores (URL base, cómo se autentica,
qué endpoints leer, qué cifras guardar y qué alertas disparar). No hace falta escribir otro .py por cada app.

Se conecta en app.py igual que llaves.py / monitor.py:
    import conectores
    app.register_blueprint(conectores.crear_blueprint(app, db, registrar, crear_notificacion, Proyecto))
y en el vigilante, junto a llaves.revisar():
    conectores.revisar()

Las llaves NO se guardan aquí: viven cifradas en llaves.py bajo el proveedor «API de plataforma (lectura)» (ver PROVEEDOR).
Un conector las toma del pool de su plataforma; si tienes varias APIs en la misma plataforma, pon una etiqueta distinta a cada
llave y escribe esa etiqueta en el conector.

Seguridad (todo es de lectura):
  · Solo GET. Nunca se manda nada al otro sistema salvo la llave en la cabecera.
  · Solo https (http únicamente con CONECTORES_PERMITIR_HTTP=1, para pruebas locales).
  · No sigue redirecciones: la llave jamás viaja a otro sitio distinto del configurado.
  · Bloquea hosts que resuelvan a IPs privadas/locales (SSRF). CONECTORES_PERMITIR_PRIVADOS=1 lo desactiva (solo desarrollo).
  · CONECTORES_HOSTS=a.com,b.com (opcional) limita a una lista de dominios permitidos.
  · Respuesta máxima 2 MB, tiempo máximo 8 s. La respuesta completa NO se guarda en la base: solo vive en memoria unos minutos.
    En la base solo quedan las cifras (KPIs) que tú elijas, una por día.
  · Los campos con nombre tipo password/token/secret/hash/key nunca se muestran.
  · Solo administradores con TOTP activo pueden crear o editar conectores (igual que en Llaves).

Uso desde el resto de app.py:
    d = conectores.datos("Zmarthket", "Resumen")          # dict/list ya leído (caché), o None si no hay dato
    conectores.panel_plataforma(proyecto.id)                # para la ficha de la plataforma: estado y cifras

Reglas de KPIs y alertas (una por línea):
    KPIs:     ruta | Etiqueta              ej.  ingresos_mes | Ingresos del mes
    Alertas:  ruta OPERADOR valor | Mensaje ej.  vencidos > 0 | Hay cobros vencidos
    Rutas:    a.b.c  (puntos para entrar), a.0.b (posición en lista) y «#» para contar:  cobros.#  → cuántos cobros hay.
    Operadores: > >= < <= == !=
"""
import ipaddress
import json
import operator
import os
import re
import socket
import threading
import time
import urllib.error
import urllib.request
from datetime import date, datetime, timedelta
from functools import wraps
from urllib.parse import urlparse

from flask import Blueprint, render_template, request, redirect, url_for, abort, Response
from flask_login import current_user

import llaves

PROVEEDOR = "API de plataforma (lectura)"      # agrégalo a PROVEEDORES en llaves.py
AUTH_TIPOS = {
    "bearer": "Authorization: Bearer <llave>",
    "x-api-key": "X-API-Key: <llave>",
    "cabecera": "Otra cabecera (tú eliges el nombre)",
}
TIMEOUT = 8
MAX_BYTES = 2 * 1024 * 1024
TTL_DEFECTO = 120
MAX_PRUEBAS_LLAVE = 3
MAX_VIGILADOS_POR_RONDA = 20
FALLOS_PARA_AVISAR = 3

MENSAJES = {
    "creado": "Conector creado. Ahora agrega los endpoints que quieres leer.",
    "editado": "Conector actualizado.",
    "eliminado": "Conector eliminado (las llaves siguen en Llaves, sin tocar).",
    "activado": "Conector activado.",
    "desactivado": "Conector desactivado: no se leerá hasta que lo actives.",
    "endpoint_ok": "Endpoint guardado.",
    "endpoint_borrado": "Endpoint eliminado.",
    "probado_ok": "Conexión correcta: la API respondió y la llave fue aceptada.",
    "probado_mal": "La prueba falló. Revisa la URL, la llave en Llaves y el tipo de autenticación.",
}

_ERR_HTTP = {
    301: "Redirección bloqueada (la llave no se envía a otro sitio). Corrige la URL base.",
    302: "Redirección bloqueada (la llave no se envía a otro sitio). Corrige la URL base.",
    307: "Redirección bloqueada (la llave no se envía a otro sitio). Corrige la URL base.",
    308: "Redirección bloqueada (la llave no se envía a otro sitio). Corrige la URL base.",
    400: "La API rechazó la petición (400).",
    401: "La API rechazó la llave (401): inválida, vencida o revocada.",
    403: "La API negó el acceso (403): la llave no tiene permiso para esa ruta.",
    404: "Ruta no encontrada (404). Revisa el endpoint.",
    429: "La API pidió bajar el ritmo (429).",
}

_SENSIBLE = re.compile(r"pass|pwd|token|secret|hash|api_?key|clave|llave|otp|totp|bearer", re.I)
_RE_ALERTA = re.compile(r"^\s*([A-Za-z0-9_.#\-]+)\s*(>=|<=|==|!=|>|<)\s*([^|]+?)\s*(?:\|\s*(.+?))?\s*$")
_RE_RUTA_ENDPOINT = re.compile(r"^/[A-Za-z0-9._~!$&'()*+,;=:%/\-]*(\?[A-Za-z0-9._~!$&'()*+,;=:%/?\-]*)?$")
_RE_CABECERA = re.compile(r"^[A-Za-z0-9\-]{1,60}$")
_OPS = {">": operator.gt, ">=": operator.ge, "<": operator.lt, "<=": operator.le, "==": operator.eq, "!=": operator.ne}

_api = {}                       # lo llena crear_blueprint (misma técnica que llaves.py)
_cache = {}                     # endpoint_id -> (time.time(), resultado). Solo en memoria: la respuesta completa nunca se guarda.
_cache_lock = threading.Lock()


# --- API pública (para el resto de app.py) -----------------------------------------------------
def datos(conector, endpoint, forzar=False):
    """JSON ya leído de un endpoint (con caché), o None si no hay dato. Nunca lanza error."""
    try:
        return _api["datos"](conector, endpoint, forzar)
    except Exception:
        return None


def panel_plataforma(proyecto_id):
    """Para la ficha de una plataforma: lista de conectores con el estado de sus endpoints y sus cifras. Sin secretos."""
    try:
        return _api["panel_plat"](proyecto_id)
    except Exception:
        return []


def revisar():
    """Para el vigilante de app.py: lee los endpoints marcados «vigilar», guarda sus cifras y dispara alertas."""
    try:
        _api["revisar"]()
    except Exception:           # nunca debe tumbar al vigilante
        pass


# --- Utilidades puras (sin base de datos: fáciles de probar) ----------------------------------
def _valor(data, ruta):
    """(encontrado, valor) siguiendo a.b.0.c; «#» da el tamaño de una lista o diccionario."""
    cur = data
    for parte in ruta.split("."):
        if parte == "#" and isinstance(cur, (list, dict)):
            cur = len(cur)
        elif isinstance(cur, dict) and parte in cur:
            cur = cur[parte]
        elif isinstance(cur, list) and parte.isdigit() and int(parte) < len(cur):
            cur = cur[int(parte)]
        else:
            return False, None
    return True, cur


def _num(x):
    if isinstance(x, bool) or x is None:
        return None
    if isinstance(x, (int, float)):
        return float(x)
    try:
        return float(str(x).replace(",", "").strip())
    except ValueError:
        return None


def _cumple(actual, op, ref):
    a, r = _num(actual), _num(ref)
    if a is not None and r is not None:
        return _OPS[op](a, r)
    if op not in ("==", "!="):
        return False
    return _OPS[op](str(actual).strip().lower(), str(ref).strip().lower())


def _redactar(o):
    if isinstance(o, dict):
        return {k: ("•••" if _SENSIBLE.search(str(k)) else _redactar(v)) for k, v in o.items()}
    if isinstance(o, list):
        return [_redactar(x) for x in o[:500]]
    return o


def _pretty(o):
    t = json.dumps(_redactar(o), indent=2, ensure_ascii=False, default=str)
    return t if len(t) <= 6000 else t[:6000] + "\n… (recortado)"


def _celda(v):
    if v is None:
        return "—"
    if isinstance(v, bool):
        return "Sí" if v else "No"
    if isinstance(v, (int, float)):
        return v
    if isinstance(v, (dict, list)):
        return json.dumps(v, ensure_ascii=False, default=str)[:120]
    return str(v)[:200]


def _resumir(data):
    """Convierte cualquier JSON en lo que la pantalla sabe mostrar: cifras sueltas, tablas y bloques de texto."""
    kpis, tablas, otros = [], [], []

    def tabla(titulo, lista):
        filas = [x for x in lista if isinstance(x, dict)]
        if not filas:
            return False
        cols = []
        for f in filas[:50]:
            for k, v in f.items():
                if k not in cols and not isinstance(v, (dict, list)) and not _SENSIBLE.search(str(k)):
                    cols.append(k)
        cols = cols[:12]
        tablas.append({"titulo": titulo, "cols": cols, "total": len(filas),
                       "filas": [[_celda(f.get(c)) for c in cols] for f in filas[:200]]})
        return True

    esc = (str, int, float, bool, type(None))
    if isinstance(data, list):
        if not tabla("Resultados", data):
            otros.append(("Datos", _pretty(data)))
    elif isinstance(data, dict):
        for k, v in data.items():
            if _SENSIBLE.search(str(k)):
                continue
            if isinstance(v, esc):
                kpis.append((k, _celda(v)))
            elif isinstance(v, list):
                if not tabla(k, v):
                    otros.append((k, _pretty(v)))
            elif isinstance(v, dict):
                if v and all(isinstance(b, esc) for b in v.values()):
                    kpis += [(f"{k}.{a}", _celda(b)) for a, b in v.items() if not _SENSIBLE.search(str(a))]
                else:
                    otros.append((k, _pretty(v)))
    else:
        otros.append(("Datos", _pretty(data)))
    return {"kpis": kpis, "tablas": tablas, "otros": otros}


def _limpiar_base(raw):
    raw = (raw or "").strip().rstrip("/")
    if len(raw) > 300:
        return None, "La URL base es demasiado larga."
    u = urlparse(raw)
    http_ok = os.environ.get("CONECTORES_PERMITIR_HTTP") == "1"
    if u.scheme != "https" and not (http_ok and u.scheme == "http"):
        return None, "La URL base debe empezar con https://"
    if not u.hostname or u.username or u.password or u.query or u.fragment or u.params:
        return None, "URL no válida: solo dominio (y puerto/ruta base si hace falta), sin usuario, ? ni #."
    return raw, None


def _limpiar_ruta(raw):
    raw = (raw or "").strip()
    if len(raw) > 300 or raw.startswith("//") or not _RE_RUTA_ENDPOINT.match(raw):
        return None, "La ruta debe empezar con «/» (ej. /api/global/resumen) y no llevar espacios ni caracteres raros."
    return raw, None


def _host_ok(host):
    """Evita que un conector apunte a la red interna (SSRF). Resuelve el dominio y exige IPs públicas."""
    if os.environ.get("CONECTORES_PERMITIR_PRIVADOS") == "1":
        return True, ""
    permitidos = [h.strip().lower() for h in os.environ.get("CONECTORES_HOSTS", "").split(",") if h.strip()]
    if permitidos and (host or "").lower() not in permitidos:
        return False, "Ese dominio no está en CONECTORES_HOSTS."
    try:
        infos = socket.getaddrinfo(host, None)
    except (socket.gaierror, UnicodeError):
        return False, "No se pudo resolver el dominio."
    for i in infos:
        try:
            if not ipaddress.ip_address(i[4][0].split("%")[0]).is_global:
                return False, "El dominio apunta a una red privada o local: no permitido."
        except ValueError:
            return False, "Dirección no válida."
    return True, ""


class _SinRedireccion(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):      # None = no seguir: urllib lanza HTTPError 3xx y la llave no sale del sitio configurado
        return None


def _pedir(c, ruta, secreto):
    """Un GET autenticado. Devuelve {ok, status, data, error, ms}. El error NUNCA contiene la llave."""
    t0 = time.time()
    url = c.base_url.rstrip("/") + ruta
    ms = lambda: int((time.time() - t0) * 1000)
    ok, motivo = _host_ok(urlparse(url).hostname)
    if not ok:
        return {"ok": False, "status": 0, "error": motivo, "ms": ms()}
    h = {"Accept": "application/json", "User-Agent": "Zedyth-Conectores/1.0"}
    if c.auth == "x-api-key":
        h["X-API-Key"] = secreto
    elif c.auth == "cabecera":
        h[c.cabecera or "X-API-Key"] = secreto
    else:
        h["Authorization"] = "Bearer " + secreto
    try:
        with urllib.request.build_opener(_SinRedireccion).open(urllib.request.Request(url, headers=h, method="GET"), timeout=TIMEOUT) as r:
            raw, status = r.read(MAX_BYTES + 1), r.status
    except urllib.error.HTTPError as e:
        return {"ok": False, "status": e.code, "error": _ERR_HTTP.get(e.code, f"La API respondió HTTP {e.code}."), "ms": ms()}
    except (urllib.error.URLError, socket.timeout, TimeoutError, OSError, ValueError):
        return {"ok": False, "status": 0, "error": "No respondió (red caída o tiempo agotado).", "ms": ms()}
    if len(raw) > MAX_BYTES:
        return {"ok": False, "status": status, "error": "La respuesta es demasiado grande (máx. 2 MB).", "ms": ms()}
    try:
        data = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return {"ok": False, "status": status, "error": "La respuesta no es JSON.", "ms": ms()}
    return {"ok": True, "status": status, "data": data, "error": "", "ms": ms()}


# --- Blueprint ----------------------------------------------------------------------------------
def crear_blueprint(app, db, registrar, avisar, Proyecto):
    bp = Blueprint("conectores", __name__)

    class Conector(db.Model):
        __tablename__ = "conector"
        id = db.Column(db.Integer, primary_key=True)
        nombre = db.Column(db.String(80), nullable=False, unique=True)
        proyecto_id = db.Column(db.Integer, db.ForeignKey("proyecto.id"))     # None = no ligado a una plataforma
        base_url = db.Column(db.String(300), nullable=False)
        auth = db.Column(db.String(20), default="bearer")
        cabecera = db.Column(db.String(60))                                   # solo si auth == "cabecera"
        llave_etiqueta = db.Column(db.String(80))                             # opcional: usar solo la llave con esta etiqueta
        ambiente = db.Column(db.String(20), default="Producción")
        activo = db.Column(db.Boolean, default=True)
        nota = db.Column(db.String(300))
        creado = db.Column(db.DateTime, default=datetime.utcnow)
        creado_por = db.Column(db.String(80))
        proyecto = db.relationship(Proyecto)
        endpoints = db.relationship("ConectorEndpoint", backref="conector", order_by="ConectorEndpoint.id",
                                    cascade="all, delete-orphan")

    class ConectorEndpoint(db.Model):
        __tablename__ = "conector_endpoint"
        id = db.Column(db.Integer, primary_key=True)
        conector_id = db.Column(db.Integer, db.ForeignKey("conector.id"), nullable=False)
        nombre = db.Column(db.String(80), nullable=False)
        ruta = db.Column(db.String(300), nullable=False)
        kpis = db.Column(db.Text)                       # una por línea:  ruta | Etiqueta
        alertas = db.Column(db.Text)                    # una por línea:  ruta OP valor | Mensaje
        ttl_seg = db.Column(db.Integer, default=TTL_DEFECTO)
        vigilar = db.Column(db.Boolean, default=False)  # el vigilante lo lee solo y guarda sus cifras
        ultimo_ok = db.Column(db.Boolean)
        ultimo_status = db.Column(db.Integer)
        ultimo_error = db.Column(db.String(200))
        ultima_lectura = db.Column(db.DateTime)
        ultimo_ms = db.Column(db.Integer)
        fallos_seguidos = db.Column(db.Integer, default=0)

    class ConectorKpi(db.Model):
        """Una cifra por endpoint, etiqueta y DÍA (la última del día): sirve para ver tendencia sin guardar datos de personas."""
        __tablename__ = "conector_kpi"
        endpoint_id = db.Column(db.Integer, primary_key=True)
        clave = db.Column(db.String(80), primary_key=True)
        dia = db.Column(db.Date, primary_key=True)
        valor = db.Column(db.Float)
        texto = db.Column(db.String(120))
        actualizado = db.Column(db.DateTime, default=datetime.utcnow)

    estado_tablas = {"ok": False}

    def asegurar():
        if estado_tablas["ok"]:
            return
        for m in (Conector, ConectorEndpoint, ConectorKpi):
            m.__table__.create(db.engine, checkfirst=True)
        estado_tablas["ok"] = True

    # --- acceso ------------------------------------------------------------------------------
    def es_admin():
        return current_user.is_authenticated and (getattr(current_user, "rol", "") or "").lower() == "admin"

    def mfa_ok():
        return os.environ.get("LLAVES_SIN_MFA") == "1" or bool(getattr(current_user, "totp_activo", False))

    def solo_admin(f):
        @wraps(f)
        def w(*a, **k):
            if not es_admin():
                abort(403)
            return f(*a, **k)
        return w

    def escribe(f):
        @wraps(f)
        @solo_admin
        def w(*a, **k):
            if not mfa_ok():
                return Response("Activa la verificación en dos pasos (TOTP) en Seguridad antes de administrar conectores.", 403)
            return f(*a, **k)
        return w

    def mal(texto):
        return Response(f"Dato no válido: {texto}", 400)

    def txt(campo, n):
        return (request.form.get(campo) or "").strip()[:n]

    # --- lectura con pool de llaves ----------------------------------------------------------
    def llaves_de(c):
        lista = llaves.obtener_llaves(PROVEEDOR, c.proyecto_id, c.ambiente or "Producción", heredar=False)
        if c.llave_etiqueta:
            lista = [k for k in lista if k.etiqueta == c.llave_etiqueta]
        return lista

    def con_pool(c, ruta):
        lista = llaves_de(c)
        if not lista:
            return {"ok": False, "status": 0, "sin_llave": True, "ms": 0,
                    "error": f"Sin llave utilizable. Súbela en Llaves con el proveedor «{PROVEEDOR}»"
                             + (f" y la etiqueta «{c.llave_etiqueta}»." if c.llave_etiqueta else ".")}
        ultimo = None
        for k in lista[:MAX_PRUEBAS_LLAVE]:
            r = _pedir(c, ruta, k.secreto)
            if r["status"] in (401, 403, 429):        # la saca del pool (429 descansa; 401/403 queda inválida) y prueba la siguiente
                llaves.reportar_fallo(k.id, r["status"])
                ultimo = r
                continue
            if r["ok"]:
                llaves.registrar_uso(k.id, 1)
            return r
        return ultimo

    def guardar_kpis(ep, data):
        hoy = date.today()
        for linea in (ep.kpis or "").splitlines()[:20]:
            ruta, _, etiqueta = linea.partition("|")
            ruta = ruta.strip()
            if not ruta:
                continue
            ok, v = _valor(data, ruta)
            if not ok or isinstance(v, (dict, list)):
                continue
            etiqueta = (etiqueta.strip() or ruta)[:80]
            n = _num(v)
            fila = db.session.get(ConectorKpi, (ep.id, etiqueta, hoy))
            if fila is None:
                fila = ConectorKpi(endpoint_id=ep.id, clave=etiqueta, dia=hoy)
                db.session.add(fila)
            fila.valor = n
            fila.texto = None if n is not None else str(v)[:120]
            fila.actualizado = datetime.utcnow()

    def evaluar_alertas(ep, data):
        c = ep.conector
        for i, linea in enumerate((ep.alertas or "").splitlines()[:10]):
            m = _RE_ALERTA.match(linea)
            if not m:
                continue
            ruta, op, ref, msg = m.groups()
            ok, v = _valor(data, ruta)
            if ok and _cumple(v, op, ref):
                avisar("Conector", f"{c.nombre} · {msg or ruta + ' ' + op + ' ' + ref}",
                       f"{ep.nombre}: {ruta} = {_celda(v)} (regla {op} {ref})", f"/conectores/{c.id}?e={ep.id}",
                       urgente=True, clave=f"conector-{ep.id}-{i}-{date.today():%Y%m%d}")

    def leer(ep, forzar=False):
        """Lee un endpoint (con caché en memoria). Actualiza su estado, sus cifras y sus alertas."""
        asegurar()
        ttl = max(ep.ttl_seg or TTL_DEFECTO, 30)
        with _cache_lock:
            previo = _cache.get(ep.id)
        if previo and time.time() - previo[0] < (10 if forzar else ttl):      # incluso «Actualizar» respeta 10 s entre lecturas
            return {**previo[1], "cached": True, "ts": previo[0]}
        c = ep.conector
        r = con_pool(c, ep.ruta) if c.activo else {"ok": False, "status": 0, "error": "Conector desactivado.", "ms": 0}
        try:
            ep.ultimo_ok, ep.ultimo_status, ep.ultimo_ms = bool(r["ok"]), r["status"], r.get("ms")
            ep.ultimo_error = (r.get("error") or "")[:200] or None
            ep.ultima_lectura = datetime.utcnow()
            if r["ok"]:
                ep.fallos_seguidos = 0
                guardar_kpis(ep, r["data"])
            elif not r.get("sin_llave"):
                ep.fallos_seguidos = (ep.fallos_seguidos or 0) + 1
            db.session.commit()
            if r["ok"]:
                evaluar_alertas(ep, r["data"])
            elif ep.fallos_seguidos == FALLOS_PARA_AVISAR:
                avisar("Conector", f"{c.nombre} · {ep.nombre}: sin respuesta", r.get("error") or "", f"/conectores/{c.id}?e={ep.id}",
                       urgente=True, clave=f"conector-caido-{ep.id}-{date.today():%Y%m%d}")
        except Exception as e:
            db.session.rollback()
            app.logger.warning("Conector %s/%s: no se pudo guardar el estado: %s", c.nombre, ep.nombre, e)
        with _cache_lock:
            if len(_cache) > 200:
                _cache.clear()
            _cache[ep.id] = (time.time(), r)
        return {**r, "cached": False, "ts": time.time()}

    def kpis_recientes(eids):
        """{endpoint_id: {etiqueta: {valor, texto, antes}}} con el último dato y el anterior (para la flecha de tendencia)."""
        if not eids:
            return {}
        filas = (ConectorKpi.query.filter(ConectorKpi.endpoint_id.in_(eids), ConectorKpi.dia >= date.today() - timedelta(days=10))
                 .order_by(ConectorKpi.dia.desc()).all())
        out = {}
        for f in filas:
            d = out.setdefault(f.endpoint_id, {})
            if f.clave not in d:
                d[f.clave] = {"valor": f.valor, "texto": f.texto, "antes": None, "dia": f.dia}
            elif d[f.clave]["antes"] is None:
                d[f.clave]["antes"] = f.valor
        return out

    def estado_conector(c):
        eps = c.endpoints
        if not c.activo:
            return "desactivado"
        if not eps or all(e.ultimo_ok is None for e in eps):
            return "sin lecturas"
        return "con fallas" if any(e.ultimo_ok is False for e in eps) else "ok"

    # --- API interna -------------------------------------------------------------------------
    def _datos(conector, endpoint, forzar):
        asegurar()
        c = Conector.query.filter_by(nombre=conector).first()
        ep = next((e for e in c.endpoints if e.nombre == endpoint), None) if c else None
        if not ep:
            return None
        r = leer(ep, forzar)
        return r["data"] if r.get("ok") else None

    def _panel_plat(pid):
        asegurar()
        cs = Conector.query.filter_by(proyecto_id=pid).order_by(Conector.nombre).all()
        kp = kpis_recientes([e.id for c in cs for e in c.endpoints])
        return [{"id": c.id, "nombre": c.nombre, "estado": estado_conector(c), "activo": c.activo,
                 "endpoints": [{"id": e.id, "nombre": e.nombre, "ok": e.ultimo_ok, "error": e.ultimo_error,
                                "lectura": e.ultima_lectura, "kpis": kp.get(e.id, {})} for e in c.endpoints]} for c in cs]

    def _revisar():
        asegurar()
        ahora = datetime.utcnow()
        eps = (ConectorEndpoint.query.join(Conector, Conector.id == ConectorEndpoint.conector_id)
               .filter(Conector.activo.is_(True), ConectorEndpoint.vigilar.is_(True)).all())
        n = 0
        for ep in eps:
            if ep.ultima_lectura and ep.ultima_lectura > ahora - timedelta(seconds=max(ep.ttl_seg or TTL_DEFECTO, 60)):
                continue
            if n >= MAX_VIGILADOS_POR_RONDA:
                break
            leer(ep, forzar=True)
            n += 1
        ConectorKpi.query.filter(ConectorKpi.dia < date.today() - timedelta(days=400)).delete()
        db.session.commit()

    _api.update(datos=_datos, panel_plat=_panel_plat, revisar=_revisar)

    # --- pantallas ---------------------------------------------------------------------------
    def contexto_comun():
        return dict(mensaje=MENSAJES.get(request.args.get("m", "")), mfa=mfa_ok(), proveedor=PROVEEDOR, auth_tipos=AUTH_TIPOS,
                    ambientes=llaves.AMBIENTES, plataformas=Proyecto.query.order_by(Proyecto.nombre).all(),
                    cifrado=llaves.cifrado_listo(), ttl_defecto=TTL_DEFECTO)

    @bp.route("/conectores")
    @solo_admin
    def index():
        asegurar()
        cs = Conector.query.order_by(Conector.nombre).all()
        kp = kpis_recientes([e.id for c in cs for e in c.endpoints])
        filas = []
        for c in cs:
            try:
                n_llaves = len(llaves_de(c))
            except Exception:
                n_llaves = 0
            filas.append({"c": c, "estado": estado_conector(c), "llaves": n_llaves,
                          "eps": [{"e": e, "kpis": kp.get(e.id, {})} for e in c.endpoints]})
        return render_template("conectores.html", vista="lista", filas=filas, **contexto_comun())

    @bp.route("/conectores/<int:cid>")
    @solo_admin
    def detalle(cid):
        asegurar()
        c = db.get_or_404(Conector, cid)
        sel = request.args.get("e", type=int)
        ep = next((e for e in c.endpoints if e.id == sel), None) or (c.endpoints[0] if c.endpoints else None)
        lectura = resumen = None
        if ep:
            lectura = leer(ep, forzar=request.args.get("actualizar") == "1")
            if lectura.get("ok"):
                resumen = _resumir(lectura["data"])
        return render_template("conectores.html", vista="detalle", c=c, ep=ep, lectura=lectura, resumen=resumen,
                               llaves_n=len(llaves_de(c)), estado=estado_conector(c), **contexto_comun())

    # --- altas, cambios y bajas (solo admin con TOTP) ----------------------------------------
    def leer_conector():
        """Valida el formulario del conector. Devuelve (campos, error)."""
        nombre = txt("nombre", 80)
        if len(nombre) < 3:
            return None, "Ponle un nombre de al menos 3 letras."
        base, err = _limpiar_base(request.form.get("base_url"))
        if err:
            return None, err
        auth = request.form.get("auth") if request.form.get("auth") in AUTH_TIPOS else "bearer"
        cabecera = txt("cabecera", 60)
        if auth == "cabecera" and not _RE_CABECERA.match(cabecera):
            return None, "El nombre de la cabecera solo puede llevar letras, números y guiones."
        pid = (request.form.get("proyecto_id") or "").strip()
        if pid and (not pid.isdigit() or db.session.get(Proyecto, int(pid)) is None):
            return None, "Plataforma no encontrada."
        amb = request.form.get("ambiente") if request.form.get("ambiente") in llaves.AMBIENTES else "Producción"
        return dict(nombre=nombre, base_url=base, auth=auth, cabecera=cabecera if auth == "cabecera" else None,
                    proyecto_id=int(pid) if pid else None, ambiente=amb, llave_etiqueta=txt("llave_etiqueta", 80) or None,
                    nota=txt("nota", 300) or None), None

    @bp.route("/conectores/nuevo", methods=["POST"])
    @escribe
    def nuevo():
        asegurar()
        campos, err = leer_conector()
        if err:
            return mal(err)
        if Conector.query.filter_by(nombre=campos["nombre"]).first():
            return mal("Ya hay un conector con ese nombre.")
        c = Conector(creado_por=(getattr(current_user, "username", "") or "")[:80], **campos)
        db.session.add(c)
        db.session.flush()
        registrar("conector_creado", "Conector", c.id, f"{c.nombre} · {c.base_url}")
        db.session.commit()
        return redirect(url_for("conectores.detalle", cid=c.id, m="creado"))

    @bp.route("/conectores/<int:cid>/editar", methods=["POST"])
    @escribe
    def editar(cid):
        c = db.get_or_404(Conector, cid)
        campos, err = leer_conector()
        if err:
            return mal(err)
        otro = Conector.query.filter_by(nombre=campos["nombre"]).first()
        if otro and otro.id != c.id:
            return mal("Ya hay un conector con ese nombre.")
        for k, v in campos.items():
            setattr(c, k, v)
        with _cache_lock:
            for e in c.endpoints:
                _cache.pop(e.id, None)
        registrar("conector_editado", "Conector", c.id, f"{c.nombre} · {c.base_url}")
        db.session.commit()
        return redirect(url_for("conectores.detalle", cid=c.id, m="editado"))

    @bp.route("/conectores/<int:cid>/activar", methods=["POST"])
    @escribe
    def activar(cid):
        c = db.get_or_404(Conector, cid)
        c.activo = not c.activo
        registrar("conector_activado" if c.activo else "conector_desactivado", "Conector", c.id, c.nombre)
        db.session.commit()
        return redirect(url_for("conectores.detalle", cid=c.id, m="activado" if c.activo else "desactivado"))

    @bp.route("/conectores/<int:cid>/eliminar", methods=["POST"])
    @escribe
    def eliminar(cid):
        c = db.get_or_404(Conector, cid)
        eids = [e.id for e in c.endpoints]
        if eids:
            ConectorKpi.query.filter(ConectorKpi.endpoint_id.in_(eids)).delete(synchronize_session=False)
        with _cache_lock:
            for i in eids:
                _cache.pop(i, None)
        registrar("conector_eliminado", "Conector", c.id, f"{c.nombre} · {c.base_url}")
        db.session.delete(c)
        db.session.commit()
        return redirect(url_for("conectores.index", m="eliminado"))

    @bp.route("/conectores/<int:cid>/probar", methods=["POST"])
    @escribe
    def probar(cid):
        c = db.get_or_404(Conector, cid)
        ruta = c.endpoints[0].ruta if c.endpoints else "/"
        r = con_pool(c, ruta)
        registrar("conector_prueba", "Conector", c.id, f"{c.nombre} · {'ok' if r['ok'] else 'falló'} ({r['status']})")
        db.session.commit()
        return redirect(url_for("conectores.detalle", cid=c.id, m="probado_ok" if r["ok"] else "probado_mal"))

    def leer_endpoint():
        nombre = txt("nombre", 80)
        if len(nombre) < 2:
            return None, "Ponle un nombre al endpoint (ej. Resumen)."
        ruta, err = _limpiar_ruta(request.form.get("ruta"))
        if err:
            return None, err
        kpis = [l.strip()[:120] for l in (request.form.get("kpis") or "").splitlines() if l.strip()][:20]
        alertas = [l.strip()[:160] for l in (request.form.get("alertas") or "").splitlines() if l.strip()][:10]
        for i, l in enumerate(alertas, 1):
            if not _RE_ALERTA.match(l):
                return None, f"La alerta {i} no se entiende. Formato: ruta > valor | Mensaje (operadores: > >= < <= == !=)."
        try:
            ttl = min(max(int(request.form.get("ttl_seg") or TTL_DEFECTO), 30), 86400)
        except ValueError:
            return None, "El tiempo de caché debe ser un número de segundos."
        return dict(nombre=nombre, ruta=ruta, kpis="\n".join(kpis) or None, alertas="\n".join(alertas) or None, ttl_seg=ttl,
                    vigilar=request.form.get("vigilar") == "1"), None

    @bp.route("/conectores/<int:cid>/endpoint", methods=["POST"])
    @escribe
    def endpoint_nuevo(cid):
        c = db.get_or_404(Conector, cid)
        campos, err = leer_endpoint()
        if err:
            return mal(err)
        if len(c.endpoints) >= 30:
            return mal("Máximo 30 endpoints por conector.")
        ep = ConectorEndpoint(conector_id=c.id, **campos)
        db.session.add(ep)
        db.session.flush()
        registrar("conector_endpoint", "Conector", c.id, f"{c.nombre} · +{ep.nombre} {ep.ruta}")
        db.session.commit()
        return redirect(url_for("conectores.detalle", cid=c.id, e=ep.id, m="endpoint_ok"))

    @bp.route("/conectores/endpoint/<int:eid>/editar", methods=["POST"])
    @escribe
    def endpoint_editar(eid):
        ep = db.get_or_404(ConectorEndpoint, eid)
        campos, err = leer_endpoint()
        if err:
            return mal(err)
        for k, v in campos.items():
            setattr(ep, k, v)
        with _cache_lock:
            _cache.pop(ep.id, None)
        registrar("conector_endpoint", "Conector", ep.conector_id, f"{ep.conector.nombre} · {ep.nombre} {ep.ruta}")
        db.session.commit()
        return redirect(url_for("conectores.detalle", cid=ep.conector_id, e=ep.id, m="endpoint_ok"))

    @bp.route("/conectores/endpoint/<int:eid>/eliminar", methods=["POST"])
    @escribe
    def endpoint_eliminar(eid):
        ep = db.get_or_404(ConectorEndpoint, eid)
        cid = ep.conector_id
        ConectorKpi.query.filter_by(endpoint_id=ep.id).delete()
        with _cache_lock:
            _cache.pop(ep.id, None)
        registrar("conector_endpoint", "Conector", cid, f"{ep.conector.nombre} · -{ep.nombre}")
        db.session.delete(ep)
        db.session.commit()
        return redirect(url_for("conectores.detalle", cid=cid, m="endpoint_borrado"))

    return bp
