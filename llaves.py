"""llaves.py — Registro de llaves de API: cifradas, con pool de rotación, uso diario y bitácora.

Se conecta en app.py igual que monitor.py:
    import llaves
    app.register_blueprint(llaves.crear_blueprint(app, db, registrar, crear_notificacion, Proyecto, Auditoria))

Cifrado: ya NO hace falta ninguna variable nueva. Sin LLAVES_MASTER, las llaves se cifran con una clave derivada de
SECRET_KEY (la que ya tienes en Render). Si defines LLAVES_MASTER, esa pasa a ser la principal y lo guardado antes
sigue abriéndose. Opcionales (Render):
    LLAVES_MASTER       clave Fernet principal. Genérala con:
                        python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
    LLAVES_MASTER_ANT   (opcional) claves anteriores separadas por coma, para rotar la maestra sin perder llaves.
    LLAVES_ENFRIAR_MIN  minutos que una llave descansa tras un error 429 (por defecto 15).
    LLAVES_SIN_MFA=1    (no recomendado) permite administrar llaves sin tener TOTP activado.

Uso desde el resto de la app (dentro de un contexto de aplicación):
    k = llaves.obtener_llave("Anthropic", proyecto_id)          # None si no hay ninguna disponible
    resp = llamar_api(k.secreto)
    if resp.status_code in (401, 403, 429):
        llaves.reportar_fallo(k.id, resp.status_code)            # la saca del pool (429: descansa; 401/403: inválida)
        k = llaves.obtener_llave("Anthropic", proyecto_id)       # y pide la siguiente
    llaves.registrar_uso(k.id, peticiones=1, tokens_in=1200, tokens_out=300, costo=0.012)

El valor completo de una llave NUNCA se muestra ni se escribe en la bitácora: solo los últimos 4 caracteres.
"""
import base64
import hashlib
import json
import os
import random
import re
import secrets
import threading
import time
import urllib.error
import urllib.request
from collections import namedtuple
from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime, timedelta, timezone
from functools import wraps
from urllib.parse import urlencode

try:
    from zoneinfo import ZoneInfo
except ImportError:          # Python < 3.9
    ZoneInfo = None

from cryptography.fernet import Fernet, MultiFernet, InvalidToken
from flask import Blueprint, render_template, request, redirect, url_for, abort, Response, jsonify, make_response
from flask_login import current_user
from sqlalchemy import or_
from sqlalchemy.exc import IntegrityError

PROVEEDORES = ["Anthropic", "OpenAI", "Google (Gemini)", "Meta (WhatsApp)", "Cloudinary", "Cloudflare R2",
               "Neon", "Render", "Stripe / procesador de pagos", "PAC / CFDI", "API de plataforma (lectura)", "Otro"]
AMBIENTES = ["Producción", "Pruebas", "Desarrollo"]
ENFRIAR_MIN = int(os.environ.get("LLAVES_ENFRIAR_MIN", "15"))
AVISO_VENCE_DIAS = 14
UMBRAL_USO = 0.80
# Si una plataforma no tiene llave propia de un proveedor, ¿puede usar la global del negocio? Por defecto sí (como siempre).
# Con LLAVES_HEREDAR_GLOBAL=0 cada plataforma usa SOLO las suyas. También se decide por llamada con heredar=True/False.
HEREDAR_GLOBAL = os.environ.get("LLAVES_HEREDAR_GLOBAL", "1") != "0"

LlaveEntregada = namedtuple("LlaveEntregada", "id secreto proveedor etiqueta")

# --- Gemini: importación desde el entorno, pruebas y día de cuota -------------------------------------
GEMINI = "Google (Gemini)"
URL_GEMINI = "https://generativelanguage.googleapis.com/v1beta"
PROBAR_HILOS = 8                                               # pruebas en paralelo (solo red; la base se escribe al final)
PROBAR_AUTO = os.environ.get("LLAVES_PROBAR_AUTO", "1") != "0"   # revisión diaria automática (models.list, no gasta cuota)
PROBAR_CADA_HORAS = 24
# Modelo de la "prueba real" (1 petición de 1 token). app.py lo apunta a zedith.modelo para usar el mismo que el chat.
MODELO_PRUEBA = lambda: os.environ.get("LLAVES_MODELO_PRUEBA") or "gemini-3.5-flash-lite"
ETIQ_PRUEBA = {"valida": "válida", "con_cuota": "válida y con cuota", "sin_cuota": "sin cuota ahora", "invalida": "inválida",
               "rechazada": "rechazada", "sin_red": "sin conexión", "error": "error"}
_RE_ENTORNO = re.compile(r"^GEMINI_KEY_?\d+$")
_RE_NOMBRE_VAR = re.compile(r"^[A-Za-z_][A-Za-z0-9_ ]{0,60}$")
TIPO_PLATAFORMA = "Plataforma propia"      # Proyecto.tipo de las plataformas (las llaves se asignan solo a plataformas)

MENSAJES = {
    "importada": "Importación terminada. Las llaves quedaron cifradas; las variables de Render no se tocaron.",
    "probando": "Pruebas en marcha: la página se actualiza sola. Puedes seguir trabajando.",
    "probada": "Llave probada. El resultado quedó en la columna Prueba.",
    "asignada": "Plataformas actualizadas para esas llaves.",
    "creada": "Llave guardada (cifrada). Solo se mostrarán sus últimos 4 caracteres.",
    "api_ok": "API conectada: la llave quedó guardada (cifrada) y se hizo la primera lectura. Abajo ves el resultado.",
    "rotada": "Llave rotada: el valor anterior ya no existe en el sistema.",
    "desactivada": "Llave desactivada al instante.",
    "activada": "Llave activada de nuevo.",
    "revocada": "Llave revocada: el secreto se borró del sistema.",
    "editada": "Datos de la llave actualizados.",
    "movida": "Orden del pool actualizado.",
    "token_revocado": "Token revocado: esa plataforma ya no puede pedir llaves al panel.",
    "recifrada": "Todas las llaves se volvieron a cifrar con la clave maestra actual.",
}

_api = {}      # lo llena crear_blueprint (misma técnica que monitor.py)
_base_cifrado = {"secreto": None}     # SECRET_KEY de la app (solo si es fija); la pone crear_blueprint


# --- Utilidades sin base de datos (se pueden probar solas) ----------------------------------------
def huella(secreto):
    """Identificador estable de una llave que NO revela su valor. Dos plataformas con la misma llave dan la misma huella."""
    return hashlib.sha256(("llaves-huella|" + secreto).encode()).hexdigest()[:16]


def _zona_google():
    """La cuota diaria gratuita de Gemini se reinicia a medianoche, hora del Pacífico (no UTC ni hora de México)."""
    try:
        return ZoneInfo("America/Los_Angeles")
    except Exception:
        return timezone(timedelta(hours=-8))      # sin base de zonas horarias en el servidor: aproximación


def hoy_google():
    return datetime.now(_zona_google()).date()


def _medianoche_google_utc():
    z = _zona_google()
    sig = (datetime.now(z) + timedelta(days=1)).replace(hour=0, minute=0, second=1, microsecond=0)
    return sig.astimezone(timezone.utc).replace(tzinfo=None)


def descanso_429(cuerpo="", ahora=None):
    """Según el cuerpo del error 429 de Google: (hasta cuándo descansa la llave en UTC, explicación).
    Cuota del día → hasta medianoche del Pacífico; cuota por minuto → lo que pida Google (retryDelay)."""
    ahora = ahora or datetime.utcnow()
    t = (cuerpo or "").lower()
    if "perday" in t or "per day" in t:
        return _medianoche_google_utc(), "cuota del DÍA agotada; vuelve a medianoche (hora del Pacífico)"
    m = re.search(r'retrydelay"?\s*:\s*"?(\d+(?:\.\d+)?)s', t)
    if m:
        seg = int(min(max(float(m.group(1)), 5), 3600))
        return ahora + timedelta(seconds=seg + 1), f"límite por minuto; reintenta en {seg} s"
    return ahora + timedelta(minutes=ENFRIAR_MIN), f"descansa {ENFRIAR_MIN} min"


def llaves_del_entorno(entorno=None):
    """[(nombre de la variable, valor)] de las llaves de Gemini de ESTE servidor: GEMINI_KEY_1, GEMINI_KEY_2, ... (sin tope),
    y también GEMINI_KEYS / GEMINI_API_KEYS (varias separadas por coma) y GEMINI_API_KEY. Sin repetidas."""
    e = os.environ if entorno is None else entorno
    vistas, salida = set(), []

    def agregar(nombre, valor):
        v = str(valor or "").strip().strip('"').strip("'").strip()
        if 8 <= len(v) <= 4000 and not any(c.isspace() for c in v) and v not in vistas:
            vistas.add(v)
            salida.append((nombre, v))

    for nombre in sorted((k for k in e if _RE_ENTORNO.match(k)), key=lambda k: int(re.sub(r"\D", "", k))):
        agregar(nombre, e[nombre])
    for nombre in ("GEMINI_KEYS", "GEMINI_API_KEYS", "GEMINI_API_KEY"):
        for i, parte in enumerate(re.split(r"[,;\r\n]+", e.get(nombre) or ""), 1):
            agregar(f"{nombre} #{i}", parte)
    return salida


def llaves_de_texto(texto):
    """[(nombre o '', valor)] de un texto pegado: una llave por línea o separadas por coma/punto y coma. Acepta el formato de
    Render (GEMINI_KEY_7=AIza...), con o sin comillas. Sin repetidas."""
    vistas, salida = set(), []
    for trozo in re.split(r"[\r\n,;]+", str(texto or "")[:400000]):
        t = trozo.strip()
        if not t:
            continue
        nombre, valor = "", t
        if "=" in t:
            izq, _, der = t.partition("=")
            if _RE_NOMBRE_VAR.match(izq.strip()):
                nombre, valor = izq.strip(), der
        valor = valor.strip().strip('"').strip("'").strip()
        if 8 <= len(valor) <= 4000 and not any(c.isspace() for c in valor) and valor not in vistas:
            vistas.add(valor)
            salida.append((nombre, valor))
    return salida


def _mensaje_google(texto):
    try:
        return str(json.loads(texto)["error"]["message"])[:200]
    except Exception:
        return (texto or "").strip().replace("\n", " ")[:200]


def _http(url, llave, cuerpo=None, timeout=10):
    """(código HTTP o 0 si no hubo respuesta, texto del cuerpo, milisegundos)."""
    req = urllib.request.Request(url, method="POST" if cuerpo is not None else "GET",
                                 data=json.dumps(cuerpo).encode() if cuerpo is not None else None,
                                 headers={"x-goog-api-key": llave, "Content-Type": "application/json"})
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            r.read(4000)
            return r.status, "", int((time.time() - t0) * 1000)
    except urllib.error.HTTPError as e:
        try:
            txt = e.read().decode("utf-8", "replace")[:4000]
        except Exception:
            txt = ""
        return e.code, txt, int((time.time() - t0) * 1000)
    except Exception as e:
        return 0, f"{type(e).__name__}: {e}"[:200], int((time.time() - t0) * 1000)


def probar_gemini(llave, real=False, url_base=URL_GEMINI, modelo=None):
    """Comprueba una llave de Gemini. Siempre llama a models.list (no gasta cuota de generación).
    real=True además hace UNA petición de 1 token para saber si hoy le queda cuota (gasta 1 petición de esa llave).
    Devuelve {resultado, detalle, ms, hasta}. resultado: valida | con_cuota | sin_cuota | invalida | rechazada | sin_red | error."""
    codigo, txt, ms = _http(f"{url_base}/models?pageSize=1", llave)
    baja = txt.lower()
    if codigo == 0:
        return {"resultado": "sin_red", "detalle": txt, "ms": ms, "hasta": None}
    if codigo == 400 and ("api key not valid" in baja or "api_key_invalid" in baja):
        return {"resultado": "invalida", "detalle": "Google dice que la llave no es válida (borrada o mal copiada).", "ms": ms, "hasta": None}
    if codigo in (401, 403):
        return {"resultado": "rechazada", "detalle": _mensaje_google(txt) or f"HTTP {codigo}", "ms": ms, "hasta": None}
    if codigo == 429:
        hasta, motivo = descanso_429(txt)
        return {"resultado": "sin_cuota", "detalle": motivo, "ms": ms, "hasta": hasta}
    if codigo != 200:
        return {"resultado": "error", "detalle": f"HTTP {codigo}: {_mensaje_google(txt)}", "ms": ms, "hasta": None}
    if not real:
        return {"resultado": "valida", "detalle": "", "ms": ms, "hasta": None}
    modelo = modelo or MODELO_PRUEBA()
    c2, t2, ms2 = _http(f"{url_base}/models/{modelo}:generateContent", llave,
                        {"contents": [{"parts": [{"text": "ok"}]}], "generationConfig": {"maxOutputTokens": 1}})
    if c2 == 200:
        return {"resultado": "con_cuota", "detalle": f"respondió con {modelo}", "ms": ms2, "hasta": None}
    if c2 == 429:
        hasta, motivo = descanso_429(t2)
        return {"resultado": "sin_cuota", "detalle": motivo, "ms": ms2, "hasta": hasta}
    if c2 in (401, 403):
        return {"resultado": "rechazada", "detalle": _mensaje_google(t2) or f"HTTP {c2}", "ms": ms2, "hasta": None}
    return {"resultado": "valida", "detalle": f"models.list ok; no pude comprobar la cuota (HTTP {c2}: {_mensaje_google(t2)})", "ms": ms2, "hasta": None}


# --- API pública (para el resto de app.py) ------------------------------------------------------
def obtener_llave(proveedor, proyecto_id=None, ambiente="Producción", heredar=None, mezclar=False):
    """Primera llave disponible del pool (por orden), o None. Salta las desactivadas, vencidas o en descanso.
    heredar=False: solo las de esa plataforma (nunca las globales). None = lo que diga LLAVES_HEREDAR_GLOBAL.
    mezclar=True: elige al azar entre las disponibles (reparte la carga cuando hay muchas llaves gratuitas)."""
    return _api["obtener"](proveedor, proyecto_id, ambiente, heredar, mezclar)


def obtener_llaves(proveedor, proyecto_id=None, ambiente="Producción", heredar=None, mezclar=False):
    """Lista de todas las llaves utilizables, en orden de pool (o mezcladas con mezclar=True). Útil para probarlas una por una."""
    return _api["todas"](proveedor, proyecto_id, ambiente, heredar, mezclar)


def reportar_fallo(llave_id, codigo_http, cuerpo=""):
    """429 → la llave descansa (hasta medianoche del Pacífico si es cuota del día, o lo que pida Google si es por minuto);
    401/403 → queda inválida hasta que alguien la revise. `cuerpo` es el texto del error (opcional, afina el descanso)."""
    _api["fallo"](llave_id, codigo_http, cuerpo)


def registrar_uso(llave_id, peticiones=1, tokens_in=0, tokens_out=0, costo=0.0):
    """Suma el consumo del día a la llave y avisa al llegar al 80 % de su límite diario."""
    _api["uso"](llave_id, peticiones, tokens_in, tokens_out, costo)


def costo_mes(proyecto_id=None):
    """Costo de IA del mes en curso (de todas las plataformas, o de una). Para conectarlo a Finanzas."""
    return _api["costo_mes"](proyecto_id)


def estado_pool(proveedor, proyecto_id=None):
    """Resumen del pool de un proveedor (todas las plataformas y ambientes, o solo una), para la pantalla de Servicios:
    {total, usables, invalidas, vencidas, descanso, desactivadas}. Las revocadas no cuentan."""
    return _api["estado_pool"](proveedor, proyecto_id)


def crear_llave(proveedor, proyecto_id, etiqueta, secreto, ambiente="Producción"):
    """Guarda una llave cifrada ligada a una plataforma (la usa conectores.py). Devuelve (id, error)."""
    return _api["crear"](proveedor, proyecto_id, etiqueta, secreto, ambiente)


def panel_plataforma(proyecto_id):
    """Todo lo que necesita la pestaña Conexiones de la ficha: llaves de la plataforma (sin secretos), resumen y avisos."""
    return _api["panel_plat"](proyecto_id)


def resumen_plataforma(proyecto_id):
    """Para la ficha de una plataforma: {total, activas, problemas, por_vencer, heredadas, costo_mes}. Sin secretos."""
    return _api["resumen_plat"](proyecto_id)


def revisar():
    """Para el vigilante de app.py: avisa llaves por vencer, vencidas o con rotación programada pendiente."""
    try:
        _api["revisar"]()
    except Exception:       # nunca debe tumbar al vigilante
        pass


# --- Cifrado ------------------------------------------------------------------------------------
def _fernet():
    """MultiFernet: LLAVES_MASTER primero (si existe), luego las anteriores y, al final, la clave derivada de SECRET_KEY.
    Sin LLAVES_MASTER, la derivada es la principal. None solo si no hay ninguna (local sin SECRET_KEY fija)."""
    claves = []
    principal = (os.environ.get("LLAVES_MASTER") or "").strip()
    anteriores = [k.strip() for k in (os.environ.get("LLAVES_MASTER_ANT") or "").split(",") if k.strip()]
    try:
        claves += [Fernet(k) for k in ([principal] if principal else []) + anteriores]
    except (ValueError, TypeError):
        return None
    base = _base_cifrado["secreto"]
    if base:
        claves.append(Fernet(base64.urlsafe_b64encode(hashlib.sha256(("llaves|" + base).encode()).digest())))
    return MultiFernet(claves) if claves else None


def cifrado_listo():
    return _fernet() is not None


def crear_blueprint(app, db, registrar, avisar, Proyecto, Auditoria, limitar=None):
    bp = Blueprint("llaves", __name__)
    if app.config.get("SECRET_KEY_FIJA", True):          # una SECRET_KEY al azar por arranque no sirve para cifrar lo guardado
        _base_cifrado["secreto"] = str(app.config["SECRET_KEY"])

    class LlaveApi(db.Model):
        __tablename__ = "llave_api"
        id = db.Column(db.Integer, primary_key=True)
        proveedor = db.Column(db.String(40), nullable=False)
        proyecto_id = db.Column(db.Integer, db.ForeignKey("proyecto.id"))      # None = llave global del negocio
        etiqueta = db.Column(db.String(80), nullable=False)
        ambiente = db.Column(db.String(20), default="Producción")
        ultimos4 = db.Column(db.String(4))
        secreto = db.Column(db.Text)                                           # Fernet; None si fue revocada
        creada = db.Column(db.DateTime, default=datetime.utcnow)
        vence = db.Column(db.Date)
        estado = db.Column(db.String(12), default="activa")                    # activa | desactivada | invalida | revocada
        orden = db.Column(db.Integer, default=0)                               # posición en su pool
        bloqueada_hasta = db.Column(db.DateTime)                               # descanso tras un 429
        fallos = db.Column(db.Integer, default=0)
        rotar_cada_dias = db.Column(db.Integer)
        rotada_en = db.Column(db.DateTime)
        creado_por = db.Column(db.String(80))
        limite_peticiones = db.Column(db.Integer)                              # por día
        limite_tokens = db.Column(db.BigInteger)                               # por día
        ultimo_uso = db.Column(db.DateTime)
        proyecto = db.relationship(Proyecto)

    class UsoIA(db.Model):
        __tablename__ = "uso_ia"
        fecha = db.Column(db.Date, primary_key=True)
        llave_id = db.Column(db.Integer, primary_key=True)
        proyecto_id = db.Column(db.Integer)
        proveedor = db.Column(db.String(40))
        peticiones = db.Column(db.Integer, default=0)
        tokens_in = db.Column(db.BigInteger, default=0)
        tokens_out = db.Column(db.BigInteger, default=0)
        costo = db.Column(db.Float, default=0.0)

    class LlaveMeta(db.Model):
        """Datos extra de cada llave en una tabla aparte (así no hay que alterar llave_api): huella y última prueba."""
        __tablename__ = "llave_meta"
        llave_id = db.Column(db.Integer, primary_key=True)
        huella = db.Column(db.String(16), index=True)
        origen = db.Column(db.String(20), default="manual")                    # manual | entorno | pegada | render
        prueba_fecha = db.Column(db.DateTime)
        prueba_resultado = db.Column(db.String(16))
        prueba_detalle = db.Column(db.String(240))
        prueba_ms = db.Column(db.Integer)

    class LlaveToken(db.Model):
        """Token con el que UNA plataforma pide llaves al panel (API /api/llaves/v1). Solo se guarda su huella SHA-256."""
        __tablename__ = "llave_token"
        proyecto_id = db.Column(db.Integer, primary_key=True)
        huella_token = db.Column(db.String(64), index=True, nullable=False)
        ultimos4 = db.Column(db.String(4))
        creado = db.Column(db.DateTime, default=datetime.utcnow)
        creado_por = db.Column(db.String(80))
        ultimo_uso = db.Column(db.DateTime)
        activo = db.Column(db.Boolean, default=True)

    class LlavePlat(db.Model):
        """Una llave global (compartida) usada por varias plataformas: una fila por pareja llave–plataforma."""
        __tablename__ = "llave_plat"
        llave_id = db.Column(db.Integer, primary_key=True)
        proyecto_id = db.Column(db.Integer, primary_key=True)

    estado_tablas = {"ok": False, "huellas": False}
    estado_prueba = {"corriendo": False, "hechas": 0, "total": 0, "inicio": None, "real": False}
    cerrojo = threading.Lock()

    def asegurar():
        if estado_tablas["ok"]:
            return
        for m in (LlaveApi, UsoIA, LlaveMeta, LlavePlat, LlaveToken):
            m.__table__.create(db.engine, checkfirst=True)
        estado_tablas["ok"] = True

    def rellenar_huellas():
        """Llaves creadas antes de esta versión: calcula su huella una vez. Hace commit: no llamarla a mitad de una transacción ajena."""
        if estado_tablas["huellas"]:
            return
        f = _fernet()
        if f is None:
            return
        ya = {m.llave_id for m in LlaveMeta.query.all()}
        nuevas = False
        for k in LlaveApi.query.filter(LlaveApi.secreto.isnot(None)).all():
            if k.id in ya:
                continue
            try:
                db.session.add(LlaveMeta(llave_id=k.id, huella=huella(f.decrypt(k.secreto.encode()).decode()), origen="manual"))
                nuevas = True
            except InvalidToken:
                continue
        if nuevas:
            db.session.commit()
        estado_tablas["huellas"] = True

    def fijar_meta(k, secreto, origen="manual"):
        """Guarda la huella de la llave (k ya tiene id). No hace commit."""
        m = db.session.get(LlaveMeta, k.id)
        if m is None:
            db.session.add(LlaveMeta(llave_id=k.id, huella=huella(secreto), origen=origen))
        else:
            m.huella = huella(secreto)

    def nombre_visible(p):
        return p.nombre if p.tipo == TIPO_PLATAFORMA else f"{p.nombre} (proyecto de cliente)"

    def ids_asignadas(pid):
        return [a.llave_id for a in LlavePlat.query.filter_by(proyecto_id=pid).all()]

    def llaves_de(pid):
        """Query de las llaves de una plataforma: las suyas y las compartidas que se le asignaron."""
        cond = LlaveApi.proyecto_id == pid
        ids = ids_asignadas(pid)
        if ids:
            cond = or_(cond, LlaveApi.id.in_(ids))
        return LlaveApi.query.filter(cond)

    def plataformas_por_llave(ids):
        """{llave_id: [nombres de plataformas]} (dueña + asignadas) para mostrar «también en»."""
        if not ids:
            return {}
        nombres = {p.id: nombre_visible(p) for p in Proyecto.query.all()}
        r = {}
        for a in LlavePlat.query.filter(LlavePlat.llave_id.in_(ids)).all():
            if a.proyecto_id in nombres:
                r.setdefault(a.llave_id, []).append(nombres[a.proyecto_id])
        for k in LlaveApi.query.filter(LlaveApi.id.in_(ids), LlaveApi.proyecto_id.isnot(None)).all():
            nom = nombres.get(k.proyecto_id)
            if nom and nom not in r.setdefault(k.id, []):
                r[k.id].insert(0, nom)
        for v in r.values():
            v.sort()
        return r

    # --- reglas de acceso ------------------------------------------------------------------------
    def es_admin():
        return current_user.is_authenticated and (getattr(current_user, "rol", "") or "").lower() == "admin"

    def mfa_ok():
        return os.environ.get("LLAVES_SIN_MFA") == "1" or bool(getattr(current_user, "totp_activo", False))

    def solo_admin(f):
        @wraps(f)
        def envoltura(*a, **k):
            if not es_admin():
                abort(403)
            return f(*a, **k)
        return envoltura

    def escribe(f):
        """Admin + cifrado configurado + TOTP activo (guardar llaves sin MFA no es aceptable)."""
        @wraps(f)
        @solo_admin
        def envoltura(*a, **k):
            if not mfa_ok():
                return Response("Activa la verificación en dos pasos (TOTP) en Seguridad antes de administrar llaves.", 403)
            return f(*a, **k)
        return envoltura

    def mal(texto):
        return Response(f"Dato no válido: {texto}", 400)

    def plat_activa():
        """La plataforma con la que se trabaja (?plataforma=N en la URL o en el formulario), o None = vista general."""
        raw = request.values.get("plataforma")
        if not raw:
            return None
        p = db.session.get(Proyecto, int(raw)) if raw.isdigit() else None
        if p is None:
            abort(404)
        return p

    def volver(m=None, **extra):
        """extra: contadores para el mensaje (n, d, r...) que solo muestra la pantalla /llaves."""
        dest = request.form.get("volver") or ""
        if dest.startswith("/plataformas/") and "//" not in dest and "\\" not in dest:
            if m and m in MENSAJES:
                dest += ("&" if "?" in dest else "?") + "m=" + m
            return redirect(dest)
        p = plat_activa()
        return redirect(url_for("llaves.index", m=m, plataforma=p.id if p else None, **extra))

    # --- utilidades -------------------------------------------------------------------------------
    def leer_secreto(campo):
        s = (request.form.get(campo) or "").strip()
        if not 8 <= len(s) <= 4000:
            return None, "El valor de la llave debe tener entre 8 y 4000 caracteres."
        if any(c.isspace() for c in s):
            return None, "El valor de la llave no puede llevar espacios ni saltos de línea."
        return s, None

    def leer_fecha(campo):
        v = (request.form.get(campo) or "").strip()
        if not v:
            return None, None
        try:
            return date.fromisoformat(v), None
        except ValueError:
            return None, f"«{campo}» no es una fecha válida."

    def leer_entero(campo, minimo=1, maximo=10**12):
        v = (request.form.get(campo) or "").replace(",", "").strip()
        if not v:
            return None, None
        if not v.isdigit() or not minimo <= int(v) <= maximo:
            return None, f"«{campo}» debe ser un número entero entre {minimo} y {maximo}."
        return int(v), None

    def grupo(k):
        return db.and_(LlaveApi.proveedor == k.proveedor, LlaveApi.ambiente == k.ambiente,
                       LlaveApi.proyecto_id == k.proyecto_id if k.proyecto_id else LlaveApi.proyecto_id.is_(None))

    def estado_visible(k, ahora, hoy):
        if k.estado != "activa":
            return k.estado
        if k.vence and k.vence < hoy:
            return "vencida"
        if k.bloqueada_hasta and k.bloqueada_hasta > ahora:
            return "en descanso"
        return "activa"

    def cifrar(secreto):
        return _fernet().encrypt(secreto.encode()).decode()

    # --- API interna -------------------------------------------------------------------------------
    def _disponibles(proveedor, proyecto_id, ambiente, heredar=None, mezclar=False):
        """Todas las llaves utilizables, en orden de pool (las de la plataforma y las compartidas que se le asignaron primero;
        las globales solo si se hereda). mezclar=True las devuelve en orden aleatorio."""
        asegurar()
        if heredar is None:
            heredar = HEREDAR_GLOBAL
        f = _fernet()
        if f is None:
            return []
        ahora, hoy = datetime.utcnow(), date.today()

        def buscar(pid):
            q = LlaveApi.query.filter(LlaveApi.proveedor == proveedor, LlaveApi.ambiente == ambiente,
                                      LlaveApi.estado == "activa", LlaveApi.secreto.isnot(None),
                                      or_(LlaveApi.vence.is_(None), LlaveApi.vence >= hoy),
                                      or_(LlaveApi.bloqueada_hasta.is_(None), LlaveApi.bloqueada_hasta <= ahora))
            if pid:
                cond = LlaveApi.proyecto_id == pid
                ids = ids_asignadas(pid)
                q = q.filter(or_(cond, LlaveApi.id.in_(ids)) if ids else cond)
            else:
                q = q.filter(LlaveApi.proyecto_id.is_(None))
            return q.order_by(LlaveApi.orden, LlaveApi.id).all()

        filas, vistas = [], set()
        for k in buscar(proyecto_id) + (buscar(None) if proyecto_id and heredar else []):
            if k.id not in vistas:          # una llave asignada a la plataforma también es global: no repetirla
                vistas.add(k.id)
                filas.append(k)
        salida = []
        for k in filas:
            try:
                salida.append(LlaveEntregada(k.id, f.decrypt(k.secreto.encode()).decode(), k.proveedor, k.etiqueta))
            except InvalidToken:
                app.logger.error("Llave %s no se pudo descifrar (¿cambió LLAVES_MASTER?)", k.id)
        if mezclar:
            random.shuffle(salida)
        return salida

    def _obtener(proveedor, proyecto_id, ambiente, heredar=None, mezclar=False):
        lista = _disponibles(proveedor, proyecto_id, ambiente, heredar, mezclar)
        return lista[0] if lista else None

    def _fallo(llave_id, codigo, cuerpo=""):
        asegurar()
        k = db.session.execute(db.select(LlaveApi).where(LlaveApi.id == llave_id).with_for_update()).scalar_one_or_none()
        if k is None:
            return
        k.fallos = (k.fallos or 0) + 1
        if codigo == 429:
            k.bloqueada_hasta, motivo = descanso_429(cuerpo)
            detalle = f"HTTP 429: {motivo}; el pool pasa a la siguiente"
            urgente = False
        elif codigo in (401, 403):
            k.estado = "invalida"
            detalle = f"HTTP {codigo}: rechazada por el proveedor; fuera del pool hasta revisarla"
            urgente = True
        else:
            db.session.rollback()
            return
        registrar("llave_fallo", "LlaveApi", k.id, f"{k.proveedor} · {k.etiqueta} · ****{k.ultimos4} · {detalle}")
        db.session.commit()
        if codigo == 429:
            # Con decenas de llaves gratuitas, un 429 suelto es normal: solo se avisa cuando ya no queda NINGUNA utilizable.
            if _estado_pool(k.proveedor)["usables"] == 0:
                avisar("Llave", f"Sin llaves disponibles de {k.proveedor}", "Todas están en descanso, inválidas o vencidas.",
                       "/llaves", urgente=True, clave=f"llave-pool-vacio-{k.proveedor}-{datetime.utcnow():%Y%m%d%H}")
            return
        avisar("Llave", f"Llave {k.proveedor} · {k.etiqueta}: error {codigo}", detalle, "/llaves",
               urgente=urgente, clave=f"llave-fallo-{k.id}-{codigo}-{datetime.utcnow():%Y%m%d%H}")

    def _uso(llave_id, peticiones, tokens_in, tokens_out, costo):
        asegurar()
        hoy = hoy_google()
        for _ in range(2):
            try:
                u = db.session.execute(db.select(UsoIA).where(UsoIA.fecha == hoy, UsoIA.llave_id == llave_id).with_for_update()).scalar_one_or_none()
                k = db.session.get(LlaveApi, llave_id)
                if k is None:
                    return
                if u is None:
                    u = UsoIA(fecha=hoy, llave_id=llave_id, proyecto_id=k.proyecto_id, proveedor=k.proveedor,
                              peticiones=0, tokens_in=0, tokens_out=0, costo=0.0)
                    db.session.add(u)
                u.peticiones = (u.peticiones or 0) + int(peticiones)
                u.tokens_in = (u.tokens_in or 0) + int(tokens_in)
                u.tokens_out = (u.tokens_out or 0) + int(tokens_out)
                u.costo = round((u.costo or 0.0) + float(costo), 6)
                k.ultimo_uso = datetime.utcnow()
                db.session.commit()
                break
            except IntegrityError:
                db.session.rollback()       # otro worker creó la fila al mismo tiempo: se reintenta una vez
        else:
            return
        for nombre, usado, limite in (("peticiones", u.peticiones, k.limite_peticiones),
                                      ("tokens", (u.tokens_in or 0) + (u.tokens_out or 0), k.limite_tokens)):
            if limite and usado >= UMBRAL_USO * limite:
                pct = int(usado * 100 / limite)
                avisar("Llave", f"{k.proveedor} · {k.etiqueta}: {pct}% del límite diario de {nombre}",
                       f"{usado:,} de {limite:,} {nombre} hoy.", "/llaves", urgente=pct >= 100,
                       clave=f"llave80-{k.id}-{hoy}-{nombre}-{'100' if pct >= 100 else '80'}")

    def _costo_mes(proyecto_id):
        asegurar()
        ini = date.today().replace(day=1)
        q = db.select(db.func.coalesce(db.func.sum(UsoIA.costo), 0.0)).where(UsoIA.fecha >= ini)
        if proyecto_id:
            q = q.where(UsoIA.proyecto_id == proyecto_id)
        return float(db.session.scalar(q) or 0.0)

    def _estado_pool(proveedor, proyecto_id=None):
        asegurar()
        ahora, hoy = datetime.utcnow(), date.today()
        r = {"total": 0, "usables": 0, "invalidas": 0, "vencidas": 0, "descanso": 0, "desactivadas": 0}
        listo = cifrado_listo()
        q = LlaveApi.query.filter(LlaveApi.proveedor == proveedor, LlaveApi.estado != "revocada")
        if proyecto_id:
            ids = ids_asignadas(proyecto_id)
            q = q.filter(or_(LlaveApi.proyecto_id == proyecto_id, LlaveApi.id.in_(ids)) if ids else LlaveApi.proyecto_id == proyecto_id)
        for k in q.all():
            r["total"] += 1
            e = estado_visible(k, ahora, hoy)
            if e == "activa":
                r["usables"] += 1 if (listo and k.secreto) else 0
            elif e == "invalida":
                r["invalidas"] += 1
            elif e == "vencida":
                r["vencidas"] += 1
            elif e == "en descanso":
                r["descanso"] += 1
            else:
                r["desactivadas"] += 1
        return r

    def _resumen_plat(pid):
        asegurar()
        ahora, hoy = datetime.utcnow(), date.today()
        r = {"total": 0, "activas": 0, "problemas": 0, "por_vencer": 0, "heredadas": 0, "compartidas": 0, "costo_mes": _costo_mes(pid)}
        asignadas = set(ids_asignadas(pid))
        for k in llaves_de(pid).filter(LlaveApi.estado != "revocada").all():
            r["total"] += 1
            if k.proyecto_id != pid:
                r["compartidas"] += 1
            e = estado_visible(k, ahora, hoy)
            if e == "activa":
                r["activas"] += 1
            elif e in ("invalida", "vencida", "en descanso"):
                r["problemas"] += 1
            if k.estado == "activa" and k.vence and 0 <= (k.vence - hoy).days <= AVISO_VENCE_DIAS:
                r["por_vencer"] += 1
        if HEREDAR_GLOBAL:      # llaves globales que esta plataforma todavía puede usar
            r["heredadas"] = LlaveApi.query.filter(LlaveApi.proyecto_id.is_(None), LlaveApi.estado == "activa",
                                                   LlaveApi.id.notin_(asignadas or [0])).count()
        return r

    def _panel_plat(pid):
        asegurar()
        rellenar_huellas()
        ahora, hoy = datetime.utcnow(), hoy_google()
        ks = llaves_de(pid).order_by(LlaveApi.proveedor, LlaveApi.ambiente, LlaveApi.orden, LlaveApi.id).all()
        ids = [k.id for k in ks]
        uso = {u.llave_id: u for u in UsoIA.query.filter(UsoIA.fecha == hoy, UsoIA.llave_id.in_(ids)).all()} if ks else {}
        meta = {m.llave_id: m for m in LlaveMeta.query.filter(LlaveMeta.llave_id.in_(ids)).all()} if ks else {}
        donde = plataformas_por_llave(ids)
        filas, mi_nombre = [], nombre_de(pid)
        for k in ks:
            m = meta.get(k.id)
            filas.append({"id": k.id, "proveedor": k.proveedor, "etiqueta": k.etiqueta, "ambiente": k.ambiente, "ultimos4": k.ultimos4,
                          "estado": estado_visible(k, ahora, hoy), "vence": k.vence,
                          "dias": (k.vence - date.today()).days if k.vence else None,
                          "pet": uso[k.id].peticiones if k.id in uso else 0,
                          "tok": ((uso[k.id].tokens_in or 0) + (uso[k.id].tokens_out or 0)) if k.id in uso else 0,
                          "compartida": k.proyecto_id != pid,
                          "tambien": [n for n in donde.get(k.id, []) if n != mi_nombre],
                          "prueba": m.prueba_resultado if m else None, "prueba_txt": ETIQ_PRUEBA.get(m.prueba_resultado, "") if m else "",
                          "prueba_fecha": m.prueba_fecha if m else None, "prueba_detalle": (m.prueba_detalle or "") if m else ""})
        return {"llaves": filas, "resumen": _resumen_plat(pid), "proveedores": PROVEEDORES, "ambientes": AMBIENTES,
                "mfa": mfa_ok(), "cifrado": cifrado_listo(), "heredar": HEREDAR_GLOBAL, "probando": dict(estado_prueba),
                "globales_gemini": LlaveApi.query.filter(LlaveApi.proveedor == GEMINI, LlaveApi.proyecto_id.is_(None),
                                                         LlaveApi.estado != "revocada").count()}

    def nombre_de(pid):
        p = db.session.get(Proyecto, pid)
        return p.nombre if p else ""

    def _url_llaves(k):
        return f"/llaves?plataforma={k.proyecto_id}" if k.proyecto_id else "/llaves"

    def _revisar():
        asegurar()
        ahora, hoy = datetime.utcnow(), date.today()
        for k in LlaveApi.query.filter(LlaveApi.estado == "activa").all():
            nombre = f"{k.proveedor} · {k.etiqueta}"
            if k.vence:
                dias = (k.vence - hoy).days
                if dias <= AVISO_VENCE_DIAS:
                    titulo = f"Llave vencida: {nombre}" if dias < 0 else f"Llave por vencer en {dias} día(s): {nombre}"
                    avisar("Llave", titulo, "Rótala o renueva la fecha en /llaves.", _url_llaves(k), urgente=dias <= 3,
                           clave=f"llave-vence-{k.id}-{k.vence}-{'v' if dias < 0 else 'p'}")
            if k.rotar_cada_dias:
                base = k.rotada_en or k.creada or ahora
                if base + timedelta(days=k.rotar_cada_dias) <= ahora:
                    avisar("Llave", f"Toca rotar la llave: {nombre}", f"Programada cada {k.rotar_cada_dias} días.", _url_llaves(k),
                           urgente=False, clave=f"llave-rotar-{k.id}-{base:%Y%m%d}")
        if PROBAR_AUTO:        # revisión diaria de las llaves de Gemini (models.list: no gasta cuota)
            ultima = db.session.scalar(db.select(db.func.max(LlaveMeta.prueba_fecha)))
            if ultima is None or ahora - ultima > timedelta(hours=PROBAR_CADA_HORAS):
                ids = [k.id for k in LlaveApi.query.filter(LlaveApi.proveedor == GEMINI, LlaveApi.estado == "activa",
                                                           LlaveApi.secreto.isnot(None)).all()]
                if ids:
                    lanzar_pruebas(ids, False, "sistema")

    def _crear(proveedor, proyecto_id, etiqueta, secreto, ambiente="Producción"):
        asegurar()
        if not cifrado_listo():
            return None, "No hay clave de cifrado: define SECRET_KEY (o LLAVES_MASTER)."
        if proveedor not in PROVEEDORES or ambiente not in AMBIENTES:
            return None, "proveedor o ambiente desconocido."
        etiqueta = (etiqueta or "").strip()
        if not 2 <= len(etiqueta) <= 80:
            return None, "la etiqueta debe tener entre 2 y 80 caracteres."
        secreto = (secreto or "").strip()
        if not 8 <= len(secreto) <= 4000 or any(c.isspace() for c in secreto):
            return None, "La llave debe tener entre 8 y 4000 caracteres y sin espacios."
        ultimo = db.session.scalar(db.select(db.func.max(LlaveApi.orden)).where(
            LlaveApi.proveedor == proveedor, LlaveApi.ambiente == ambiente,
            LlaveApi.proyecto_id == proyecto_id if proyecto_id else LlaveApi.proyecto_id.is_(None)))
        k = LlaveApi(proveedor=proveedor, proyecto_id=proyecto_id, etiqueta=etiqueta, ambiente=ambiente, ultimos4=secreto[-4:],
                     secreto=cifrar(secreto), orden=(ultimo if ultimo is not None else -1) + 1,
                     creado_por=getattr(current_user, "username", None))
        db.session.add(k)
        db.session.flush()
        fijar_meta(k, secreto)
        registrar("crear_llave", "LlaveApi", k.id, f"{proveedor} · {etiqueta} · {ambiente} · ****{k.ultimos4}")
        return k.id, None          # el commit lo hace quien llama (así conector + llave se guardan juntos)

    def guardar_prueba(k, r, secreto=None):
        """Anota el resultado de una prueba y aplica sus consecuencias (inválida → fuera del pool; sin cuota → descanso). No hace commit."""
        m = db.session.get(LlaveMeta, k.id)
        if m is None:
            m = LlaveMeta(llave_id=k.id, huella=huella(secreto) if secreto else None, origen="manual")
            db.session.add(m)
        m.prueba_fecha, m.prueba_resultado = datetime.utcnow(), r["resultado"]
        m.prueba_detalle, m.prueba_ms = (r.get("detalle") or "")[:240], r.get("ms")
        if r["resultado"] in ("invalida", "rechazada") and k.estado == "activa":
            k.estado = "invalida"
            registrar("llave_fallo", "LlaveApi", k.id, f"{k.proveedor} · {k.etiqueta} · ****{k.ultimos4} · prueba: {r['detalle']}")
        elif r["resultado"] == "sin_cuota" and r.get("hasta"):
            k.bloqueada_hasta = r["hasta"]

    def lanzar_pruebas(ids, real, quien):
        """Prueba varias llaves en un hilo aparte (100 llaves tardan más que el tiempo máximo de una petición web).
        Devuelve False si ya hay una corrida en marcha."""
        with cerrojo:
            if estado_prueba["corriendo"]:
                return False
            estado_prueba.update(corriendo=True, hechas=0, total=len(ids), inicio=datetime.utcnow(), real=bool(real))

        def trabajo():
            try:
                with app.app_context():
                    f = _fernet()
                    trabajos = []
                    for k in LlaveApi.query.filter(LlaveApi.id.in_(ids), LlaveApi.secreto.isnot(None)).all():
                        try:
                            trabajos.append((k.id, f.decrypt(k.secreto.encode()).decode()))
                        except (InvalidToken, AttributeError):
                            pass
                    with cerrojo:
                        estado_prueba["total"] = len(trabajos)
                    modelo = MODELO_PRUEBA() if real else None      # se resuelve aquí (con contexto de la app), no en los hilos
                    db.session.rollback()          # no mantener una transacción abierta mientras se espera a la red

                    def una(t):
                        r = probar_gemini(t[1], real, modelo=modelo)
                        with cerrojo:
                            estado_prueba["hechas"] += 1
                        return t[0], t[1], r

                    with ThreadPoolExecutor(PROBAR_HILOS) as ex:
                        resultados = list(ex.map(una, trabajos))
                    cuenta = {}
                    for lid, secreto, r in resultados:
                        k = db.session.get(LlaveApi, lid)
                        if k is not None:
                            guardar_prueba(k, r, secreto)
                            cuenta[r["resultado"]] = cuenta.get(r["resultado"], 0) + 1
                    resumen = ", ".join(f"{ETIQ_PRUEBA.get(c, c)}: {n}" for c, n in sorted(cuenta.items())) or "sin llaves que probar"
                    registrar("probar_llaves", "LlaveApi", None, f"{len(resultados)} llaves ({'con petición real' if real else 'models.list'}) · {resumen}",
                              usuario=quien)
                    db.session.commit()
            except Exception as e:
                app.logger.error("Prueba de llaves falló: %s", e)
                try:
                    db.session.rollback()
                except Exception:
                    pass
            finally:
                with cerrojo:
                    estado_prueba["corriendo"] = False
                try:
                    db.session.remove()
                except Exception:
                    pass

        threading.Thread(target=trabajo, daemon=True, name="llaves-pruebas").start()
        return True

    _api.update(obtener=_obtener, todas=_disponibles, fallo=_fallo, uso=_uso, costo_mes=_costo_mes, revisar=_revisar,
                estado_pool=_estado_pool, resumen_plat=_resumen_plat, panel_plat=_panel_plat, crear=_crear)

    # --- pantallas ------------------------------------------------------------------------------------
    @bp.route("/llaves")
    @solo_admin
    def index():
        asegurar()
        rellenar_huellas()
        ahora, hoy, hoy_g = datetime.utcnow(), date.today(), hoy_google()
        act = plat_activa()
        q = llaves_de(act.id) if act else LlaveApi.query
        prov = request.args.get("proveedor", "")
        if prov in PROVEEDORES:
            q = q.filter(LlaveApi.proveedor == prov)
        llaves = q.order_by(LlaveApi.proveedor, LlaveApi.proyecto_id, LlaveApi.ambiente, LlaveApi.orden, LlaveApi.id).all()
        ids_todas = [k.id for k in llaves]
        uso_hoy = {u.llave_id: u for u in UsoIA.query.filter_by(fecha=hoy_g).all()}
        meta = {m.llave_id: m for m in LlaveMeta.query.all()}
        donde = plataformas_por_llave(ids_todas)
        asig = {}
        for a in LlavePlat.query.all():
            asig.setdefault(a.llave_id, []).append(a.proyecto_id)
        filas = []
        for k in llaves:
            u = uso_hoy.get(k.id)
            m = meta.get(k.id)
            tokens = ((u.tokens_in or 0) + (u.tokens_out or 0)) if u else 0
            filas.append({
                "k": k, "estado": estado_visible(k, ahora, hoy),
                "dias": (k.vence - hoy).days if k.vence else None,
                "pet": u.peticiones if u else 0, "tok": tokens,
                "pct_pet": int((u.peticiones if u else 0) * 100 / k.limite_peticiones) if k.limite_peticiones else None,
                "pct_tok": int(tokens * 100 / k.limite_tokens) if k.limite_tokens else None,
                "prueba": m.prueba_resultado if m else None, "prueba_txt": ETIQ_PRUEBA.get(m.prueba_resultado, "") if m else "",
                "prueba_fecha": m.prueba_fecha if m else None, "prueba_detalle": (m.prueba_detalle or "") if m else "",
                "prueba_ms": m.prueba_ms if m else None,
                "plataformas": donde.get(k.id, []), "asig": asig.get(k.id, []), "origen": m.origen if m else "manual",
            })
        ini = hoy_g.replace(day=1)
        cons = db.select(UsoIA.proyecto_id, UsoIA.proveedor, db.func.sum(UsoIA.peticiones), db.func.sum(UsoIA.tokens_in + UsoIA.tokens_out),
                         db.func.sum(UsoIA.costo)).where(UsoIA.fecha >= ini)
        if act:
            cons = cons.where(UsoIA.proyecto_id == act.id)
        mes = db.session.execute(cons.group_by(UsoIA.proyecto_id, UsoIA.proveedor).order_by(db.func.sum(UsoIA.costo).desc())).all()
        proyectos = Proyecto.query.order_by(Proyecto.nombre).all()
        nombres = {p.id: nombre_visible(p) for p in proyectos}
        plataformas = [p for p in proyectos if p.tipo == TIPO_PLATAFORMA]
        malas = ("invalida", "rechazada", "sin_cuota")
        resumen = {
            "activas": sum(1 for f in filas if f["estado"] == "activa"),
            "por_vencer": sum(1 for f in filas if f["dias"] is not None and 0 <= f["dias"] <= AVISO_VENCE_DIAS and f["k"].estado == "activa"),
            "problemas": sum(1 for f in filas if f["estado"] in ("invalida", "vencida", "en descanso")),
            "costo_mes": sum((m[4] or 0) for m in mes),
            "sin_probar": sum(1 for f in filas if f["k"].proveedor == GEMINI and f["k"].secreto and not f["prueba"]),
            "probadas_mal": sum(1 for f in filas if f["prueba"] in malas),
            "total": len(filas),
        }
        ver = request.args.get("ver", "")
        if ver == "problemas":
            filas = [f for f in filas if f["estado"] in ("invalida", "vencida", "en descanso") or f["prueba"] in malas]
        elif ver == "sinprobar":
            filas = [f for f in filas if f["k"].proveedor == GEMINI and f["k"].secreto and not f["prueba"]]
        bq = Auditoria.query.filter_by(entidad="LlaveApi")
        if act:
            bq = bq.filter(Auditoria.entidad_id.in_(ids_todas)) if ids_todas else None
        bitacora = bq.order_by(Auditoria.fecha.desc(), Auditoria.id.desc()).limit(15).all() if bq is not None else []
        # Llaves de Gemini que este servidor trae en sus variables de entorno y todavía no están registradas aquí
        entorno = {"detectadas": 0, "nuevas": 0}
        if cifrado_listo():
            conocidas = {m.huella for m in meta.values() if m.huella}
            det = llaves_del_entorno()
            entorno = {"detectadas": len(det), "nuevas": sum(1 for _, v in det if huella(v) not in conocidas)}
        mensaje = MENSAJES.get(request.args.get("m", ""))
        if mensaje and request.args.get("m") == "importada":
            mensaje = (f"Importé {request.args.get('n', '0')} llave(s) nuevas; {request.args.get('d', '0')} ya estaban registradas"
                       + (f"; {request.args.get('r')} se omitieron porque las revocaste antes." if request.args.get("r", "0") != "0" else ".")
                       + " Quedaron cifradas; las variables de Render no se tocaron.")
        return render_template("llaves.html", filas=filas, resumen=resumen, mes=mes, nombres=nombres, proyectos=proyectos, plataformas=plataformas,
                               proveedores=PROVEEDORES, ambientes=AMBIENTES, bitacora=bitacora,
                               cifrado=cifrado_listo(), mfa=mfa_ok(), enfriar=ENFRIAR_MIN, mensaje=mensaje,
                               act=act, qplat=(f"?plataforma={act.id}" if act else ""), entorno=entorno, tokens={t.proyecto_id: t for t in LlaveToken.query.all()},
                               probando=dict(estado_prueba), prov_filtro=prov, ver=ver, gemini=GEMINI)

    @bp.route("/llaves/nueva", methods=["POST"])
    @escribe
    def nueva():
        asegurar()
        if not cifrado_listo():
            return mal("No hay clave de cifrado: define SECRET_KEY (o LLAVES_MASTER).")
        proveedor = request.form.get("proveedor", "")
        ambiente = request.form.get("ambiente", "")
        etiqueta = (request.form.get("etiqueta") or "").strip()
        if proveedor not in PROVEEDORES or ambiente not in AMBIENTES:
            return mal("proveedor o ambiente desconocido.")
        if not 2 <= len(etiqueta) <= 80:
            return mal("la etiqueta debe tener entre 2 y 80 caracteres.")
        secreto, err = leer_secreto("secreto")
        if err:
            return mal(err)
        vence, err = leer_fecha("vence")
        if err:
            return mal(err)
        rotar, err = leer_entero("rotar_cada_dias", 1, 3650)
        if err:
            return mal(err)
        lim_p, err = leer_entero("limite_peticiones")
        if err:
            return mal(err)
        lim_t, err = leer_entero("limite_tokens")
        if err:
            return mal(err)
        pid = None
        act = plat_activa()
        if act:
            pid = act.id                      # desde la pantalla de una plataforma NUNCA se crea una llave global
        elif request.form.get("proyecto_id"):
            p = db.session.get(Proyecto, int(request.form["proyecto_id"])) if request.form["proyecto_id"].isdigit() else None
            if p is None:
                return mal("plataforma no encontrada.")
            pid = p.id
        ultimo = db.session.scalar(db.select(db.func.max(LlaveApi.orden)).where(
            LlaveApi.proveedor == proveedor, LlaveApi.ambiente == ambiente,
            LlaveApi.proyecto_id == pid if pid else LlaveApi.proyecto_id.is_(None)))
        k = LlaveApi(proveedor=proveedor, proyecto_id=pid, etiqueta=etiqueta, ambiente=ambiente, ultimos4=secreto[-4:],
                     secreto=cifrar(secreto), vence=vence, orden=(ultimo if ultimo is not None else -1) + 1,
                     rotar_cada_dias=rotar, limite_peticiones=lim_p, limite_tokens=lim_t, creado_por=current_user.username)
        db.session.add(k)
        db.session.flush()
        fijar_meta(k, secreto)
        registrar("crear_llave", "LlaveApi", k.id, f"{proveedor} · {etiqueta} · {ambiente} · ****{k.ultimos4}")
        db.session.commit()
        return volver("creada")

    def cargar(lid, compartida_ok=False, bloquear=True):
        """Desde la pantalla de una plataforma solo se tocan SUS llaves. Las compartidas (de varias plataformas) solo se pueden
        probar o quitar de esa plataforma: desactivarlas, rotarlas o revocarlas afectaría a todas, y eso se hace en /llaves."""
        q = db.select(LlaveApi).where(LlaveApi.id == lid)
        k = db.session.execute(q.with_for_update() if bloquear else q).scalar_one_or_none()
        if k is None:
            abort(404)
        act = plat_activa()
        if act and k.proyecto_id != act.id:
            if not (compartida_ok and db.session.get(LlavePlat, (k.id, act.id))):
                abort(404)
        return k

    @bp.route("/llaves/<int:lid>/rotar", methods=["POST"])
    @escribe
    def rotar(lid):
        asegurar()
        if not cifrado_listo():
            return mal("No hay clave de cifrado: define SECRET_KEY (o LLAVES_MASTER).")
        k = cargar(lid)
        if k.estado == "revocada" and not request.form.get("secreto"):
            return mal("falta el nuevo valor de la llave.")
        secreto, err = leer_secreto("secreto")
        if err:
            return mal(err)
        antes = k.ultimos4
        k.secreto, k.ultimos4 = cifrar(secreto), secreto[-4:]
        fijar_meta(k, secreto)
        k.rotada_en, k.fallos, k.bloqueada_hasta, k.estado = datetime.utcnow(), 0, None, "activa"
        vence, err = leer_fecha("vence")
        if err:
            db.session.rollback()
            return mal(err)
        if request.form.get("vence"):
            k.vence = vence
        registrar("rotar_llave", "LlaveApi", k.id, f"{k.proveedor} · {k.etiqueta} · ****{antes} → ****{k.ultimos4}")
        db.session.commit()
        return volver("rotada")

    @bp.route("/llaves/<int:lid>/desactivar", methods=["POST"])
    @escribe
    def desactivar(lid):
        asegurar()
        k = cargar(lid)
        if k.estado == "revocada":
            db.session.rollback()
            return volver()
        k.estado = "desactivada"
        registrar("desactivar_llave", "LlaveApi", k.id, f"{k.proveedor} · {k.etiqueta} · ****{k.ultimos4}")
        db.session.commit()
        return volver("desactivada")

    @bp.route("/llaves/<int:lid>/activar", methods=["POST"])
    @escribe
    def activar(lid):
        asegurar()
        k = cargar(lid)
        if k.estado == "revocada" or not k.secreto:
            db.session.rollback()
            return mal("una llave revocada no se reactiva: rótala con un valor nuevo.")
        k.estado, k.fallos, k.bloqueada_hasta = "activa", 0, None
        registrar("activar_llave", "LlaveApi", k.id, f"{k.proveedor} · {k.etiqueta} · ****{k.ultimos4}")
        db.session.commit()
        return volver("activada")

    @bp.route("/llaves/<int:lid>/revocar", methods=["POST"])
    @escribe
    def revocar(lid):
        asegurar()
        k = cargar(lid)
        k.estado, k.secreto = "revocada", None          # el secreto se borra de verdad
        registrar("revocar_llave", "LlaveApi", k.id, f"{k.proveedor} · {k.etiqueta} · ****{k.ultimos4}")
        db.session.commit()
        return volver("revocada")

    @bp.route("/llaves/<int:lid>/editar", methods=["POST"])
    @escribe
    def editar(lid):
        asegurar()
        k = cargar(lid)
        etiqueta = (request.form.get("etiqueta") or "").strip()
        if not 2 <= len(etiqueta) <= 80:
            db.session.rollback()
            return mal("la etiqueta debe tener entre 2 y 80 caracteres.")
        vence, e1 = leer_fecha("vence")
        rotar, e2 = leer_entero("rotar_cada_dias", 1, 3650)
        lim_p, e3 = leer_entero("limite_peticiones")
        lim_t, e4 = leer_entero("limite_tokens")
        if e1 or e2 or e3 or e4:
            db.session.rollback()
            return mal(e1 or e2 or e3 or e4)
        k.etiqueta, k.vence, k.rotar_cada_dias, k.limite_peticiones, k.limite_tokens = etiqueta, vence, rotar, lim_p, lim_t
        registrar("editar_llave", "LlaveApi", k.id, f"{k.proveedor} · {k.etiqueta} · ****{k.ultimos4}")
        db.session.commit()
        return volver("editada")

    @bp.route("/llaves/<int:lid>/mover", methods=["POST"])
    @escribe
    def mover(lid):
        asegurar()
        k = cargar(lid)
        sube = request.form.get("dir") == "subir"
        hermanas = LlaveApi.query.filter(grupo(k)).order_by(LlaveApi.orden, LlaveApi.id).all()
        for i, h in enumerate(hermanas):          # normaliza 0..n-1 y luego intercambia
            h.orden = i
        i = next(n for n, h in enumerate(hermanas) if h.id == k.id)
        j = i - 1 if sube else i + 1
        if 0 <= j < len(hermanas):
            hermanas[i].orden, hermanas[j].orden = hermanas[j].orden, hermanas[i].orden
            registrar("ordenar_llave", "LlaveApi", k.id, f"{k.proveedor} · {k.etiqueta} · {'sube' if sube else 'baja'} en el pool")
        db.session.commit()
        return volver("movida")

    # --- Gemini: importar del entorno, asignar a plataformas, probar ------------------------------------
    def destinos_pedidos(campo="asignar"):
        pedidas = [int(x) for x in request.form.getlist(campo) if x.isdigit()]
        if not pedidas:
            return set()
        return {p.id for p in Proyecto.query.filter(Proyecto.id.in_(pedidas), Proyecto.tipo == TIPO_PLATAFORMA).all()}

    def importar_lista(candidatas, destinos, origen):
        """Registra (cifradas) las llaves que no existan (se reconocen por su huella) y las asigna a `destinos`.
        Una llave que ya estaba y se vuelve a importar para otra plataforma solo suma esa plataforma. Sin commit."""
        rellenar_huellas()
        conocidas = {m.huella: m.llave_id for m in LlaveMeta.query.all() if m.huella}
        ultimo = db.session.scalar(db.select(db.func.max(LlaveApi.orden)).where(
            LlaveApi.proveedor == GEMINI, LlaveApi.ambiente == "Producción", LlaveApi.proyecto_id.is_(None)))
        siguiente = (ultimo if ultimo is not None else -1) + 1
        nuevas = repetidas = omitidas = 0
        afectadas = []
        for nombre, valor in candidatas:
            h = huella(valor)
            if h in conocidas:
                k = db.session.get(LlaveApi, conocidas[h])
                if k is None or k.estado == "revocada":
                    omitidas += 1
                else:
                    repetidas += 1
                    if k.proyecto_id is None:
                        afectadas.append(k.id)
                continue
            etiqueta = (f"{nombre} ····{valor[-4:]}" if origen == "pegada" and nombre else
                        f"Gemini ····{valor[-4:]}" if origen == "pegada" else nombre)[:80]
            k = LlaveApi(proveedor=GEMINI, proyecto_id=None, etiqueta=etiqueta, ambiente="Producción", ultimos4=valor[-4:],
                         secreto=cifrar(valor), orden=siguiente, creado_por=current_user.username)
            siguiente += 1
            db.session.add(k)
            db.session.flush()
            db.session.add(LlaveMeta(llave_id=k.id, huella=h, origen=origen))
            conocidas[h] = k.id
            afectadas.append(k.id)
            nuevas += 1
        asignaciones = 0
        if destinos and afectadas:
            ya = {(a.llave_id, a.proyecto_id) for a in LlavePlat.query.filter(LlavePlat.llave_id.in_(afectadas)).all()}
            for lid in afectadas:
                for pid in destinos:
                    if (lid, pid) not in ya:
                        db.session.add(LlavePlat(llave_id=lid, proyecto_id=pid))
                        asignaciones += 1
        registrar("importar_llaves", "LlaveApi", None,
                  f"{nuevas} nuevas, {repetidas} ya estaban, {omitidas} revocadas omitidas · origen: {origen} · "
                  f"{asignaciones} asignaciones a {len(destinos)} plataforma(s)")
        return nuevas, repetidas, omitidas

    @bp.route("/llaves/importar-entorno", methods=["POST"])
    @escribe
    def importar_entorno():
        """Copia (cifradas) a este registro las llaves GEMINI_KEY_N de las variables de Render de ESTE servidor (el admin solo ve
        las suyas; las de otras apps se pegan con /llaves/importar-pegadas). Idempotente. Las variables de Render no se modifican."""
        asegurar()
        if not cifrado_listo():
            return mal("No hay clave de cifrado: define SECRET_KEY (o LLAVES_MASTER).")
        candidatas = llaves_del_entorno()
        if not candidatas:
            return mal("No encontré llaves GEMINI_KEY_1, GEMINI_KEY_2... en las variables de este servidor.")
        n, d, r = importar_lista(candidatas, destinos_pedidos(), "entorno")
        db.session.commit()
        return volver("importada", n=n, d=d, r=r)

    @bp.route("/llaves/importar-pegadas", methods=["POST"])
    @escribe
    def importar_pegadas():
        """Llaves pegadas desde otra app (Zelecte, Zmarthket...): se asignan a las plataformas marcadas. Si una llave ya estaba
        registrada (por ejemplo porque otra app también la tiene), solo se le suma esa plataforma: así se arma «dónde se usa»."""
        asegurar()
        if not cifrado_listo():
            return mal("No hay clave de cifrado: define SECRET_KEY (o LLAVES_MASTER).")
        candidatas = llaves_de_texto(request.form.get("pegadas"))
        if not candidatas:
            return mal("no encontré llaves en lo que pegaste (una por línea, o NOMBRE=valor como en Render).")
        destinos = destinos_pedidos()
        if not destinos:
            return mal("marca al menos una plataforma: es la que usa esas llaves.")
        n, d, r = importar_lista(candidatas, destinos, "pegada")
        db.session.commit()
        return volver("importada", n=n, d=d, r=r)

    # --- Gemini: leer las variables de cada servicio por la API de Render ---------------------------------
    def leer_de_render():
        """(fuentes, error, avisos). Lee con las llaves generales de Render las GEMINI_KEY_N de cada servicio y grupo de
        variables, y a cada fuente le calcula sus plataformas (por repositorio, dirección o nombre: render_panel.vincular).
        Las fuentes traen secretos: no se devuelven al navegador ni se guardan. Necesita contexto de petición."""
        import render_panel
        llaves_render = render_panel._llaves()
        if not llaves_render:
            return [], "No hay ninguna llave de la API de Render guardada: agrégala en Conexiones.", []
        fuentes, avisos = render_panel.fuentes_gemini(llaves_render)
        plataformas_ = Proyecto.query.filter_by(tipo=TIPO_PLATAFORMA).all()
        for f in fuentes:
            f["plataformas"] = [p for p in plataformas_
                                if render_panel.vincular(p, f["servicios"], [x.nombre for x in p.subdominios])]
        return fuentes, None, avisos

    @bp.route("/llaves/render-detectar")
    @escribe
    def render_detectar():
        """Vista previa SIN secretos: por servicio, qué llaves de Gemini hay (solo últimos 4), cuáles son nuevas y a qué plataforma
        se asignarían solas. No escribe nada."""
        asegurar()
        if not cifrado_listo():
            return jsonify(ok=False, error="No hay clave de cifrado: define SECRET_KEY (o LLAVES_MASTER)."), 400
        try:
            fuentes, error, avisos = leer_de_render()
        except Exception:
            return jsonify(ok=False, error="No se pudo leer Render."), 502
        if error:
            return jsonify(ok=False, error=error), 400
        rellenar_huellas()
        conocidas = {m.huella for m in LlaveMeta.query.all() if m.huella}
        salida = [{"nombre": f["nombre"], "cuenta": f["cuenta"], "tipo": f["tipo"],
                   "plataformas": [p.nombre for p in f["plataformas"]],
                   "llaves": [{"variable": n, "final": v[-4:], "nueva": huella(v) not in conocidas} for n, v in f["llaves"]]}
                  for f in fuentes]
        return jsonify(ok=True, fuentes=salida, avisos=avisos,
                       nuevas=len({huella(v) for f in fuentes for _, v in f["llaves"]} - conocidas))

    @bp.route("/llaves/importar-render", methods=["POST"])
    @escribe
    def importar_render():
        """Copia (cifradas) a este registro las llaves de Gemini que Render guarda en las variables de tus servicios. Cada una
        se asigna sola a la plataforma ligada a su servicio; si un servicio no se pudo ligar, a las plataformas marcadas en el
        formulario (o a ninguna). Idempotente (se reconocen por huella). Render solo se LEE: sus variables no se modifican."""
        asegurar()
        if not cifrado_listo():
            return mal("No hay clave de cifrado: define SECRET_KEY (o LLAVES_MASTER).")
        try:
            fuentes, error, avisos = leer_de_render()
        except Exception:
            return mal("no se pudo leer Render.")
        if error:
            return mal(error)
        if not fuentes:
            return mal("no encontré variables GEMINI_KEY_1, GEMINI_KEY_2... en los servicios de Render." + (f" ({avisos[0]})" if avisos else ""))
        manuales = destinos_pedidos()
        n = d = r = 0
        for f in fuentes:
            destinos = {p.id for p in f["plataformas"]} or manuales
            candidatas = [(f"{var} · {f['nombre']} ····{valor[-4:]}", valor) for var, valor in f["llaves"]]
            a, b, c = importar_lista(candidatas, destinos, "render")
            n, d, r = n + a, d + b, r + c
        db.session.commit()
        return volver("importada", n=n, d=d, r=r)

    # --- API interna: las plataformas piden sus llaves al panel (token Bearer propio por plataforma) -----------------
    # Solo Gemini. Cada plataforma recibe únicamente las llaves que tiene asignadas (nunca las demás). Las llaves viajan por
    # HTTPS en la respuesta, nunca se escriben en la bitácora, y el token se guarda como huella (el valor solo se ve al crearlo).
    PROV_API = {"gemini": GEMINI}
    API_MAX_LLAVES = 5
    _locales = {}

    def _sha_token(t):
        return hashlib.sha256(("llaves-token|" + t).encode()).hexdigest()

    def _permitir(clave, maximo, segundos, sumar=True):
        """Límite por ventana: el de app.py (en base, vale con varios workers) y, si no se le pasó, uno en memoria."""
        if limitar:
            return limitar(clave, maximo, segundos, sumar)
        ahora = time.time()
        ts = [x for x in _locales.get(clave, []) if ahora - x < segundos]
        ok = len(ts) < maximo
        if ok and sumar:
            ts.append(ahora)
        _locales[clave] = ts
        return ok

    def _json(datos, codigo=200):
        r = jsonify(datos)
        r.status_code = codigo
        r.headers["Cache-Control"] = "no-store"
        return r

    def autenticar():
        """(fila de token, None) o (None, respuesta de error). Pocos fallos por IP; luego un tope por plataforma."""
        ip = request.remote_addr or "-"
        if not _permitir(f"llaves-api-fallos-{ip}", 10, 600, sumar=False):
            return None, _json({"ok": False, "error": "demasiados_intentos"}, 429)
        h = request.headers.get("Authorization", "")
        tok = h[7:].strip() if h[:7].lower() == "bearer " else ""
        fila = None
        if tok.startswith("zlk_") and len(tok) <= 200:
            asegurar()
            fila = LlaveToken.query.filter_by(huella_token=_sha_token(tok), activo=True).first()
        if fila is None:
            _permitir(f"llaves-api-fallos-{ip}", 10, 600)             # cuenta un fallo
            return None, _json({"ok": False, "error": "no_autorizado"}, 401)
        if not _permitir(f"llaves-api-{fila.proyecto_id}", 240, 60):
            return None, _json({"ok": False, "error": "demasiadas_peticiones"}, 429)
        ahora = datetime.utcnow()
        if fila.ultimo_uso is None or (ahora - fila.ultimo_uso).total_seconds() > 300:   # no escribir en cada llamada (cuida la base)
            fila.ultimo_uso = ahora
            db.session.commit()
        return fila, None

    def _de_la_plataforma(pid, llave_id):
        """La llave de Gemini si es de esa plataforma o se le asignó; si no, None (un token no toca llaves ajenas)."""
        k = db.session.get(LlaveApi, llave_id) if isinstance(llave_id, int) and not isinstance(llave_id, bool) else None
        if k is None or k.proveedor != GEMINI:
            return None
        return k if (k.proyecto_id == pid or k.id in ids_asignadas(pid)) else None

    def _entero(v, tope):
        try:
            return max(0, min(int(v), tope))
        except (TypeError, ValueError):
            return 0

    @bp.route("/api/llaves/v1/<prov>")
    def api_pedir(prov):
        """GET con Authorization: Bearer zlk_... → {"ok", "llaves": [{"id", "llave"}], "disponibles"}. ?n=1..5 (al azar)."""
        tok, err = autenticar()
        if err:
            return err
        proveedor = PROV_API.get(prov.lower())
        if not proveedor:
            return _json({"ok": False, "error": "proveedor_no_disponible"}, 404)
        n = _entero(request.args.get("n", "1"), API_MAX_LLAVES) or 1
        lista = _disponibles(proveedor, tok.proyecto_id, "Producción", heredar=False, mezclar=True)
        if not lista:
            return _json({"ok": False, "error": "sin_llaves"}, 503)
        return _json({"ok": True, "llaves": [{"id": k.id, "llave": k.secreto} for k in lista[:n]], "disponibles": len(lista)})

    @bp.route("/api/llaves/v1/reportar", methods=["POST"])
    def api_reportar():
        """JSON {"llave_id", "codigo": 429|400|401|403, "cuerpo"}. 429: la llave descansa. 400/401/403: el panel la comprueba con
        Google antes de sacarla del pool (un token comprometido no puede vaciar el pool por su cuenta)."""
        tok, err = autenticar()
        if err:
            return err
        j = request.get_json(silent=True)
        j = j if isinstance(j, dict) else {}
        k, codigo = _de_la_plataforma(tok.proyecto_id, j.get("llave_id")), j.get("codigo")
        if k is None or codigo not in (400, 401, 403, 429):
            return _json({"ok": False, "error": "solicitud_no_valida"}, 400)
        if k.estado != "activa" or not k.secreto:
            return _json({"ok": True, "accion": "ignorada"})
        if codigo == 429:
            _fallo(k.id, 429, str(j.get("cuerpo") or "")[:4000])
            return _json({"ok": True, "accion": "en_descanso"})
        if not _permitir(f"llaves-api-verif-{tok.proyecto_id}", 30, 3600):
            return _json({"ok": False, "error": "demasiadas_peticiones"}, 429)
        try:
            secreto = _fernet().decrypt(k.secreto.encode()).decode()
        except Exception:
            return _json({"ok": False, "error": "no_se_pudo_verificar"}, 500)
        if probar_gemini(secreto)["resultado"] in ("invalida", "rechazada"):
            _fallo(k.id, 403)
            return _json({"ok": True, "accion": "invalidada"})
        return _json({"ok": True, "accion": "ignorada"})

    @bp.route("/api/llaves/v1/uso", methods=["POST"])
    def api_uso():
        """JSON {"llave_id", "peticiones", "tokens_in", "tokens_out"}: suma el consumo del día (se puede mandar por lotes)."""
        tok, err = autenticar()
        if err:
            return err
        j = request.get_json(silent=True)
        j = j if isinstance(j, dict) else {}
        k = _de_la_plataforma(tok.proyecto_id, j.get("llave_id"))
        if k is None:
            return _json({"ok": False, "error": "solicitud_no_valida"}, 400)
        _uso(k.id, _entero(j.get("peticiones", 1), 100000), _entero(j.get("tokens_in"), 100000000),
             _entero(j.get("tokens_out"), 100000000), 0.0)
        return _json({"ok": True})

    csrf_ext = app.extensions.get("csrf")        # las llamadas de otras plataformas no llevan token CSRF: las protege el Bearer
    if csrf_ext:
        for _vista in (api_pedir, api_reportar, api_uso):
            csrf_ext.exempt(_vista)

    @bp.route("/llaves/token/<int:pid>/generar", methods=["POST"])
    @escribe
    def token_generar(pid):
        """Crea o rota el token de una plataforma. El valor se muestra UNA vez, en esta misma respuesta; el anterior muere al instante."""
        asegurar()
        p = db.session.get(Proyecto, pid)
        if p is None or p.tipo != TIPO_PLATAFORMA:
            abort(404)
        token = "zlk_" + secrets.token_urlsafe(32)
        fila = db.session.get(LlaveToken, pid)
        if fila is None:
            fila = LlaveToken(proyecto_id=pid)
            db.session.add(fila)
        fila.huella_token, fila.ultimos4 = _sha_token(token), token[-4:]
        fila.creado, fila.creado_por, fila.ultimo_uso, fila.activo = datetime.utcnow(), current_user.username, None, True
        registrar("token_llaves", "LlaveToken", pid, f"Token de acceso al pool generado para {p.nombre} ····{token[-4:]}")
        db.session.commit()
        r = make_response(render_template("llaves_token.html", plataforma=p, token=token,
                                          url=request.url_root.rstrip("/")))
        r.headers["Cache-Control"] = "no-store"
        return r

    @bp.route("/llaves/token/<int:pid>/revocar", methods=["POST"])
    @escribe
    def token_revocar(pid):
        asegurar()
        fila = db.session.get(LlaveToken, pid)
        if fila is not None:
            db.session.delete(fila)
            registrar("token_llaves", "LlaveToken", pid, "Token de acceso al pool revocado")
            db.session.commit()
        return volver("token_revocado")

    @bp.route("/llaves/asignar-masivo", methods=["POST"])
    @escribe
    def asignar_masivo():
        """Agrega o quita de plataformas TODAS las llaves globales de un proveedor (por defecto Gemini)."""
        asegurar()
        proveedor = request.form.get("proveedor") or GEMINI
        if proveedor not in PROVEEDORES:
            return mal("proveedor desconocido.")
        accion = request.form.get("accion")
        if accion not in ("agregar", "quitar"):
            return mal("acción desconocida.")
        act = plat_activa()
        destinos = {act.id} if act else destinos_pedidos("proyecto_ids")
        if not destinos:
            return mal("elige al menos una plataforma.")
        ids = [k.id for k in LlaveApi.query.filter(LlaveApi.proveedor == proveedor, LlaveApi.proyecto_id.is_(None),
                                                    LlaveApi.estado != "revocada").all()]
        if not ids:
            return mal("no hay llaves globales de ese proveedor.")
        existentes = {(a.llave_id, a.proyecto_id): a for a in LlavePlat.query.filter(LlavePlat.llave_id.in_(ids)).all()}
        cambios = 0
        for pid in destinos:
            for lid in ids:
                a = existentes.get((lid, pid))
                if accion == "agregar" and a is None:
                    db.session.add(LlavePlat(llave_id=lid, proyecto_id=pid))
                    cambios += 1
                elif accion == "quitar" and a is not None:
                    db.session.delete(a)
                    cambios += 1
        registrar("asignar_llaves", "LlaveApi", None, f"{accion}: {len(ids)} llaves de {proveedor} · {len(destinos)} plataforma(s) · {cambios} cambios")
        db.session.commit()
        return volver("asignada")

    @bp.route("/llaves/<int:lid>/plataformas", methods=["POST"])
    @escribe
    def plataformas_llave(lid):
        """Agrega o quita UNA plataforma a una llave global. Desde la pantalla de una plataforma, «quitar» la saca solo de ella."""
        asegurar()
        k = cargar(lid, compartida_ok=True)
        if k.proyecto_id is not None:
            db.session.rollback()
            return mal("esta llave pertenece a una sola plataforma; solo las globales se comparten.")
        act = plat_activa()
        pid = act.id if act else (int(request.form["proyecto_id"]) if (request.form.get("proyecto_id") or "").isdigit() else None)
        pr = db.session.get(Proyecto, pid) if pid is not None else None
        accion = request.form.get("accion")
        if pr is None or (accion == "agregar" and pr.tipo != TIPO_PLATAFORMA):
            db.session.rollback()
            return mal("plataforma no encontrada.")
        a = db.session.get(LlavePlat, (k.id, pid))
        if accion == "agregar" and a is None:
            db.session.add(LlavePlat(llave_id=k.id, proyecto_id=pid))
        elif accion == "quitar" and a is not None:
            db.session.delete(a)
        else:
            db.session.rollback()
            return volver()
        registrar("asignar_llave", "LlaveApi", k.id, f"{k.proveedor} · {k.etiqueta} · ****{k.ultimos4} · {accion} plataforma #{pid}")
        db.session.commit()
        return volver("asignada")

    @bp.route("/llaves/<int:lid>/probar", methods=["POST"])
    @escribe
    def probar(lid):
        asegurar()
        k = cargar(lid, compartida_ok=True, bloquear=False)
        f = _fernet()
        if k.proveedor != GEMINI or not k.secreto or f is None:
            return mal("solo se pueden probar llaves de Gemini que tengan su valor guardado.")
        try:
            secreto = f.decrypt(k.secreto.encode()).decode()
        except InvalidToken:
            return mal("no se pudo descifrar la llave (¿cambió la clave maestra?).")
        db.session.rollback()          # que no quede abierta una transacción mientras se espera a Google
        r = probar_gemini(secreto, real=request.form.get("modo") == "real")
        k = db.session.get(LlaveApi, lid)
        guardar_prueba(k, r, secreto)
        db.session.commit()
        return volver("probada")

    @bp.route("/llaves/probar-todas", methods=["POST"])
    @escribe
    def probar_todas():
        """Prueba en segundo plano las llaves de Gemini de todo el negocio o, desde una plataforma, solo las suyas."""
        asegurar()
        act = plat_activa()
        q = llaves_de(act.id) if act else LlaveApi.query
        ids = [k.id for k in q.filter(LlaveApi.proveedor == GEMINI, LlaveApi.estado.in_(("activa", "invalida")),
                                      LlaveApi.secreto.isnot(None)).all()]
        if not ids:
            return mal("no hay llaves de Gemini con valor guardado para probar.")
        lanzar_pruebas(ids, request.form.get("modo") == "real", current_user.username)
        return volver("probando")

    @bp.route("/llaves/probar-estado")
    @solo_admin
    def probar_estado():
        with cerrojo:
            e = dict(estado_prueba)
        e["inicio"] = e["inicio"].isoformat() if e.get("inicio") else None
        return jsonify(e)

    @bp.route("/llaves/recifrar", methods=["POST"])
    @escribe
    def recifrar():
        """Tras cambiar LLAVES_MASTER (poniendo la vieja en LLAVES_MASTER_ANT): todo pasa a la clave nueva."""
        asegurar()
        f = _fernet()
        if f is None:
            return mal("No hay clave de cifrado: define SECRET_KEY (o LLAVES_MASTER).")
        n = 0
        for k in LlaveApi.query.filter(LlaveApi.secreto.isnot(None)).with_for_update().all():
            try:
                k.secreto = f.rotate(k.secreto.encode()).decode()
                n += 1
            except InvalidToken:
                db.session.rollback()
                return mal(f"la llave #{k.id} no se pudo descifrar con ninguna clave maestra: no se cambió nada.")
        registrar("recifrar_llaves", "LlaveApi", None, f"{n} llaves re-cifradas con la clave maestra actual")
        db.session.commit()
        return volver("recifrada")

    return bp